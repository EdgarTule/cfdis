package cmd

import (
	"archive/zip"
	"bufio"
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/pem"
	"encoding/xml"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/antchfx/xmlquery"
	"github.com/beevik/etree"
	_ "github.com/mattn/go-sqlite3"
	"github.com/russellhaering/goxmldsig"
	"github.com/youmark/pkcs8"
)

// Custom KeyStore for goxmldsig
type MemoryKeyStore struct {
	key  *rsa.PrivateKey
	cert *x509.Certificate
}
func (m *MemoryKeyStore) GetKeyPair() (*rsa.PrivateKey, []byte, error) {
	return m.key, m.cert.Raw, nil
}

// Structs for parsing responses
type SoapAuthResponse struct {
	XMLName xml.Name `xml:"Envelope"`
	Body    struct {
		AutenticaResponse struct {
			AutenticaResult string `xml:"AutenticaResult"`
		} `xml:"AutenticaResponse"`
	} `xml:"Body"`
}
type Campo struct {
	Nombre string
	Tipo   string
	XPath  string
}

// SatService provides methods to interact with SAT web services.
type SatService struct {
	rfc       string
	rfcDir    string
	key       *rsa.PrivateKey
	cert      *x509.Certificate
	token     string
	tokenPath string
}

// NewSatService creates a new service client.
func NewSatService(rfc string, keyPath string, cerPath string, password []byte) (*SatService, error) {
	homeDir, _ := os.UserHomeDir()
	rfcDir := filepath.Join(homeDir, ".sat", rfc)

	var rsaPrivateKey *rsa.PrivateKey
	var cert *x509.Certificate

	if keyPath != "" && cerPath != "" && password != nil {
		keyBytes, err := ioutil.ReadFile(keyPath)
		if err != nil { return nil, err }
		cerBytes, err := ioutil.ReadFile(cerPath)
		if err != nil { return nil, err }

		privateKey, err := pkcs8.ParsePKCS8PrivateKey(keyBytes, password)
		if err != nil { return nil, err }
		var ok bool
		rsaPrivateKey, ok = privateKey.(*rsa.PrivateKey)
		if !ok { return nil, fmt.Errorf("la llave no es de tipo RSA") }

		// Handle both PEM and DER certificate formats
		var certBytes []byte
		pemBlock, _ := pem.Decode(cerBytes)
		if pemBlock != nil {
			certBytes = pemBlock.Bytes
		} else {
			certBytes = cerBytes // Assume DER
		}
		cert, err = x509.ParseCertificate(certBytes)
		if err != nil { return nil, fmt.Errorf("parsear certificado: %w", err) }
	}

	return &SatService{
		rfc: rfc, rfcDir: rfcDir, key: rsaPrivateKey, cert: cert,
		tokenPath: filepath.Join(rfcDir, "token.txt"),
	}, nil
}

// --- Authentication ---
func (s *SatService) EnsureAuthenticated() error {
	if s.key == nil {
		return fmt.Errorf("las credenciales (e.firma) no se cargaron; no se puede autenticar")
	}
	if info, err := os.Stat(s.tokenPath); err == nil && time.Since(info.ModTime()) < (4*time.Minute) {
		tokenBytes, err := ioutil.ReadFile(s.tokenPath)
		if err == nil {
			s.token = string(tokenBytes)
			fmt.Println("Usando token de autenticación guardado.")
			return nil
		}
	}
	fmt.Println("Token no encontrado o expirado. Solicitando nueva autenticación...")
	return s.authenticate()
}

func (s *SatService) authenticate() error {
	now := time.Now().UTC()
	created := now.Format("2006-01-02T15:04:05.000Z")
	expires := now.Add(5 * time.Minute).Format("2006-01-02T15:04:05.000Z")
	timestampXML := fmt.Sprintf(`<u:Timestamp xmlns:u="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" u:Id="_0"><u:Created>%s</u:Created><u:Expires>%s</u:Expires></u:Timestamp>`, created, expires)
	digestHasher := sha1.New()
	digestHasher.Write([]byte(timestampXML))
	digest := base64.StdEncoding.EncodeToString(digestHasher.Sum(nil))
	signedInfoXML := fmt.Sprintf(`<SignedInfo xmlns="http://www.w3.org/2000/09/xmldsig#"><CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></CanonicalizationMethod><SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"></SignatureMethod><Reference URI="#_0"><Transforms><Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></Transform></Transforms><DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"></DigestMethod><DigestValue>%s</DigestValue></Reference></SignedInfo>`, digest)
	signInfoHasher := sha1.New()
	signInfoHasher.Write([]byte(signedInfoXML))
	signedInfoDigest := signInfoHasher.Sum(nil)
	signatureBytes, err := rsa.SignPKCS1v15(rand.Reader, s.key, crypto.SHA1, signedInfoDigest)
	if err != nil { return fmt.Errorf("firmar digest: %w", err) }
	signature := base64.StdEncoding.EncodeToString(signatureBytes)
	certBase64 := base64.StdEncoding.EncodeToString(s.cert.Raw)
	soapRequest := fmt.Sprintf(`<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" xmlns:u="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"><s:Header><o:Security s:mustUnderstand="1" xmlns:o="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"><u:Timestamp u:Id="_0"><u:Created>%s</u:Created><u:Expires>%s</u:Expires></u:Timestamp><o:BinarySecurityToken u:Id="uuid-ee5df542-c65a-423c-974a-a0cb38f6501a-1" ValueType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3" EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary">%s</o:BinarySecurityToken><Signature xmlns="http://www.w3.org/2000/09/xmldsig#"><SignedInfo><CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/><Reference URI="#_0"><Transforms><Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></Transforms><DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/><DigestValue>%s</DigestValue></Reference></SignedInfo><SignatureValue>%s</SignatureValue><KeyInfo><o:SecurityTokenReference><o:Reference ValueType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3" URI="#uuid-ee5df542-c65a-423c-974a-a0cb38f6501a-1"/></o:SecurityTokenReference></KeyInfo></Signature></o:Security></s:Header><s:Body><Autentica xmlns="http://DescargaMasivaTerceros.gob.mx"/></s:Body></s:Envelope>`, created, expires, certBase64, digest, signature)
	req, err := http.NewRequest("POST", "https://cfdidescargamasivasolicitud.clouda.sat.gob.mx/Autenticacion/Autenticacion.svc", strings.NewReader(soapRequest))
	if err != nil { return err }
	req.Header.Set("Content-Type", "text/xml;charset=UTF-8")
	req.Header.Set("SOAPAction", "http://DescargaMasivaTerceros.gob.mx/IAutenticacion/Autentica")
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil { return err }
	defer resp.Body.Close()
	respBody, _ := ioutil.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK { return fmt.Errorf("respuesta SAT (%d): %s", resp.StatusCode, string(respBody)) }
	var authResponse SoapAuthResponse
	if err := xml.Unmarshal(respBody, &authResponse); err != nil { return fmt.Errorf("parsear respuesta: %w\nRespuesta: %s", err, string(respBody)) }
	if authResponse.Body.AutenticaResponse.AutenticaResult == "" { return fmt.Errorf("token vacío en respuesta: %s", string(respBody)) }

	// Guardar solo el valor del token, no toda la cabecera.
	s.token = fmt.Sprintf("WRAP access_token=\"%s\"", authResponse.Body.AutenticaResponse.AutenticaResult)
	if err := ioutil.WriteFile(s.tokenPath, []byte(s.token), 0644); err != nil { return fmt.Errorf("guardar token: %w", err) }

	fmt.Println("Autenticación exitosa. Token guardado.")
	return nil
}


// --- Generic Sending Logic ---
func (s *SatService) sendSoapRequest(soapAction, url string, envelope *etree.Element) ([]byte, error) {
	doc := etree.NewDocument()
	doc.SetRoot(envelope)
	requestBody, err := doc.WriteToString()
	if err != nil {
		return nil, fmt.Errorf("error al serializar el XML: %w", err)
	}

	req, _ := http.NewRequest("POST", url, strings.NewReader(requestBody))
	req.Header.Set("Content-Type", "text/xml;charset=UTF-8")
	req.Header.Set("SOAPAction", soapAction)
	req.Header.Set("Authorization", s.token)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil { return nil, err }
	defer resp.Body.Close()

	respBody, _ := ioutil.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("respuesta SAT (%d): %s", resp.StatusCode, string(respBody))
	}
	return respBody, nil
}

// buildSoapEnvelope crea el sobre SOAP y firma el nodo especificado.
func (s *SatService) buildSoapEnvelope(bodyContent, nodeToSign *etree.Element) (*etree.Element, error) {
	envelope := etree.NewElement("s:Envelope")
	envelope.CreateAttr("xmlns:s", "http://schemas.xmlsoap.org/soap/envelope/")
	envelope.CreateAttr("xmlns:des", "http://DescargaMasivaTerceros.sat.gob.mx")
	envelope.CreateAttr("xmlns:xd", "http://www.w3.org/2000/09/xmldsig#")
	envelope.CreateElement("s:Header")
	bodyContainer := envelope.CreateElement("s:Body")
	bodyContainer.AddChild(bodyContent)

	// Firmar el nodo correcto
	ctx := dsig.NewDefaultSigningContext(&MemoryKeyStore{key: s.key, cert: s.cert})
	signedNode, err := ctx.SignEnveloped(nodeToSign)
	if err != nil {
		return nil, fmt.Errorf("error al firmar el elemento: %w", err)
	}

	// Reemplazar el nodo original con el firmado
	parent := nodeToSign.Parent()
	parent.RemoveChild(nodeToSign)
	parent.AddChild(signedNode)

	return envelope, nil
}


// --- Service Methods ---
func (s *SatService) SendRequest(reqTipo, reqSubTipo, startDate, endDate string) (string, error) {
	// 1. Construir la estructura XML completa
	var body *etree.Element
	if reqSubTipo == "emitidos" {
		body = etree.NewElement("des:SolicitaDescargaEmitidos")
	} else {
		body = etree.NewElement("des:SolicitaDescargaRecibidos")
	}
	solicitud := body.CreateElement("des:solicitud") // Este es el nodo que se firmará
	solicitud.CreateAttr("FechaInicial", startDate)
	solicitud.CreateAttr("FechaFinal", endDate)
	if reqSubTipo == "emitidos" {
		solicitud.CreateAttr("RfcEmisor", s.rfc)
	} else {
		solicitud.CreateAttr("RfcReceptor", s.rfc)
	}

	if reqTipo == "retenciones" {
		solicitud.CreateAttr("TipoSolicitud", "Retencion")
	} else {
		solicitud.CreateAttr("TipoSolicitud", "CFDI")
	}
	solicitud.CreateAttr("EstadoComprobante", "Vigente")

	// 2. Firmar el nodo <solicitud> y construir el sobre
	envelope, err := s.buildSoapEnvelope(body, solicitud)
	if err != nil {
		return "", err
	}

	// 3. Enviar la petición
	var soapAction string
	if reqSubTipo == "emitidos" {
		soapAction = "http://DescargaMasivaTerceros.sat.gob.mx/ISolicitaDescargaService/SolicitaDescargaEmitidos"
	} else {
		soapAction = "http://DescargaMasivaTerceros.sat.gob.mx/ISolicitaDescargaService/SolicitaDescargaRecibidos"
	}
	respBody, err := s.sendSoapRequest(
		soapAction,
		"https://cfdidescargamasivasolicitud.clouda.sat.gob.mx/SolicitaDescargaService.svc",
		envelope,
	)
	if err != nil { return "", err }

	// 4. Parsear la respuesta
	doc, err := xmlquery.Parse(strings.NewReader(string(respBody)))
	if err != nil {
		return "", fmt.Errorf("error al parsear XML de respuesta: %w", err)
	}
	faultNode := xmlquery.FindOne(doc, "//*[local-name()='Fault']")
	if faultNode != nil {
		faultCode := xmlquery.FindOne(faultNode, "//*[local-name()='faultcode']")
		faultString := xmlquery.FindOne(faultNode, "//*[local-name()='faultstring']")
		return "", fmt.Errorf("el servidor SAT devolvió un error (SOAP Fault): [%s] %s", faultCode.InnerText(), faultString.InnerText())
	}
	resultNode := xmlquery.FindOne(doc, "//*[@CodEstatus and @IdSolicitud]")
	if resultNode == nil {
		return "", fmt.Errorf("no se encontró un nodo de resultado con CodEstatus y IdSolicitud ni 'Fault' en la respuesta. Respuesta cruda: %s", string(respBody))
	}
	codEstatus := resultNode.SelectAttr("CodEstatus")
	mensaje := resultNode.SelectAttr("Mensaje")
	if codEstatus != "5000" {
		return "", fmt.Errorf("error del SAT: [%s] %s", codEstatus, mensaje)
	}
	idSolicitud := resultNode.SelectAttr("IdSolicitud")
	if idSolicitud == "" {
		return "", fmt.Errorf("el IdSolicitud vino vacío en una respuesta exitosa")
	}
	return idSolicitud, nil
}

func (s *SatService) VerifyRequest(requestID string) (int, []string, error) {
	body := etree.NewElement("des:VerificaSolicitudDescarga")
	solicitud := body.CreateElement("des:solicitud")
	solicitud.CreateAttr("IdSolicitud", requestID)
	solicitud.CreateAttr("RfcSolicitante", s.rfc)

	envelope, err := s.buildSoapEnvelope(body, solicitud)
	if err != nil {
		return 0, nil, err
	}

	respBody, err := s.sendSoapRequest(
		"http://DescargaMasivaTerceros.sat.gob.mx/IVerificaSolicitudDescargaService/VerificaSolicitudDescarga",
		"https://cfdidescargamasivasolicitud.clouda.sat.gob.mx/VerificaSolicitudDescargaService.svc",
		envelope,
	)
	if err != nil { return 0, nil, err }

	doc, err := xmlquery.Parse(strings.NewReader(string(respBody)))
	if err != nil {
		return 0, nil, fmt.Errorf("error al parsear XML de respuesta: %w", err)
	}
	faultNode := xmlquery.FindOne(doc, "//*[local-name()='Fault']")
	if faultNode != nil {
		faultCode := xmlquery.FindOne(faultNode, "//*[local-name()='faultcode']")
		faultString := xmlquery.FindOne(faultNode, "//*[local-name()='faultstring']")
		return 0, nil, fmt.Errorf("el servidor SAT devolvió un error (SOAP Fault): [%s] %s", faultCode.InnerText(), faultString.InnerText())
	}
	resultNode := xmlquery.FindOne(doc, "//*[@CodEstatus and @EstadoSolicitud]")
	if resultNode == nil {
		return 0, nil, fmt.Errorf("no se encontró un nodo de resultado válido ni 'Fault' en la respuesta. Respuesta cruda: %s", string(respBody))
	}
	codEstatus := resultNode.SelectAttr("CodEstatus")
	if codEstatus != "5000" {
		mensaje := resultNode.SelectAttr("Mensaje")
		return 0, nil, fmt.Errorf("error del SAT: [%s] %s", codEstatus, mensaje)
	}
	estadoSolicitud := resultNode.SelectAttr("EstadoSolicitud")
	status, _ := strconv.Atoi(estadoSolicitud)
	var downloadIDs []string
	idPaquetesNode := xmlquery.FindOne(resultNode, "//*[local-name()='IdsPaquetes']")
	if idPaquetesNode != nil {
		for _, n := range idPaquetesNode.SelectElements("*") {
			downloadIDs = append(downloadIDs, n.InnerText())
		}
	}
	return status, downloadIDs, nil
}

func (s *SatService) DownloadPackage(packageID string, targetDir string) error {
	body := etree.NewElement("des:PeticionDescargaMasivaTercerosEntrada")
	peticion := body.CreateElement("des:peticionDescarga")
	peticion.CreateAttr("IdPaquete", packageID)
	peticion.CreateAttr("RfcSolicitante", s.rfc)

	envelope, err := s.buildSoapEnvelope(body, peticion)
	if err != nil {
		return err
	}

	respBody, err := s.sendSoapRequest(
		"http://DescargaMasivaTerceros.sat.gob.mx/IDescargaMasivaTercerosService/Descargar",
		"https://cfdidescargamasiva.clouda.sat.gob.mx/DescargaMasivaService.svc",
		envelope,
	)
	if err != nil { return err }

	doc, err := xmlquery.Parse(strings.NewReader(string(respBody)))
	if err != nil {
		return fmt.Errorf("error al parsear XML de respuesta: %w", err)
	}
	faultNode := xmlquery.FindOne(doc, "//*[local-name()='Fault']")
	if faultNode != nil {
		faultCode := xmlquery.FindOne(faultNode, "//*[local-name()='faultcode']")
		faultString := xmlquery.FindOne(faultNode, "//*[local-name()='faultstring']")
		return fmt.Errorf("el servidor SAT devolvió un error (SOAP Fault): [%s] %s", faultCode.InnerText(), faultString.InnerText())
	}
	paqueteNode := xmlquery.FindOne(doc, "//*[local-name()='Paquete']")
	if paqueteNode == nil {
		return fmt.Errorf("no se encontró el nodo 'Paquete' ni 'Fault' en la respuesta. Respuesta cruda: %s", string(respBody))
	}
	zipData, err := base64.StdEncoding.DecodeString(paqueteNode.InnerText())
	if err != nil {
		return fmt.Errorf("decodificar paquete: %w", err)
	}

	zipReader, err := zip.NewReader(bytes.NewReader(zipData), int64(len(zipData)))
	if err != nil { return err }

	for _, f := range zipReader.File {
		fpath := filepath.Join(targetDir, f.Name)
		if _, err := os.Stat(fpath); err == nil { continue }
		if f.FileInfo().IsDir() {
			os.MkdirAll(fpath, os.ModePerm)
			continue
		}
		if err := os.MkdirAll(filepath.Dir(fpath), os.ModePerm); err != nil { return err }
		outFile, err := os.OpenFile(fpath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
		if err != nil { return err }
		rc, err := f.Open()
		if err != nil { return err }
		_, err = io.Copy(outFile, rc)
		outFile.Close()
		rc.Close()
		if err != nil { return err }
	}
	return nil
}

func (s *SatService) SyncDatabase() error {
	camposFile := filepath.Join(s.rfcDir, "campos")
	if _, err := os.Stat(camposFile); os.IsNotExist(err) {
		defaultCampos := `uuid CHAR(50) string(//*[local-name()='TimbreFiscalDigital']/@UUID)
emisor_rfc CHAR(13) string(//*[local-name()='Emisor']/@Rfc)
receptor_rfc CHAR(13) string(//*[local-name()='Receptor']/@Rfc)
fecha DATETIME string(//@Fecha)
total DECIMAL(18,2) string(//@Total)`
		if err := ioutil.WriteFile(camposFile, []byte(defaultCampos), 0644); err != nil {
			return fmt.Errorf("no se pudo crear el archivo de campos por defecto: %w", err)
		}
		fmt.Printf("Archivo 'campos' no encontrado. Se creó uno por defecto en %s\n", camposFile)
	}

	campos, err := parseCamposFile(camposFile)
	if err != nil {
		return err
	}

	dbPath := filepath.Join(s.rfcDir, "sat.db")
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return err
	}
	defer db.Close()

	if err := createTable(db, campos); err != nil {
		return err
	}

	cfdiDir := filepath.Join(s.rfcDir, "cfdis")
	files, err := ioutil.ReadDir(cfdiDir)
	if err != nil {
		return fmt.Errorf("no se pudo leer el directorio de cfdis: %w", err)
	}

	for _, file := range files {
		if !strings.HasSuffix(file.Name(), ".xml") {
			continue
		}
		xmlPath := filepath.Join(cfdiDir, file.Name())
		if err := s.processXMLFile(db, xmlPath, campos); err != nil {
			fmt.Printf("Error procesando %s: %v\n", file.Name(), err)
		}
	}

	return nil
}

func parseCamposFile(path string) ([]Campo, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var campos []Campo
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		parts := strings.Fields(scanner.Text())
		if len(parts) < 3 {
			continue
		}
		campos = append(campos, Campo{
			Nombre: parts[0],
			Tipo:   parts[1],
			XPath:  strings.Join(parts[2:], " "),
		})
	}
	return campos, scanner.Err()
}

func createTable(db *sql.DB, campos []Campo) error {
	var sb strings.Builder
	sb.WriteString("CREATE TABLE IF NOT EXISTS cfdis (id INTEGER PRIMARY KEY AUTOINCREMENT, uuid TEXT UNIQUE, xml_path TEXT, ")
	for i, campo := range campos {
		sb.WriteString(fmt.Sprintf("%s %s", campo.Nombre, campo.Tipo))
		if i < len(campos)-1 {
			sb.WriteString(", ")
		}
	}
	sb.WriteString(");")

	_, err := db.Exec(sb.String())
	return err
}

func (s *SatService) processXMLFile(db *sql.DB, xmlPath string, campos []Campo) error {
	xmlBytes, err := ioutil.ReadFile(xmlPath)
	if err != nil {
		return err
	}

	cleanedXML := strings.NewReader(
		strings.ReplaceAll(string(xmlBytes), "cfdi:", ""),
	)
	doc, err := xmlquery.Parse(cleanedXML)
	if err != nil {
		return fmt.Errorf("parsear xml: %w", err)
	}

	uuidNode := xmlquery.FindOne(doc, "//*[local-name()='TimbreFiscalDigital']/@UUID")
	if uuidNode == nil {
		return fmt.Errorf("no se encontró el UUID en el XML")
	}
	uuid := uuidNode.InnerText()

	var count int
	err = db.QueryRow("SELECT COUNT(*) FROM cfdis WHERE uuid = ?", uuid).Scan(&count)
	if err != nil {
		return err
	}
	if count > 0 {
		return nil
	}
	fmt.Printf("Insertando XML en la DB: %s\n", filepath.Base(xmlPath))

	values := make([]interface{}, len(campos)+2)
	values[0] = uuid
	values[1] = xmlPath
	for i, campo := range campos {
		node := xmlquery.FindOne(doc, campo.XPath)
		if node != nil {
			values[i+2] = node.InnerText()
		} else {
			values[i+2] = nil
		}
	}

	var cols, placeholders strings.Builder
	cols.WriteString("uuid, xml_path")
	placeholders.WriteString("?, ?")
	for _, campo := range campos {
		cols.WriteString(", " + campo.Nombre)
		placeholders.WriteString(", ?")
	}

	stmt := fmt.Sprintf("INSERT INTO cfdis (%s) VALUES (%s)", cols.String(), placeholders.String())
	_, err = db.Exec(stmt, values...)
	return err
}
