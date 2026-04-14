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

	"crypto/md5"
	"encoding/hex"
	"github.com/antchfx/xmlquery"
	"github.com/beevik/etree"
	"github.com/russellhaering/goxmldsig"
	"github.com/youmark/pkcs8"
	_ "modernc.org/sqlite"
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
	rfc         string
	rfcDir      string
	key         *rsa.PrivateKey
	cert        *x509.Certificate
	token       string
	tokenPath   string
	serviceType string // "cfdi" o "retenciones"
}

// NewSatService creates a new service client.
func NewSatService(rfc string, keyPath string, cerPath string, password []byte) (*SatService, error) {
	homeDir, _ := os.UserHomeDir()
	rfcDir := filepath.Join(homeDir, ".sat", rfc)
	os.MkdirAll(rfcDir, 0755)

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
		serviceType: "cfdi",
		tokenPath:   filepath.Join(rfcDir, "token_cfdi.txt"),
	}, nil
}

func (s *SatService) SetServiceType(t string) {
	s.serviceType = t
	s.tokenPath = filepath.Join(s.rfcDir, "token_"+t+".txt")
	s.token = "" // Reset token to force reload/re-auth if type changes
}

func (s *SatService) getBaseURL(service string) string {
	prefix := "cfdi"
	if s.serviceType == "retenciones" {
		prefix = "reten"
	}

	switch service {
	case "auth", "solicita", "verifica":
		return fmt.Sprintf("https://%sdescargamasivasolicitud.clouda.sat.gob.mx", prefix)
	case "descarga":
		return fmt.Sprintf("https://%sdescargamasiva.clouda.sat.gob.mx", prefix)
	default:
		return ""
	}
}

// --- Authentication ---
func (s *SatService) EnsureAuthenticated() error {
	if s.key == nil {
		return fmt.Errorf("las credenciales (e.firma) no se cargaron; no se puede autenticar")
	}
	// Si cambiamos de tipo de servicio, el tokenPath ya fue actualizado en SetServiceType.
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
	authURL := s.getBaseURL("auth") + "/Autenticacion/Autenticacion.svc"
	req, err := http.NewRequest("POST", authURL, strings.NewReader(soapRequest))
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
func (s *SatService) SendRequest(reqSubTipo, startDate, endDate string) (string, error) {
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
	solicitud.CreateAttr("RfcSolicitante", s.rfc)
	if reqSubTipo == "emitidos" {
		solicitud.CreateAttr("RfcEmisor", s.rfc)
	} else {
		solicitud.CreateAttr("RfcReceptor", s.rfc)
	}

	// El valor de TipoSolicitud siempre debe ser CFDI o Metadata.
	// Para retenciones, se usa el endpoint de retenciones pero el valor sigue siendo CFDI.
	solicitud.CreateAttr("TipoSolicitud", "CFDI")
	solicitud.CreateAttr("EstadoComprobante", "Vigente")

	// 2. Firmar el nodo <solicitud> y construir el sobre
	envelope, err := s.buildSoapEnvelope(body, solicitud)
	if err != nil {
		return "", err
	}

	// 3. Enviar la petición
	var soapAction string
	ns := "http://DescargaMasivaTerceros.sat.gob.mx"
	if reqSubTipo == "emitidos" {
		soapAction = ns + "/ISolicitaDescargaService/SolicitaDescargaEmitidos"
	} else {
		soapAction = ns + "/ISolicitaDescargaService/SolicitaDescargaRecibidos"
	}
	solicitaURL := s.getBaseURL("solicita") + "/SolicitaDescargaService.svc"
	respBody, err := s.sendSoapRequest(
		soapAction,
		solicitaURL,
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

func (s *SatService) VerifyRequest(requestID string) (int, []string, string, string, error) {
	body := etree.NewElement("des:VerificaSolicitudDescarga")
	solicitud := body.CreateElement("des:solicitud")
	solicitud.CreateAttr("IdSolicitud", requestID)
	solicitud.CreateAttr("RfcSolicitante", s.rfc)

	envelope, err := s.buildSoapEnvelope(body, solicitud)
	if err != nil {
		return 0, nil, "", "", err
	}

	verificaURL := s.getBaseURL("verifica") + "/VerificaSolicitudDescargaService.svc"
	respBody, err := s.sendSoapRequest(
		"http://DescargaMasivaTerceros.sat.gob.mx/IVerificaSolicitudDescargaService/VerificaSolicitudDescarga",
		verificaURL,
		envelope,
	)
	if err != nil {
		return 0, nil, "", "", err
	}

	doc, err := xmlquery.Parse(strings.NewReader(string(respBody)))
	if err != nil {
		return 0, nil, "", "", fmt.Errorf("error al parsear XML de respuesta: %w", err)
	}
	faultNode := xmlquery.FindOne(doc, "//*[local-name()='Fault']")
	if faultNode != nil {
		faultCode := xmlquery.FindOne(faultNode, "//*[local-name()='faultcode']")
		faultString := xmlquery.FindOne(faultNode, "//*[local-name()='faultstring']")
		return 0, nil, "", "", fmt.Errorf("el servidor SAT devolvió un error (SOAP Fault): [%s] %s", faultCode.InnerText(), faultString.InnerText())
	}
	resultNode := xmlquery.FindOne(doc, "//*[@CodEstatus and @EstadoSolicitud]")
	if resultNode == nil {
		return 0, nil, "", "", fmt.Errorf("no se encontró un nodo de resultado válido ni 'Fault' en la respuesta. Respuesta cruda: %s", string(respBody))
	}
	codEstatus := resultNode.SelectAttr("CodEstatus")
	if codEstatus != "5000" {
		mensaje := resultNode.SelectAttr("Mensaje")
		return 0, nil, "", "", fmt.Errorf("error del SAT: [%s] %s", codEstatus, mensaje)
	}
	estadoSolicitud := resultNode.SelectAttr("EstadoSolicitud")
	status, _ := strconv.Atoi(estadoSolicitud)
	codigoEstadoSolicitud := resultNode.SelectAttr("CodigoEstadoSolicitud")
	mensaje := resultNode.SelectAttr("Mensaje")

	var downloadIDs []string
	idPaquetesNode := xmlquery.FindOne(resultNode, "//*[local-name()='IdsPaquetes']")
	if idPaquetesNode != nil {
		for _, n := range idPaquetesNode.SelectElements("*") {
			downloadIDs = append(downloadIDs, n.InnerText())
		}
	}
	return status, downloadIDs, codigoEstadoSolicitud, mensaje, nil
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

	descargaURL := s.getBaseURL("descarga") + "/DescargaMasivaService.svc"
	respBody, err := s.sendSoapRequest(
		"http://DescargaMasivaTerceros.sat.gob.mx/IDescargaMasivaTercerosService/Descargar",
		descargaURL,
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
	dbPath := filepath.Join(s.rfcDir, "sat.db")
	hashFile := filepath.Join(s.rfcDir, "campos.md5")

	// Crear archivo de campos por defecto si no existe
	if _, err := os.Stat(camposFile); os.IsNotExist(err) {
		defaultCampos := `# ==============================================================================
# GUÍA DEFINITIVA DE CAMPOS CFDI (3.3 Y 4.0) Y RETENCIONES (1.0 Y 2.0)
# Formato: nombre_columna TIPO_SQL XPath
# ==============================================================================

# CAMPOS GENERALES DEL COMPROBANTE (CFDI)
version TEXT //*[local-name()='Comprobante']/@Version
serie TEXT //*[local-name()='Comprobante']/@Serie
folio TEXT //*[local-name()='Comprobante']/@Folio
fecha DATETIME //*[local-name()='Comprobante']/@Fecha
forma_pago TEXT //*[local-name()='Comprobante']/@FormaPago
no_certificado TEXT //*[local-name()='Comprobante']/@NoCertificado
condiciones_pago TEXT //*[local-name()='Comprobante']/@CondicionesDePago
subtotal DECIMAL(18,2) //*[local-name()='Comprobante']/@SubTotal
descuento DECIMAL(18,2) //*[local-name()='Comprobante']/@Descuento
moneda TEXT //*[local-name()='Comprobante']/@Moneda
tipo_cambio DECIMAL(18,2) //*[local-name()='Comprobante']/@TipoCambio
total DECIMAL(18,2) //*[local-name()='Comprobante']/@Total
tipo_comprobante TEXT //*[local-name()='Comprobante']/@TipoDeComprobante
exportacion TEXT //*[local-name()='Comprobante']/@Exportacion
metodo_pago TEXT //*[local-name()='Comprobante']/@MetodoPago
lugar_expedicion TEXT //*[local-name()='Comprobante']/@LugarExpedicion
confirmacion TEXT //*[local-name()='Comprobante']/@Confirmacion

# INFORMACIÓN GLOBAL (CFDI 4.0)
global_periodicidad TEXT //*[local-name()='InformacionGlobal']/@Periodicidad
global_meses TEXT //*[local-name()='InformacionGlobal']/@Meses
global_año TEXT //*[local-name()='InformacionGlobal']/@Año

# CFDI RELACIONADOS (PRIMER REGISTRO)
relacion_tipo TEXT //*[local-name()='CfdiRelacionados']/@TipoRelacion
relacion_uuid TEXT //*[local-name()='CfdiRelacionado']/@UUID

# EMISOR (CFDI)
emisor_rfc TEXT //*[local-name()='Emisor']/@Rfc
emisor_nombre TEXT //*[local-name()='Emisor']/@Nombre
emisor_regimen_fiscal TEXT //*[local-name()='Emisor']/@RegimenFiscal

# RECEPTOR (CFDI)
receptor_rfc TEXT //*[local-name()='Receptor']/@Rfc
receptor_nombre TEXT //*[local-name()='Receptor']/@Nombre
receptor_domicilio_fiscal TEXT //*[local-name()='Receptor']/@DomicilioFiscalReceptor
receptor_regimen_fiscal TEXT //*[local-name()='Receptor']/@RegimenFiscalReceptor
receptor_uso_cfdi TEXT //*[local-name()='Receptor']/@UsoCFDI

# CONCEPTOS (EXTRACCIÓN DEL PRIMER CONCEPTO)
concepto_clave_prod_serv TEXT //*[local-name()='Concepto'][1]/@ClaveProdServ
concepto_descripcion TEXT //*[local-name()='Concepto'][1]/@Descripcion
concepto_cantidad DECIMAL(18,4) //*[local-name()='Concepto'][1]/@Cantidad
concepto_valor_unitario DECIMAL(18,2) //*[local-name()='Concepto'][1]/@ValorUnitario
concepto_importe DECIMAL(18,2) //*[local-name()='Concepto'][1]/@Importe
concepto_objeto_imp TEXT //*[local-name()='Concepto'][1]/@ObjetoImp

# TIMBRE FISCAL DIGITAL (TFD)
tfd_version TEXT //*[local-name()='TimbreFiscalDigital']/@Version
tfd_uuid TEXT //*[local-name()='TimbreFiscalDigital']/@UUID
tfd_fecha_timbrado DATETIME //*[local-name()='TimbreFiscalDigital']/@FechaTimbrado
tfd_rfc_prov_certif TEXT //*[local-name()='TimbreFiscalDigital']/@RfcProvCertif
tfd_no_certificado_sat TEXT //*[local-name()='TimbreFiscalDigital']/@NoCertificadoSAT

# IMPUESTOS FEDERALES (TOTALES GENERALES)
total_impuestos_retenidos DECIMAL(18,2) //*[local-name()='Impuestos']/@TotalImpuestosRetenidos
total_impuestos_trasladados DECIMAL(18,2) //*[local-name()='Impuestos']/@TotalImpuestosTrasladados

# DESGLOSE DE IMPUESTOS FEDERALES (FILTRADO POR TIPO)
iva_trasladado DECIMAL(18,2) //*[local-name()='Traslado'][@Impuesto='002']/@Importe
iva_retenido DECIMAL(18,2) //*[local-name()='Retencion'][@Impuesto='002']/@Importe
isr_retenido DECIMAL(18,2) //*[local-name()='Retencion'][@Impuesto='001']/@Importe
ieps_trasladado DECIMAL(18,2) //*[local-name()='Traslado'][@Impuesto='003']/@Importe

# IMPUESTOS LOCALES
total_retenciones_locales DECIMAL(18,2) //*[local-name()='ImpuestosLocales']/@TotaldeRetenciones
total_traslados_locales DECIMAL(18,2) //*[local-name()='ImpuestosLocales']/@TotaldeTraslados

# ------------------------------------------------------------------------------
# RETENCIONES E INFORMACIÓN DE PAGOS (COMPATIBLE v1.0 Y v2.0)
# ------------------------------------------------------------------------------
reten_version TEXT //*[local-name()='Retenciones']/@Version
reten_folio_int TEXT //*[local-name()='Retenciones']/@FolioInt
reten_fecha_exp DATETIME //*[local-name()='Retenciones']/@FechaExp
reten_cve_retenc TEXT //*[local-name()='Retenciones']/@CveRetenc
reten_desc_retenc TEXT //*[local-name()='Retenciones']/@DescRetenc

# EMISOR Y RECEPTOR (RETENCIONES)
# Nota: Soporta variantes v1.0 (@RfcE, @RFCEmisor) y v2.0 (@RfcEmisor)
reten_emisor_rfc TEXT //*[local-name()='Emisor']/@RfcE | //*[local-name()='Emisor']/@RFCEmisor | //*[local-name()='Emisor']/@RfcEmisor
reten_emisor_nombre TEXT //*[local-name()='Emisor']/@NomDenRazSocE | //*[local-name()='Emisor']/@Nombre
# Receptor: v1.0 usa nodo Nacional (@RFCRecep) o directo (@RfcR); v2.0 atributos directos (@RfcReceptor)
reten_receptor_rfc TEXT //*[local-name()='Receptor']/*[local-name()='Nacional']/@RFCRecep | //*[local-name()='Receptor']/@RfcR | //*[local-name()='Receptor']/@RfcReceptor
reten_receptor_nombre TEXT //*[local-name()='Receptor']/*[local-name()='Nacional']/@NomDenRazSocR | //*[local-name()='Receptor']/@Nombre

# PERIODO Y TOTALES
reten_periodo_mes_ini INTEGER //*[local-name()='Periodo']/@MesIni
reten_periodo_mes_fin INTEGER //*[local-name()='Periodo']/@MesFin
reten_periodo_ejercicio INTEGER //*[local-name()='Periodo']/@Ejerc | //*[local-name()='Periodo']/@Ejercicio

reten_total_operacion DECIMAL(18,2) //*[local-name()='Totales']/@montoTotOper | //*[local-name()='Totales']/@MontoTotOper
reten_total_exento DECIMAL(18,2) //*[local-name()='Totales']/@montoTotExent | //*[local-name()='Totales']/@MontoTotExent
reten_total_gravado DECIMAL(18,2) //*[local-name()='Totales']/@montoTotGrav | //*[local-name()='Totales']/@MontoTotGrav
reten_total_retenido DECIMAL(18,2) //*[local-name()='Totales']/@montoTotRet | //*[local-name()='Totales']/@MontoTotRet
reten_total_iva_retenido DECIMAL(18,2) //*[local-name()='Totales']/@montoTotIVARet | //*[local-name()='Totales']/@MontoTotIVARet

# DESGLOSE DE RETENCIONES ESPECÍFICAS (HASTA 3 IMPUESTOS)
reten_imp1_base DECIMAL(18,2) //*[local-name()='ImpRetenidos'][1]/@BaseRet
reten_imp1_impuesto TEXT //*[local-name()='ImpRetenidos'][1]/@Impuesto | //*[local-name()='ImpRetenidos'][1]/@ImpuestoRet
reten_imp1_monto DECIMAL(18,2) //*[local-name()='ImpRetenidos'][1]/@montoRet | //*[local-name()='ImpRetenidos'][1]/@MontoRet

reten_imp2_base DECIMAL(18,2) //*[local-name()='ImpRetenidos'][2]/@BaseRet
reten_imp2_impuesto TEXT //*[local-name()='ImpRetenidos'][2]/@Impuesto | //*[local-name()='ImpRetenidos'][2]/@ImpuestoRet
reten_imp2_monto DECIMAL(18,2) //*[local-name()='ImpRetenidos'][2]/@montoRet | //*[local-name()='ImpRetenidos'][2]/@MontoRet

reten_imp3_base DECIMAL(18,2) //*[local-name()='ImpRetenidos'][3]/@BaseRet
reten_imp3_impuesto TEXT //*[local-name()='ImpRetenidos'][3]/@Impuesto | //*[local-name()='ImpRetenidos'][3]/@ImpuestoRet
reten_imp3_monto DECIMAL(18,2) //*[local-name()='ImpRetenidos'][3]/@montoRet | //*[local-name()='ImpRetenidos'][3]/@MontoRet

# ------------------------------------------------------------------------------
# COMPLEMENTOS ESPECÍFICOS (CFDI)
# ------------------------------------------------------------------------------

# COMPLEMENTO DE NOMINA (1.2) - GENERAL
nomina_version TEXT //*[local-name()='Nomina']/@Version
nomina_tipo_nomina TEXT //*[local-name()='Nomina']/@TipoNomina
nomina_fecha_pago TEXT //*[local-name()='Nomina']/@FechaPago
nomina_total_percepciones DECIMAL(18,2) //*[local-name()='Nomina']/@TotalPercepciones
nomina_total_deducciones DECIMAL(18,2) //*[local-name()='Nomina']/@TotalDeducciones
nomina_total_otros_pagos DECIMAL(18,2) //*[local-name()='Nomina']/@TotalOtrosPagos
nomina_receptor_num_empleado TEXT //*[local-name()='Nomina']/*[local-name()='Receptor']/@NumEmpleado
nomina_receptor_curp TEXT //*[local-name()='Nomina']/*[local-name()='Receptor']/@Curp

# DESGLOSE DE PERCEPCIONES (POR CÓDIGO SAT)
nom_perc_sueldos_grav DECIMAL(18,2) //*[local-name()='Percepcion'][@TipoPercepcion='001']/@ImporteGravado
nom_perc_sueldos_exen DECIMAL(18,2) //*[local-name()='Percepcion'][@TipoPercepcion='001']/@ImporteExento
nom_perc_aguinaldo_grav DECIMAL(18,2) //*[local-name()='Percepcion'][@TipoPercepcion='002']/@ImporteGravado
nom_perc_aguinaldo_exen DECIMAL(18,2) //*[local-name()='Percepcion'][@TipoPercepcion='002']/@ImporteExento
nom_perc_ptu_grav DECIMAL(18,2) //*[local-name()='Percepcion'][@TipoPercepcion='003']/@ImporteGravado
nom_perc_ptu_exen DECIMAL(18,2) //*[local-name()='Percepcion'][@TipoPercepcion='003']/@ImporteExento
nom_perc_prima_vac_grav DECIMAL(18,2) //*[local-name()='Percepcion'][@TipoPercepcion='022']/@ImporteGravado
nom_perc_prima_vac_exen DECIMAL(18,2) //*[local-name()='Percepcion'][@TipoPercepcion='022']/@ImporteExento
nom_perc_prima_dom_grav DECIMAL(18,2) //*[local-name()='Percepcion'][@TipoPercepcion='023']/@ImporteGravado
nom_perc_prima_dom_exen DECIMAL(18,2) //*[local-name()='Percepcion'][@TipoPercepcion='023']/@ImporteExento
nom_perc_horas_ext_grav DECIMAL(18,2) //*[local-name()='Percepcion'][@TipoPercepcion='019']/@ImporteGravado
nom_perc_horas_ext_exen DECIMAL(18,2) //*[local-name()='Percepcion'][@TipoPercepcion='019']/@ImporteExento

# DESGLOSE DE DEDUCCIONES (POR CÓDIGO SAT)
nom_ded_seg_social DECIMAL(18,2) //*[local-name()='Deduccion'][@TipoDeduccion='001']/@Importe
nom_ded_isr DECIMAL(18,2) //*[local-name()='Deduccion'][@TipoDeduccion='002']/@Importe
nom_ded_infonavit DECIMAL(18,2) //*[local-name()='Deduccion'][@TipoDeduccion='009']/@Importe
nom_ded_prestamos DECIMAL(18,2) //*[local-name()='Deduccion'][@TipoDeduccion='004']/@Importe
nom_ded_cuota_sindical DECIMAL(18,2) //*[local-name()='Deduccion'][@TipoDeduccion='005']/@Importe

# COMPLEMENTO DE PAGO (RECIBO ELECTRÓNICO DE PAGOS 2.0)
pagos_version TEXT //*[local-name()='Pagos']/@Version
pagos_monto_total_pagos DECIMAL(18,2) //*[local-name()='Totales']/@MontoTotalPagos
pagos_total_traslados_impuesto_iva_16 DECIMAL(18,2) //*[local-name()='Totales']/@TotalTrasladosImpuestoIVA16

# COMPLEMENTO CARTA PORTE (2.0/3.0)
cp_version TEXT //*[local-name()='CartaPorte']/@Version
cp_transp_internac TEXT //*[local-name()='CartaPorte']/@TranspInternac
cp_total_dist_recorrida DECIMAL(18,2) //*[local-name()='CartaPorte']/@TotalDistRecorrida`
		if err := ioutil.WriteFile(camposFile, []byte(defaultCampos), 0644); err != nil {
			return fmt.Errorf("no se pudo crear el archivo de campos por defecto: %w", err)
		}
		fmt.Printf("Archivo 'campos' no encontrado. Se creó uno por defecto en %s\n", camposFile)
	}

	// Comprobar si el archivo campos ha cambiado
	camposBytes, err := ioutil.ReadFile(camposFile)
	if err != nil {
		return fmt.Errorf("no se pudo leer el archivo de campos: %w", err)
	}
	currentHash := md5.Sum(camposBytes)
	currentHashStr := hex.EncodeToString(currentHash[:])

	savedHashBytes, err := ioutil.ReadFile(hashFile)
	if err == nil && string(savedHashBytes) != currentHashStr {
		fmt.Println("El archivo 'campos' ha cambiado. Re-sincronizando la base de datos desde cero...")
		if err := os.Remove(dbPath); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("no se pudo borrar la base de datos antigua: %w", err)
		}
	}

	// Proceder con la sincronización
	campos, err := parseCamposFile(camposFile)
	if err != nil {
		return err
	}

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return err
	}
	defer db.Close()

	if err := createTable(db, campos); err != nil {
		return err
	}

	// Asegurar que la columna 'tipo' exista para retrocompatibilidad
	_, _ = db.Exec("ALTER TABLE cfdis ADD COLUMN tipo TEXT")

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

	// Guardar el hash del archivo de campos actual para futuras comparaciones
	if err := ioutil.WriteFile(hashFile, []byte(currentHashStr), 0644); err != nil {
		return fmt.Errorf("no se pudo guardar el hash del archivo de campos: %w", err)
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
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Fields(line)
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
	sb.WriteString("CREATE TABLE IF NOT EXISTS cfdis (id INTEGER PRIMARY KEY AUTOINCREMENT, uuid TEXT UNIQUE, xml_path TEXT, tipo TEXT, ")
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

	doc, err := xmlquery.Parse(strings.NewReader(string(xmlBytes)))
	if err != nil {
		return fmt.Errorf("parsear xml: %w", err)
	}

	// UUID se maneja por separado ya que es la clave principal.
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

	// Determinar el tipo de comprobante
	tipo := "cfdi"
	if xmlquery.FindOne(doc, "//*[local-name()='Retenciones']") != nil {
		tipo = "retenciones"
	}

	values := make([]interface{}, len(campos)+3)
	values[0] = uuid
	values[1] = xmlPath
	values[2] = tipo
	for i, campo := range campos {
		node := xmlquery.FindOne(doc, campo.XPath)
		if node != nil {
			values[i+3] = node.InnerText()
		} else {
			values[i+3] = nil
		}
	}

	var cols, placeholders strings.Builder
	cols.WriteString("uuid, xml_path, tipo")
	placeholders.WriteString("?, ?, ?")
	for _, campo := range campos {
		cols.WriteString(", " + campo.Nombre)
		placeholders.WriteString(", ?")
	}

	stmt := fmt.Sprintf("INSERT INTO cfdis (%s) VALUES (%s)", cols.String(), placeholders.String())
	_, err = db.Exec(stmt, values...)
	return err
}
