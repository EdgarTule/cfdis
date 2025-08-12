package main

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"github.com/youmark/pkcs8"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// SatClient manages the state and methods for interacting with the SAT WS.
type SatClient struct {
	rfc        string
	httpClient *http.Client
	token      string
	cert       *x509.Certificate
	privateKey interface{}
	verbose    bool
}

// NewSatClient creates a new client for a given RFC.
// It loads the certificate and private key from the config directory.
func NewSatClient(rfc, password string) (*SatClient, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("error getting user home directory: %w", err)
	}
	rfcPath := filepath.Join(homeDir, ".satxml", rfc)

	// Load certificate
	certPath := filepath.Join(rfcPath, "cer.cer")
	certData, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read certificate file: %w", err)
	}
	cert, err := x509.ParseCertificate(certData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	// Load and decrypt private key
	keyPath := filepath.Join(rfcPath, "key.key")
	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read private key file: %w", err)
	}
	privateKey, err := pkcs8.ParsePKCS8PrivateKey(keyData, []byte(password))
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt private key (check password?): %w", err)
	}

	return &SatClient{
		rfc:        rfc,
		httpClient: &http.Client{Timeout: 30 * time.Second},
		cert:       cert,
		privateKey: privateKey,
	}, nil
}

const authEndpoint = "https://cfdidescargamasivasolicitud.clouda.sat.gob.mx/Autenticacion/Autenticacion.svc"

// Authenticate performs the authentication request and stores the token.
func (c *SatClient) Authenticate() error {
	// 1. Create the SOAP request body
	created := time.Now().UTC().Format("2006-01-02T15:04:05.000Z")
	expires := time.Now().UTC().Add(5 * time.Minute).Format("2006-01-02T15:04:05.000Z")

	// This is the part that needs to be digested.
	// The canonicalization required by SAT is very specific.
	timestampStr := fmt.Sprintf(`<u:Timestamp u:Id="_0"><u:Created>%s</u:Created><u:Expires>%s</u:Expires></u:Timestamp>`, created, expires)

	// 2. Generate the digest
	digest := sha1.Sum([]byte(timestampStr))
	digestB64 := base64.StdEncoding.EncodeToString(digest[:])

	// 3. Create SignedInfo and sign it
	// The canonicalization required by the SAT is very specific, so we
	// construct the SignedInfo string manually to ensure self-closing tags.
	signedInfoStr := fmt.Sprintf(
		`<SignedInfo xmlns="http://www.w3.org/2000/09/xmldsig#"><CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/><Reference URI="#_0"><Transforms><Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></Transforms><DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/><DigestValue>%s</DigestValue></Reference></SignedInfo>`,
		digestB64,
	)

	// We also need the struct for placing it in the final envelope
	signedInfo := SignedInfo{
		CanonicalizationMethod: CanonicalizationMethod{Algorithm: "http://www.w3.org/2001/10/xml-exc-c14n#"},
		SignatureMethod:        SignatureMethod{Algorithm: "http://www.w3.org/2000/09/xmldsig#rsa-sha1"},
		Reference: Reference{
			URI: "#_0",
			Transforms: Transforms{
				Transform: Transform{Algorithm: "http://www.w3.org/2001/10/xml-exc-c14n#"},
			},
			DigestMethod: DigestMethod{Algorithm: "http://www.w3.org/2000/09/xmldsig#sha1"},
			DigestValue:  digestB64,
		},
	}

	hasher := sha1.New()
	hasher.Write([]byte(signedInfoStr))
	hashed := hasher.Sum(nil)

	signature, err := rsa.SignPKCS1v15(rand.Reader, c.privateKey.(*rsa.PrivateKey), crypto.SHA1, hashed)
	if err != nil {
		return fmt.Errorf("failed to sign digest: %w", err)
	}
	signatureB64 := base64.StdEncoding.EncodeToString(signature)

	// 4. Construct the full SOAP envelope
	certStr := base64.StdEncoding.EncodeToString(c.cert.Raw)

	requestBody := AuthRequest{
		Xmlns: "http://DescargaMasivaTerceros.gob.mx",
	}

	envelope := SoapEnvelope{
		XmlnsS: "http://schemas.xmlsoap.org/soap/envelope/",
		XmlnsU: "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd",
		Header: SoapHeader{
			Security: &Security{
				XmlnsO:         "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd",
				MustUnderstand: "1",
				Timestamp: Timestamp{
					Id:      "_0",
					Created: created,
					Expires: expires,
				},
				BinaryToken: &BinarySecurityToken{
					Id:           "uuid-placeholder-1", // This can be a placeholder
					ValueType:    "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3",
					EncodingType: "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary",
					Content:      certStr,
				},
				Signature: &Signature{
					Xmlns:          "http://www.w3.org/2000/09/xmldsig#",
					SignedInfo:     signedInfo,
					SignatureValue: signatureB64,
					KeyInfo: KeyInfo{
						SecurityTokenRef: &SecurityTokenReference{
							Reference: OReference{
								ValueType: "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3",
								URI:       "#uuid-placeholder-1",
							},
						},
					},
				},
			},
		},
		Body: SoapBody{
			Content: &requestBody,
		},
	}

	// 5. Marshal and send request
	xmlBytes, err := xml.MarshalIndent(envelope, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal soap envelope: %w", err)
	}

	if c.verbose {
		fmt.Println("--- SOAP Request ---")
		fmt.Println(string(xmlBytes))
		fmt.Println("--------------------")
	}

	req, err := http.NewRequest("POST", authEndpoint, bytes.NewBuffer(xmlBytes))
	if err != nil {
		return fmt.Errorf("failed to create http request: %w", err)
	}
	req.Header.Set("Content-Type", "text/xml;charset=UTF-8")
	req.Header.Set("SOAPAction", "http://DescargaMasivaTerceros.gob.mx/IAutenticacion/Autentica")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send http request: %w", err)
	}
	defer resp.Body.Close()

	// 6. Unmarshal the response and store the token
	respBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %w", err)
	}

	// Basic parsing to find the token
	// A full unmarshal is tricky due to nested/weird namespaces in the response.
	bodyStr := string(respBody)
	tokenStart := strings.Index(bodyStr, "<AutenticaResult>")
	tokenEnd := strings.Index(bodyStr, "</AutenticaResult>")
	if tokenStart == -1 || tokenEnd == -1 {
		return fmt.Errorf("could not find token in response: %s", bodyStr)
	}

	c.token = bodyStr[tokenStart+len("<AutenticaResult>") : tokenEnd]
	fmt.Println("Authentication successful. Token obtained.")
	return nil
}

const solicitaEndpoint = "https://cfdidescargamasivasolicitud.clouda.sat.gob.mx/SolicitaDescargaService.svc"

// Solicitar performs a request to download CFDI files.
func (c *SatClient) Solicitar(startDate, endDate, solicitudType string) (string, error) {
	if c.token == "" {
		fmt.Println("No authentication token found, authenticating first...")
		if err := c.Authenticate(); err != nil {
			return "", fmt.Errorf("auto-authentication failed: %w", err)
		}
	}

	// 1. Create the request body
	var requestPayload SolicitudPayload
	var soapAction string

	if solicitudType == "E" {
		requestPayload = SolicitudPayload{
			RfcEmisor:     c.rfc,
			FechaInicial:  startDate,
			FechaFinal:    endDate,
			TipoSolicitud: "CFDI",
		}
		soapAction = "http://DescargaMasivaTerceros.sat.gob.mx/ISolicitaDescargaService/SolicitaDescargaEmitidos"
	} else { // "R"
		requestPayload = SolicitudPayload{
			RfcReceptor:   c.rfc,
			FechaInicial:  startDate,
			FechaFinal:    endDate,
			TipoSolicitud: "CFDI",
		}
		soapAction = "http://DescargaMasivaTerceros.sat.gob.mx/ISolicitaDescargaService/SolicitaDescargaRecibidos"
	}


	// The signature for this request is different.
	// We need to create a digest of the <des:solicitud> element.
	// Let's create a temporary struct for marshalling just this part.
	tempSolicitudForDigest, err := xml.Marshal(requestPayload)
	if err != nil {
		return "", fmt.Errorf("failed to marshal solicitud for digest: %w", err)
	}

	// Manual adjustments for canonicalization
	solicitudStr := strings.Replace(string(tempSolicitudForDigest), "<SolicitudPayload", `<des:solicitud`, 1)
	solicitudStr = strings.Replace(solicitudStr, "</SolicitudPayload>", `</des:solicitud>`, 1)
	solicitudStr = strings.Replace(solicitudStr, ` xmlns="des:solicitud"`, ``, 1)


	digest := sha1.Sum([]byte(solicitudStr))
	digestB64 := base64.StdEncoding.EncodeToString(digest[:])

	// Manually construct SignedInfo to ensure self-closing tags
	signedInfoStr := fmt.Sprintf(
		`<SignedInfo xmlns="http://www.w3.org/2000/09/xmldsig#"><CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/><Reference URI="#_0"><Transforms><Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></Transforms><DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/><DigestValue>%s</DigestValue></Reference></SignedInfo>`,
		digestB64,
	)

	// We also need the struct for placing it in the final envelope
	signedInfo := SignedInfo{
		CanonicalizationMethod: CanonicalizationMethod{Algorithm: "http://www.w3.org/2001/10/xml-exc-c14n#"},
		SignatureMethod:        SignatureMethod{Algorithm: "http://www.w3.org/2000/09/xmldsig#rsa-sha1"},
		Reference: Reference{
			URI:          "#_0", // This seems to be a placeholder for these requests
			Transforms:   Transforms{Transform: Transform{Algorithm: "http://www.w3.org/2001/10/xml-exc-c14n#"}},
			DigestMethod: DigestMethod{Algorithm: "http://www.w3.org/2000/09/xmldsig#sha1"},
			DigestValue:  digestB64,
		},
	}

	hasher := sha1.New()
	hasher.Write([]byte(signedInfoStr))
	hashed := hasher.Sum(nil)

	signature, err := rsa.SignPKCS1v15(rand.Reader, c.privateKey.(*rsa.PrivateKey), crypto.SHA1, hashed)
	if err != nil {
		return "", fmt.Errorf("failed to sign digest: %w", err)
	}
	signatureB64 := base64.StdEncoding.EncodeToString(signature)

	// Add signature to the payload
	requestPayload.Signature = &Signature{
		Xmlns:          "http://www.w3.org/2000/09/xmldsig#",
		SignedInfo:     signedInfo,
		SignatureValue: signatureB64,
		KeyInfo: KeyInfo{
			X509Data: &X509Data{
				X509IssuerSerial: X509IssuerSerial{
					X509IssuerName:   c.cert.Issuer.String(),
					X509SerialNumber: c.cert.SerialNumber.String(),
				},
				X509Certificate: base64.StdEncoding.EncodeToString(c.cert.Raw),
			},
		},
	}

	// Construct the full SOAP envelope
	envelope := SoapEnvelope{
		XmlnsS:   "http://schemas.xmlsoap.org/soap/envelope/",
		XmlnsDes: "http://DescargaMasivaTerceros.sat.gob.mx",
		Body: SoapBody{
			Content: &SolicitaDescarga{
				Solicitud: requestPayload,
			},
		},
	}

	xmlBytes, err := xml.MarshalIndent(envelope, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal soap envelope: %w", err)
	}

	if c.verbose {
		fmt.Println("--- SOAP Request ---")
		fmt.Println(string(xmlBytes))
		fmt.Println("--------------------")
	}

	req, err := http.NewRequest("POST", solicitaEndpoint, bytes.NewBuffer(xmlBytes))
	if err != nil {
		return "", fmt.Errorf("failed to create http request: %w", err)
	}
	req.Header.Set("Content-Type", "text/xml;charset=UTF-8")
	req.Header.Set("SOAPAction", soapAction)
	req.Header.Set("Authorization", "WRAP access_token=\""+c.token+"\"")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to send http request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response body: %w", err)
	}

	if c.verbose {
		fmt.Println("--- SOAP Response ---")
		fmt.Println(string(respBody))
		fmt.Println("---------------------")
	}

	var soapResponse SoapEnvelope
	soapResponse.Body.Content = &SolicitaResponse{}
	if err := xml.Unmarshal(respBody, &soapResponse); err != nil {
		return "", fmt.Errorf("failed to unmarshal soap response: %w", err)
	}

	solicitaResponse := soapResponse.Body.Content.(*SolicitaResponse)
	if solicitaResponse.CodEstatus != "5000" {
		return "", fmt.Errorf("SAT Error: %s", solicitaResponse.Mensaje)
	}

	fmt.Printf("Solicitud exitosa. ID de solicitud: %s\n", solicitaResponse.IdSolicitud)

	// Save the request ID for later verification
	homeDir, _ := os.UserHomeDir()
	solicitudesFile := filepath.Join(homeDir, ".satxml", c.rfc, "solicitudes.txt")
	f, err := os.OpenFile(solicitudesFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return "", fmt.Errorf("failed to open solicitudes.txt for writing: %w", err)
	}
	defer f.Close()
	if _, err := f.WriteString(solicitaResponse.IdSolicitud + "\n"); err != nil {
		return "", fmt.Errorf("failed to write to solicitudes.txt: %w", err)
	}

	return solicitaResponse.IdSolicitud, nil
}

const verificaEndpoint = "https://cfdidescargamasivasolicitud.clouda.sat.gob.mx/VerificaSolicitudDescargaService.svc"

// Verificar checks the status of a download request.
func (c *SatClient) Verificar(requestID string) (*VerificaResponse, error) {
	if c.token == "" {
		fmt.Println("No authentication token found, authenticating first...")
		if err := c.Authenticate(); err != nil {
			return nil, fmt.Errorf("auto-authentication failed: %w", err)
		}
	}

	// 1. Create request body
	requestPayload := VerificaSolicitudPayload{
		RfcSolicitante: c.rfc,
		IdSolicitud:    requestID,
	}

	// Similar signing process as Solicitar
	tempVerificaForDigest, err := xml.Marshal(requestPayload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal verifica for digest: %w", err)
	}
	verificaStr := strings.Replace(string(tempVerificaForDigest), "<VerificaSolicitudPayload", `<des:solicitud`, 1)
	verificaStr = strings.Replace(verificaStr, "</VerificaSolicitudPayload>", `</des:solicitud>`, 1)
	verificaStr = strings.Replace(verificaStr, ` xmlns="des:solicitud"`, ``, 1)

	digest := sha1.Sum([]byte(verificaStr))
	digestB64 := base64.StdEncoding.EncodeToString(digest[:])

	// Manually construct SignedInfo to ensure self-closing tags
	signedInfoStr := fmt.Sprintf(
		`<SignedInfo xmlns="http://www.w3.org/2000/09/xmldsig#"><CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/><Reference URI="#_0"><Transforms><Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></Transforms><DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/><DigestValue>%s</DigestValue></Reference></SignedInfo>`,
		digestB64,
	)

	signedInfo := SignedInfo{
		CanonicalizationMethod: CanonicalizationMethod{Algorithm: "http://www.w3.org/2001/10/xml-exc-c14n#"},
		SignatureMethod:        SignatureMethod{Algorithm: "http://www.w3.org/2000/09/xmldsig#rsa-sha1"},
		Reference:              Reference{URI: "#_0", Transforms: Transforms{Transform: Transform{Algorithm: "http://www.w3.org/2001/10/xml-exc-c14n#"}}, DigestMethod: DigestMethod{Algorithm: "http://www.w3.org/2000/09/xmldsig#sha1"}, DigestValue: digestB64},
	}

	hasher := sha1.New()
	hasher.Write([]byte(signedInfoStr))
	hashed := hasher.Sum(nil)
	signature, err := rsa.SignPKCS1v15(rand.Reader, c.privateKey.(*rsa.PrivateKey), crypto.SHA1, hashed)
	if err != nil {
		return nil, fmt.Errorf("failed to sign digest: %w", err)
	}
	signatureB64 := base64.StdEncoding.EncodeToString(signature)

	requestPayload.Signature = &Signature{
		Xmlns: "http://www.w3.org/2000/09/xmldsig#",
		SignedInfo: signedInfo,
		SignatureValue: signatureB64,
		KeyInfo: KeyInfo{X509Data: &X509Data{X509IssuerSerial: X509IssuerSerial{X509IssuerName: c.cert.Issuer.String(), X509SerialNumber: c.cert.SerialNumber.String()}, X509Certificate: base64.StdEncoding.EncodeToString(c.cert.Raw)}},
	}

	envelope := SoapEnvelope{
		XmlnsS: "http://schemas.xmlsoap.org/soap/envelope/",
		XmlnsDes: "http://DescargaMasivaTerceros.sat.gob.mx",
		Body: SoapBody{Content: &VerificaSolicitudDescarga{Solicitud: requestPayload}},
	}

	xmlBytes, err := xml.MarshalIndent(envelope, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal soap envelope: %w", err)
	}

	if c.verbose {
		fmt.Println("--- SOAP Request ---")
		fmt.Println(string(xmlBytes))
		fmt.Println("--------------------")
	}

	req, err := http.NewRequest("POST", verificaEndpoint, bytes.NewBuffer(xmlBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to create http request: %w", err)
	}
	req.Header.Set("Content-Type", "text/xml;charset=UTF-8")
	req.Header.Set("SOAPAction", "http://DescargaMasivaTerceros.sat.gob.mx/IVerificaSolicitudDescargaService/VerificaSolicitudDescarga")
	req.Header.Set("Authorization", "WRAP access_token=\""+c.token+"\"")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send http request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	if c.verbose {
		fmt.Println("--- SOAP Response ---")
		fmt.Println(string(respBody))
		fmt.Println("---------------------")
	}

	var soapResponse SoapEnvelope
	soapResponse.Body.Content = &VerificaResponse{}
	if err := xml.Unmarshal(respBody, &soapResponse); err != nil {
		return nil, fmt.Errorf("failed to unmarshal soap response: %w", err)
	}

	verificaResponse := soapResponse.Body.Content.(*VerificaResponse)
	if verificaResponse.CodEstatus != "5000" {
		return nil, fmt.Errorf("SAT Error: %s", verificaResponse.Mensaje)
	}

	return verificaResponse, nil
}

const descargaEndpoint = "https://cfdidescargamasiva.clouda.sat.gob.mx/DescargaMasivaService.svc"

// Descargar downloads a package of CFDI files.
func (c *SatClient) Descargar(packageID string) ([]byte, error) {
	if c.token == "" {
		fmt.Println("No authentication token found, authenticating first...")
		if err := c.Authenticate(); err != nil {
			return nil, fmt.Errorf("auto-authentication failed: %w", err)
		}
	}

	// 1. Create request body
	requestPayload := PeticionDescargaPayload{
		RfcSolicitante: c.rfc,
		IdPaquete:      packageID,
	}

	// Signing process is similar to aabs
	tempDescargaForDigest, err := xml.Marshal(requestPayload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal descarga for digest: %w", err)
	}
	descargaStr := strings.Replace(string(tempDescargaForDigest), "<PeticionDescargaPayload", `<des:peticionDescarga`, 1)
	descargaStr = strings.Replace(descargaStr, "</PeticionDescargaPayload>", `</des:peticionDescarga>`, 1)
	descargaStr = strings.Replace(descargaStr, ` xmlns="des:peticionDescarga"`, ``, 1)

	digest := sha1.Sum([]byte(descargaStr))
	digestB64 := base64.StdEncoding.EncodeToString(digest[:])

	// Manually construct SignedInfo to ensure self-closing tags
	signedInfoStr := fmt.Sprintf(
		`<SignedInfo xmlns="http://www.w3.org/2000/09/xmldsig#"><CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/><Reference URI="#_0"><Transforms><Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></Transforms><DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/><DigestValue>%s</DigestValue></Reference></SignedInfo>`,
		digestB64,
	)

	signedInfo := SignedInfo{
		CanonicalizationMethod: CanonicalizationMethod{Algorithm: "http://www.w3.org/2001/10/xml-exc-c14n#"},
		SignatureMethod:        SignatureMethod{Algorithm: "http://www.w3.org/2000/09/xmldsig#rsa-sha1"},
		Reference:              Reference{URI: "#_0", Transforms: Transforms{Transform: Transform{Algorithm: "http://www.w3.org/2001/10/xml-exc-c14n#"}}, DigestMethod: DigestMethod{Algorithm: "http://www.w3.org/2000/09/xmldsig#sha1"}, DigestValue: digestB64},
	}

	hasher := sha1.New()
	hasher.Write([]byte(signedInfoStr))
	hashed := hasher.Sum(nil)
	signature, err := rsa.SignPKCS1v15(rand.Reader, c.privateKey.(*rsa.PrivateKey), crypto.SHA1, hashed)
	if err != nil {
		return nil, fmt.Errorf("failed to sign digest: %w", err)
	}
	signatureB64 := base64.StdEncoding.EncodeToString(signature)

	requestPayload.Signature = &Signature{
		Xmlns: "http://www.w3.org/2000/09/xmldsig#",
		SignedInfo: signedInfo,
		SignatureValue: signatureB64,
		KeyInfo: KeyInfo{X509Data: &X509Data{X509IssuerSerial: X509IssuerSerial{X509IssuerName: c.cert.Issuer.String(), X509SerialNumber: c.cert.SerialNumber.String()}, X509Certificate: base64.StdEncoding.EncodeToString(c.cert.Raw)}},
	}

	envelope := SoapEnvelope{
		XmlnsS: "http://schemas.xmlsoap.org/soap/envelope/",
		XmlnsDes: "http://DescargaMasivaTerceros.sat.gob.mx",
		Body: SoapBody{Content: &PeticionDescarga{PeticionDescarga: requestPayload}},
	}

	xmlBytes, err := xml.MarshalIndent(envelope, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal soap envelope: %w", err)
	}

	if c.verbose {
		fmt.Println("--- SOAP Request ---")
		fmt.Println(string(xmlBytes))
		fmt.Println("--------------------")
	}

	req, err := http.NewRequest("POST", descargaEndpoint, bytes.NewBuffer(xmlBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to create http request: %w", err)
	}
	req.Header.Set("Content-Type", "text/xml;charset=UTF-8")
	req.Header.Set("SOAPAction", "http://DescargaMasivaTerceros.sat.gob.mx/IDescargaMasivaTercerosService/Descargar")
	req.Header.Set("Authorization", "WRAP access_token=\""+c.token+"\"")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send http request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	if c.verbose {
		fmt.Println("--- SOAP Response ---")
		// Printing the whole body might be too much as it contains the zip file.
		// Let's just print the first 200 chars.
		if len(respBody) > 200 {
			fmt.Println(string(respBody[:200]) + "...")
		} else {
			fmt.Println(string(respBody))
		}
		fmt.Println("---------------------")
	}

	var soapResponse SoapEnvelope
	soapResponse.Body.Content = &DescargaResponse{}
	if err := xml.Unmarshal(respBody, &soapResponse); err != nil {
		return nil, fmt.Errorf("failed to unmarshal soap response: %w", err)
	}

	descargaResponse := soapResponse.Body.Content.(*DescargaResponse)
	if descargaResponse.CodEstatus != "5000" {
		return nil, fmt.Errorf("SAT Error: %s", descargaResponse.Mensaje)
	}

	// The actual zip file is in the Paquete field, base64 encoded.
	zipData, err := base64.StdEncoding.DecodeString(descargaResponse.Paquete)
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64 package: %w", err)
	}

	return zipData, nil
}
