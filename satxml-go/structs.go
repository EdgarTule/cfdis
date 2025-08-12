package main

import "encoding/xml"

// General SOAP Envelope Structure
type SoapEnvelope struct {
	XMLName   xml.Name `xml:"s:Envelope"`
	XmlnsS    string   `xml:"xmlns:s,attr"`
	XmlnsU    string   `xml:"xmlns:u,attr,omitempty"`
	XmlnsDes  string   `xml:"xmlns:des,attr,omitempty"`
	XmlnsXsi  string   `xml:"xmlns:xsi,attr,omitempty"`
	XmlnsXsd  string   `xml:"xmlns:xsd,attr,omitempty"`
	Header    SoapHeader
	Body      SoapBody
}

type SoapHeader struct {
	XMLName  xml.Name    `xml:"s:Header"`
	Security *Security `xml:"o:Security,omitempty"`
}

type SoapBody struct {
	XMLName xml.Name    `xml:"s:Body"`
	Content interface{} `xml:",innerxml"`
}

// --- Security and Signature Structs (Common) ---

type Security struct {
	XMLName        xml.Name `xml:"o:Security"`
	XmlnsO         string   `xml:"xmlns:o,attr"`
	MustUnderstand string   `xml:"s:mustUnderstand,attr"`
	Timestamp      Timestamp
	BinaryToken    *BinarySecurityToken `xml:"o:BinarySecurityToken,omitempty"`
	Signature      *Signature
}

type Timestamp struct {
	XMLName xml.Name `xml:"u:Timestamp"`
	Id      string   `xml:"u:Id,attr"`
	Created string   `xml:"u:Created"`
	Expires string   `xml:"u:Expires"`
}

type BinarySecurityToken struct {
	XMLName      xml.Name `xml:"o:BinarySecurityToken"`
	Id           string   `xml:"u:Id,attr"`
	ValueType    string   `xml:"ValueType,attr"`
	EncodingType string   `xml:"EncodingType,attr"`
	Content      string   `xml:",chardata"`
}

type Signature struct {
	XMLName        xml.Name `xml:"Signature"`
	Xmlns          string   `xml:"xmlns,attr"`
	SignedInfo     SignedInfo
	SignatureValue string `xml:"SignatureValue"`
	KeyInfo        KeyInfo
}

type SignedInfo struct {
	XMLName                xml.Name `xml:"SignedInfo"`
	CanonicalizationMethod CanonicalizationMethod
	SignatureMethod        SignatureMethod
	Reference              Reference
}

type CanonicalizationMethod struct {
	XMLName   xml.Name `xml:"CanonicalizationMethod"`
	Algorithm string   `xml:"Algorithm,attr"`
}

type SignatureMethod struct {
	XMLName   xml.Name `xml:"SignatureMethod"`
	Algorithm string   `xml:"Algorithm,attr"`
}

type Reference struct {
	XMLName      xml.Name `xml:"Reference"`
	URI          string   `xml:"URI,attr"`
	Transforms   Transforms
	DigestMethod DigestMethod
	DigestValue  string `xml:"DigestValue"`
}

type Transforms struct {
	XMLName   xml.Name  `xml:"Transforms"`
	Transform Transform `xml:"Transform"`
}

type Transform struct {
	XMLName   xml.Name `xml:"Transform"`
	Algorithm string   `xml:"Algorithm,attr"`
}

type DigestMethod struct {
	XMLName   xml.Name `xml:"DigestMethod"`
	Algorithm string   `xml:"Algorithm,attr"`
}

type KeyInfo struct {
	XMLName              xml.Name `xml:"KeyInfo"`
	SecurityTokenRef     *SecurityTokenReference `xml:"o:SecurityTokenReference,omitempty"`
	X509Data             *X509Data             `xml:"X509Data,omitempty"`
}

type SecurityTokenReference struct {
	XMLName   xml.Name `xml:"o:SecurityTokenReference"`
	Reference OReference `xml:"o:Reference"`
}

type OReference struct {
	XMLName   xml.Name `xml:"o:Reference"`
	ValueType string   `xml:"ValueType,attr"`
	URI       string   `xml:"URI,attr"`
}

type X509Data struct {
	XMLName        xml.Name `xml:"X509Data"`
	X509IssuerSerial X509IssuerSerial
	X509Certificate  string `xml:"X509Certificate"`
}

type X509IssuerSerial struct {
	XMLName        xml.Name `xml:"X509IssuerSerial"`
	X509IssuerName   string `xml:"X509IssuerName"`
	X509SerialNumber string `xml:"X509SerialNumber"`
}


// --- Request Specific Structs ---

// Auth
type AuthRequest struct {
	XMLName xml.Name `xml:"Autentica"`
	Xmlns   string   `xml:"xmlns,attr"`
}

// Solicitud
type SolicitaDescarga struct {
	XMLName   xml.Name         `xml:"des:SolicitaDescarga"`
	Solicitud SolicitudPayload `xml:"des:solicitud"`
}

type SolicitudPayload struct {
	XMLName       xml.Name   `xml:"des:solicitud"`
	FechaInicial  string     `xml:"FechaInicial,attr"`
	FechaFinal    string     `xml:"FechaFinal,attr"`
	RfcEmisor     string     `xml:"RfcEmisor,attr,omitempty"`
	RfcReceptor   string     `xml:"RfcReceptor,attr,omitempty"`
	TipoSolicitud string     `xml:"TipoSolicitud,attr"`
	Signature     *Signature `xml:"Signature"`
}

// Verifica
type VerificaSolicitudDescarga struct {
	XMLName   xml.Name                `xml:"des:VerificaSolicitudDescarga"`
	Solicitud VerificaSolicitudPayload `xml:"des:solicitud"`
}

type VerificaSolicitudPayload struct {
	XMLName        xml.Name   `xml:"des:solicitud"`
	IdSolicitud    string     `xml:"IdSolicitud,attr"`
	RfcSolicitante string     `xml:"RfcSolicitante,attr"`
	Signature      *Signature `xml:"Signature"`
}

// Descarga
type PeticionDescarga struct {
	XMLName          xml.Name               `xml:"des:PeticionDescargaMasivaTercerosEntrada"`
	PeticionDescarga PeticionDescargaPayload `xml:"des:peticionDescarga"`
}

type PeticionDescargaPayload struct {
	XMLName        xml.Name   `xml:"des:peticionDescarga"`
	IdPaquete      string     `xml:"IdPaquete,attr"`
	RfcSolicitante string     `xml:"RfcSolicitante,attr"`
	Signature      *Signature `xml:"Signature"`
}

// --- Response Structs ---

type AuthResponse struct {
	XMLName xml.Name `xml:"AutenticaResponse"`
	Token   string   `xml:"AutenticaResult"`
}

type SolicitaResponse struct {
	XMLName         xml.Name `xml:"SolicitaDescargaResult"`
	CodEstatus      string   `xml:"CodEstatus,attr"`
	IdSolicitud     string   `xml:"IdSolicitud,attr"`
	Mensaje         string   `xml:"Mensaje,attr"`
}

type VerificaResponse struct {
	XMLName           xml.Name `xml:"VerificaSolicitudDescargaResult"`
	CodEstatus        string   `xml:"CodEstatus,attr"`
	EstadoSolicitud   string   `xml:"EstadoSolicitud,attr"`
	NumeroCFDIs       string   `xml:"NumeroCFDIs,attr"`
	Mensaje           string   `xml:"Mensaje,attr"`
	IdsPaquetes       []string `xml:"IdsPaquetes>IdPaquete"`
}

type DescargaResponse struct {
	XMLName    xml.Name `xml:"PeticionDescargaMasivaTercerosResult"`
	CodEstatus string   `xml:"CodEstatus,attr"`
	Mensaje    string   `xml:"Mensaje,attr"`
	Paquete    string   `xml:"Paquete"`
}
