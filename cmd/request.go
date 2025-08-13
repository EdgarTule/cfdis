package cmd

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/term"
)

var (
	reqRfc     string
	reqType    string
	reqStart   string
	reqEnd     string
)

const (
	requestURL = "https://cfdidescargamasivasolicitud.clouda.sat.gob.mx/SolicitaDescargaService.svc"

	// Nota: El digest se calcula sobre el contenido de <des:solicitud>, no sobre todo el envelope.
	soapRequestTemplate = `<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" xmlns:des="http://DescargaMasivaTerceros.sat.gob.mx" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"><s:Header/><s:Body>%s</s:Body></s:Envelope>`

	solicitudEmitidosTemplate = `<des:SolicitaDescarga><des:solicitud FechaFinal="%s" FechaInicial="%s" RfcEmisor="%s" TipoSolicitud="CFDI"><Signature xmlns="http://www.w3.org/2000/09/xmldsig#"><SignedInfo><CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/><Reference URI="#_0"><Transforms><Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></Transforms><DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/><DigestValue>%s</DigestValue></Reference></SignedInfo><SignatureValue>%s</SignatureValue><KeyInfo><X509Data><X509IssuerSerial><X509IssuerName>%s</X509IssuerName><X509SerialNumber>%s</X509SerialNumber></X509IssuerSerial><X509Certificate>%s</X509Certificate></X509Data></KeyInfo></Signature></des:solicitud></des:SolicitaDescarga>`

	solicitudRecibidosTemplate = `<des:SolicitaDescarga><des:solicitud FechaFinal="%s" FechaInicial="%s" RfcReceptores="%s" TipoSolicitud="CFDI"><Signature xmlns="http://www.w3.org/2000/09/xmldsig#"><SignedInfo><CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/><Reference URI="#_0"><Transforms><Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></Transforms><DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/><DigestValue>%s</DigestValue></Reference></SignedInfo><SignatureValue>%s</SignatureValue><KeyInfo><X509Data><X509IssuerSerial><X509IssuerName>%s</X509IssuerName><X509SerialNumber>%s</X509SerialNumber></X509IssuerSerial><X509Certificate>%s</X509Certificate></X509Data></KeyInfo></Signature></des:solicitud></des:SolicitaDescarga>`
)

type SoapRequestResponse struct {
	XMLName xml.Name `xml:"Envelope"`
	Body    struct {
		SolicitaDescargaResponse struct {
			SolicitaDescargaResult struct {
				ID         string `xml:"IdSolicitud,attr"`
				CodEstatus string `xml:"CodEstatus,attr"`
				Mensaje    string `xml:"Mensaje,attr"`
			} `xml:"SolicitaDescargaResult"`
		} `xml:"SolicitaDescargaResponse"`
	} `xml:"Body"`
}

var requestCmd = &cobra.Command{
	Use:   "request",
	Short: "Envía una solicitud de descarga de CFDI (emitidos o recibidos).",
	Run: func(cmd *cobra.Command, args []string) {
		// --- Validar entradas ---
		reqType = strings.ToLower(reqType)
		if reqType != "emitidos" && reqType != "recibidos" {
			fmt.Println("Error: el tipo de solicitud debe ser 'emitidos' o 'recibidos'.")
			return
		}
		// TODO: Validar formato de fecha

		// --- Cargar configuración y credenciales ---
		homeDir, _ := os.UserHomeDir()
		configPath := filepath.Join(homeDir, ".sat", reqRfc, "config.json")
		if _, err := os.Stat(configPath); os.IsNotExist(err) {
			fmt.Printf("Error: No se encontró configuración para el RFC %s.\n", reqRfc)
			return
		}
		var config map[string]string
		configBytes, _ := ioutil.ReadFile(configPath)
		json.Unmarshal(configBytes, &config)

		fmt.Print("Por favor, introduce la contraseña de la e.firma: ")
		password, _ := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Println()

		// --- Autenticar y preparar servicio ---
		service, err := NewSatService(reqRfc, config["keyPath"], config["cerPath"], password)
		if err != nil {
			fmt.Printf("Error al inicializar servicio: %v\n", err)
			return
		}
		if err := service.EnsureAuthenticated(); err != nil {
			fmt.Printf("Error de autenticación: %v\n", err)
			return
		}

		// --- Firmar y enviar solicitud ---
		id, err := service.SendRequest(reqType, reqStart, reqEnd)
		if err != nil {
			fmt.Printf("Error al enviar la solicitud: %v\n", err)
			return
		}

		fmt.Printf("Solicitud enviada exitosamente. ID de Solicitud: %s\n", id)

		// --- Guardar ID de solicitud ---
		requestsFile := filepath.Join(service.rfcDir, "solicitudes.txt")
		f, err := os.OpenFile(requestsFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			fmt.Printf("Error al abrir el archivo de solicitudes: %v\n", err)
			return
		}
		defer f.Close()
		if _, err := f.WriteString(id + "\n"); err != nil {
			fmt.Printf("Error al guardar el ID de solicitud: %v\n", err)
		}
		fmt.Printf("ID guardado en %s\n", requestsFile)
	},
}

func init() {
	requestCmd.Flags().StringVar(&reqRfc, "rfc", "", "RFC del contribuyente")
	requestCmd.Flags().StringVar(&reqType, "type", "", "Tipo de solicitud: 'emitidos' o 'recibidos'")
	requestCmd.Flags().StringVar(&reqStart, "start", "", "Fecha de inicio (YYYY-MM-DDTHH:MM:SS)")
	requestCmd.Flags().StringVar(&reqEnd, "end", "", "Fecha de fin (YYYY-MM-DDTHH:MM:SS)")
	requestCmd.MarkFlagRequired("rfc")
	requestCmd.MarkFlagRequired("type")
	requestCmd.MarkFlagRequired("start")
	requestCmd.MarkFlagRequired("end")

	rootCmd.AddCommand(requestCmd)
}
