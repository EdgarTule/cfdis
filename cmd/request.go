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
	reqRfc       string
	reqTipo      string
	reqSubTipo   string
	reqStart     string
	reqEnd       string
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
	Short: "Envía una solicitud de descarga de CFDI o Retenciones.",
	Run: func(cmd *cobra.Command, args []string) {
		// --- Validar entradas ---
		reqTipo = strings.ToLower(reqTipo)
		if reqTipo != "cfdi" && reqTipo != "retenciones" {
			fmt.Println("Error: el tipo de solicitud debe ser 'cfdi' o 'retenciones'.")
			return
		}
		reqSubTipo = strings.ToLower(reqSubTipo)
		if reqSubTipo != "emitidos" && reqSubTipo != "recibidos" {
			fmt.Println("Error: el sub-tipo de solicitud debe ser 'emitidos' o 'recibidos'.")
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
		service.SetServiceType(reqTipo)

		if err := service.EnsureAuthenticated(); err != nil {
			fmt.Printf("Error de autenticación: %v\n", err)
			return
		}

		// --- Firmar y enviar solicitud ---
		id, err := service.SendRequest(reqSubTipo, reqStart, reqEnd)
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
		if _, err := f.WriteString(fmt.Sprintf("%s|%s\n", id, reqTipo)); err != nil {
			fmt.Printf("Error al guardar el ID de solicitud: %v\n", err)
		}
		fmt.Printf("ID guardado en %s\n", requestsFile)
	},
}

func init() {
	requestCmd.Flags().StringVar(&reqRfc, "rfc", "", "RFC del contribuyente")
	requestCmd.Flags().StringVar(&reqTipo, "solicitud", "cfdi", "Tipo de solicitud: 'cfdi' o 'retenciones'")
	requestCmd.Flags().StringVar(&reqSubTipo, "tipo", "", "Tipo de comprobante: 'emitidos' o 'recibidos'")
	requestCmd.Flags().StringVar(&reqStart, "start", "", "Fecha de inicio (YYYY-MM-DDTHH:MM:SS)")
	requestCmd.Flags().StringVar(&reqEnd, "end", "", "Fecha de fin (YYYY-MM-DDTHH:MM:SS)")
	requestCmd.MarkFlagRequired("rfc")
	requestCmd.MarkFlagRequired("tipo")
	requestCmd.MarkFlagRequired("start")
	requestCmd.MarkFlagRequired("end")

	rootCmd.AddCommand(requestCmd)
}
