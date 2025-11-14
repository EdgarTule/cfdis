package cmd

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"encoding/json"

	"github.com/spf13/cobra"
	"golang.org/x/term"
)

var (
	downloadRfc string
	downloadID  string
)

var downloadCmd = &cobra.Command{
	Use:   "download",
	Short: "Descarga un paquete de CFDI.",
	Long:  `Descarga un paquete específico por su ID, o todos los paquetes pendientes si no se proporciona un ID.`,
	Run: func(cmd *cobra.Command, args []string) {
		// --- Cargar configuración y credenciales ---
		homeDir, _ := os.UserHomeDir()
		configPath := filepath.Join(homeDir, ".sat", downloadRfc, "config.json")
		if _, err := os.Stat(configPath); os.IsNotExist(err) {
			fmt.Printf("Error: No se encontró configuración para el RFC %s.\n", downloadRfc)
			return
		}
		var config map[string]string
		configBytes, _ := ioutil.ReadFile(configPath)
		json.Unmarshal(configBytes, &config)

		fmt.Print("Por favor, introduce la contraseña de la e.firma: ")
		password, _ := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Println()

		service, err := NewSatService(downloadRfc, config["keyPath"], config["cerPath"], password)
		if err != nil {
			fmt.Printf("Error al inicializar servicio: %v\n", err)
			return
		}

		if err := service.EnsureAuthenticated(); err != nil {
			fmt.Printf("Error de autenticación: %v\n", err)
			return
		}

		// --- Lógica de descarga ---
		if downloadID != "" {
			// Descargar un solo ID
			fmt.Printf("Descargando paquete: %s\n", downloadID)
			// No se conoce el estado, se asume Vigente
			targetDir := filepath.Join(service.rfcDir, "cfdis", "Vigente")
			os.MkdirAll(targetDir, 0755)
			err := service.DownloadPackage(downloadID, targetDir)
			if err != nil {
				fmt.Printf("Error al descargar: %v\n", err)
			}
		} else {
			// Descargar todos los IDs pendientes
			fmt.Println("Descargando todos los paquetes pendientes...")
			idsDescargaFile := filepath.Join(service.rfcDir, "idsdescarga.json")

			type Descarga struct {
				ID     string `json:"id"`
				Estado string `json:"estado"`
			}

			var descargas []Descarga
			if _, err := os.Stat(idsDescargaFile); err == nil {
				data, err := ioutil.ReadFile(idsDescargaFile)
				if err != nil {
					fmt.Printf("Error al leer el archivo de descargas: %v\n", err)
					return
				}
				json.Unmarshal(data, &descargas)
			}

			var remainingDescargas []Descarga
			for _, desc := range descargas {
				fmt.Printf("Descargando paquete: %s (%s)\n", desc.ID, desc.Estado)
				targetDir := filepath.Join(service.rfcDir, "cfdis", desc.Estado)
				os.MkdirAll(targetDir, 0755)
				err := service.DownloadPackage(desc.ID, targetDir)
				if err != nil {
					fmt.Printf("  > Error al descargar el paquete %s: %v\n", desc.ID, err)
					remainingDescargas = append(remainingDescargas, desc) // Reintentar más tarde
				} else {
					fmt.Printf("  > Paquete %s descargado y procesado.\n", desc.ID)
				}
			}
			// Reescribir el archivo con los IDs que fallaron
			data, err := json.MarshalIndent(remainingDescargas, "", "  ")
			if err != nil {
				fmt.Printf("Error al serializar el archivo de descargas: %v\n", err)
				return
			}
			ioutil.WriteFile(idsDescargaFile, data, 0644)
		}
	},
}


func init() {
	downloadCmd.Flags().StringVar(&downloadRfc, "rfc", "", "RFC del contribuyente")
	downloadCmd.Flags().StringVar(&downloadID, "id", "", "ID del paquete a descargar (opcional)")
	downloadCmd.MarkFlagRequired("rfc")

	rootCmd.AddCommand(downloadCmd)
}
