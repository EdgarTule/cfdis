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
		cfdiDir := filepath.Join(service.rfcDir, "cfdis")
		os.MkdirAll(cfdiDir, 0755)

		if downloadID != "" {
			// Descargar un solo ID
			fmt.Printf("Descargando paquete: %s\n", downloadID)
			err := service.DownloadPackage(downloadID, cfdiDir)
			if err != nil {
				fmt.Printf("Error al descargar: %v\n", err)
			}
		} else {
			// Descargar todos los IDs pendientes
			fmt.Println("Descargando todos los paquetes pendientes...")
			idsDescargaFile := filepath.Join(service.rfcDir, "idsdescarga.txt")
			ids, err := readLines(idsDescargaFile)
			if err != nil {
				fmt.Printf("No se pudieron leer los IDs de descarga o el archivo no existe: %v\n", err)
				return
			}

			var remainingIDs []string
			for _, id := range ids {
				if id == "" {
					continue
				}
				fmt.Printf("Descargando paquete: %s\n", id)
				err := service.DownloadPackage(id, cfdiDir)
				if err != nil {
					fmt.Printf("  > Error al descargar el paquete %s: %v\n", id, err)
					remainingIDs = append(remainingIDs, id) // Reintentar más tarde
				} else {
					fmt.Printf("  > Paquete %s descargado y procesado.\n", id)
				}
			}
			// Reescribir el archivo con los IDs que fallaron
			writeLines(idsDescargaFile, remainingIDs)
		}
	},
}


func init() {
	downloadCmd.Flags().StringVar(&downloadRfc, "rfc", "", "RFC del contribuyente")
	downloadCmd.Flags().StringVar(&downloadID, "id", "", "ID del paquete a descargar (opcional)")
	downloadCmd.MarkFlagRequired("rfc")

	rootCmd.AddCommand(downloadCmd)
}
