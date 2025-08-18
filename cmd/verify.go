package cmd

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"encoding/json"

	"github.com/spf13/cobra"
	"golang.org/x/term"
)

var (
	verifyRfc string
	verifyID  string
)

var verifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Verifica el estado de una solicitud de descarga.",
	Long:  `Verifica el estado de una solicitud específica por su ID, o todas las solicitudes pendientes si no se proporciona un ID.`,
	Run: func(cmd *cobra.Command, args []string) {
		// --- Cargar configuración y credenciales ---
		homeDir, _ := os.UserHomeDir()
		configPath := filepath.Join(homeDir, ".sat", verifyRfc, "config.json")
		if _, err := os.Stat(configPath); os.IsNotExist(err) {
			fmt.Printf("Error: No se encontró configuración para el RFC %s.\n", verifyRfc)
			return
		}
		var config map[string]string
		configBytes, _ := ioutil.ReadFile(configPath)
		json.Unmarshal(configBytes, &config)

		fmt.Print("Por favor, introduce la contraseña de la e.firma: ")
		password, _ := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Println()

		service, err := NewSatService(verifyRfc, config["keyPath"], config["cerPath"], password)
		if err != nil {
			fmt.Printf("Error al inicializar servicio: %v\n", err)
			return
		}

		if err := service.EnsureAuthenticated(); err != nil {
			fmt.Printf("Error de autenticación: %v\n", err)
			return
		}

		// --- Lógica de verificación ---
		if verifyID != "" {
			// Verificar un solo ID
			fmt.Printf("Verificando ID: %s\n", verifyID)
			status, downloadIDs, err := service.VerifyRequest(verifyID)
			if err != nil {
				fmt.Printf("Error al verificar: %v\n", err)
				return
			}
			handleVerificationResult(service, verifyID, status, downloadIDs)
		} else {
			// Verificar todos los IDs pendientes
			fmt.Println("Verificando todas las solicitudes pendientes...")
			solicitudesFile := filepath.Join(service.rfcDir, "solicitudes.txt")
			ids, err := readLines(solicitudesFile)
			if err != nil {
				fmt.Printf("No se pudieron leer las solicitudes pendientes o el archivo no existe: %v\n", err)
				return
			}

			var remainingIDs []string
			for _, id := range ids {
				if id == "" {
					continue
				}
				fmt.Printf("Verificando ID: %s\n", id)
				status, downloadIDs, err := service.VerifyRequest(id)
				if err != nil {
					fmt.Printf("Error al verificar ID %s: %v\n", id, err)
					remainingIDs = append(remainingIDs, id) // Keep it for next time
					continue
				}
				if !handleVerificationResult(service, id, status, downloadIDs) {
					remainingIDs = append(remainingIDs, id)
				}
			}
			// Reescribir el archivo de solicitudes con los que no se completaron
			writeLines(solicitudesFile, remainingIDs)
		}
	},
}

// handleVerificationResult procesa el resultado y devuelve true si la solicitud se completó (y debe ser eliminada de la lista de pendientes).
func handleVerificationResult(s *SatService, requestID string, status int, downloadIDs []string) bool {
	fmt.Printf("  > Estado: %s (%d)\n", statusToString(status), status)

	// Si la solicitud está Terminada (3), se considera manejada, independientemente de si tiene paquetes o no.
	if status == 3 {
		if len(downloadIDs) > 0 {
			fmt.Printf("  > ¡Éxito! IDs de descarga recibidos: %v\n", downloadIDs)
			idsDescargaFile := filepath.Join(s.rfcDir, "idsdescarga.txt")
			f, err := os.OpenFile(idsDescargaFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
			if err != nil {
				fmt.Printf("  > Error al abrir archivo de descargas: %v\n", err)
				return false // No se pudo guardar, reintentar en el futuro.
			}
			defer f.Close()
			for _, id := range downloadIDs {
				if _, err := f.WriteString(id + "\n"); err != nil {
					fmt.Printf("  > Error al guardar ID de descarga %s: %v\n", id, err)
				}
			}
		} else {
			fmt.Println("  > La solicitud ha terminado pero no generó paquetes de descarga (posiblemente no se encontraron CFDI).")
		}
		return true // La solicitud se completó y se manejó, con o sin paquetes.
	}

	// Si la solicitud ya no está en un estado pendiente o en proceso (Error, Rechazada, Vencida), también se considera manejada.
	if status >= 4 {
		fmt.Printf("  > La solicitud ha finalizado con un estado de error/terminal y será eliminada de la lista de pendientes.\n")
		return true
	}

	// Si el estado es 1 (Aceptada) o 2 (En proceso), sigue pendiente.
	return false
}

func statusToString(status int) string {
	switch status {
	case 1:
		return "Aceptada"
	case 2:
		return "En proceso"
	case 3:
		return "Terminada"
	case 4:
		return "Error"
	case 5:
		return "Rechazada"
	case 6:
		return "Vencida"
	default:
		return "Desconocido"
	}
}

// readLines lee un archivo y devuelve sus líneas.
func readLines(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	return lines, scanner.Err()
}

// writeLines escribe líneas a un archivo, sobrescribiéndolo.
func writeLines(path string, lines []string) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()
	w := bufio.NewWriter(file)
	for _, line := range lines {
		fmt.Fprintln(w, line)
	}
	return w.Flush()
}

func init() {
	verifyCmd.Flags().StringVar(&verifyRfc, "rfc", "", "RFC del contribuyente")
	verifyCmd.Flags().StringVar(&verifyID, "id", "", "ID de la solicitud a verificar (opcional)")
	verifyCmd.MarkFlagRequired("rfc")

	rootCmd.AddCommand(verifyCmd)
}
