package cmd

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

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
			status, downloadIDs, mensaje, err := service.VerifyRequest(verifyID)
			if err != nil {
				fmt.Printf("Error al verificar: %v\n", err)
				return
			}
			// El estado no se conoce aquí, así que lo dejamos vacío.
			handleVerificationResult(service, verifyID, "", status, downloadIDs, mensaje)
		} else {
			// Verificar todos los IDs pendientes
			fmt.Println("Verificando todas las solicitudes pendientes...")
			solicitudesFile := filepath.Join(service.rfcDir, "solicitudes.json")

			type Solicitud struct {
				ID     string `json:"id"`
				Estado string `json:"estado"`
			}

			var solicitudes []Solicitud
			if _, err := os.Stat(solicitudesFile); err == nil {
				data, err := ioutil.ReadFile(solicitudesFile)
				if err != nil {
					fmt.Printf("Error al leer el archivo de solicitudes: %v\n", err)
					return
				}
				json.Unmarshal(data, &solicitudes)
			}

			var remainingSolicitudes []Solicitud
			for _, sol := range solicitudes {
				fmt.Printf("Verificando ID: %s\n", sol.ID)
				status, downloadIDs, mensaje, err := service.VerifyRequest(sol.ID)
				if err != nil {
					fmt.Printf("Error al verificar ID %s: %v\n", sol.ID, err)
					remainingSolicitudes = append(remainingSolicitudes, sol) // Keep it for next time
					continue
				}
				if !handleVerificationResult(service, sol.ID, sol.Estado, status, downloadIDs, mensaje) {
					remainingSolicitudes = append(remainingSolicitudes, sol)
				}
			}

			// Reescribir el archivo de solicitudes con los que no se completaron
			data, err := json.MarshalIndent(remainingSolicitudes, "", "  ")
			if err != nil {
				fmt.Printf("Error al serializar el archivo de solicitudes: %v\n", err)
				return
			}
			ioutil.WriteFile(solicitudesFile, data, 0644)
		}
	},
}

// handleVerificationResult procesa el resultado y devuelve true si la solicitud se completó (y debe ser eliminada de la lista de pendientes).
func handleVerificationResult(s *SatService, requestID, estado string, status int, downloadIDs []string, mensaje string) bool {
	fmt.Printf("  > Estado: %s (%d) - %s\n", statusToString(status), status, mensaje)

	// Si la solicitud está Terminada (3), se considera manejada.
	if status == 3 {
		// Si el SAT devuelve explícitamente los IDs de paquetes, los usamos.
		if len(downloadIDs) > 0 {
			fmt.Printf("  > ¡Éxito! IDs de descarga recibidos explícitamente: %v\n", downloadIDs)
			saveDownloadIDs(s, downloadIDs, estado)
		} else {
			// Si no, aplicamos el truco descubierto: usar el ID de la solicitud con sufijo.
			fmt.Println("  > Solicitud terminada sin IDs de paquete explícitos. Intentando generar ID de descarga alternativo.")
			alternativeID := strings.ToUpper(requestID) + "_01"
			fmt.Printf("  > ID de descarga generado: %s\n", alternativeID)
			saveDownloadIDs(s, []string{alternativeID}, estado)
		}
		return true // La solicitud se completó y se manejó.
	}

	// Si la solicitud ya no está en un estado pendiente o en proceso (Error, Rechazada, Vencida), también se considera manejada.
	if status >= 4 {
		fmt.Printf("  > La solicitud ha finalizado con un estado de error/terminal y será eliminada de la lista de pendientes.\n")
		return true
	}

	// Si el estado es 1 (Aceptada) o 2 (En proceso), sigue pendiente.
	return false
}

// saveDownloadIDs guarda una lista de IDs en el archivo idsdescarga.json
func saveDownloadIDs(s *SatService, ids []string, estado string) {
	idsDescargaFile := filepath.Join(s.rfcDir, "idsdescarga.json")

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

	for _, id := range ids {
		descargas = append(descargas, Descarga{ID: id, Estado: estado})
	}

	data, err := json.MarshalIndent(descargas, "", "  ")
	if err != nil {
		fmt.Printf("Error al serializar el archivo de descargas: %v\n", err)
		return
	}

	err = ioutil.WriteFile(idsDescargaFile, data, 0644)
	if err != nil {
		fmt.Printf("Error al guardar el ID de descarga: %v\n", err)
	}
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
