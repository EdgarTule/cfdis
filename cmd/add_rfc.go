package cmd

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"

	"github.com/spf13/cobra"
)

var (
	keyPath string
	cerPath string
)

var addRfcCmd = &cobra.Command{
	Use:   "add-rfc",
	Short: "Registra un nuevo RFC usando los archivos de la e.firma",
	Long: `Lee el archivo .cer para extraer el RFC, crea un directorio de trabajo
en ~/.sat/<RFC> y guarda la configuración de los archivos de la e.firma.`,
	Run: func(cmd *cobra.Command, args []string) {
		// Validar que las rutas de los archivos no estén vacías
		if keyPath == "" || cerPath == "" {
			fmt.Println("Error: Debes proporcionar la ruta a los archivos .key y .cer usando --key y --cer.")
			return
		}

		// Leer el archivo .cer
		cerBytes, err := ioutil.ReadFile(cerPath)
		if err != nil {
			fmt.Printf("Error al leer el archivo .cer: %v\n", err)
			return
		}

		// Intentar decodificar como PEM primero. Si falla, asumir que es DER.
		block, _ := pem.Decode(cerBytes)
		var certBytes []byte
		if block != nil {
			// Es PEM
			certBytes = block.Bytes
		} else {
			// No es PEM, asumir que es DER crudo
			certBytes = cerBytes
		}

		// Parsear el certificado desde los bytes (PEM decodificados o DER crudos)
		cert, err := x509.ParseCertificate(certBytes)
		if err != nil {
			fmt.Printf("Error al parsear el certificado: %v\n", err)
			fmt.Println("Asegúrate de que el archivo .cer sea válido y esté en formato PEM o DER.")
			return
		}

		// Extraer el RFC de forma robusta
		rfc, err := findRfcInCertificate(cert)
		if err != nil {
			fmt.Println("Error: No se pudo encontrar un RFC válido en el certificado.")
			fmt.Println("Asegúrate de que el certificado es el de la e.firma emitido por el SAT.")
			return
		}
		fmt.Printf("RFC extraído del certificado: %s\n", rfc)

		// Obtener el directorio HOME del usuario
		homeDir, err := os.UserHomeDir()
		if err != nil {
			fmt.Printf("Error al obtener el directorio HOME: %v\n", err)
			return
		}

		// Crear la ruta del directorio para el RFC
		rfcDir := filepath.Join(homeDir, ".sat", rfc)
		if err := os.MkdirAll(rfcDir, 0755); err != nil {
			fmt.Printf("Error al crear el directorio para el RFC: %v\n", err)
			return
		}
		fmt.Printf("Directorio de trabajo creado en: %s\n", rfcDir)

		// Crear y guardar el archivo de configuración
		config := map[string]string{
			"keyPath": keyPath,
			"cerPath": cerPath,
		}
		configBytes, err := json.MarshalIndent(config, "", "  ")
		if err != nil {
			fmt.Printf("Error al generar el archivo de configuración: %v\n", err)
			return
		}

		configPath := filepath.Join(rfcDir, "config.json")
		if err := ioutil.WriteFile(configPath, configBytes, 0644); err != nil {
			fmt.Printf("Error al guardar el archivo de configuración: %v\n", err)
			return
		}

		fmt.Printf("Configuración guardada exitosamente en: %s\n", configPath)
		fmt.Printf("RFC %s ha sido registrado correctamente.\n", rfc)
	},
}

// findRfcInCertificate busca el RFC en varios campos comunes de un certificado de e.firma.
func findRfcInCertificate(cert *x509.Certificate) (string, error) {
	// Estrategia 1: Buscar en el OID específico de RFC (UniqueIdentifier)
	oidRFC := "2.5.4.45"
	for _, attr := range cert.Subject.Names {
		if attr.Type.String() == oidRFC {
			if rfc, ok := attr.Value.(string); ok {
				return rfc, nil
			}
		}
	}

	// Estrategia 2: Usar regex para buscar un RFC en la cadena completa del Subject
	rfcRegex := regexp.MustCompile(`([A-Z&Ñ]{3,4}\d{6}[A-Z0-9]{3})`)
	matches := rfcRegex.FindStringSubmatch(cert.Subject.String())
	if len(matches) > 1 {
		return matches[1], nil
	}

	return "", fmt.Errorf("no se encontró un RFC en los campos del certificado")
}


func init() {
	rootCmd.AddCommand(addRfcCmd)
	addRfcCmd.Flags().StringVar(&keyPath, "key", "", "Ruta al archivo .key de la e.firma")
	addRfcCmd.Flags().StringVar(&cerPath, "cer", "", "Ruta al archivo .cer de la e.firma")
	addRfcCmd.MarkFlagRequired("key")
	addRfcCmd.MarkFlagRequired("cer")
}
