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

		// Decodificar el PEM
		block, _ := pem.Decode(cerBytes)
		if block == nil {
			fmt.Println("Error: No se pudo decodificar el archivo .cer. Asegúrate de que sea un certificado PEM válido.")
			return
		}

		// Parsear el certificado
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			fmt.Printf("Error al parsear el certificado: %v\n", err)
			return
		}

		// Extraer el RFC del campo Subject
		// El RFC se encuentra en el campo UID (OID 2.5.4.45) dentro del Subject.
		rfcRegex := regexp.MustCompile(`OID\.2\.5\.4\.45=([A-Z&Ñ]{3,4}\d{6}[A-Z0-9]{3})`)
		matches := rfcRegex.FindStringSubmatch(cert.Subject.String())
		if len(matches) < 2 {
			fmt.Println("Error: No se pudo encontrar el RFC en el certificado.")
			fmt.Println("Asegúrate de que el certificado es el de la e.firma emitido por el SAT.")
			return
		}
		rfc := matches[1]
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

func init() {
	rootCmd.AddCommand(addRfcCmd)
	addRfcCmd.Flags().StringVar(&keyPath, "key", "", "Ruta al archivo .key de la e.firma")
	addRfcCmd.Flags().StringVar(&cerPath, "cer", "", "Ruta al archivo .cer de la e.firma")
	addRfcCmd.MarkFlagRequired("key")
	addRfcCmd.MarkFlagRequired("cer")
}
