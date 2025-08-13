package cmd

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"golang.org/x/term"
)

var authCmd = &cobra.Command{
	Use:   "auth",
	Short: "Prueba la autenticación con el web service del SAT.",
	Long:  `Usa la e.firma registrada para un RFC para solicitar un token de autenticación al SAT. Forzará una nueva autenticación aunque exista un token reciente.`,
	Run: func(cmd *cobra.Command, args []string) {
		rfc, _ := cmd.Flags().GetString("rfc")
		if rfc == "" {
			fmt.Println("Error: Debes proporcionar el RFC a autenticar usando --rfc.")
			return
		}

		// --- Cargar configuración ---
		homeDir, err := os.UserHomeDir()
		if err != nil {
			fmt.Printf("Error al obtener el directorio HOME: %v\n", err)
			return
		}
		configPath := filepath.Join(homeDir, ".sat", rfc, "config.json")

		if _, err := os.Stat(configPath); os.IsNotExist(err) {
			fmt.Printf("Error: No se encontró una configuración para el RFC %s.\n", rfc)
			return
		}

		var config map[string]string
		configBytes, err := ioutil.ReadFile(configPath)
		if err != nil {
			fmt.Printf("Error al leer el archivo de configuración: %v\n", err)
			return
		}
		json.Unmarshal(configBytes, &config)

		// --- Solicitar contraseña ---
		fmt.Print("Por favor, introduce la contraseña de la e.firma: ")
		password, err := term.ReadPassword(int(os.Stdin.Fd()))
		if err != nil {
			fmt.Printf("\nError al leer la contraseña: %v\n", err)
			return
		}
		fmt.Println()

		// --- Usar el servicio para autenticar ---
		service, err := NewSatService(rfc, config["keyPath"], config["cerPath"], password)
		if err != nil {
			fmt.Printf("Error al inicializar el servicio SAT: %v\n", err)
			return
		}

		// Forzar una nueva autenticación
		if err := service.authenticate(); err != nil {
			fmt.Printf("Error durante la autenticación: %v\n", err)
			return
		}

		fmt.Println("Comando 'auth' ejecutado exitosamente.")
	},
}

func init() {
	authCmd.Flags().String("rfc", "", "RFC a autenticar")
	authCmd.MarkFlagRequired("rfc")
	rootCmd.AddCommand(authCmd)
}
