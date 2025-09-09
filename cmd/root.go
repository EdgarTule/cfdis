package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "sat",
	Short: "Una aplicación CLI para la descarga masiva de CFDI y retenciones del SAT.",
	Long: `sat es una herramienta de línea de comandos para interactuar
con los web services de descarga masiva del SAT, permitiendo
registrar RFCs, solicitar, verificar y descargar comprobantes.`,
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Hubo un error al ejecutar la aplicación: '%s'", err)
		os.Exit(1)
	}
}
