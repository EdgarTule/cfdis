package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
)

var (
	dbSyncRfc string
)

var dbSyncCmd = &cobra.Command{
	Use:   "db-sync",
	Short: "Sincroniza los XML descargados a una base de datos SQLite.",
	Long:  `Escanea el directorio de CFDI, parsea los XML y guarda los datos en una base de datos SQLite para futuras consultas y reportes.`,
	Run: func(cmd *cobra.Command, args []string) {
		homeDir, _ := os.UserHomeDir()
		rfcDir := filepath.Join(homeDir, ".sat", dbSyncRfc)
		if _, err := os.Stat(rfcDir); os.IsNotExist(err) {
			fmt.Printf("Error: No se encontró directorio para el RFC %s. Registre el RFC primero.\n", dbSyncRfc)
			return
		}

		// Creamos una instancia de servicio sin credenciales, ya que no son necesarias para esta operación.
		service := &SatService{
			rfc:    dbSyncRfc,
			rfcDir: rfcDir,
		}

		fmt.Println("Iniciando sincronización de la base de datos...")
		err := service.SyncDatabase()
		if err != nil {
			fmt.Printf("Error durante la sincronización: %v\n", err)
			return
		}

		fmt.Println("Sincronización completada exitosamente.")
	},
}

func init() {
	dbSyncCmd.Flags().StringVar(&dbSyncRfc, "rfc", "", "RFC del contribuyente a sincronizar")
	dbSyncCmd.MarkFlagRequired("rfc")

	rootCmd.AddCommand(dbSyncCmd)
}
