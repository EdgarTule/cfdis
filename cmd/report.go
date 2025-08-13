package cmd

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	_ "github.com/mattn/go-sqlite3"
	"github.com/spf13/cobra"
)

var (
	reportRfc   string
	reportQuery string
)

const defaultQuery = "SELECT * FROM cfdis ORDER BY fecha ASC;"

var reportCmd = &cobra.Command{
	Use:   "report",
	Short: "Genera un reporte desde la base de datos de CFDI.",
	Long:  `Ejecuta una consulta en la base de datos SQLite y muestra los resultados. Se puede proporcionar una consulta personalizada.`,
	Run: func(cmd *cobra.Command, args []string) {
		homeDir, _ := os.UserHomeDir()
		dbPath := filepath.Join(homeDir, ".sat", reportRfc, "sat.db")
		if _, err := os.Stat(dbPath); os.IsNotExist(err) {
			fmt.Printf("Error: No se encontró la base de datos para el RFC %s. Ejecute 'db-sync' primero.\n", reportRfc)
			return
		}

		query := defaultQuery
		if reportQuery != "" {
			query = reportQuery
		}

		fmt.Printf("Ejecutando consulta: %s\n\n", query)

		err := runReport(dbPath, query)
		if err != nil {
			fmt.Printf("Error al generar el reporte: %v\n", err)
		}
	},
}

func runReport(dbPath, query string) error {
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return err
	}
	defer db.Close()

	rows, err := db.Query(query)
	if err != nil {
		return err
	}
	defer rows.Close()

	columns, err := rows.Columns()
	if err != nil {
		return err
	}

	// Imprimir encabezados
	fmt.Println(strings.Join(columns, "|"))

	// Preparar para escanear
	values := make([]interface{}, len(columns))
	scanArgs := make([]interface{}, len(values))
	for i := range values {
		scanArgs[i] = &values[i]
	}

	rowCount := 0
	for rows.Next() {
		err = rows.Scan(scanArgs...)
		if err != nil {
			return err
		}

		var rowStrings []string
		for _, v := range values {
			switch val := v.(type) {
			case []byte:
				rowStrings = append(rowStrings, string(val))
			case string:
				rowStrings = append(rowStrings, val)
			case int64:
				rowStrings = append(rowStrings, fmt.Sprintf("%d", val))
			case float64:
				rowStrings = append(rowStrings, fmt.Sprintf("%f", val))
			case nil:
				rowStrings = append(rowStrings, "NULL")
			default:
				rowStrings = append(rowStrings, fmt.Sprintf("%v", v))
			}
		}
		fmt.Println(strings.Join(rowStrings, "|"))
		rowCount++
	}

	fmt.Printf("\nTotal de registros: %d\n", rowCount)

	return rows.Err()
}

func init() {
	reportCmd.Flags().StringVar(&reportRfc, "rfc", "", "RFC del contribuyente")
	reportCmd.Flags().StringVarP(&reportQuery, "query", "q", "", "Consulta SQL personalizada a ejecutar")
	reportCmd.MarkFlagRequired("rfc")

	rootCmd.AddCommand(reportCmd)
}
