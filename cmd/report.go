package cmd

import (
	"database/sql"
	"encoding/csv"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	_ "modernc.org/sqlite"
)

var (
	reportRfc   string
	reportQuery string
	reportCsv   string
)

const defaultQuery = "SELECT * FROM cfdis ORDER BY fecha ASC;"

var reportCmd = &cobra.Command{
	Use:   "report",
	Short: "Genera un reporte desde la base de datos de CFDI y Retenciones.",
	Long:  `Ejecuta una consulta en la base de datos SQLite y muestra los resultados en consola o los exporta a un archivo CSV.`,
}

var reportCfdiCmd = &cobra.Command{
	Use:   "cfdi",
	Short: "Genera un reporte de CFDIs normales.",
	Run: func(cmd *cobra.Command, args []string) {
		runReportWithType("cfdi")
	},
}

var reportRetencionesCmd = &cobra.Command{
	Use:   "retenciones",
	Short: "Genera un reporte de Retenciones.",
	Run: func(cmd *cobra.Command, args []string) {
		runReportWithType("retenciones")
	},
}

func runReportWithType(tipo string) {
	homeDir, _ := os.UserHomeDir()
	dbPath := filepath.Join(homeDir, ".sat", reportRfc, "sat.db")
	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		fmt.Printf("Error: No se encontró la base de datos para el RFC %s. Ejecute 'db-sync' primero.\n", reportRfc)
		return
	}

	query := reportQuery
	if query == "" {
		if tipo == "cfdi" {
			query = "SELECT * FROM cfdis WHERE tipo = 'cfdi' ORDER BY fecha ASC;"
		} else {
			query = "SELECT * FROM cfdis WHERE tipo = 'retenciones' ORDER BY reten_fecha_exp ASC;"
		}
	}

	if reportCsv == "" {
		fmt.Printf("Ejecutando consulta: %s\n\n", query)
	}

	err := runReport(dbPath, query, reportCsv, tipo)
	if err != nil {
		fmt.Printf("Error al generar el reporte: %v\n", err)
	}
}

func runReport(dbPath, query, csvPath, tipo string) error {
	db, err := sql.Open("sqlite", dbPath)
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

	// Filtrar columnas según el tipo
	var filteredIndices []int
	var filteredColumns []string
	for i, col := range columns {
		if tipo == "cfdi" && strings.HasPrefix(col, "reten_") {
			continue
		}
		if tipo == "retenciones" && !strings.HasPrefix(col, "reten_") && col != "uuid" && col != "xml_path" && col != "tipo" && col != "id" {
			continue
		}
		filteredIndices = append(filteredIndices, i)
		filteredColumns = append(filteredColumns, col)
	}

	var csvWriter *csv.Writer
	var csvFile *os.File
	if csvPath != "" {
		csvFile, err = os.Create(csvPath)
		if err != nil {
			return fmt.Errorf("crear archivo csv: %w", err)
		}
		defer csvFile.Close()
		csvWriter = csv.NewWriter(csvFile)
		defer csvWriter.Flush()
		if err := csvWriter.Write(filteredColumns); err != nil {
			return err
		}
	} else {
		// Imprimir encabezados a consola
		fmt.Println(strings.Join(filteredColumns, "|"))
	}

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
		for _, idx := range filteredIndices {
			v := values[idx]
			switch val := v.(type) {
			case []byte:
				rowStrings = append(rowStrings, string(val))
			case string:
				rowStrings = append(rowStrings, val)
			case int64:
				rowStrings = append(rowStrings, fmt.Sprintf("%d", val))
			case float64:
				rowStrings = append(rowStrings, fmt.Sprintf("%v", val))
			case nil:
				rowStrings = append(rowStrings, "")
			default:
				rowStrings = append(rowStrings, fmt.Sprintf("%v", v))
			}
		}

		if csvWriter != nil {
			if err := csvWriter.Write(rowStrings); err != nil {
				return err
			}
		} else {
			fmt.Println(strings.Join(rowStrings, "|"))
		}
		rowCount++
	}

	if csvWriter != nil {
		fmt.Printf("Reporte exportado exitosamente a %s (%d registros).\n", csvPath, rowCount)
	} else {
		fmt.Printf("\nTotal de registros: %d\n", rowCount)
	}

	return rows.Err()
}

func init() {
	reportCmd.PersistentFlags().StringVar(&reportRfc, "rfc", "", "RFC del contribuyente")
	reportCmd.PersistentFlags().StringVarP(&reportQuery, "query", "q", "", "Consulta SQL personalizada a ejecutar")
	reportCmd.PersistentFlags().StringVar(&reportCsv, "csv", "", "Ruta del archivo CSV para exportar los resultados")
	reportCmd.MarkPersistentFlagRequired("rfc")

	reportCmd.AddCommand(reportCfdiCmd)
	reportCmd.AddCommand(reportRetencionesCmd)

	rootCmd.AddCommand(reportCmd)
}
