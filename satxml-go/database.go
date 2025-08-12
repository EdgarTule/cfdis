package main

import (
	"archive/zip"
	"bufio"
	"bytes"
	"database/sql"
	"fmt"
	"github.com/antchfx/xmlquery"
	"io"
	"os"
	"path/filepath"
	"strings"

	_ "github.com/mattn/go-sqlite3"
)

// Campo defines the structure for a field from the 'campos' file.
type Campo struct {
	Nombre string
	Tipo   string
	XPath  string
}

// parseCamposFile reads the campos file and returns a slice of Campo structs.
func parseCamposFile(rfc string) ([]*Campo, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}

	// Prefer user-specific campos file, otherwise use default.
	camposPath := filepath.Join(homeDir, ".satxml", "campos")
	if _, err := os.Stat(camposPath); os.IsNotExist(err) {
		// This path needs to be adjusted for a real installation
		camposPath = "/usr/share/satxml/campos"
	}

	file, err := os.Open(camposPath)
	if err != nil {
		return nil, fmt.Errorf("el archivo 'campos' no se encuentra en ~/.satxml/ ni en /usr/share/satxml/")
	}
	defer file.Close()

	var campos []*Campo
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) < 3 {
			continue
		}
		campo := &Campo{
			Nombre: parts[0],
			Tipo:   parts[1],
			XPath:  strings.Join(parts[2:], " "),
		}
		campos = append(campos, campo)
	}

	return campos, scanner.Err()
}

// initDB creates and initializes the SQLite database for a given RFC.
func initDB(rfc string, campos []*Campo) (*sql.DB, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	dbPath := filepath.Join(homeDir, ".satxml", rfc, "db")

	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, err
	}

	// Build CREATE TABLE statement
	var sb strings.Builder
	sb.WriteString("CREATE TABLE IF NOT EXISTS cfdis (id TEXT PRIMARY KEY, archivo TEXT")
	for _, campo := range campos {
		sb.WriteString(fmt.Sprintf(", %s %s", campo.Nombre, campo.Tipo))
	}
	sb.WriteString(");")

	_, err = db.Exec(sb.String())
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to create table: %w", err)
	}

	return db, nil
}

// ProcessZipFile reads a zip file, extracts data from each XML, and inserts it into the DB.
func ProcessZipFile(rfc, zipFilePath string) error {
	campos, err := parseCamposFile(rfc)
	if err != nil {
		return fmt.Errorf("error al procesar el archivo campos: %w", err)
	}

	db, err := initDB(rfc, campos)
	if err != nil {
		return fmt.Errorf("error al inicializar la base de datos: %w", err)
	}
	defer db.Close()

	r, err := zip.OpenReader(zipFilePath)
	if err != nil {
		return fmt.Errorf("failed to open zip file: %w", err)
	}
	defer r.Close()

	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}

	// Prepare statement
	var sb strings.Builder
	sb.WriteString("INSERT OR REPLACE INTO cfdis (id, archivo")
	for _, campo := range campos {
		sb.WriteString(", " + campo.Nombre)
	}
	sb.WriteString(") VALUES (?, ?")
	for range campos {
		sb.WriteString(", ?")
	}
	sb.WriteString(");")

	stmt, err := tx.Prepare(sb.String())
	if err != nil {
		return fmt.Errorf("failed to prepare statement: %w", err)
	}
	defer stmt.Close()

	for _, f := range r.File {
		if !strings.HasSuffix(strings.ToLower(f.Name), ".xml") {
			continue
		}

		rc, err := f.Open()
		if err != nil {
			fmt.Printf("failed to open file inside zip %s: %v\n", f.Name, err)
			continue
		}

		xmlData, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			fmt.Printf("failed to read file inside zip %s: %v\n", f.Name, err)
			continue
		}

		doc, err := xmlquery.Parse(bytes.NewReader(xmlData))
		if err != nil {
			fmt.Printf("failed to parse xml %s: %v\n", f.Name, err)
			continue
		}

		// This is the UUID, used as primary key
		uuidNode := xmlquery.FindOne(doc, `//tfd:TimbreFiscalDigital/@UUID`)
		if uuidNode == nil {
			continue // Skip if no UUID
		}
		uuid := uuidNode.InnerText()

		args := []interface{}{uuid, f.Name}
		for _, campo := range campos {
			node := xmlquery.FindOne(doc, campo.XPath)
			if node != nil {
				args = append(args, node.InnerText())
			} else {
				args = append(args, nil) // Insert NULL if node not found
			}
		}

		_, err = stmt.Exec(args...)
		if err != nil {
			// Try to rollback, but don't hide the original error
			tx.Rollback()
			return fmt.Errorf("failed to execute statement for %s: %w", f.Name, err)
		}
	}

	fmt.Println("Committing transaction...")
	return tx.Commit()
}

// queryDB connects to the DB and executes a read-only query, printing the results.
func queryDB(rfc, query string) error {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	dbPath := filepath.Join(homeDir, ".satxml", rfc, "db")

	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return err
	}
	defer db.Close()

	rows, err := db.Query(query)
	if err != nil {
		return fmt.Errorf("failed to execute query: %w", err)
	}
	defer rows.Close()

	cols, err := rows.Columns()
	if err != nil {
		return fmt.Errorf("failed to get columns: %w", err)
	}

	// Print header
	fmt.Println(strings.Join(cols, " | "))
	fmt.Println(strings.Repeat("-", len(strings.Join(cols, " | "))))

	for rows.Next() {
		columns := make([]interface{}, len(cols))
		columnPointers := make([]interface{}, len(cols))
		for i := range columns {
			columnPointers[i] = &columns[i]
		}

		if err := rows.Scan(columnPointers...); err != nil {
			return fmt.Errorf("failed to scan row: %w", err)
		}

		var rowStr []string
		for _, col := range columns {
			if col == nil {
				rowStr = append(rowStr, "NULL")
			} else {
				rowStr = append(rowStr, fmt.Sprintf("%s", col))
			}
		}
		fmt.Println(strings.Join(rowStr, " | "))
	}

	return rows.Err()
}
