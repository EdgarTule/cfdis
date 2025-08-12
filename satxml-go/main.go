package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	// Subcommand definition
	rfcCmd := flag.NewFlagSet("rfc", flag.ExitOnError)
	rfcKey := rfcCmd.String("k", "", "Ruta al archivo key de la FIEL")
	rfcCer := rfcCmd.String("c", "", "Ruta al archivo cer de la FIEL")
	rfcPass := rfcCmd.String("p", "", "Contraseña de la FIEL")

	solECmd := flag.NewFlagSet("solE", flag.ExitOnError)
	solEInicio := solECmd.String("i", "", "Fecha inicio, en formato: 2023-01-01T00:00:00")
	solEFin := solECmd.String("f", "", "Fecha fin, en formato: 2023-01-31T23:59:59")

	autCmd := flag.NewFlagSet("aut", flag.ExitOnError)
	autPass := autCmd.String("p", "", "Contraseña de la FIEL (si no está en el config)")
	autVerbose := autCmd.Bool("v", false, "Muestra los mensajes SOAP")

	verCmd := flag.NewFlagSet("ver", flag.ExitOnError)
	verID := verCmd.String("I", "", "ID de la solicitud a verificar")
	verVerbose := verCmd.Bool("v", false, "Muestra los mensajes SOAP")

	desCmd := flag.NewFlagSet("des", flag.ExitOnError)
	desID := desCmd.String("I", "", "ID del paquete a descargar")
	desVerbose := desCmd.Bool("v", false, "Muestra los mensajes SOAP")

	rbdCmd := flag.NewFlagSet("rbd", flag.ExitOnError)
	rbdVerbose := rbdCmd.Bool("v", false, "Muestra los mensajes SOAP")

	repCmd := flag.NewFlagSet("rep", flag.ExitOnError)
	repQuery := repCmd.String("q", "SELECT * FROM cfdis ORDER BY fecha ASC", "Query para generar el reporte")

	// ... other subcommands can be defined here ...

	// Parsing the subcommand
	switch os.Args[1] {
	case "rfc":
		rfcCmd.Parse(os.Args[2:])
		rfc := rfcCmd.Arg(0)
		if rfc == "" || *rfcKey == "" || *rfcCer == "" || *rfcPass == "" {
			fmt.Println("El comando 'rfc' requiere el RFC y las opciones -k, -c y -p")
			rfcCmd.Usage()
			os.Exit(1)
		}
		handleRfc(rfc, *rfcKey, *rfcCer, *rfcPass)
	case "aut":
		autCmd.Parse(os.Args[2:])
		rfc := autCmd.Arg(0)
		if rfc == "" {
			fmt.Println("El comando 'aut' requiere un RFC.")
			autCmd.Usage()
			os.Exit(1)
		}
		handleAuth(rfc, *autPass, *autVerbose)
	case "solE":
		solECmd.Parse(os.Args[2:])
		rfc := solECmd.Arg(0)
		if rfc == "" || *solEInicio == "" || *solEFin == "" {
			fmt.Println("El comando 'solE' requiere el RFC y las opciones -i y -f")
			solECmd.Usage()
			os.Exit(1)
		}
		handleSolicitar(rfc, *solEInicio, *solEFin, "E", *autVerbose)
	case "solR":
		// solR uses the same flags as solE
		solECmd.Parse(os.Args[2:])
		rfc := solECmd.Arg(0)
		if rfc == "" || *solEInicio == "" || *solEFin == "" {
			fmt.Println("El comando 'solR' requiere el RFC y las opciones -i y -f")
			solECmd.Usage()
			os.Exit(1)
		}
		handleSolicitar(rfc, *solEInicio, *solEFin, "R", *autVerbose)
	case "ver":
		verCmd.Parse(os.Args[2:])
		rfc := verCmd.Arg(0)
		if rfc == "" || *verID == "" {
			fmt.Println("El comando 'ver' requiere el RFC y la opción -I")
			verCmd.Usage()
			os.Exit(1)
		}
		handleVerificar(rfc, *verID, *verVerbose)
	case "des":
		desCmd.Parse(os.Args[2:])
		rfc := desCmd.Arg(0)
		if rfc == "" || *desID == "" {
			fmt.Println("El comando 'des' requiere el RFC y la opción -I")
			desCmd.Usage()
			os.Exit(1)
		}
		handleDescargar(rfc, *desID, *desVerbose)
	case "rbd":
		rbdCmd.Parse(os.Args[2:])
		rfc := rbdCmd.Arg(0)
		if rfc == "" {
			fmt.Println("El comando 'rbd' requiere un RFC.")
			rbdCmd.Usage()
			os.Exit(1)
		}
		handleRebuildDB(rfc, *rbdVerbose)
	case "rep":
		repCmd.Parse(os.Args[2:])
		rfc := repCmd.Arg(0)
		if rfc == "" {
			fmt.Println("El comando 'rep' requiere un RFC.")
			repCmd.Usage()
			os.Exit(1)
		}
		handleReport(rfc, *repQuery)
	default:
		printUsage()
		os.Exit(1)
	}
}

func handleRebuildDB(rfc string, verbose bool) {
	fmt.Println("Reconstruyendo la base de datos para:", rfc)
	homeDir, _ := os.UserHomeDir()
	rfcPath := filepath.Join(homeDir, ".satxml", rfc)
	dbPath := filepath.Join(rfcPath, "db")

	// Delete old DB
	os.Remove(dbPath)
	fmt.Println("Base de datos anterior eliminada.")

	// Find all zip files in the current directory (simplification)
	files, err := filepath.Glob("*.zip")
	if err != nil {
		fmt.Println("Error al buscar archivos zip:", err)
		return
	}

	if len(files) == 0 {
		fmt.Println("No se encontraron archivos .zip para procesar en el directorio actual.")
		return
	}

	for _, file := range files {
		fmt.Println("Procesando:", file)
		err := ProcessZipFile(rfc, file)
		if err != nil {
			fmt.Printf("Error procesando %s: %v\n", file, err)
		}
	}
	fmt.Println("Reconstrucción de la base de datos completada.")
}

func handleReport(rfc, query string) {
	fmt.Println("Generando reporte para:", rfc)
	err := queryDB(rfc, query)
	if err != nil {
		fmt.Println("Error al generar el reporte:", err)
	}
}

func handleVerificar(rfc, requestID string, verbose bool) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		fmt.Println("Error al obtener el directorio del usuario:", err)
		os.Exit(1)
	}
	rfcPath := filepath.Join(homeDir, ".satxml", rfc)

	passFile := filepath.Join(rfcPath, "keypass.txt")
	passBytes, err := os.ReadFile(passFile)
	if err != nil {
		fmt.Printf("No se pudo leer la contraseña desde %s.\n", passFile)
		os.Exit(1)
	}
	password := strings.TrimSpace(string(passBytes))

	client, err := NewSatClient(rfc, password)
	if err != nil {
		fmt.Println("Error al crear el cliente SAT:", err)
		os.Exit(1)
	}
	client.verbose = verbose

	if requestID != "" {
		// Single verification
		verificacion, err := client.Verificar(requestID)
		if err != nil {
			fmt.Println("Error during verification:", err)
			os.Exit(1)
		}
		printVerificacionStatus(requestID, verificacion)
	} else {
		// Concurrent verification of all pending requests
		solicitudesFile := filepath.Join(rfcPath, "solicitudes.txt")
		ids, err := readLines(solicitudesFile)
		if err != nil {
			fmt.Println("No hay solicitudes pendientes o no se pudo leer el archivo:", err)
			return
		}

		var wg sync.WaitGroup
		results := make(chan *VerificaResponse, len(ids))
		completedReqs := make(map[string]bool)

		for _, id := range ids {
			wg.Add(1)
			go func(reqID string) {
				defer wg.Done()
				fmt.Printf("Verificando %s...\n", reqID)
				res, err := client.Verificar(reqID)
				if err != nil {
					fmt.Printf("Error verificando %s: %v\n", reqID, err)
					return
				}
				results <- res
				if res.EstadoSolicitud == "3" { // Accepted, ready for download
					completedReqs[reqID] = true
				}
			}(id)
		}

		wg.Wait()
		close(results)

		// Process results and update files
		var newPackageIDs []string
		for res := range results {
			if len(res.IdsPaquetes) > 0 {
				newPackageIDs = append(newPackageIDs, res.IdsPaquetes...)
			}
		}

		if len(newPackageIDs) > 0 {
			appendLines(filepath.Join(rfcPath, "idsdescarga.txt"), newPackageIDs)
			fmt.Printf("%d nuevos paquetes listos para descargar.\n", len(newPackageIDs))
		}

		// Remove completed requests from solicitudes.txt
		var remainingReqs []string
		for _, id := range ids {
			if !completedReqs[id] {
				remainingReqs = append(remainingReqs, id)
			}
		}
		writeLines(solicitudesFile, remainingReqs)
		fmt.Println("Verificación concurrente completada.")
	}
}

func printVerificacionStatus(requestID string, verificacion *VerificaResponse) {
	fmt.Printf("Estado de la solicitud %s: %s\n", requestID, verificacion.EstadoSolicitud)
	fmt.Printf("Código de estado: %s\n", verificacion.CodEstatus)
	fmt.Printf("Número de CFDI: %s\n", verificacion.NumeroCFDIs)
	if len(verificacion.IdsPaquetes) > 0 {
		fmt.Println("IDs de paquetes listos para descargar:")
		for _, pkgID := range verificacion.IdsPaquetes {
			fmt.Println(" -", pkgID)
		}
	}
}

// Helper functions for file operations
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

func writeLines(path string, lines []string) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()
	for _, line := range lines {
		fmt.Fprintln(file, line)
	}
	return nil
}

func appendLines(path string, lines []string) error {
	file, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer file.Close()
	for _, line := range lines {
		fmt.Fprintln(file, line)
	}
	return nil
}

func handleDescargar(rfc, packageID string, verbose bool) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		fmt.Println("Error al obtener el directorio del usuario:", err)
		os.Exit(1)
	}
	rfcPath := filepath.Join(homeDir, ".satxml", rfc)

	passFile := filepath.Join(rfcPath, "keypass.txt")
	passBytes, err := os.ReadFile(passFile)
	if err != nil {
		fmt.Printf("No se pudo leer la contraseña desde %s.\n", passFile)
		os.Exit(1)
	}
	password := strings.TrimSpace(string(passBytes))

	client, err := NewSatClient(rfc, password)
	if err != nil {
		fmt.Println("Error al crear el cliente SAT:", err)
		os.Exit(1)
	}
	client.verbose = verbose

	if packageID != "" {
		// Single download
		downloadAndSave(client, packageID)
	} else {
		// Concurrent download of all pending packages
		idsFile := filepath.Join(rfcPath, "idsdescarga.txt")
		ids, err := readLines(idsFile)
		if err != nil {
			fmt.Println("No hay paquetes pendientes o no se pudo leer el archivo:", err)
			return
		}

		var wg sync.WaitGroup
		completedDownloads := make(chan string, len(ids))

		for _, id := range ids {
			wg.Add(1)
			go func(pkgID string) {
				defer wg.Done()
				fmt.Printf("Descargando %s...\n", pkgID)
				err := downloadAndSave(client, pkgID)
				if err != nil {
					fmt.Printf("Error descargando %s: %v\n", pkgID, err)
					return
				}
				completedDownloads <- pkgID
			}(id)
		}

		wg.Wait()
		close(completedDownloads)

		// Remove completed downloads from idsdescarga.txt
		var completedIDs = make(map[string]bool)
		for id := range completedDownloads {
			completedIDs[id] = true
		}

		var remainingIDs []string
		for _, id := range ids {
			if !completedIDs[id] {
				remainingIDs = append(remainingIDs, id)
			}
		}
		writeLines(idsFile, remainingIDs)
		fmt.Println("Descarga concurrente completada.")
	}
}

func downloadAndSave(c *SatClient, packageID string) error {
	zipData, err := c.Descargar(packageID)
	if err != nil {
		return err
	}

	zipFileName := fmt.Sprintf("%s.zip", packageID)
	err = os.WriteFile(zipFileName, zipData, 0644)
	if err != nil {
		return fmt.Errorf("error al guardar el archivo zip '%s': %w", zipFileName, err)
	}

	fmt.Printf("Paquete descargado y guardado como %s\n", zipFileName)

	fmt.Printf("Procesando archivo zip e insertando en la base de datos para %s...\n", c.rfc)
	err = ProcessZipFile(c.rfc, zipFileName)
	if err != nil {
		return fmt.Errorf("error al procesar el archivo zip: %w", err)
	}

	return nil
}

func handleSolicitar(rfc, startDate, endDate, requestType string, verbose bool) {
	// For this command, we need the password from the config file.
	homeDir, err := os.UserHomeDir()
	if err != nil {
		fmt.Println("Error al obtener el directorio del usuario:", err)
		os.Exit(1)
	}
	passFile := filepath.Join(homeDir, ".satxml", rfc, "keypass.txt")
	passBytes, err := os.ReadFile(passFile)
	if err != nil {
		fmt.Printf("No se pudo leer la contraseña desde %s. Registre el RFC primero con el comando 'rfc'.\n", passFile)
		os.Exit(1)
	}
	password := strings.TrimSpace(string(passBytes))

	client, err := NewSatClient(rfc, password)
	if err != nil {
		fmt.Println("Error al crear el cliente SAT:", err)
		os.Exit(1)
	}
	client.verbose = verbose

	_, err = client.Solicitar(startDate, endDate, requestType)
	if err != nil {
		fmt.Println("Error durante la solicitud:", err)
		os.Exit(1)
	}
}

func handleRfc(rfc, keyFile, cerFile, password string) {
	fmt.Printf("Configurando RFC: %s...\n", rfc)

	// Get user's home directory
	homeDir, err := os.UserHomeDir()
	if err != nil {
		fmt.Println("Error al obtener el directorio del usuario:", err)
		os.Exit(1)
	}

	// Create the RFC configuration path
	rfcPath := filepath.Join(homeDir, ".satxml", rfc)
	if err := os.MkdirAll(rfcPath, 0755); err != nil {
		fmt.Println("Error al crear el directorio de configuración:", err)
		os.Exit(1)
	}

	// Copy key file
	if err := copyFile(keyFile, filepath.Join(rfcPath, "key.key")); err != nil {
		fmt.Println("Error al copiar el archivo .key:", err)
		os.Exit(1)
	}

	// Copy cer file
	if err := copyFile(cerFile, filepath.Join(rfcPath, "cer.cer")); err != nil {
		fmt.Println("Error al copiar el archivo .cer:", err)
		os.Exit(1)
	}

	// Save password
	passFile := filepath.Join(rfcPath, "keypass.txt")
	if err := os.WriteFile(passFile, []byte(password), 0600); err != nil {
		fmt.Println("Error al guardar la contraseña:", err)
		os.Exit(1)
	}

	fmt.Println("RFC configurado exitosamente en:", rfcPath)
}

func handleAuth(rfc, password string, verbose bool) {
	fmt.Println("Autenticando RFC:", rfc)

	// If password is not provided via flag, read it from config file
	if password == "" {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			fmt.Println("Error al obtener el directorio del usuario:", err)
			os.Exit(1)
		}
		passFile := filepath.Join(homeDir, ".satxml", rfc, "keypass.txt")
		passBytes, err := os.ReadFile(passFile)
		if err != nil {
			fmt.Printf("No se pudo leer la contraseña desde %s. Use el flag -p.\n", passFile)
			os.Exit(1)
		}
		password = strings.TrimSpace(string(passBytes))
	}

	client, err := NewSatClient(rfc, password)
	if err != nil {
		fmt.Println("Error al crear el cliente SAT:", err)
		os.Exit(1)
	}
	client.verbose = verbose

	err = client.Authenticate()
	if err != nil {
		fmt.Println("Error durante la autenticación:", err)
		os.Exit(1)
	}
}

// copyFile utility function
func copyFile(src, dst string) error {
	sourceFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer sourceFile.Close()

	destFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer destFile.Close()

	_, err = io.Copy(destFile, sourceFile)
	return err
}

func printUsage() {
	fmt.Println("Uso: satxml-go <comando> [opciones]")
	fmt.Println("\nComandos:")
	fmt.Println("  rfc <RFC> -k <key> -c <cer> -p <pass>    Inicializa/Actualiza un rfc.")
	fmt.Println("  solE <RFC> -i <inicio> -f <fin>           Solicitud de descarga de EMITIDOS.")
	// ... other usage info ...
}
