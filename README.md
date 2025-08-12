# satxml-go

Una reescritura completa de la herramienta `satxml` en Go. Esta versión ofrece mejoras masivas de rendimiento, concurrencia nativa para descargas y una instalación más sencilla a través de un único ejecutable binario.

## Ventajas sobre la versión original en Bash

*   **Rendimiento Superior:** Al ser una aplicación compilada, se elimina la sobrecarga de llamar a docenas de procesos externos (`curl`, `openssl`, `xmllint`).
*   **Descargas Concurrentes:** Los comandos `ver` y `des` ahora pueden procesar todas las solicitudes pendientes en paralelo, reduciendo drásticamente los tiempos de espera.
*   **Base de Datos Eficiente:** La inserción de datos en la base de datos SQLite se realiza mediante transacciones masivas (bulk inserts), lo que es órdenes de magnitud más rápido que el método anterior.
*   **Instalación Sencilla:** No hay dependencias externas. Solo se necesita descargar un único archivo ejecutable para su sistema operativo.

## Instalación

La forma más sencilla de instalar es descargar el binario precompilado para su sistema operativo desde la página de "Releases" de este repositorio.

Coloque el ejecutable en un directorio incluido en su `PATH` del sistema (por ejemplo, `/usr/local/bin` en Linux/macOS).

### Compilación desde la fuente

Si prefiere compilarlo usted mismo, necesita tener Go (versión 1.18 o superior) instalado.

```bash
git clone https://github.com/alberto2236/satxml.git
cd satxml/satxml-go
go build
```

Para compilación cruzada (por ejemplo, generar un ejecutable para Windows desde Linux):

```bash
# Para Windows
GOOS=windows GOARCH=amd64 go build -o satxml-go.exe

# Para macOS (Apple Silicon)
GOOS=darwin GOARCH=arm64 go build -o satxml-go_macos
```

## Uso

El uso es casi idéntico al de la versión original.

### Inicializar RFC
```bash
satxml-go rfc XAXX010101000 -k ruta/fiel/archivo.key -c ruta/fiel/archivo.cer -p fielpass
```

### Solicitar/Verificar/Descargar
```bash
# Solicitar Emitidos
satxml-go solE XAXX010101000 -i "2023-02-01T00:00:00" -f "2023-02-28T23:59:59"

# Solicitar Recibidos
satxml-go solR XAXX010101000 -i "2023-02-01T00:00:00" -f "2023-02-28T23:59:59"

# Verificar todas las solicitudes pendientes (en paralelo)
satxml-go ver XAXX010101000

# Descargar todos los paquetes listos (en paralelo)
satxml-go des XAXX010101000
```

### Reportes y Base de Datos
```bash
# Generar un reporte con el query por defecto
satxml-go rep XAXX010101000

# Generar un reporte con un query personalizado
satxml-go rep XAXX010101000 -q "SELECT emisor, total FROM cfdis WHERE tipo='I' LIMIT 10"

# Reconstruir la base de datos desde los archivos .zip en el directorio actual
satxml-go rbd XAXX010101000
```
