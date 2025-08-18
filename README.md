# SAT CLI Tool in Go

Esta es una herramienta de línea de comandos (CLI) escrita en Go para interactuar con los web services de descarga masiva del SAT en México. Es una re-implementación en Go de la funcionalidad proporcionada por el script de Bash `satxml`.

La aplicación permite registrar RFCs, autenticarse, solicitar, verificar y descargar paquetes de CFDI, y sincronizar los metadatos de los XML a una base de datos SQLite para su posterior análisis y reporte.

## Características

- **Gestión por RFC:** Cada RFC registrado tiene su propio directorio de trabajo en `~/.sat/<RFC>/`, que contiene su configuración, token de autenticación y archivos descargados.
- **Flujo de Descarga Completo:** Soporta todo el ciclo de vida de la descarga masiva: autenticación, solicitud, verificación y descarga.
- **Base de Datos Personalizable:** Sincroniza los metadatos de los archivos XML descargados a una base de datos SQLite. La estructura de la tabla se puede definir mediante un archivo `campos`.
- **Reportes:** Permite ejecutar consultas SQL sobre la base de datos para generar reportes.

## Instalación

Para compilar la aplicación desde la fuente, clona el repositorio y ejecuta el siguiente comando. Esto creará un ejecutable llamado `sat` en el directorio actual.

```bash
go build -o sat .
```

## Uso

A continuación se muestran ejemplos de cómo usar cada comando.

### 1. Registrar un RFC

Este es el primer paso. Debes registrar un RFC usando los archivos de tu e.firma. La aplicación extraerá el RFC del certificado, creará el directorio de trabajo y guardará la configuración.

```bash
./sat add-rfc --key /ruta/a/tu/llave.key --cer /ruta/a/tu/certificado.cer
```

### 2. Probar Autenticación

Puedes forzar una nueva autenticación para verificar que tus credenciales son correctas. Se te pedirá la contraseña de tu e.firma.

```bash
./sat auth --rfc TU_RFC_AQUI
```

### 3. Solicitar una Descarga

Envía una solicitud para descargar CFDI o Retenciones, ya sean emitidos o recibidos, en un rango de fechas.

- `--solicitud`: Especifica el tipo de documento. Puede ser `cfdi` (por defecto) o `retenciones`.
- `--tipo`: Especifica si son `emitidos` o `recibidos`.

```bash
# Solicitar CFDI Emitidos
./sat request --rfc TU_RFC_AQUI --tipo emitidos --start "2023-01-01T00:00:00" --end "2023-01-31T23:59:59"

# Solicitar Retenciones Recibidas
./sat request --rfc TU_RFC_AQUI --solicitud retenciones --tipo recibidos --start "2023-01-01T00:00:00" --end "2023-01-31T23:59:59"
```
El ID de la solicitud se guardará en `~/.sat/<RFC>/solicitudes.txt`.

### 4. Verificar el Estado de las Solicitudes

Verifica el estado de las solicitudes pendientes. Si una solicitud está terminada, su ID de descarga se moverá a `idsdescarga.txt`.

```bash
# Verificar todas las solicitudes pendientes para un RFC
./sat verify --rfc TU_RFC_AQUI

# Verificar una solicitud específica por su ID
./sat verify --rfc TU_RFC_AQUI --id "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
```

### 5. Descargar los Paquetes

Descarga los paquetes que ya han sido procesados por el SAT. Los archivos XML se guardarán en `~/.sat/<RFC>/cfdis/`. La aplicación evitará descargar archivos XML que ya existan en esa carpeta.

```bash
# Descargar todos los paquetes listos para un RFC
./sat download --rfc TU_RFC_AQUI

# Descargar un paquete específico por su ID
./sat download --rfc TU_RFC_AQUI --id "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
```

### 6. Sincronizar la Base de Datos

Escanea los XML descargados y guarda sus metadatos en una base de datos SQLite (`~/.sat/<RFC>/sat.db`).

```bash
./sat db-sync --rfc TU_RFC_AQUI
```
La primera vez que se ejecuta, creará un archivo `campos` por defecto en `~/.sat/<RFC>/campos`. Puedes editar este archivo para personalizar los campos que se extraen de los XML.

### 7. Generar un Reporte

Ejecuta una consulta sobre la base de datos SQLite.

```bash
# Ejecutar una consulta por defecto (SELECT * FROM cfdis)
./sat report --rfc TU_RFC_AQUI

# Ejecutar una consulta personalizada
./sat report --rfc TU_RFC_AQUI -q "SELECT uuid, fecha, total FROM cfdis WHERE total > 1000;"
```
