feat/sat-cli-tool
# SAT CLI Tool in Go

Esta es una herramienta de línea de comandos (CLI) escrita en Go para interactuar con los web services de descarga masiva del SAT en México. Es una re-implementación en Go de la funcionalidad proporcionada por el script de Bash `satxml`.

La aplicación permite registrar RFCs, autenticarse, solicitar, verificar y descargar paquetes de CFDI, y sincronizar los metadatos de los XML a una base de datos SQLite para su posterior análisis y reporte.

## Características

- **Gestión por RFC:** Cada RFC registrado tiene su propio directorio de trabajo en `~/.sat/<RFC>/`, que contiene su configuración, token de autenticación y archivos descargados.
- **Flujo de Descarga Completo:** Soporta todo el ciclo de vida de la descarga masiva: autenticación, solicitud, verificación y descarga.
- **Base de Datos Personalizable:** Sincroniza los metadatos de los archivos XML descargados a una base de datos SQLite con tablas separadas para **CFDI** y **Retenciones**. La estructura de las tablas se puede definir mediante archivos de configuración (`campos` y `campos_retenciones`). Soporta **CFDI (3.3 y 4.0)** y **Retenciones (1.0 y 2.0)**, incluyendo impuestos, desgloses de nómina y complementos.
- **Reportes y Exportación:** Permite ejecutar consultas SQL sobre la base de datos para generar reportes en consola o exportarlos directamente a archivos **CSV**.

## Instalación

Para compilar la aplicación desde la fuente, clona el repositorio y ejecuta el siguiente comando.

**En Linux/macOS:**
```bash
go build -o sat .
```

**En Windows (CMD o PowerShell):**
```batch
go build -o sat.exe .
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

Escanea los XML descargados y guarda sus metadatos en una base de datos SQLite (`~/.sat/<RFC>/sat.db`). Los datos se dividen automáticamente en dos tablas: `cfdis` y `retenciones`.

```bash
./sat db-sync --rfc TU_RFC_AQUI
```
La primera vez que se ejecuta, se crearán dos archivos de configuración en `~/.sat/<RFC>/`:
- `campos`: Para configurar la extracción de CFDIs estándar (Facturas, Nómina, Pagos).
- `campos_retenciones`: Para configurar la extracción de comprobantes de Retenciones e Información de Pagos.

Ambas tablas incluyen una columna automática `subtipo` que indica si el comprobante es **emitido** o **recibido**.

**Características de los archivos de campos:**
- **Comentarios:** Puedes usar `#` para agregar comentarios u organizar tus campos.
- **Flexibilidad:** Puedes añadir o quitar campos según tus necesidades.
- **Referencia:** Consulta los archivos `campos_cfdi_referencia.txt` y `campos_reten_referencia.txt` en la raíz de este repositorio para ver todos los XPaths disponibles para cada tipo de reporte.

## Especificaciones Técnicas de XPath

La aplicación utiliza el motor de XPath `antchfx/xpath`, que implementa:
- **XPath 1.0:** Soporte completo para ejes, predicados y operadores.
- **XPath 2.0 (Funciones Seleccionadas):** Incluye funciones extendidas como `lower-case()`, `ends-with()`, `matches()` (regex) y `replace()`.

Se recomienda el uso de `local-name()` en las expresiones de los campos para garantizar la compatibilidad entre distintas versiones de CFDI y proveedores, evitando problemas con los prefijos de espacios de nombres (`cfdi:`, `tfd:`, etc.).

### 7. Generar un Reporte

El comando `report` se divide en dos subcomandos para acceder a las tablas correspondientes.

#### Reporte de CFDIs Normales
Consulta la tabla `cfdis`.

```bash
# Ejecutar consulta por defecto para CFDIs
./sat report cfdi --rfc TU_RFC_AQUI

# Filtrar por subtipo (emitidos/recibidos)
./sat report cfdi --rfc TU_RFC_AQUI -q "SELECT * FROM cfdis WHERE subtipo = 'emitido';"

# Exportar a CSV
./sat report cfdi --rfc TU_RFC_AQUI --csv reporte_facturas.csv
```

#### Reporte de Retenciones
Consulta la tabla `retenciones`.

```bash
# Ejecutar consulta por defecto para Retenciones
./sat report retenciones --rfc TU_RFC_AQUI

# Consulta personalizada filtrando por ejercicio
./sat report retenciones --rfc TU_RFC_AQUI -q "SELECT * FROM retenciones WHERE reten_periodo_ejercicio = 2023;"
```

#### Flags Globales de Reporte
- `--rfc`: (Obligatorio) RFC del contribuyente.
- `-q, --query`: Consulta SQL personalizada. Aunque se use una consulta personalizada, el comando seguirá filtrando las columnas visibles según el subcomando elegido (`cfdi` o `retenciones`).
- `--csv`: Ruta del archivo para exportar los resultados.
