# NetMonitor

Monitor de red local para Windows con ventana propia: tráfico en vivo del PC, todos los dispositivos de la red, tráfico por dispositivo leído del router, conexiones por programa, latencia y estado de exposición a internet. Vive en la bandeja del sistema, arranca con Windows y está pensado también para dejarlo fijo en un monitor vertical.

Escrito en **Rust + [Tauri 2](https://tauri.app)** (WebView2). El instalador ocupa ~2 MB y el ejecutable ~5 MB.

---

## Índice
1. [Qué muestra](#qué-muestra)
2. [Cómo se usa](#cómo-se-usa)
3. [Instalación](#instalación)
4. [Compilar desde el código](#compilar-desde-el-código)
5. [Arquitectura](#arquitectura)
6. [Cómo obtiene cada dato](#cómo-obtiene-cada-dato)
7. [Protocolo del router TP-Link](#protocolo-del-router-tp-link)
8. [Datos que guarda](#datos-que-guarda)
9. [Seguridad y privacidad](#seguridad-y-privacidad)
10. [Limitaciones conocidas](#limitaciones-conocidas)
11. [Historia del proyecto](#historia-del-proyecto)

---

## Qué muestra

| Sección | Contenido |
|---|---|
| **Cabecera** | Interfaz activa (nombre, velocidad de enlace, IP, puerta de enlace) y tres indicadores: router, barrido de la red local e internet. |
| **Ahora** | Bajada y subida actuales en cifras grandes, pico y total de la sesión. Debajo, gráfica espejo de los últimos 15 min: la bajada crece hacia arriba (azul) y la subida hacia abajo (ámbar), cada mitad con su propia escala. Al pasar el ratón se ve el valor de cualquier instante. |
| **Indicadores** | Latencia al router y a internet (1.1.1.1) con media, jitter, pérdidas y minigráfica; dispositivos activos y sin identificar; conexiones TCP (a internet / locales); IP pública, difuminada hasta pasar el ratón. |
| **Dispositivos** | Una fila por dispositivo de la red: icono según el tipo (router, PC, móvil, TV, enchufe, robot, repetidor), nombre, IP, MAC, velocidad de bajada y subida según el router y minigráfica de 10 min. Marca los **sin identificar**, los **nuevos** y las **MAC aleatorias** (privacidad de los móviles). Se ordena por actividad o por IP, y un clic en el nombre lo renombra. |
| **Reparto del tráfico** | Gráfico de flujo (*streamgraph*) con una banda por dispositivo: quién usa la red en los últimos 10 minutos y qué porcentaje le corresponde. |
| **Programas con red** | Procesos de este PC con conexiones abiertas, cuántas tienen y a qué hosts van. |
| **Conexiones** | Tabla de todas las conexiones TCP establecidas, con programa, destino (con DNS inverso), puerto, LAN o Internet e IPv6. Se puede filtrar. |
| **Actividad** | Registro de conexiones nuevas, dispositivos que entran o salen de la red, dispositivos nunca vistos y cambios de estado del router. |
| **Exposición desde internet** | Resultado de la última auditoría manual (puertos, UPnP, gestión remota, cortafuegos…), un botón para repetir la prueba en GRC ShieldsUP y los puertos a la escucha en este PC. |

Además:
- **Icono de bandeja vivo**: dos barras (bajada y subida) que se mueven con el tráfico; el tooltip muestra la velocidad.
- **Notificación de Windows** cuando se conecta un dispositivo que nunca se había visto en la red.

## Cómo se usa

| Acción | Cómo |
|---|---|
| Ocultar a la bandeja | Cerrar la ventana (✕). El programa sigue funcionando. |
| Mostrar u ocultar | Clic izquierdo en el icono de la bandeja, o volver a abrir NetMonitor desde el menú Inicio (solo hay una instancia). |
| Salir del todo | Clic derecho en el icono de la bandeja → **Salir**. |
| Modo panel | Botón de la chincheta, menú de la bandeja o Ajustes: quita los bordes y deja la ventana siempre encima, pensado para un monitor vertical. Se arrastra por la cabecera. |
| Pantalla completa | Botón ⛶ o **F11**. |
| Renombrar un dispositivo | Clic en su nombre, escribir y Enter (Esc cancela). Si el nombre se deja vacío, se vuelve al que da el router. |
| Ajustes | Botón de los controles deslizantes: iniciar con Windows, arrancar en la bandeja y modo panel. |

La ventana recuerda su posición, su tamaño y si estaba maximizada, también entre monitores con distinta escala (por ejemplo, un 4K horizontal y otro vertical).

## Instalación

1. Ejecutar `NetMonitor_x.y.z_x64-setup.exe`. Instala solo para el usuario actual, sin pedir permisos de administrador, en `%LOCALAPPDATA%\NetMonitor`.
2. **Contraseña del router** (opcional, para ver el tráfico por dispositivo): crear una variable de entorno de usuario `TPLINK_PASS` con la contraseña de administración del router. En PowerShell:
   ```powershell
   [Environment]::SetEnvironmentVariable('TPLINK_PASS', 'tu-contraseña', 'User')
   ```
   La lee también del registro (`HKCU\Environment`), así que no hace falta reiniciar la sesión.
3. **Activar el monitor de tráfico del router**: en la web del router, *Advanced → System Tools → Traffic Monitor*. Ojo: en el MR600, activarlo desactiva *NAT Boost* (aceleración por hardware). Con fibra de 1 Gb/s esto puede limitar el caudal máximo.
4. La primera vez se añade a *Inicio con Windows* (se puede desactivar en Ajustes) y arranca minimizado en la bandeja.

Para desinstalar: *Configuración de Windows → Aplicaciones → NetMonitor*. Los datos de `%APPDATA%\NetMonitor` se conservan.

## Compilar desde el código

Requisitos: Windows 10/11, [Rust](https://rustup.rs) (toolchain MSVC), Visual Studio Build Tools con C++, Node.js (solo para la CLI de Tauri) y WebView2 (viene con Windows 11).

```powershell
npm install                 # instala @tauri-apps/cli
npx tauri build             # → src-tauri/target/release/bundle/nsis/NetMonitor_2.0.0_x64-setup.exe
```

Para desarrollar:
```powershell
cd src-tauri
cargo build                 # compilación de depuración (segundos tras la primera)
.\target\debug\netmonitor.exe
```

La interfaz es un único `ui/index.html` sin dependencias ni paso de compilación: HTML, CSS y JS a mano, con gráficas en `<canvas>`. Tauri la incrusta en el ejecutable.

Iconos: `python make_icon.py` genera `icon-1024.png` (necesita Pillow) y después `npx tauri icon icon-1024.png` produce todos los tamaños.

**Nombres iniciales:** `src-tauri/known_seed.json` se copia a `%APPDATA%\NetMonitor\known.json` en la primera ejecución. En el repositorio está vacío; `known_seed.example.json` muestra el formato (MAC con guiones → nombre).

## Arquitectura

```
ui/index.html            interfaz: sondea el backend con invoke('api', {path})
src-tauri/src/
  main.rs                ventana, bandeja, menú, notificaciones, modo panel, instancia única, comando `api`
  net.rs                 interfaz, caudal, tabla TCP, nombres de proceso, DNS inverso, latencia, IP pública
  lan.rs                 barrido ARP y detección de dispositivos nuevos
  router.rs              cliente del router TP-Link y sondeo del monitor de tráfico
  win.rs                 posición de la ventana (Win32), color de la barra de título (DWM), inicio con Windows
  util.rs                carpeta de datos, JSON, ajustes, nombres conocidos, registro
```

- El backend usa **hilos de fondo** independientes (caudal 1 s, latencia 2 s, router 3 s, barrido ARP 25 s, IP pública 10 min) que escriben en estructuras compartidas (`Mutex`/`RwLock`).
- La interfaz **sondea** esos datos con un solo comando de Tauri, `api(path, body)`, que devuelve JSON: `rate`, `history`, `conns`, `lan`, `router`, `ping`, `info`, `settings`, y con cuerpo `known`, `settings` y `open`. Al arrancar pide `history` para rellenar las gráficas con lo ya medido, aunque la ventana estuviera oculta.
- La ventana se crea **oculta** y se muestra ya colocada en su sitio, para que no parpadee. Con `--minimized` (arranque con Windows) se queda en la bandeja.
- Las llamadas a Win32 se declaran a mano (`extern "system"`) en lugar de con el crate `windows`, para no depender de sus cambios de API.

Crates principales: `tauri` (+ `tray-icon`), `tauri-plugin-single-instance`, `tauri-plugin-notification`, `tauri-plugin-opener`, `netdev`, `dns-lookup`, `ureq`, `aes`/`cbc`, `num-bigint`, `md-5`, `base64`, `winreg`, `serde_json`.

## Cómo obtiene cada dato

| Dato | Fuente |
|---|---|
| Interfaz activa, IP, gateway, MAC, velocidad | `netdev::get_default_interface()`, que se revisa cada 60 s por si cambias de cable a Wi-Fi. |
| Caudal del PC | Contadores de bytes de la interfaz (`GetIfEntry2` vía netdev) cada segundo, convertidos en diferencias. Se guardan 15 min. |
| Conexiones TCP y puertos a la escucha | `GetExtendedTcpTable` (IPv4 e IPv6, `TCP_TABLE_OWNER_PID_ALL`). Excluye las conexiones del propio NetMonitor. |
| Nombre del programa | `QueryFullProcessImageNameW`; si el proceso está protegido, una instantánea `CreateToolhelp32Snapshot`. |
| Nombre del host remoto | DNS inverso (`getnameinfo`) en 8 hilos y con caché. |
| Dispositivos de la LAN | `SendARP` a las 254 direcciones de la subred en paralelo, cada 25 s. Se suman los que conoce el router aunque no respondan al ARP (móviles dormidos). |
| Dispositivo nuevo | Una MAC que no está en `seen.json`. La primera ejecución sirve de referencia y no avisa de nada. |
| Latencia | Tiempo de conexión TCP al router (puerto 80) y a 1.1.1.1:443 cada 2 s. No usa ICMP porque requeriría permisos. |
| IP pública | `https://api.ipify.org` cada 10 min. |
| Tráfico por dispositivo | Monitor de tráfico del router: `currBytesRx/Tx` (B/s actuales) y totales; ver la sección siguiente. |
| Exposición | Captura fija de una auditoría manual (panel del router + ShieldsUP). No se mide en vivo. |

## Protocolo del router TP-Link

Probado con el **Archer MR600 v3**. Es el protocolo `cgi_gdpr` de la familia MR/VR, portado del cliente MR de [tplinkrouterc6u](https://github.com/AlexandrErohin/TP-Link-Archer-C6U) con dos particularidades de este modelo: `/cgi/getParm` responde JSON en lugar de variables JS, y el código `ret` puede venir en JSON.

1. **Clave pública**: `POST /cgi/getParm` → `{ret, nn, ee, seq}` (módulo RSA de 512 bits, exponente y número de secuencia).
2. **Clave de sesión**: el cliente genera una clave y un IV AES-128 de 16 caracteres (marca de tiempo + dígitos aleatorios).
3. **Login**: cifra `admin\n<contraseña>` con AES-CBC/PKCS7 y lo codifica en base64. La firma es RSA *sin relleno* (bloques de 64 bytes rellenos con ceros, en hexadecimal) de `key=…&iv=…&h=md5("admin"+pass)&s=seq+len(datos)`. Se envía todo como parámetros de `POST /cgi/login`. La respuesta pone la cookie `JSESSIONID`.
4. **Token**: `GET /` contiene `var token="…"`, que va en la cabecera `TokenID` de cada petición.
5. **Consultas**: `POST /cgi_gdpr` con el cuerpo `sign=<RSA(h=…&s=…)>\r\ndata=<AES(base64)>\r\n`. El texto plano tiene la forma `5\r\n[STAT_ENTRY#0,0,0,0,0,0#0,0,0,0,0,0]0,0\r\n\r\n` (5 = GL, lista; 1 = GET). La respuesta, descifrada, son bloques `[i,j,k,0,0,0]0` seguidos de líneas `clave=valor`.
6. Se piden `STAT_CFG` (¿está activado el monitor?) y `STAT_ENTRY` (una entrada por dispositivo: `macAddress`, `ipAddress` como entero, `hostName`, `currBytesRx/Tx`, `totalBytesRx/Tx`).

Si el router devuelve el código **71233** (contraseña incorrecta), NetMonitor **no vuelve a intentarlo** hasta que cambie `TPLINK_PASS`, para no provocar el bloqueo por intentos fallidos. Si se pierde la sesión, inicia sesión de nuevo pasados 5 s.

## Datos que guarda

Todo en `%APPDATA%\NetMonitor`:

| Archivo | Contenido |
|---|---|
| `known.json` | Nombres que has puesto a cada MAC. |
| `seen.json` | Cada MAC vista alguna vez, con la fecha, para detectar dispositivos nuevos. |
| `settings.json` | Arrancar en la bandeja, modo panel, posición de la ventana (`placement`, en píxeles físicos) y si ya se mostró el aviso de la bandeja. |
| `netmonitor.log` | Errores de red y del router, y dispositivos nuevos. |

Inicio con Windows: valor `NetMonitor` en `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` con `"…\netmonitor.exe" --minimized`. La ruta se actualiza en cada arranque.

## Seguridad y privacidad

- **No envía nada a ningún servidor propio.** Las únicas conexiones salientes son al router, a `api.ipify.org` (IP pública) y a `1.1.1.1:443` (solo se abre y se cierra para medir la latencia).
- La contraseña del router **no se guarda** en ningún archivo del programa: se lee de la variable de entorno del usuario.
- La interfaz no carga recursos externos (sin CDN ni fuentes web). El comando `open` solo abre URLs `https://` en el navegador.
- La comunicación con el router va por HTTP en la LAN, como su propia web. El cuerpo va cifrado con AES, pero la clave de sesión viaja cifrada con RSA de 512 bits, que es débil. Es una limitación del firmware del router.
- No necesita permisos de administrador.

## Limitaciones conocidas

- El monitor de tráfico del router **solo cuenta IPv4**. Lo que va por IPv6 (mucho de Google, Netflix, Cloudflare…) no aparece en el tráfico por dispositivo, aunque sí en el caudal total del PC.
- El router no informa de sí mismo ni del repetidor ("sin datos del router").
- Activar el monitor de tráfico en el MR600 desactiva NAT Boost.
- Solo funciona en Windows. El cliente del router solo está probado con el MR600 v3; otros modelos MR/VR con el mismo firmware deberían funcionar.
- La sección de exposición es una captura fija de la auditoría del 19/11/2026. Para actualizarla hay que repetir la prueba y editar `exposure()` en `main.rs`.
- Las gráficas empiezan vacías tras arrancar el programa: el historial vive en memoria.

## Historia del proyecto

1. Prueba de concepto con PowerShell + una página HTML.
2. Versión 1: Python (psutil, pywebview, PyInstaller), con una interfaz neón; unos 41 MB.
3. **Versión 2 (este repositorio)**: reescrita en Rust + Tauri con una interfaz nueva, bandeja del sistema, notificaciones nativas, modo panel y una gestión de la posición de la ventana que funciona con monitores de distinta escala.
