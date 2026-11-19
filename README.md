# NetMonitor

Monitor de red local para Windows con ventana propia. Muestra el tráfico en vivo del PC, todos los dispositivos de la red y el tráfico de cada uno leído del router. Guarda un historial (consumo, latencia, cortes y velocidad), avisa en el móvil cuando pasa algo raro, enseña a qué países se conecta el PC y comprueba en vivo qué expone el router a internet. Desde la propia app se puede bloquear un dispositivo.

Vive en la bandeja del sistema, arranca con Windows y está pensado también para dejarlo fijo en un monitor vertical. Se actualiza solo desde las *releases* de GitHub.

Escrito en **Rust + [Tauri 2](https://tauri.app)** (WebView2). El instalador ocupa unos 3 MB.

---

## Índice
1. [Qué muestra](#qué-muestra)
2. [Cómo se usa](#cómo-se-usa)
3. [Instalación](#instalación)
4. [Alertas en el móvil](#alertas-en-el-móvil)
5. [Compilar y publicar](#compilar-y-publicar)
6. [Arquitectura](#arquitectura)
7. [Cómo obtiene cada dato](#cómo-obtiene-cada-dato)
8. [Protocolo del router TP-Link](#protocolo-del-router-tp-link)
9. [Datos que guarda](#datos-que-guarda)
10. [Seguridad y privacidad](#seguridad-y-privacidad)
11. [Limitaciones conocidas](#limitaciones-conocidas)
12. [Historia del proyecto](#historia-del-proyecto)

---

## Qué muestra

La ventana tiene cinco pestañas.

### En vivo
| Sección | Contenido |
|---|---|
| **Ahora** | Bajada y subida actuales, pico y total de la sesión. Gráfica espejo de 15 min: la bajada crece hacia arriba (azul) y la subida hacia abajo (ámbar), cada mitad con su escala. |
| **Indicadores** | Latencia al router y a internet con media, jitter, pérdidas y minigráfica. Dispositivos activos y sin identificar, conexiones TCP e IP pública (difuminada hasta pasar el ratón). |
| **Dispositivos** | Una fila por dispositivo, con icono según el tipo, nombre, IP, MAC, fabricante y modelo (detectados solos), bajada/subida según el router y minigráfica de 10 min. Marca los **sin identificar**, los **nuevos**, las **MAC aleatorias** y los **bloqueados**. Clic en el nombre para renombrarlo y botón ⊘ para bloquearlo en el router. |
| **Reparto del tráfico** | *Streamgraph* con una banda por dispositivo durante los últimos 10 minutos. |
| **Programas con red** | Procesos con conexiones abiertas. Como administrador muestra además los **bytes por segundo de cada programa**. |
| **Conexiones** | Todas las conexiones TCP establecidas: programa, destino (DNS inverso), **país**, puerto, LAN o Internet. Se pueden filtrar. |
| **Actividad** | Conexiones nuevas, dispositivos que entran y salen, dispositivos nunca vistos y cambios de estado del router. |

### Historial
- **Consumo por dispositivo** en 24 h, 7, 30 o 90 días, en barras apiladas, con una tabla de quién consume más. Incluye el total real del PC (IPv4 + IPv6).
- **Calidad de la conexión**: latencia media al router y a internet, pérdidas y franjas de corte. Debajo, la lista de cortes con su duración, marcando aparte las reconexiones de la fibra (PPPoE).
- **Velocidad**: test contra Cloudflare (latencia, bajada y subida con 4 flujos en paralelo), manual o programado cada 3, 6, 12 o 24 h. Una gráfica muestra la evolución, con líneas discontinuas para la velocidad contratada.

### Mundo
Mapa con los países a los que conecta el PC ahora mismo, con arcos desde casa, más una lista por país con sus programas y los hosts con más conexiones. La geolocalización es local (base de datos de DB-IP), sin consultar servicios externos.

### DNS
- **Este PC**: dominios que resuelve, leídos de la caché DNS de Windows, con un filtro de posibles rastreadores. En Windows 11 reciente esto requiere ejecutar como administrador.
- **Toda la red**: si tienes **AdGuard Home**, muestra las consultas y bloqueos por dispositivo, los dominios más consultados y el registro en vivo. NetMonitor no instala AdGuard ni cambia el DNS del router: la vista explica cómo hacerlo.

### Seguridad
- **Exposición del router, en vivo**: gestión remota, redirecciones de puertos, DMZ, UPnP, ping desde internet, TR-069, SNMP, cortafuegos SPI IPv4/IPv6, Telnet/SSH y control de acceso. Se lee del router cada 10 min y **avisa si algo cambia**.
- **Alertas recientes**, dispositivos bloqueados (con botón para desbloquear) y puertos a la escucha en este PC.

Además:
- **Icono de bandeja vivo** con dos barras que se mueven con el tráfico.
- **Nombres automáticos**: fabricante por la MAC (base OUI del IEEE incluida), más los nombres que anuncian los propios dispositivos por mDNS, NetBIOS y UPnP/SSDP (modelo incluido).

## Cómo se usa

| Acción | Cómo |
|---|---|
| Ocultar a la bandeja | Cerrar la ventana (✕). El programa sigue funcionando. |
| Mostrar u ocultar | Clic en el icono de la bandeja, o abrir NetMonitor desde el menú Inicio (solo hay una instancia). |
| Salir del todo | Clic derecho en el icono de la bandeja → **Salir**. |
| Modo panel | Botón de la chincheta: sin bordes y siempre encima, pensado para un monitor vertical. |
| Pantalla completa | Botón ⛶ o **F11**. |
| Renombrar un dispositivo | Clic en su nombre, escribir y Enter (Esc cancela). |
| Bloquear un dispositivo | Botón ⊘ de su fila → confirmar. Se desbloquea igual o desde *Seguridad*. |
| Medir la velocidad | *Historial → Medir ahora*. |
| Ajustes | Botón de los controles deslizantes: inicio con Windows, alertas, avisos al móvil, test de velocidad, AdGuard, permisos y actualizaciones. |

La ventana recuerda su posición, tamaño y estado, también entre monitores con distinta escala.

### Bloqueo de dispositivos
Usa el **control de acceso** del router en modo **lista negra**, igual que su web. Crea un host con la MAC del dispositivo y una regla de bloqueo. Si el control de acceso estaba apagado, lo enciende en modo lista negra y lo vuelve a apagar al desbloquear el último dispositivo. Si el router está en modo lista blanca, NetMonitor se niega a tocarlo. Siempre pide confirmación. No se puede bloquear el propio PC ni el router.

### Modo administrador
Sin permisos, NetMonitor funciona entero salvo dos cosas: los **bytes por programa** (estadísticas TCP por conexión de Windows) y la **caché DNS** en Windows 11 reciente. *Ajustes → Permisos → Reiniciar como administrador* lo relanza con UAC. El arranque con Windows sigue siendo sin permisos.

## Instalación

1. Ejecutar `NetMonitor_x.y.z_x64-setup.exe`. Instala solo para el usuario actual, sin permisos de administrador, en `%LOCALAPPDATA%\NetMonitor`.
2. **Contraseña del router** (para el tráfico por dispositivo, la exposición y el bloqueo): crear la variable de entorno de usuario `TPLINK_PASS`:
   ```powershell
   [Environment]::SetEnvironmentVariable('TPLINK_PASS', 'tu-contraseña', 'User')
   ```
3. **Activar el monitor de tráfico del router**: *Advanced → System Tools → Traffic Monitor*. En el MR600 esto desactiva *NAT Boost*, lo que puede limitar el caudal máximo con fibra de 1 Gb/s.
4. **Actualizaciones**: el repositorio es privado, así que NetMonitor usa la [CLI de GitHub](https://cli.github.com) (`gh`) con tu sesión para ver y descargar las *releases*. Sin `gh` autenticado, todo lo demás funciona igual.

Para desinstalar: *Configuración → Aplicaciones → NetMonitor*. Los datos de `%APPDATA%\NetMonitor` se conservan.

## Alertas en el móvil

Cada alerta se puede activar o desactivar en Ajustes:

| Alerta | Cuándo |
|---|---|
| Dispositivo nuevo | Aparece una MAC que nunca se había visto en la red. |
| Madrugada | Un dispositivo sin nombre está conectado en el horario configurado (por defecto, de 0 a 7 h). Una vez por dispositivo y noche. |
| Subida inusual | Un dispositivo sube más de lo configurado (2 Mb/s por defecto) y más de 4 veces su p95 de la última semana, durante 2 minutos seguidos. |
| Cortes | Internet deja de responder (3 fallos seguidos), vuelve (con la duración del corte) o la fibra renegocia la sesión PPPoE. |
| Exposición | Cambia algo de la sección de exposición del router. |
| Velocidad | Un test da menos de la mitad de lo contratado. |
| Actualización | Hay una versión nueva. |

Siempre salen como notificación de Windows y quedan en el historial. Para recibirlas además en el móvil:
- **ntfy**: instala la app [ntfy](https://ntfy.sh), suscríbete a un tema con un nombre difícil de adivinar y pega su URL (`https://ntfy.sh/mi-tema-secreto`) en Ajustes.
- **Telegram**: crea un bot con @BotFather, pega su token y tu *chat id*.

*Enviar prueba* comprueba los canales.

## Compilar y publicar

Requisitos: Windows 10/11, [Rust](https://rustup.rs) (MSVC), Visual Studio Build Tools con C++, Node.js y WebView2.

```powershell
npm install
npx tauri build             # → src-tauri/target/release/bundle/nsis/NetMonitor_2.1.0_x64-setup.exe
```

Para desarrollar: `cd src-tauri; cargo build; .\target\debug\netmonitor.exe`.

**Publicar una versión**: subir la versión en `src-tauri/Cargo.toml`, `src-tauri/tauri.conf.json` y `package.json`, hacer commit y crear una etiqueta: `git tag v2.1.0; git push --tags`. El workflow `.github/workflows/release.yml` compila el instalador en `windows-latest` y crea la *release* con él. Las copias instaladas lo detectan en menos de 6 h (o con *Buscar ahora*).

**Datos incluidos**: `python tools/gen_data.py <carpeta con oui.csv>` regenera `src-tauri/data/oui.tsv.gz` (fabricantes, del [registro MA-L/MA-M/MA-S del IEEE](https://regauth.standards.ieee.org/)) y `ui/world.js` (mapa [world-atlas](https://github.com/topojson/world-atlas) 110m y códigos ISO, desde `node_modules`).

**Nombres iniciales**: `src-tauri/known_seed.json` se copia a `known.json` en la primera ejecución (vacío en el repositorio; ver `known_seed.example.json`).

## Arquitectura

```
ui/index.html            estructura y estilos (sin dependencias ni compilación)
ui/app.js                lógica de las vistas; gráficas en <canvas>
ui/world.js              mapa (TopoJSON) generado por tools/gen_data.py
src-tauri/src/
  main.rs                ventana, bandeja, comando `api`, arranque de hilos, elevación
  net.rs                 interfaz, caudal, TCP, procesos, bytes por programa (EStats), DNS inverso, latencia, IP pública
  lan.rs                 barrido ARP, dispositivos nuevos, mejor nombre de cada MAC
  router.rs              cliente TP-Link: tráfico, sesión PPPoE, exposición, control de acceso
  monitor.rs             agregación por minuto, cortes, subida inusual, madrugada
  history.rs             SQLite: tráfico, latencia, cortes, tests de velocidad, alertas
  alerts.rs              reglas activas, notificación de Windows, ntfy y Telegram
  speed.rs               test de velocidad contra Cloudflare y programación
  discover.rs            fabricante por OUI, mDNS, NetBIOS, SSDP/UPnP
  geo.rs                 base de países DB-IP (descarga mensual) y búsqueda por IP
  dns.rs                 caché DNS de Windows y API de AdGuard Home
  update.rs              comprobación e instalación de releases con `gh`
  win.rs                 posición de la ventana, barra de título, inicio con Windows
  util.rs                carpeta de datos, JSON, ajustes, registro
```

- Hilos de fondo independientes: caudal 1 s, latencia 2 s, router 3 s (exposición y bloqueos cada 10 min, PPPoE cada minuto), ARP 25 s, agregación cada minuto, descubrimiento 10 min, caché DNS 15 s, GeoIP y actualizaciones 6 h.
- La interfaz sondea con un único comando `api(path, body)` que devuelve JSON.
- Las acciones sobre el router (bloquear, comprobar exposición) se envían por un canal al hilo del router, que es el único que mantiene la sesión.
- Las llamadas a Win32 se declaran a mano (`extern "system"`).

Crates principales: `tauri`, `tauri-plugin-{single-instance,notification,opener}`, `netdev`, `dns-lookup`, `ureq`, `rusqlite` (SQLite incluido), `flate2`, `aes`/`cbc`, `num-bigint`, `md-5`, `base64`, `winreg`, `serde_json`.

## Cómo obtiene cada dato

| Dato | Fuente |
|---|---|
| Caudal del PC | Contadores de la interfaz (`GetIfEntry2` vía netdev) cada segundo. |
| Conexiones y puertos | `GetExtendedTcpTable` (IPv4 e IPv6). |
| Bytes por programa | `SetPerTcpConnectionEStats` + `GetPerTcpConnectionEStats` (`TcpConnectionEstatsData`) para cada conexión, sumados por proceso cada 2 s. Requiere administrador y solo cubre TCP. |
| Dispositivos | `SendARP` a toda la subred cada 25 s, más los que conoce el router. |
| Fabricante | Prefijo de la MAC en la base OUI incluida (bloques de 24, 28 y 36 bits). Las MAC aleatorias no tienen fabricante. |
| Nombre anunciado | mDNS (PTR inverso unicast al 5353), NetBIOS (*node status* al 137) y SSDP M-SEARCH + XML de descripción UPnP. |
| Latencia | Conexión TCP al router (80) y a 1.1.1.1:443 cada 2 s, agregada por minuto. |
| Cortes | 3 fallos seguidos hacia internet; si el router tampoco responde, el corte se marca como "router inaccesible". Las reconexiones PPPoE se detectan porque baja el *uptime* de la sesión. |
| País | Rango de IP en DB-IP *IP to Country Lite* (CSV mensual, ~7 MB comprimido), descargado de db-ip.com a `%APPDATA%`. |
| Velocidad | `speed.cloudflare.com`: 8 pings (mediana y jitter), 7 s de bajada y 7 s de subida con 4 flujos, descartando el primer segundo. |
| Caché DNS | `DnsGetCacheDataTable` (dnsapi) cada 15 s. |
| AdGuard Home | `/control/stats` y `/control/querylog` con autenticación básica. |
| IP pública | `https://api.ipify.org` cada 10 min. |
| Tráfico por dispositivo, exposición, bloqueo | Router; ver la sección siguiente. |

## Protocolo del router TP-Link

Probado con el **Archer MR600 v3**. Es el protocolo `cgi_gdpr` de la familia MR/VR, portado del cliente MR de [tplinkrouterc6u](https://github.com/AlexandrErohin/TP-Link-Archer-C6U).

1. **Clave pública**: `POST /cgi/getParm` → `{nn, ee, seq}` (RSA de 512 bits).
2. **Clave de sesión**: clave e IV AES-128 de 16 caracteres generados por el cliente.
3. **Login**: `admin\n<contraseña>` cifrado con AES-CBC/PKCS7 en base64, y firma RSA *sin relleno* de `key=…&iv=…&h=md5("admin"+pass)&s=seq+len`. `POST /cgi/login` → cookie `JSESSIONID`.
4. **Token**: `var token="…"` en `GET /`, enviado en la cabecera `TokenID`.
5. **Consultas**: `POST /cgi_gdpr` con `sign=…\r\ndata=…\r\n`. El texto plano lleva los tipos de cada acción (1 GET, 2 SET, 3 ADD, 4 DEL, 5 GL, 6 GS) y, por cada una, `[OID#pila#0,0,0,0,0,0]índice,nattrs\r\n` más los atributos. La respuesta son bloques `[pila]índice` con líneas `clave=valor`, terminados en `[error]0`.

Objetos usados:

| Para | Objetos |
|---|---|
| Tráfico | `STAT_CFG`, `STAT_ENTRY` |
| Sesión de la fibra | `WAN_PPP_CONN` (solo `enable`, `connectionStatus`, `uptime`, `name`) |
| Exposición | `HTTP_CFG` (`httpRemoteEnabled` es la gestión remota; `httpsRemoteEnabled` solo indica si usa HTTPS cuando está activa), `UPNP_CFG`, `UPNP_PORTMAPPING`, `DMZ_HOST_CFG`, `WAN_IP/PPP_CONN_PORTMAPPING`, `MANAGEMENT_SERVER` (`enableCWMP`), `SNMP_CFG`, `FIREWALL`, `IP6_FIREWALL`, `TELNET_CFG`, `DROPBEAR_CFG`, `ACL_CFG` |
| Bloqueo | `FIREWALL` (`enable`, `firewallMode`), `INTERNAL_HOST`, `RULE`, `IP6_FIREWALL` |

Detalles del firmware: una respuesta de error invalida la sesión, así que los objetos de exposición se piden de uno en uno. Solo se piden atributos concretos para no leer credenciales PPPoE ni de TR-069. Ante el código **71233** (contraseña incorrecta), NetMonitor no reintenta hasta que cambie `TPLINK_PASS`.

## Datos que guarda

Todo en `%APPDATA%\NetMonitor`:

| Archivo | Contenido |
|---|---|
| `history.db` | SQLite: tráfico por minuto y dispositivo, latencia por minuto, cortes, tests de velocidad y alertas. Se conservan 120 días. |
| `known.json` | Nombres que has puesto a cada MAC. |
| `seen.json` | MAC vistas alguna vez, para detectar dispositivos nuevos. |
| `settings.json` | Ventana, modo panel, alertas, canales del móvil (token de Telegram incluido), test de velocidad, AdGuard (contraseña incluida), actualizaciones y estado del bloqueo. |
| `geo/` | Base de países de DB-IP y su mes. |
| `netmonitor.log` | Errores y eventos. |

## Seguridad y privacidad

- **No envía datos a ningún servidor propio.** Conexiones salientes: el router; `api.ipify.org` (IP pública); `1.1.1.1:443` (latencia); `download.db-ip.com` (una vez al mes); `speed.cloudflare.com` (solo al medir); ntfy o Telegram (solo si los configuras, con el texto de la alerta); AdGuard Home en tu red (si lo configuras); GitHub vía `gh` (actualizaciones).
- La contraseña del router **no se guarda**: se lee de la variable de entorno. El token de Telegram y la contraseña de AdGuard sí se guardan en `settings.json` (en texto plano, dentro de tu perfil) y la interfaz nunca los recibe de vuelta.
- Las alertas en el móvil incluyen nombres e IP locales de dispositivos. Con ntfy público, cualquiera que adivine el tema puede leerlas: usa un nombre largo y aleatorio.
- El bloqueo y la elevación siempre piden confirmación. NetMonitor no cambia el DNS del router ni ningún otro ajuste salvo el control de acceso.
- La interfaz no carga recursos externos.
- La comunicación con el router va por HTTP en la LAN, con la clave de sesión protegida por RSA de 512 bits (débil). Es una limitación del firmware.

## Limitaciones conocidas

- El monitor de tráfico del router **solo cuenta IPv4**. El tráfico IPv6 no aparece por dispositivo, aunque sí en el total del PC. Por eso un test de velocidad (que suele ir por IPv6) apenas se nota en el consumo del PC según el router.
- El router no informa de sí mismo ni del repetidor.
- Activar el monitor de tráfico en el MR600 desactiva NAT Boost.
- El bloqueo no se ha probado en todos los firmwares; se comporta como la página de control de acceso del router.
- Los bytes por programa y la caché DNS requieren administrador.
- El mapa usa la IP del destino: un CDN puede aparecer en un país distinto del del servicio.
- Solo Windows. Cliente del router probado solo con el MR600 v3.

## Historia del proyecto

1. Prueba de concepto con PowerShell + una página HTML.
2. Versión 1: Python (psutil, pywebview, PyInstaller), unos 41 MB.
3. Versión 2.0: reescrita en Rust + Tauri, con interfaz nueva, bandeja, notificaciones, modo panel y posición de la ventana entre monitores con distinta escala.
4. **Versión 2.1**: historial en SQLite, alertas al móvil, bytes por programa, nombres automáticos, exposición en vivo, test de velocidad, bloqueo de dispositivos, mapa por países, vista DNS y actualizaciones automáticas.

Geolocalización: [IP Geolocation by DB-IP](https://db-ip.com) (CC BY 4.0).
