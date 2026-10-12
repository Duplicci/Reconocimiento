# VeriFace

Prototipo local para reconocimiento facial desde el computador o un teléfono en la misma red Wi-Fi.

## Archivos

- `prototipo.html`: panel principal, análisis facial, historial, directorio de personas y gestión local de usuarios.
- `scanner.html`: página móvil para conectar el teléfono y enviar capturas.
- `scanner_server.py`: servidor HTTP local y API con almacenamiento SQLite.
- `iniciar_veriface.bat`: inicia el servidor en Windows.

## Requisitos

- Windows y Python 3.10 o posterior disponible como `py -3` o `python`.
- Conexión a Internet para cargar las bibliotecas de la interfaz y descargar los modelos faciales.
- Para usar el teléfono, ambos dispositivos deben estar en la misma red Wi-Fi.

No se requieren paquetes de Python adicionales; el servidor usa la biblioteca estándar.

## Iniciar

1. Ejecuta `iniciar_veriface.bat`.
2. Se abrirá el panel en el computador. Para conectar el teléfono, abre la pestaña **Escáner móvil**, crea una conexión y escanea el QR desde el teléfono.
3. Permite el acceso a la cámara cuando el navegador lo solicite. Si Windows muestra un aviso del Firewall, permite Python en redes privadas.

El servidor escucha en el puerto `8765`. No publiques ese puerto ni expongas este prototipo a Internet.

## Datos y privacidad

Al iniciar, el servidor crea `veriface_data.sqlite3` en esta carpeta para guardar los perfiles biométricos, las fotos de referencia, los eventos del historial y los usuarios locales. Esa base de datos está excluida de Git intencionalmente: contiene datos sensibles. No la agregues al repositorio ni compartas perfiles o fotos reales.

La pestaña **Usuarios y permisos** guarda las cuentas y los permisos asignados localmente, pero esta versión no implementa inicio de sesión ni usa los permisos para restringir funciones. No debe considerarse un sistema de control de acceso de producción. El registro de un acceso autorizado tampoco acciona una cerradura física.

## GitHub

La carpeta está preparada como proyecto fuente, pero todavía no se ha creado ni publicado un repositorio remoto. Revisa los cambios y el `.gitignore` antes de subirla a GitHub; no incluyas la base SQLite, fotos, credenciales ni datos personales.
