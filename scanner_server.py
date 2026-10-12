import base64
import binascii
import json
import mimetypes
import re
import secrets
import socket
import sqlite3
import time
import webbrowser
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlsplit


WEB_ROOT = Path(__file__).resolve().parent
HOST = "0.0.0.0"
PORT = 8765
MAX_PHOTO_BYTES = 20 * 1024 * 1024
SESSION_LIFETIME_SECONDS = 12 * 60 * 60
PHONE_TIMEOUT_SECONDS = 12
SESSIONS = {}
DATABASE_PATH = WEB_ROOT / "veriface_data.sqlite3"
MAX_PERSON_REQUEST_BYTES = 60 * 1024 * 1024
MAX_REFERENCE_PHOTO_BYTES = 5 * 1024 * 1024
ALLOWED_IMAGE_TYPES = {
    "data:image/jpeg;base64": "image/jpeg",
    "data:image/png;base64": "image/png",
    "data:image/webp;base64": "image/webp",
}
USER_ROLES = ("Administrador", "Operador senior", "Operador", "Auditor")
USER_PERMISSIONS = (
    "scan",
    "manage_people",
    "manage_users",
    "view_history",
    "export_reports",
    "manage_settings",
)


def open_database():
    connection = sqlite3.connect(DATABASE_PATH)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    connection.executescript(
        """
        CREATE TABLE IF NOT EXISTS people (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            group_name TEXT NOT NULL,
            status TEXT NOT NULL CHECK (status IN ('active', 'suspended')),
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS person_photos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            person_id TEXT NOT NULL REFERENCES people(id) ON DELETE CASCADE,
            filename TEXT NOT NULL,
            mime_type TEXT NOT NULL,
            image BLOB NOT NULL,
            descriptor TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_type TEXT NOT NULL CHECK (event_type IN ('scan', 'access')),
            outcome TEXT NOT NULL CHECK (outcome IN ('identified', 'unmatched', 'granted', 'denied')),
            person_id TEXT,
            person_name TEXT NOT NULL,
            source TEXT NOT NULL,
            operator TEXT NOT NULL,
            distance REAL,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT NOT NULL COLLATE NOCASE UNIQUE,
            role TEXT NOT NULL,
            permissions TEXT NOT NULL,
            status TEXT NOT NULL CHECK (status IN ('active', 'inactive')),
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        """
    )
    return connection


@contextmanager
def database_connection():
    connection = open_database()
    try:
        with connection:
            yield connection
    finally:
        connection.close()


def now_iso():
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime())


def validate_person_payload(payload, require_photo):
    name = payload.get("name")
    person_id = payload.get("id")
    group_name = payload.get("group")
    status = payload.get("status", "active")
    photos = payload.get("photos", [])
    remove_photo_ids = payload.get("removePhotoIds", [])
    if not isinstance(name, str) or not name.strip() or len(name.strip()) > 120:
        raise ValueError("El nombre es obligatorio y debe tener 120 caracteres o menos.")
    if isinstance(person_id, str) and not person_id.strip():
        person_id = None
    if person_id is not None and (
        not isinstance(person_id, str) or len(person_id.strip()) > 60
    ):
        raise ValueError("El ID debe tener entre 1 y 60 caracteres.")
    if not isinstance(group_name, str) or group_name not in (
        "Empleados",
        "Visitantes",
        "Contratistas",
    ):
        raise ValueError("Selecciona un grupo válido.")
    if status not in ("active", "suspended"):
        raise ValueError("Selecciona un estado válido.")
    if not isinstance(photos, list) or len(photos) > 5:
        raise ValueError("Se permiten hasta cinco fotos por persona.")
    if require_photo and not photos:
        raise ValueError("Añade al menos una foto de referencia.")
    if not isinstance(remove_photo_ids, list) or any(
        not isinstance(photo_id, int) or photo_id <= 0 for photo_id in remove_photo_ids
    ):
        raise ValueError("La lista de fotos que se eliminarán no es válida.")

    parsed_photos = []
    for photo in photos:
        if not isinstance(photo, dict):
            raise ValueError("Una foto de referencia no tiene un formato válido.")
        data_url = photo.get("dataUrl")
        descriptor = photo.get("descriptor")
        filename = photo.get("filename")
        if not isinstance(data_url, str) or "," not in data_url:
            raise ValueError("Una foto de referencia no contiene datos válidos.")
        header, encoded_data = data_url.split(",", 1)
        mime_type = ALLOWED_IMAGE_TYPES.get(header.lower())
        if not mime_type:
            raise ValueError("Las fotos deben ser JPG, PNG o WEBP.")
        try:
            image_data = base64.b64decode(encoded_data, validate=True)
        except (binascii.Error, ValueError) as error:
            raise ValueError("No se pudo decodificar una foto de referencia.") from error
        if not image_data or len(image_data) > MAX_REFERENCE_PHOTO_BYTES:
            raise ValueError("Cada foto procesada debe pesar como máximo 5 MB.")
        if not isinstance(descriptor, list) or len(descriptor) != 128:
            raise ValueError("No se recibió una plantilla facial válida para una foto.")
        if any(
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not (-2 <= value <= 2)
            for value in descriptor
        ):
            raise ValueError("La plantilla facial contiene valores no válidos.")
        parsed_photos.append(
            (
                Path(filename).name[:100] if isinstance(filename, str) else "referencia.jpg",
                mime_type,
                image_data,
                json.dumps(descriptor, separators=(",", ":")),
            )
        )
    return {
        "id": person_id.strip() if isinstance(person_id, str) else "",
        "name": name.strip(),
        "group": group_name,
        "status": status,
        "photos": parsed_photos,
        "remove_photo_ids": remove_photo_ids,
    }


def json_bytes(data):
    return json.dumps(data, ensure_ascii=False).encode("utf-8")


def get_lan_address():
    connection = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        connection.connect(("10.255.255.255", 1))
        return connection.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        connection.close()


class VeriFaceHandler(BaseHTTPRequestHandler):
    server_version = "VeriFaceScanner/1.0"

    def log_message(self, format_string, *args):
        path = urlsplit(self.path).path
        print(f"{self.address_string()} - {format_string % args} [{path}]")

    def respond(self, status, body=b"", content_type="application/json; charset=utf-8", headers=None):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        if headers:
            for name, value in headers.items():
                self.send_header(name, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body:
            self.wfile.write(body)

    def respond_json(self, status, data):
        self.respond(status, json_bytes(data))

    def read_json(self, max_bytes=64 * 1024):
        if self.headers.get_content_type() != "application/json":
            self.respond_json(415, {"error": "Content-Type debe ser application/json."})
            return None
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self.respond_json(400, {"error": "Content-Length no válido."})
            return None
        if length <= 0 or length > max_bytes:
            self.respond_json(413, {"error": "El cuerpo de la solicitud está vacío o supera el límite."})
            return None
        try:
            payload = json.loads(self.rfile.read(length))
        except (json.JSONDecodeError, UnicodeDecodeError):
            self.respond_json(400, {"error": "El cuerpo JSON no es válido."})
            return None
        if not isinstance(payload, dict):
            self.respond_json(400, {"error": "El cuerpo JSON debe ser un objeto."})
            return None
        return payload

    def require_local_client(self):
        client_address = self.client_address[0]
        try:
            local_addresses = {
                address[4][0]
                for address in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET)
            }
            local_addresses.add(get_lan_address())
        except OSError:
            local_addresses = set()
        if client_address not in ("127.0.0.1", "::1") and client_address not in local_addresses:
            self.respond_json(403, {
                "error": "El directorio biométrico solo puede administrarse desde este computador."
            })
            return False
        return True

    def person_photo_rows(self, connection, person_id):
        rows = connection.execute(
            """
            SELECT id, filename, mime_type, descriptor
            FROM person_photos WHERE person_id = ? ORDER BY id
            """,
            (person_id,),
        ).fetchall()
        return [
            {
                "id": row["id"],
                "filename": row["filename"],
                "mimeType": row["mime_type"],
                "url": f"/api/people/photo?id={row['id']}",
                "descriptor": json.loads(row["descriptor"]),
            }
            for row in rows
        ]

    def list_people(self):
        if not self.require_local_client():
            return
        try:
            with database_connection() as connection:
                people = connection.execute(
                    "SELECT id, name, group_name, status FROM people ORDER BY name COLLATE NOCASE"
                ).fetchall()
                result = [
                    {
                        "id": row["id"],
                        "name": row["name"],
                        "group": row["group_name"],
                        "status": row["status"],
                        "photos": self.person_photo_rows(connection, row["id"]),
                    }
                    for row in people
                ]
        except sqlite3.Error as error:
            print(f"No se pudo leer el directorio de personas: {error}")
            self.respond_json(500, {"error": "No se pudo leer el directorio local."})
            return
        self.respond_json(200, result)

    def save_person(self, person_id=None):
        if not self.require_local_client():
            return
        payload = self.read_json(MAX_PERSON_REQUEST_BYTES)
        if payload is None:
            return
        if payload.get("consent") is not True:
            self.respond_json(400, {"error": "Confirma que tienes autorización para registrar estas fotos."})
            return
        try:
            person = validate_person_payload(payload, require_photo=person_id is None)
        except ValueError as error:
            self.respond_json(400, {"error": str(error)})
            return

        person_id = person_id or person["id"] or f"VF-{secrets.token_hex(4).upper()}"
        timestamp = now_iso()
        try:
            with database_connection() as connection:
                if person_id is None or self.command == "POST":
                    connection.execute(
                        """
                        INSERT INTO people (id, name, group_name, status, created_at, updated_at)
                        VALUES (?, ?, ?, ?, ?, ?)
                        """,
                        (
                            person_id,
                            person["name"],
                            person["group"],
                            person["status"],
                            timestamp,
                            timestamp,
                        ),
                    )
                else:
                    current = connection.execute(
                        "SELECT id FROM people WHERE id = ?", (person_id,)
                    ).fetchone()
                    if not current:
                        self.respond_json(404, {"error": "La persona no existe."})
                        return
                    photo_count = connection.execute(
                        "SELECT COUNT(*) FROM person_photos WHERE person_id = ?",
                        (person_id,),
                    ).fetchone()[0]
                    delete_count = 0
                    if person["remove_photo_ids"]:
                        placeholders = ",".join("?" for _ in person["remove_photo_ids"])
                        delete_count = connection.execute(
                            f"SELECT COUNT(*) FROM person_photos WHERE person_id = ? AND id IN ({placeholders})",
                            [person_id, *person["remove_photo_ids"]],
                        ).fetchone()[0]
                    if photo_count - delete_count + len(person["photos"]) > 5:
                        self.respond_json(400, {"error": "Una persona puede tener hasta cinco fotos de referencia."})
                        return
                    if photo_count - delete_count + len(person["photos"]) < 1:
                        self.respond_json(400, {"error": "Cada persona debe conservar al menos una foto de referencia."})
                        return
                    connection.execute(
                        """
                        UPDATE people SET name = ?, group_name = ?, status = ?, updated_at = ?
                        WHERE id = ?
                        """,
                        (person["name"], person["group"], person["status"], timestamp, person_id),
                    )
                    if person["remove_photo_ids"]:
                        placeholders = ",".join("?" for _ in person["remove_photo_ids"])
                        connection.execute(
                            f"DELETE FROM person_photos WHERE person_id = ? AND id IN ({placeholders})",
                            [person_id, *person["remove_photo_ids"]],
                        )

                for filename, mime_type, image_data, descriptor in person["photos"]:
                    connection.execute(
                        """
                        INSERT INTO person_photos
                            (person_id, filename, mime_type, image, descriptor, created_at)
                        VALUES (?, ?, ?, ?, ?, ?)
                        """,
                        (person_id, filename, mime_type, image_data, descriptor, timestamp),
                    )
                saved = connection.execute(
                    "SELECT id, name, group_name, status FROM people WHERE id = ?",
                    (person_id,),
                ).fetchone()
                result = {
                    "id": saved["id"],
                    "name": saved["name"],
                    "group": saved["group_name"],
                    "status": saved["status"],
                    "photos": self.person_photo_rows(connection, person_id),
                }
        except sqlite3.IntegrityError:
            self.respond_json(409, {"error": "Ese ID ya está registrado. Usa otro ID."})
            return
        except sqlite3.Error as error:
            print(f"No se pudo guardar la persona: {error}")
            self.respond_json(500, {"error": "No se pudo guardar la persona en el directorio local."})
            return
        self.respond_json(201 if self.command == "POST" else 200, result)

    def delete_person(self, person_id):
        if not self.require_local_client():
            return
        try:
            with database_connection() as connection:
                cursor = connection.execute("DELETE FROM people WHERE id = ?", (person_id,))
                if cursor.rowcount == 0:
                    self.respond_json(404, {"error": "La persona no existe."})
                    return
        except sqlite3.Error as error:
            print(f"No se pudo eliminar la persona: {error}")
            self.respond_json(500, {"error": "No se pudo eliminar la persona del directorio local."})
            return
        self.respond(204, b"")

    def list_history(self):
        if not self.require_local_client():
            return
        try:
            with database_connection() as connection:
                rows = connection.execute(
                    """
                    SELECT id, event_type, outcome, person_id, person_name,
                           source, operator, distance, created_at
                    FROM history ORDER BY id DESC
                    """
                ).fetchall()
        except sqlite3.Error as error:
            print(f"No se pudo leer el historial: {error}")
            self.respond_json(500, {"error": "No se pudo leer el historial local."})
            return
        self.respond_json(200, [
            {
                "id": f"OP-{row['id']:06d}",
                "eventType": row["event_type"],
                "outcome": row["outcome"],
                "personId": row["person_id"],
                "personName": row["person_name"],
                "source": row["source"],
                "operator": row["operator"],
                "distance": row["distance"],
                "createdAt": row["created_at"],
            }
            for row in rows
        ])

    def list_users(self):
        if not self.require_local_client():
            return
        try:
            with database_connection() as connection:
                rows = connection.execute(
                    """
                    SELECT id, name, email, role, permissions, status, created_at, updated_at
                    FROM users ORDER BY name COLLATE NOCASE
                    """
                ).fetchall()
        except sqlite3.Error as error:
            print(f"No se pudieron leer los usuarios: {error}")
            self.respond_json(500, {"error": "No se pudieron leer los usuarios locales."})
            return
        self.respond_json(200, [
            {
                "id": row["id"],
                "name": row["name"],
                "email": row["email"],
                "role": row["role"],
                "permissions": json.loads(row["permissions"]),
                "status": row["status"],
                "createdAt": row["created_at"],
                "updatedAt": row["updated_at"],
            }
            for row in rows
        ])

    def save_user(self, user_id=None):
        if not self.require_local_client():
            return
        payload = self.read_json()
        if payload is None:
            return
        name = payload.get("name")
        email = payload.get("email")
        role = payload.get("role")
        permissions = payload.get("permissions")
        status = payload.get("status")
        if not isinstance(name, str) or not name.strip() or len(name.strip()) > 120:
            self.respond_json(400, {"error": "El nombre es obligatorio y debe tener 120 caracteres o menos."})
            return
        if (
            not isinstance(email, str)
            or len(email.strip()) > 254
            or not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email.strip())
        ):
            self.respond_json(400, {"error": "Escribe una dirección de correo válida."})
            return
        if role not in USER_ROLES:
            self.respond_json(400, {"error": "Selecciona un rol válido."})
            return
        if (
            not isinstance(permissions, list)
            or any(
                not isinstance(permission, str) or permission not in USER_PERMISSIONS
                for permission in permissions
            )
            or len(set(permissions)) != len(permissions)
        ):
            self.respond_json(400, {"error": "La lista de permisos contiene valores no válidos o repetidos."})
            return
        if status not in ("active", "inactive"):
            self.respond_json(400, {"error": "Selecciona un estado válido."})
            return

        timestamp = now_iso()
        try:
            with database_connection() as connection:
                if user_id is None:
                    cursor = connection.execute(
                        """
                        INSERT INTO users (name, email, role, permissions, status, created_at, updated_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            name.strip(),
                            email.strip(),
                            role,
                            json.dumps(permissions),
                            status,
                            timestamp,
                            timestamp,
                        ),
                    )
                    user_id = cursor.lastrowid
                else:
                    cursor = connection.execute(
                        """
                        UPDATE users
                        SET name = ?, email = ?, role = ?, permissions = ?, status = ?, updated_at = ?
                        WHERE id = ?
                        """,
                        (
                            name.strip(),
                            email.strip(),
                            role,
                            json.dumps(permissions),
                            status,
                            timestamp,
                            user_id,
                        ),
                    )
                    if cursor.rowcount == 0:
                        self.respond_json(404, {"error": "El usuario no existe."})
                        return
                row = connection.execute(
                    """
                    SELECT id, name, email, role, permissions, status, created_at, updated_at
                    FROM users WHERE id = ?
                    """,
                    (user_id,),
                ).fetchone()
        except sqlite3.IntegrityError:
            self.respond_json(409, {"error": "Ya existe un usuario con ese correo."})
            return
        except sqlite3.Error as error:
            print(f"No se pudo guardar el usuario: {error}")
            self.respond_json(500, {"error": "No se pudo guardar el usuario local."})
            return
        self.respond_json(201 if self.command == "POST" else 200, {
            "id": row["id"],
            "name": row["name"],
            "email": row["email"],
            "role": row["role"],
            "permissions": json.loads(row["permissions"]),
            "status": row["status"],
            "createdAt": row["created_at"],
            "updatedAt": row["updated_at"],
        })

    def delete_user(self, user_id):
        if not self.require_local_client():
            return
        try:
            with database_connection() as connection:
                cursor = connection.execute("DELETE FROM users WHERE id = ?", (user_id,))
                if cursor.rowcount == 0:
                    self.respond_json(404, {"error": "El usuario no existe."})
                    return
        except sqlite3.Error as error:
            print(f"No se pudo eliminar el usuario: {error}")
            self.respond_json(500, {"error": "No se pudo eliminar el usuario local."})
            return
        self.respond(204, b"")

    def create_history_event(self):
        if not self.require_local_client():
            return
        payload = self.read_json()
        if payload is None:
            return
        event_type = payload.get("eventType")
        outcome = payload.get("outcome")
        person_id = payload.get("personId")
        person_name = payload.get("personName")
        source = payload.get("source")
        operator = payload.get("operator", "admin")
        distance = payload.get("distance")
        if event_type not in ("scan", "access"):
            self.respond_json(400, {"error": "El tipo de evento no es válido."})
            return
        valid_outcomes = (
            ("identified", "unmatched") if event_type == "scan" else ("granted", "denied")
        )
        if outcome not in valid_outcomes:
            self.respond_json(400, {"error": "El resultado no corresponde al tipo de evento."})
            return
        if not isinstance(person_name, str) or not person_name.strip() or len(person_name) > 120:
            self.respond_json(400, {"error": "El nombre de la persona o el estado de detección es obligatorio."})
            return
        if person_id is not None and (
            not isinstance(person_id, str) or len(person_id) > 60
        ):
            self.respond_json(400, {"error": "El ID de persona no es válido."})
            return
        if not isinstance(source, str) or not source.strip() or len(source) > 120:
            self.respond_json(400, {"error": "La fuente del escaneo no es válida."})
            return
        if not isinstance(operator, str) or not operator.strip() or len(operator) > 60:
            self.respond_json(400, {"error": "El operador no es válido."})
            return
        if distance is not None and (
            isinstance(distance, bool)
            or not isinstance(distance, (int, float))
            or not (0 <= distance <= 2)
        ):
            self.respond_json(400, {"error": "La distancia facial no es válida."})
            return
        if event_type == "access":
            if not person_id or outcome == "granted" and distance is None:
                self.respond_json(400, {"error": "Un acceso requiere una persona identificada y una comparación facial."})
                return
            if outcome == "granted" and distance > 0.6:
                self.respond_json(400, {"error": "La comparación facial no alcanza el umbral requerido para autorizar el acceso."})
                return

        try:
            with database_connection() as connection:
                if event_type == "access":
                    person = connection.execute(
                        "SELECT name, status FROM people WHERE id = ?", (person_id,)
                    ).fetchone()
                    if not person or person["status"] != "active":
                        self.respond_json(400, {"error": "Solo una persona activa del directorio puede tener acceso autorizado."})
                        return
                    person_name = person["name"]
                cursor = connection.execute(
                    """
                    INSERT INTO history
                        (event_type, outcome, person_id, person_name, source, operator, distance, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        event_type,
                        outcome,
                        person_id,
                        person_name.strip(),
                        source.strip(),
                        operator.strip(),
                        distance,
                        now_iso(),
                    ),
                )
                row_id = cursor.lastrowid
        except sqlite3.Error as error:
            print(f"No se pudo guardar el evento de historial: {error}")
            self.respond_json(500, {"error": "No se pudo guardar el evento en el historial local."})
            return
        self.respond_json(201, {"id": f"OP-{row_id:06d}"})

    def clear_history(self):
        if not self.require_local_client():
            return
        try:
            with database_connection() as connection:
                connection.execute("DELETE FROM history")
                connection.execute("DELETE FROM sqlite_sequence WHERE name = 'history'")
        except sqlite3.Error as error:
            print(f"No se pudo vaciar el historial: {error}")
            self.respond_json(500, {"error": "No se pudo vaciar el historial local."})
            return
        self.respond(204, b"")

    @staticmethod
    def get_session(session_id):
        session = SESSIONS.get(session_id)
        if session and time.monotonic() - session["created_at"] > SESSION_LIFETIME_SECONDS:
            del SESSIONS[session_id]
            return None
        return session

    def do_GET(self):
        request = urlsplit(self.path)
        if request.path == "/api/history":
            self.list_history()
            return
        if request.path == "/api/users":
            self.list_users()
            return
        if request.path == "/api/people":
            self.list_people()
            return
        if request.path == "/api/people/photo":
            if not self.require_local_client():
                return
            try:
                photo_id = int(parse_qs(request.query).get("id", [""])[0])
                with database_connection() as connection:
                    photo = connection.execute(
                        "SELECT image, mime_type FROM person_photos WHERE id = ?", (photo_id,)
                    ).fetchone()
            except (ValueError, sqlite3.Error) as error:
                print(f"No se pudo abrir la foto del directorio: {error}")
                self.respond_json(400, {"error": "El identificador de foto no es válido."})
                return
            if not photo:
                self.respond_json(404, {"error": "La foto no existe."})
                return
            self.respond(200, photo["image"], photo["mime_type"])
            return
        if request.path == "/api/phone/status":
            session_id = parse_qs(request.query).get("session", [""])[0]
            session = self.get_session(session_id)
            if not session:
                self.respond_json(404, {"error": "La sesión de escáner no existe o expiró."})
                return
            connected = bool(
                session["last_seen"]
                and time.monotonic() - session["last_seen"] <= PHONE_TIMEOUT_SECONDS
            )
            self.respond_json(200, {
                "connected": connected,
                "deviceName": session["device_name"] if connected else "",
                "platform": session["platform"] if connected else "",
                "photoReady": session["photo"] is not None,
            })
            return

        if request.path == "/api/phone/photo":
            session_id = parse_qs(request.query).get("session", [""])[0]
            session = self.get_session(session_id)
            if not session:
                self.respond_json(404, {"error": "La sesión de escáner no existe o expiró."})
                return
            photo = session["photo"]
            if photo is None:
                self.respond(204, b"")
                return
            session["photo"] = None
            self.respond(
                200,
                photo["data"],
                photo["mime_type"],
                {
                    "X-Scanner-Device": photo["device_name"]
                    .encode("latin-1", "replace")
                    .decode("latin-1")
                },
            )
            return

        if request.path.startswith("/api/"):
            self.respond_json(404, {"error": "Ruta API no encontrada."})
            return

        relative_path = unquote(request.path).lstrip("/") or "prototipo.html"
        file_path = (WEB_ROOT / relative_path).resolve()
        try:
            file_path.relative_to(WEB_ROOT)
        except ValueError:
            self.respond(403, b"Acceso denegado.", "text/plain; charset=utf-8")
            return
        if not file_path.is_file():
            self.respond(404, b"Archivo no encontrado.", "text/plain; charset=utf-8")
            return
        content_type = mimetypes.guess_type(file_path.name)[0] or "application/octet-stream"
        if content_type.startswith("text/") or content_type in ("application/javascript", "application/json"):
            content_type += "; charset=utf-8"
        try:
            body = file_path.read_bytes()
        except OSError as error:
            print(f"No se pudo leer {file_path.name}: {error}")
            self.respond(500, b"No se pudo leer el archivo.", "text/plain; charset=utf-8")
            return
        self.respond(200, body, content_type)

    def do_POST(self):
        request_path = urlsplit(self.path).path
        if request_path == "/api/history":
            self.create_history_event()
            return
        if request_path == "/api/users":
            self.save_user()
            return
        if request_path == "/api/people":
            self.save_person()
            return
        if request_path == "/api/phone/session":
            session_id = secrets.token_urlsafe(24)
            SESSIONS[session_id] = {
                "created_at": time.monotonic(),
                "last_seen": 0,
                "device_name": "",
                "platform": "",
                "photo": None,
            }
            scanner_url = f"http://{get_lan_address()}:{PORT}/scanner.html"
            self.respond_json(201, {"session": session_id, "scannerUrl": scanner_url})
            return

        if request_path not in (
            "/api/phone/connect",
            "/api/phone/heartbeat",
            "/api/phone/photo",
        ):
            self.respond_json(404, {"error": "Ruta API no encontrada."})
            return

        payload = self.read_json(MAX_PHOTO_BYTES * 2)
        if payload is None:
            return
        session_id = payload.get("session")
        if not isinstance(session_id, str):
            self.respond_json(400, {"error": "Falta el identificador de sesión."})
            return
        session = self.get_session(session_id)
        if not session:
            self.respond_json(404, {"error": "La sesión de escáner no existe o expiró."})
            return

        if request_path == "/api/phone/connect":
            device_name = payload.get("deviceName")
            platform = payload.get("platform")
            if not isinstance(device_name, str) or not device_name.strip():
                self.respond_json(400, {"error": "Indica un nombre para el teléfono."})
                return
            session["device_name"] = "".join(
                character for character in device_name.strip() if character.isprintable()
            )[:60]
            session["platform"] = (
                "".join(character for character in platform.strip() if character.isprintable())[:40]
                if isinstance(platform, str)
                else ""
            )
            session["last_seen"] = time.monotonic()
            self.respond_json(200, {"connected": True})
            return

        if request_path == "/api/phone/heartbeat":
            session["last_seen"] = time.monotonic()
            self.respond_json(200, {"connected": True})
            return

        if session["photo"] is not None:
            self.respond_json(409, {"error": "El panel aún está recibiendo la foto anterior."})
            return
        data_url = payload.get("image")
        if not isinstance(data_url, str) or "," not in data_url:
            self.respond_json(400, {"error": "La imagen no tiene un formato válido."})
            return
        header, encoded_data = data_url.split(",", 1)
        allowed_types = {
            "data:image/jpeg;base64": "image/jpeg",
            "data:image/png;base64": "image/png",
            "data:image/webp;base64": "image/webp",
        }
        mime_type = allowed_types.get(header.lower())
        if not mime_type:
            self.respond_json(415, {"error": "Usa una imagen JPG, PNG o WEBP."})
            return
        try:
            image_data = base64.b64decode(encoded_data, validate=True)
        except (binascii.Error, ValueError):
            self.respond_json(400, {"error": "No se pudo decodificar la imagen."})
            return
        if not image_data or len(image_data) > MAX_PHOTO_BYTES:
            self.respond_json(413, {"error": "La foto está vacía o supera los 20 MB."})
            return
        filename = payload.get("filename")
        if not isinstance(filename, str):
            filename = "captura"
        session["photo"] = {
            "data": image_data,
            "mime_type": mime_type,
            "filename": Path(filename).name[:100],
            "device_name": session["device_name"] or "Teléfono",
        }
        session["last_seen"] = time.monotonic()
        self.respond_json(201, {"received": True})

    def do_DELETE(self):
        request = urlsplit(self.path)
        if request.path == "/api/history":
            self.clear_history()
            return
        if request.path.startswith("/api/users/"):
            raw_user_id = request.path.removeprefix("/api/users/")
            if not raw_user_id.isdecimal():
                self.respond_json(400, {"error": "El identificador de usuario no es válido."})
                return
            self.delete_user(int(raw_user_id))
            return
        if request.path.startswith("/api/people/"):
            person_id = unquote(request.path.removeprefix("/api/people/"))
            if not person_id or "/" in person_id:
                self.respond_json(400, {"error": "El ID de persona no es válido."})
                return
            self.delete_person(person_id)
            return
        if request.path != "/api/phone/session":
            self.respond_json(404, {"error": "Ruta API no encontrada."})
            return
        session_id = parse_qs(request.query).get("session", [""])[0]
        if session_id not in SESSIONS:
            self.respond_json(404, {"error": "La sesión no existe."})
            return
        del SESSIONS[session_id]
        self.respond(204, b"")

    def do_PUT(self):
        request = urlsplit(self.path)
        if request.path.startswith("/api/users/"):
            raw_user_id = request.path.removeprefix("/api/users/")
            if not raw_user_id.isdecimal():
                self.respond_json(400, {"error": "El identificador de usuario no es válido."})
                return
            self.save_user(int(raw_user_id))
            return
        if not request.path.startswith("/api/people/"):
            self.respond_json(404, {"error": "Ruta API no encontrada."})
            return
        person_id = unquote(request.path.removeprefix("/api/people/"))
        if not person_id or "/" in person_id:
            self.respond_json(400, {"error": "El ID de persona no es válido."})
            return
        self.save_person(person_id)


if __name__ == "__main__":
    address = get_lan_address()
    server = ThreadingHTTPServer((HOST, PORT), VeriFaceHandler)
    print("VeriFace servidor de escáner iniciado.")
    print(f"Panel en este computador: http://127.0.0.1:{PORT}/prototipo.html")
    print(f"VeriFace disponible en http://{address}:{PORT}/prototipo.html")
    print(f"Si el panel no carga en el teléfono, prueba abrir esta dirección en ambos dispositivos: http://{address}:{PORT}/prototipo.html")
    print("Conecta el teléfono a la misma Wi-Fi. En Windows, permite Python en redes privadas si aparece el aviso del Firewall.")
    print("No publiques este servidor ni su puerto en Internet.")
    try:
        webbrowser.open(f"http://127.0.0.1:{PORT}/prototipo.html")
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nServidor detenido.")
    finally:
        server.server_close()
