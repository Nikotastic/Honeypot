import asyncio
import logging

import asyncssh

from honeypot.commands import Shell
from honeypot.filesystem import HONEYTOKEN_PASSWORD

""" Se encarga de manejar la conexion SSH: logueo, shell interactiva y comandos directos. """

HOST = "127.0.0.1"
PORT = 2222
HOST_KEY = "ssh_host_key"
SERVER_VERSION = "OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"
FAILED_ATTEMPTS_BEFORE_LOGIN = 1


WELCOME = (
    "Welcome to Ubuntu 22.04.2 LTS (GNU/Linux 5.15.0-105-generic x86_64)\r\n"
    "\r\n"
    " * Documentation:  https://help.ubuntu.com\r\n"
    "\r\n"
)

log = logging.getLogger("honeypot")


class HoneypotSSHServer(asyncssh.SSHServer):
    """Maneja una conexion: se crea una instancia nueva para cada conexion entrante."""

    def __init__(self) -> None:
        self.ip = "desconocida"
        self.failed_attempts = 0

    # Metodos de asyncssh.SSHServer

    # connection_made sabemos que se ha establecido una conexion entrante y podemos obtener la direccion IP del atacante
    def connection_made(self, conn: asyncssh.SSHServerConnection) -> None:
        self.ip, _port = conn.get_extra_info("peername")
        log.info("Conexion entrante desde %s", self.ip)

    # connection_lost sabemos que la conexion se ha cerrado
    def connection_lost(self, exc: Exception | None) -> None:
        log.info("Conexion perdida desde %s" % self.ip)

    # begin_auth y validate_password son metodos de autenticacion: se llaman cuando el atacante intenta loguearse con un usuario y contraseña
    def begin_auth(self, username: str) -> bool:
        return True

    def password_auth_supported(self) -> bool:
        return True

    # validate_password se llama con cada intento. Rechaza el primero y acepta el siguiente. Si un servidor acepta cualquier contraseña al primer intento, es sospechoso, porque los servidores reales no hacen eso.
    def validate_password(self, username: str, password: str) -> bool:
        log.info(
            "Intento de login  | ip=%s | usuario=%s | contraseña=%s", self.ip, username, password
        )

        if password == HONEYTOKEN_PASSWORD:
            log.warning("🚨 HONEYTOKEN USADO | ip=%s | usuario=%s", self.ip, username)
            return True

        if self.failed_attempts < FAILED_ATTEMPTS_BEFORE_LOGIN:
            self.failed_attempts += 1
            return False

        log.info("Login exitoso | ip=%s | usuario=%s", self.ip, username)
        return True


# Maneja la sesion: lo que el atacante escribe despues de loguearse
async def handle_client(process: asyncssh.SSHServerProcess) -> None:
    """Maneja a sesion: lo que el atacante escribe despues de loguearse"""
    ip = process.get_extra_info("peername")[0]
    shell = Shell()

    # caso 1: el atacante se loguea y escribe un comando (ssh root@honeypot "uname -a")
    if process.command:
        log.info("Comando directo | ip=%s | comando=%s", ip, process.command)
        process.stdout.write(shell.respond(process.command))
        process.exit(0)
        return

    # caso 2: el atacante se loguea y entra a la shell interactiva (ssh root@honeypot)
    process.stdout.write(WELCOME)

    while True:
        process.stdout.write(shell.prompt())

        try:
            # Espera a que el atacante escriba un comando y presione enter
            line = await process.stdin.readline()

        # Eventos de cambio de tamaño de la terminal (por ejemplo, cuando el atacante cambia el tamaño de la ventana de la terminal)
        except asyncssh.TerminalSizeChanged:
            continue

        except (asyncssh.BreakReceived, asyncssh.SignalReceived):
            process.stdout.write("^C\r\n")
            continue

        if not line:
            break

        command = line.strip()
        if not command:
            continue

        log.info("Comando | ip=%s comando=%s", ip, command)

        if command in ("exit", "logout"):
            break

        process.stdout.write(shell.respond(command))

    process.exit(0)


# Inicia el servidor SSH
async def start_server() -> None:
    await asyncssh.create_server(
        HoneypotSSHServer,
        HOST,
        PORT,
        server_host_keys=[HOST_KEY],
        server_version=SERVER_VERSION,
        process_factory=handle_client,
    )
    log.info("Honeypot escuchando en %s:%s", HOST, PORT)
    await asyncio.Event().wait()  # Mantener el servidor en ejecución


def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
    )
    logging.getLogger("asyncssh").setLevel(logging.WARNING)
    try:
        asyncio.run(start_server())
    except KeyboardInterrupt:
        log.info("Honeypot detenido")
