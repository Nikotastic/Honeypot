"""Respuestas falsas a comandos de un atacante"""

HOSTNAME = "srv-prod-01"

# Comando que responde segun el tecto completo del comando
EXACT = {
    "uname -a": (
        f"Linux {HOSTNAME} 5.15.0-105-generic #115-Ubuntu SMP "
        "Mon Apr 15 09:52:04 UTC 2024 x86_64 x86_64 x86_64 GNU/Linux"
    ),
    "uname -m": "x86_64",
    "la -la": (
        "total 32\n"
        "drwx------  4 root root 4096 Oct 12 09:14 .\n"
        "drwxr-xr-x 19 root root 4096 Mar  3  2024 ..\n"
        "-rw-------  1 root root 1203 Nov 20 18:02 .bash_history\n"
        "-rw-r--r--  1 root root 3106 Oct 15  2021 .bashrc\n"
        "drwx------  2 root root 4096 Mar  3  2024 .ssh\n"
        "-rwxr-xr-x  1 root root  412 Sep 28 11:40 backup.sh\n"
        "-rw-r--r--  1 root root  221 Oct 12 09:14 notes.txt"
    ),
    "cat /etc/passwd": (
        "root:x:0:0:root:/root:/bin/bash\n"
        "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
        "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
        "ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash"
    ),
}

# Comando que se respionde segun el nombre, sin importar los argumentos
BY_NAME = {
    "whoami": "root",
    "id": "uid=0(root) gid=0(root) groups=0(root)",
    "pwd": "/root",
    "hostname": HOSTNAME,
    "uname": "Linux",
    "ls": "backup.sh  notes.txt",
    "nproc": "4",
    "uptime": " 14:32:01 up 47 days,  3:12,  1 user,  load average: 0.08, 0.03, 0.01",
}

# Comando que en un linux real no imprime nada
SILENT = {"cd", "export", "unset", "clear", "history"}


def run_one(command: str) -> str:
    """Responde un solo comando y devuelve su salida, sin saltos de terminal"""
    if command in EXACT:
        return EXACT[command]

    name, _, args = command.partition(" ")

    if name == "echo":
        return args.strip("\"'")
    if name in BY_NAME:
        return BY_NAME[name]
    if name in SILENT:
        return ""
    return f"-bash: {name}: command not found"


#
def respond(line: str) -> str:
    """Responde una línea completa, que puede traer varios comandos separados por ';'."""
    outputs = []
    for command in line.split(";"):
        command = command.strip()
        if command:
            output = run_one(command)
            if output:
                outputs.append(output)

    if not outputs:
        return ""
    return "\r\n".join(outputs).replace("\n", "\r\n").replace("\r\r\n", "\r\n") + "\r\n"
