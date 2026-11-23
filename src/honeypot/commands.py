"""Shell falsa: interpreta los comandos del atacante."""

from honeypot.filesystem import HOME, Directory, FakeFilesystem, File

HOSTNAME = "srv-prod-01"

# Comando que responde segun el tecto completo del comando
EXACT = {
    "uname -a": (
        f"Linux {HOSTNAME} 5.15.0-105-generic #115-Ubuntu SMP "
        "Mon Apr 15 09:52:04 UTC 2024 x86_64 x86_64 x86_64 GNU/Linux"
    ),
    "uname -m": "x86_64",
}

# Comando que se respionde segun el nombre, sin importar los argumentos
BY_NAME = {
    "whoami": "root",
    "id": "uid=0(root) gid=0(root) groups=0(root)",
    "hostname": HOSTNAME,
    "uname": "Linux",
    "nproc": "4",
    "uptime": " 14:32:01 up 47 days,  3:12,  1 user,  load average: 0.08, 0.03, 0.01",
}

# Comando que en un linux real no imprime nada
SILENT = {"export", "unset", "clear", "history"}


class Shell:
    """Una shell por sesion: cada atacante tiene su propia shell, con su propio directorio de trabajo y variables de entorno."""

    def __init__(self) -> None:
        self.fs = FakeFilesystem()
        self.cwd = HOME

    def prompt(self) -> str:
        if self.cwd == HOME:
            location = "~"
        elif self.cwd.startswith(HOME + "/"):
            location = "~" + self.cwd[len(HOME) :]
        else:
            location = self.cwd
        return f"root@{HOSTNAME}:{location}# "

    def respond(self, line: str) -> str:
        """Responde una línea completa, que puede traer varios comandos separados por ';'."""
        outputs = []
        for command in line.split(";"):
            command = command.strip()
            if command:
                output = self.run_one(command)
                if output:
                    outputs.append(output)

        if not outputs:
            return ""
        return "\n".join(outputs).replace("\n", "\r\n") + "\r\n"

    def run_one(self, command: str) -> str:
        if command in EXACT:
            return EXACT[command]

        name, _, args = command.partition(" ")
        args = args.strip()

        handlers = {"cd": self.cd, "pwd": self.pwd, "ls": self.ls, "cat": self.cat}
        if name in handlers:
            return handlers[name](args)
        if name == "echo":
            return args.strip("\"'")
        if name in BY_NAME:
            return BY_NAME[name]
        if name in SILENT:
            return ""
        return f"-bash: {name}: command not found"

    def pwd(self, args: str) -> str:
        return self.cwd

    def cd(self, args: str) -> str:
        path = self.fs.resolve(self.cwd, args)
        node = self.fs.get(path)
        if node is None:
            return f"-bash: cd: {args}: No such file or directory"
        if isinstance(node, File):
            return f"-bash: cd: {args}: Not a directory"
        self.cwd = path
        return ""

    def ls(self, args: str) -> str:
        parts = args.split()
        flags = "".join(p[1:] for p in parts if p.startswith("-"))
        paths = [p for p in parts if not p.startswith("-")]
        target = paths[0] if paths else "."

        node = self.fs.get(self.fs.resolve(self.cwd, target))
        if node is None:
            return f"ls: cannot access '{target}': No such file or directory"
        if isinstance(node, File):
            return target

        names = sorted(node.children)
        if "a" not in flags:
            names = [n for n in names if not n.startswith(".")]
        return "  ".join(names)

    def cat(self, args: str) -> str:
        if not args:
            return ""
        node = self.fs.get(self.fs.resolve(self.cwd, args))
        if node is None:
            return f"cat: {args}: No such file or directory"
        if isinstance(node, Directory):
            return f"cat: {args}: Is a directory"
        return node.content.rstrip("\n")
