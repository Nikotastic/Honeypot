"""Sistema de archivos falsos que ven los atacantes."""

import posixpath
from dataclasses import dataclass, field

HOME = "/root"
HONEYTOKEN_PASSWORD = "Pr0d-2024!"


@dataclass
class File:
    content: str = ""


@dataclass
class Directory:
    children: dict[str, "File | Directory"] = field(default_factory=dict)


type Node = File | Directory


def build_filesystem() -> Directory:
    """Crea el arbol de carpetas y archivos falsos"""
    return Directory(
        {
            "root": Directory(
                {
                    ".bashrc": File("# ~/.bashrc: executed by bash(1) for non-login shells.\n"),
                    "backup.sh": File(
                        "#!/bin/bash\n"
                        'mysqldump -u admin -p"$DB_PASS" prod > /var/backups/prod.sql\n'
                    ),
                    # Nota: este archivo contiene credenciales de base de datos que el atacante puede robar "honeytoken"
                    "notes.txt": File(
                        "TODO: rotate DB credentials before Friday\n"
                        "db_user=admin\n"
                        f"db_pass={HONEYTOKEN_PASSWORD}\n"
                    ),
                }
            ),
            "etc": Directory(
                {
                    "hostname": File("srv-prod-01\n"),
                    "passwd": File(
                        "root:x:0:0:root:/root:/bin/bash\n"
                        "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
                        "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
                        "ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash\n"
                    ),
                }
            ),
            "home": Directory({"ubuntu": Directory()}),
            "tmp": Directory(),
            "var": Directory({"backups": Directory()}),
        }
    )


class FakeFilesystem:
    def __init__(self) -> None:
        self.root = build_filesystem()

    def resolve(self, cwd: str, path: str) -> str:
        """Convierte cualquier ruta (relativa, con ~ o ..) en una ruta absoluta normalizada"""
        if path in ("", "~"):
            return HOME
        if path.startswith("~/"):
            path = HOME + path[1:]
        return posixpath.normpath(posixpath.join(cwd, path))

    def get(self, path: str) -> Node | None:
        """Busca un arcjivo o carpeta en el arbol de archivos falsos. Devuelve None si no existe"""

        node: Node = self.root
        for part in path.strip("/").split("/"):
            if not part:
                continue
            if not isinstance(node, Directory):
                return None
            child = node.children.get(part)
            if child is None:
                return None
            node = child
        return node
