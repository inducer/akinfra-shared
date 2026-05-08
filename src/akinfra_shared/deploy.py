from pyinfra import host
from pyinfra.api import deploy
from pyinfra.facts.server import Kernel
from pyinfra.operations import files, server


@deploy("Mitigate Dirtyfrag")
def mitigate_dirtyfrag():
    if host.get_fact(Kernel) == "Linux":
        for mod_name in [
                    "esp4",
                    "esp6",
                    "rxrpc",
                ]:
            files.line(
                name=f"Block {mod_name} in modprobe.d",
                path="/etc/modprobe.d/dirtyfrag.conf",
                line=f"install {mod_name} /bin/false",
                ensure_newline=True,
                _sudo=True,
            )
            server.modprobe(
                name=f"Remove {mod_name} from kernel",
                module=mod_name,
                present=False,
                _sudo=True,
            )
