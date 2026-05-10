from io import BytesIO

from pyinfra import host
from pyinfra.api import deploy
from pyinfra.facts.server import Kernel
from pyinfra.operations import files, server

from akinfra_shared.tools import needs_sudo, render_template


@deploy("Mitigate Copy Fail")
def mitigate_copyfail():
    # https://copy.fail/
    if host.get_fact(Kernel) == "Linux":
        mod_name = "algif_aead"
        files.line(
            name=f"Block {mod_name} in modprobe.d",
            path="/etc/modprobe.d/copyfail.conf",
            line=f"install {mod_name} /bin/false",
            ensure_newline=True,
            _sudo=needs_sudo(host),
        )
        server.modprobe(
            name=f"Remove {mod_name} from kernel",
            module=mod_name,
            present=False,
            _sudo=needs_sudo(host),
        )


@deploy("Mitigate Dirtyfrag")
def mitigate_dirtyfrag():
    # https://www.openwall.com/lists/oss-security/2026/05/07/8
    # Also mitigates copy-fail 2: https://github.com/0xdeadbeefnetwork/Copy_Fail2-Electric_Boogaloo/issues/8#issuecomment-4408466147
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
                _sudo=needs_sudo(host),
            )
            server.modprobe(
                name=f"Remove {mod_name} from kernel",
                module=mod_name,
                present=False,
                _sudo=needs_sudo(host),
            )


def install_sshd_config():
    sshd_config = render_template(
        "sshd_config.jinja",
        template_vars={
            "max_startups": (
                # jumphost for pyinfra
                "50:30:200"
                if host.name == "lager.cs.illinois.edu"
                else "10:3:10"),
        },
    )

    sshd_config_op = files.put(
        name="Install SSHD config",
        dest="/etc/ssh/sshd_config",
        src=BytesIO(sshd_config.encode()),
        _sudo=needs_sudo(host),
    )
    server.service(
        name="Reload SSH",
        service="ssh",
        reloaded=True,
        _if=sshd_config_op.did_change,
        _sudo=needs_sudo(host),
    )
