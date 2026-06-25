from io import BytesIO

from akinfra_shared.nebula import deploy_nebula
from akinfra_shared.restic import deploy_restic_backup
from pyinfra.api import deploy
from pyinfra.context import host
from pyinfra.facts.files import Directory
from pyinfra.facts.server import Kernel, LinuxName
from pyinfra.operations import apk, apt, files, server, systemd

from akinfra_shared.tools import needs_sudo, render_template


@deploy("Mitigate Copy Fail")
def mitigate_copyfail():
    if not host.get_fact(Directory, "/etc/modprobe.d"):
        return

    # https://copy.fail/
    if host.get_fact(Kernel) == "Linux":
        mod_name = "algif_aead"
        files.line(
            name=f"Block {mod_name} in modprobe.d",
            path="/etc/modprobe.d/copyfail.conf",
            line=f"install {mod_name} /bin/false",
            ensure_newline=True,
        )
        server.modprobe(
            name=f"Remove {mod_name} from kernel",
            module=mod_name,
            present=False,
        )


@deploy("Mitigate Dirtyfrag")
def mitigate_dirtyfrag():
    if not host.get_fact(Directory, "/etc/modprobe.d"):
        return

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
            )
            server.modprobe(
                name=f"Remove {mod_name} from kernel",
                module=mod_name,
                present=False,
            )


@deploy("Install SSHd config")
def install_sshd_config():
    if not host.get_fact(Directory, "/etc/ssh"):
        return

    sshd_config = render_template(
        "sshd_config.jinja",
        template_vars={
            "max_startups": host.data.get("sshd_max_startups", None),
            "port": host.data.get("sshd_port", None)
        },
    )

    sshd_config_op = files.put(
        name="Install SSHD config",
        dest="/etc/ssh/sshd_config",
        src=BytesIO(sshd_config.encode()),
    )
    server.service(
        name="Reload SSH",
        service="ssh",
        reloaded=True,
        _if=sshd_config_op.did_change,
    )


@deploy("Install APT sources")
def install_apt_sources():
    if host.get_fact(LinuxName) != "Debian":
        return

    apt_sources = render_template(
        "debian.sources.jinja",
        template_vars={},
    )
    files.file(
        name="Remove classic apt sources",
        path="/etc/apt/sources.list",
        present=False,
    )
    sources_op = files.put(
        name="Install apt sources",
        dest="/etc/apt/sources.list.d/debian.sources",
        src=BytesIO(apt_sources.encode()),
    )
    release_op = None
    default_release = getattr(host.data, "apt_default_release", None)
    if default_release:
        release_op = files.put(
            name="Set apt default release",
            dest="/etc/apt/apt.conf.d/01default-release",
            src=BytesIO(f'APT::Default-Release "{default_release}";'.encode()),
        )

    apt.update(
        _if=lambda: (sources_op.did_change()
            or (release_op is not None and release_op.did_change()))
    )


@deploy("Set up network via systemd-networkd/DHCP")
def set_up_network_dhcp() -> None:
    dhcp_macs = getattr(host.data, "dhcp_mac_addresses", [])
    for mac in dhcp_macs:
        network_config = render_template(
            "dhcp.network.jinja",
            template_vars={
                "mac_address": mac,
            },
        )
        config_op = files.put(
            name=f"Set up DHCP for {mac}",
            dest=f"/etc/systemd/network/80-dhcp-{mac.replace(':', '-').lower()}.conf",
                    src=BytesIO(network_config.encode()),
                )
        systemd.service(
            service="systemd-networkd",
            enabled=True,
            running=True,
        )
        systemd.service(
            service="systemd-networkd",
            restarted=True,
            _if=config_op.did_change,
        )


@deploy("Install default packages")
def install_default_packages():
    if host.get_fact(LinuxName) in ["Debian", "Ubuntu"]:
        apt.packages(
            name="Install default packages (generic)",
            packages=[
                "acl", "fail2ban", "etckeeper", "logrotate",
                "curl", "rsync",
                "htop", "iotop", "btop", "iftop", "mtr",
                "tcpdump", "ncdu", "mc",
                "micro", "vim-nox", "zsh",
                "systemd-coredump", "mdadm",
                "pipx",
            ],
            update=True,
            present=True,
        )
    if host.get_fact(LinuxName) == "Debian":
        apt.packages(
            name="Install default packages (Debian-specific)",
            packages=[
                "apt-listbugs",
            ],
            present=True,
        )

    if host.get_fact(LinuxName).startswith("OpenWrt"):
        apk.packages(
            name="Default OpenWrt packages",
            packages=[
                "htop", "tmux",
                "luci-app-upnp",
                "luci-app-ddns",

                "kmod-usb2", "kmod-usb3", "usbutils",

                "block-mount", "e2fsprogs", "kmod-fs-ext4", "kmod-usb-storage",
                "openssh-sftp-server",
                "etherwake", "luasocket",
            ],
            update=True
        )

    files.download(
        name="Download default .tmux.conf",
        src="https://raw.githubusercontent.com/inducer/config-and-scripts/refs/heads/main/dotfiles/.tmux.conf",
        dest="/root/.tmux.conf",
    )


def all():
    mitigate_copyfail(_sudo=needs_sudo(host))
    mitigate_dirtyfrag(_sudo=needs_sudo(host))
    install_sshd_config(_sudo=needs_sudo(host))
    install_apt_sources(_sudo=needs_sudo(host))
    install_default_packages(_sudo=needs_sudo(host))
    set_up_network_dhcp(_sudo=needs_sudo(host))
    deploy_nebula(_sudo=needs_sudo(host))
    deploy_restic_backup(_sudo=needs_sudo(host))
