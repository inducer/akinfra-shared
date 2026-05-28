import os
from io import BytesIO
from pathlib import Path
from typing import Any, ClassVar, Literal
from warnings import warn

import yaml
from pydantic import BaseModel, ConfigDict, Field, model_validator
from pyinfra.api import deploy
from pyinfra.context import host
from pyinfra.facts.server import Kernel, LinuxName
from pyinfra.operations import apt, files, server, systemd
from typing_extensions import Self

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


@deploy("Install SSHd config")
def install_sshd_config():
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
        _sudo=needs_sudo(host),
    )
    server.service(
        name="Reload SSH",
        service="ssh",
        reloaded=True,
        _if=sshd_config_op.did_change,
        _sudo=needs_sudo(host),
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
        _sudo=needs_sudo(host),
    )
    sources_op = files.put(
        name="Install apt sources",
        dest="/etc/apt/sources.list.d/debian.sources",
        src=BytesIO(apt_sources.encode()),
        _sudo=needs_sudo(host),
    )
    release_op = None
    default_release = getattr(host.data, "apt_default_release", None)
    if default_release:
        release_op = files.put(
            name="Set apt default release",
            dest="/etc/apt/apt.conf.d/01default-release",
            src=BytesIO(f'APT::Default-Release "{default_release}";'.encode()),
            _sudo=needs_sudo(host),
        )

    apt.update(
        _sudo=needs_sudo(host),
        _if=lambda: (sources_op.did_change()
            or (release_op is not None and release_op.did_change()))
    )


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
                    _sudo=needs_sudo(host),
                )
        systemd.service(
            service="systemd-networkd",
            enabled=True,
            running=True,
            _sudo=needs_sudo(host),
        )
        systemd.service(
            service="systemd-networkd",
            restarted=True,
            _if=config_op.did_change,
            _sudo=needs_sudo(host),
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
                "systemd-coredump",
                "pipx",
            ],
            update=True,
            present=True,
            _sudo=needs_sudo(host),
        )
    if host.get_fact(LinuxName) == "Debian":
        apt.packages(
            name="Install default packages (Debian-specific)",
            packages=[
                "apt-listbugs",
            ],
            present=True,
            _sudo=needs_sudo(host),
        )


class NebulaDNSConfig(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(extra="forbid")

    host: str
    port: int


class NebulaFirewallConnection(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(extra="forbid")

    port: int | tuple[int, int]
    proto: Literal["any", "tcp", "udp", "icmp"]
    host: str | None = None
    group: str | None = None

    @model_validator(mode="after")
    def check_host_or_group(self) -> Self:
        if not self.host and not self.group:
            raise ValueError("host or group must be supplied")

        return self

    @model_validator(mode="after")
    def check_host(self) -> Self:
        if self.host and not ("." in self.host or self.host == "any"):
            raise ValueError("host must contain a dot or be 'any'")
        return self

    def to_json(self):
        result: dict[str, Any] = {
            "proto": self.proto,
        }
        if isinstance(self.port, int):
            result["port"] = self.port
        else:
            result["port"] = f"{self.port[0]}-{self.port[1]}"

        if self.host:
            result["host"] = self.host
        if self.group:
            result["group"] = self.group
        return result


class NebulaConfig(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(extra="forbid")

    hostname: str
    am_relay: bool = False
    am_lighthouse: bool = False
    dns: NebulaDNSConfig | None = None

    inbound: list[NebulaFirewallConnection] = Field(default_factory=list)


@deploy("Deploy nebula")
def deploy_nebula():
    nebula_config = getattr(host.data, "nebula_config", None)
    if nebula_config is None:
        return
    config = NebulaConfig.model_validate(nebula_config)

    nebula_root_dir = os.environ.get("NEBULA_CONFIG")
    if nebula_root_dir is None:
        warn("Not deploying nebula, NEBULA_CONFIG unset", stacklevel=1)
        return
    nebula_root = Path(nebula_root_dir)
    del nebula_root_dir
    if not nebula_root.is_dir():
        raise RuntimeError("NEBULA_CONFIG does not point to a directory")

    apt.packages(
        name="Install package",
        packages=["nebula"],
        present=True,
        _sudo=needs_sudo(host),
    )
    ca_path = nebula_root / "ca.crt"
    key_path = nebula_root / f"{config.hostname}.key"
    cert_path = nebula_root / f"{config.hostname}.crt"
    files.put(
        name="Install CA cert",
        dest="/etc/nebula/ca.crt",
        src=BytesIO(ca_path.read_bytes()),
        mode="600",
        _sudo=needs_sudo(host),
    )
    files.put(
        name="Install host key",
        dest=f"/etc/nebula/{config.hostname}.key",
        src=BytesIO(key_path.read_bytes()),
        mode="600",
        _sudo=needs_sudo(host),
    )
    files.put(
        name="Install host cert",
        dest=f"/etc/nebula/{config.hostname}.crt",
        src=BytesIO(cert_path.read_bytes()),
        mode="600",
        _sudo=needs_sudo(host),
    )
    config_data: dict[str, Any] = {
        "pki": {
            "ca": "/etc/nebula/ca.crt",
            "cert": f"/etc/nebula/{ config.hostname }.crt",
            "key": f"/etc/nebula/{ config.hostname }.key",
        },
        "static_host_map": {
            "10.33.0.3": ["49.13.195.233:4242"]
        },
        "lighthouse": {
            "am_lighthouse": config.am_lighthouse,
            "interval": 60,
            "hosts": ["10.33.0.3"],
            "serve_dns": config.dns is not None,
        },
        "logging": {
            # panic, fatal, error, warning, info, or debug. Default is info
            "level": "info",
            # json or text formats currently available. Default is text
            "format": "text",
        },
        "relay": (
            {"am_relay": True}
            if config.am_relay else
            {"relays": ["10.33.0.3"], }
        ),
        "punchy": {
            "punch": True,
        },
        "listen": {
            "host": "[::]",
            "port": 4242,
        },
        "tun": {
            "disabled": False,
            "dev": "nebula1",
        },
        "firewall": {
            "conntrack": {
                "tcp_timeout": "12m",
                "udp_timeout": "3m",
                "default_timeout": "10m",
            },
            "outbound": [
                {"port": "any", "proto": "any", "host": "any"}
            ],
            "inbound": [
                {"port": "any", "proto": "icmp", "host": "any"},
                {"port": 22, "proto": "tcp", "host": "any"},
                *[ib.to_json() for ib in config.inbound]
            ],
        },
    }
    if config.dns is not None:
        config_data["lighthouse"]["dns"] = config.dns.model_dump()
    config_store_op = files.put(
        name="Write config file",
        dest=f"/etc/nebula/{config.hostname}.yml",
        src=BytesIO(yaml.dump(config_data, Dumper=yaml.Dumper).encode()),
        _sudo=needs_sudo(host),
    )
    service_name = f"nebula@{config.hostname}"
    systemd.service(
        name="Install/start nebula daemon",
        service=service_name,
        enabled=True,
        running=True,
        daemon_reload=True,
        _sudo=needs_sudo(host),
    )
    systemd.service(
        name="Restart nebula daemon",
        service=service_name,
        restarted=True,
        _if=config_store_op.did_change,
        _sudo=needs_sudo(host),
    )


def all():
    mitigate_copyfail()
    mitigate_dirtyfrag()
    install_sshd_config()
    install_apt_sources()
    install_default_packages()
    set_up_network_dhcp()
    deploy_nebula()
