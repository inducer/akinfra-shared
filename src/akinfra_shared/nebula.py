import os
from io import BytesIO
from pathlib import Path
from typing import Any, Literal
from warnings import warn

import tomllib
from typing_extensions import ClassVar, Self
import yaml
from pydantic import BaseModel, ConfigDict, Field, model_validator
from pyinfra.api import deploy
from pyinfra.context import host
from pyinfra.operations import apt, files, systemd

from akinfra_shared.tools import needs_sudo


class CAConfig(BaseModel):
    name: str
    duration: str = "26280h"


class NodeConfig(BaseModel):
    name: str
    ip: str
    groups: list[str] = Field(default_factory=list)


class Config(BaseModel):
    ca: CAConfig
    nodes: list[NodeConfig]


def get_nebula_root_path():
    nebula_root_dir = os.environ.get("NEBULA_CONFIG")
    if nebula_root_dir is None:
        return
    nebula_root = Path(nebula_root_dir)
    del nebula_root_dir
    if not nebula_root.is_dir():
        raise RuntimeError("NEBULA_CONFIG does not point to a directory")

    return nebula_root


def load_nebula_system_config(config_path: Path) -> Config:
    with open(config_path, "rb") as f:
        return Config.model_validate(tomllib.load(f))


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


class NebulaHostConfig(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(extra="forbid")

    hostname: str
    am_relay: bool = False
    am_lighthouse: bool = False

    inbound: list[NebulaFirewallConnection] = Field(default_factory=list)


@deploy("Deploy nebula")
def deploy_nebula():
    nebula_config = getattr(host.data, "nebula_config", None)
    if nebula_config is None:
        return
    host_config = NebulaHostConfig.model_validate(nebula_config)


    apt.packages(
        name="Install package",
        packages=["nebula"],
        present=True,
    )
    nebula_root = get_nebula_root_path()
    if nebula_root is None:
        warn("Not deploying nebula, NEBULA_CONFIG unset", stacklevel=1)
        return
    ca_path = nebula_root / "ca.crt"
    key_path = nebula_root / f"{host_config.hostname}.key"
    cert_path = nebula_root / f"{host_config.hostname}.crt"
    files.put(
        name="Install CA cert",
        dest="/etc/nebula/ca.crt",
        src=BytesIO(ca_path.read_bytes()),
        mode="600",
    )
    files.put(
        name="Install host key",
        dest=f"/etc/nebula/{host_config.hostname}.key",
        src=BytesIO(key_path.read_bytes()),
        mode="600",
    )
    files.put(
        name="Install host cert",
        dest=f"/etc/nebula/{host_config.hostname}.crt",
        src=BytesIO(cert_path.read_bytes()),
        mode="600",
    )
    config_data: dict[str, Any] = {
        "pki": {
            "ca": "/etc/nebula/ca.crt",
            "cert": f"/etc/nebula/{ host_config.hostname }.crt",
            "key": f"/etc/nebula/{ host_config.hostname }.key",
        },
        "static_host_map": {
            "10.33.0.3": ["49.13.195.233:4242"]
        },
        "lighthouse": {
            "am_lighthouse": host_config.am_lighthouse,
            "interval": 60,
            "hosts": ["10.33.0.3"],
        },
        "logging": {
            # panic, fatal, error, warning, info, or debug. Default is info
            "level": "info",
            # json or text formats currently available. Default is text
            "format": "text",
        },
        "relay": (
            {"am_relay": True}
            if host_config.am_relay else
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
                *[ib.to_json() for ib in host_config.inbound]
            ],
        },
    }
    config_store_op = files.put(
        name="Write config file",
        dest=f"/etc/nebula/{host_config.hostname}.yml",
        src=BytesIO(yaml.dump(config_data, Dumper=yaml.Dumper).encode()),
    )
    service_name = f"nebula@{host_config.hostname}"
    systemd.service(
        name="Install/start nebula daemon",
        service=service_name,
        enabled=True,
        running=True,
        daemon_reload=True,
    )
    systemd.service(
        name="Restart nebula daemon",
        service=service_name,
        restarted=True,
        _if=config_store_op.did_change,
    )
