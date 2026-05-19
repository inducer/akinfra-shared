import re
import subprocess
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from importlib import resources
from io import BytesIO
from typing import TypeAlias, cast

from minijinja import Environment
from pyinfra.api.host import Host
from pyinfra.operations import apt, files, pipx, systemd


HostData: TypeAlias = Mapping[str, object]
HostWithData: TypeAlias = tuple[str, HostData] | str
Inventory: TypeAlias = Mapping[str, Sequence[HostWithData]]


def get_bitwarden_username(search_term_or_id: str) -> str:
    return subprocess.check_output(
        ["rbw", "get", "--field", "username", search_term_or_id],
        text=True
    ).strip()


def get_bitwarden_password(search_term_or_id: str) -> str:
    return subprocess.check_output(
        ["rbw", "get", search_term_or_id],
        text=True
    ).strip()


def sudo_from_bitwarden(inventory: Inventory) -> Inventory:
    def add_sudo_password(hwd: HostWithData) -> HostWithData:
        if isinstance(hwd, str):
            return hwd

        host, data = hwd

        if "bw_sudo_id" in data:
            data = dict(data)
            bw_id = cast("str", data.pop("bw_sudo_id"))
            data = {
                **data,
                "_sudo_password": get_bitwarden_password(bw_id),
            }

        return host, data

    return {group: [add_sudo_password(hwd) for hwd in hwds]
        for group, hwds in inventory.items()}


def needs_sudo(host: Host) -> bool:
    return bool(hasattr(host.data, "_sudo_password"))


@dataclass(frozen=True, order=True)
class DebianVersion:
    epoch: int
    upstream: tuple[int | str, ...]
    revision: tuple[int | str, ...]


def parse_debian_version(v_string: str) -> DebianVersion:
    """
    Parses a Debian version string into a DebianVersion dataclass.
    Example: '2:1.14.2-1ubuntu1' ->
        DebianVersion(epoch=2, upstream=(1, 14, 2), revision=(1, 'ubuntu', 1))
    """
    # 1. Extract Epoch
    epoch = 0
    remainder = v_string
    if ":" in v_string:
        epoch_part, remainder = v_string.split(":", 1)
        try:
            epoch = int(epoch_part)
        except ValueError:
            pass  # Fallback to 0 if epoch is non-numeric

    # 2. Split Upstream and Revision
    upstream_str = remainder
    revision_str = ""
    if "-" in remainder:
        upstream_str, revision_str = remainder.split("-", 1)

    # 3. Tokenize helper
    def tokenize(s: str) -> tuple[int | str, ...]:
        # Splits "1.14rc2" into (1, 14, "rc", 2)
        tokens = re.findall(r"(\d+|[a-zA-Z]+)", s)
        return tuple(int(t) if t.isdigit() else t for t in tokens)

    return DebianVersion(
        epoch=epoch,
        upstream=tokenize(upstream_str),
        revision=tokenize(revision_str)
    )


def merge_inventories(inventories: Sequence[Inventory]) -> Inventory:
    """
    Merge multiple inventories into a single inventory.

    Groups with the same name across different inventories are merged.
    If multiple inventories contain the same group, their host lists are concatenated.

    Corner Cases:
    - If a group name exists in multiple inventories, the resulting group will contain
      all hosts from all occurrences of that group.
    - If the same host name appears multiple times within the same group (across
      different inventories or within one), a ValueError is raised.
    - Host data is not merged; each host entry is treated as a distinct entity.

    Args:
        inventories: A sequence of Inventory mappings to merge.

    Returns:
        A single merged Inventory.

    Raises:
        ValueError: If a group contains multiple hosts with the same name.
    """
    merged: dict[str, list[HostWithData]] = {}

    for inventory in inventories:
        for group, hosts in inventory.items():
            if group not in merged:
                merged[group] = []

            existing_host_names: set[str] = set()
            for hwd in hosts:
                if isinstance(hwd, str):
                    host_name = hwd
                    host_data: HostData = {}
                else:
                    host_name, host_data = hwd
                if host_name in existing_host_names:
                    raise ValueError(
                        f"Duplicate host '{host_name}' "
                        f"found in group '{group}' during merge"
                    )
                merged[group].append((host_name, host_data))
                existing_host_names.add(host_name)

    return merged


def render_template(
    template_name: str,
    module_name: str = "akinfra_shared",
    template_vars: dict[str, object] | None = None,
) -> str:
    if template_vars is None:
        template_vars = {}
    return Environment(
        undefined_behavior="strict",
        templates={
            template_name: (resources
                .files(module_name)
                .joinpath(f"data/{template_name}")
                .read_text())
    }).render_template(
        template_name,
        **template_vars,
    )


def ensure_uv(*, _sudo: bool = False, _su_user: str | None = None):
    apt.packages(
        packages=["pipx"],
        _sudo=_sudo,
    )
    pipx.packages(packages=["uv"], _sudo=_sudo, _su_user=_su_user)


def install_service(
            name: str,
            content: str,
            *, _sudo: bool = False,
            restart_if: Callable[[], bool] | None = None
        ):
    files.put(
        name=f"Install {name} systemd service file",
        dest=f"/etc/systemd/system/{name}.service",
        src=BytesIO(content.encode()),
        _sudo=_sudo,
    )
    systemd.service(
        name=f"Enable {name} systemd service",
        service=name,
        running=True,
        enabled=True,
        daemon_reload=True,
        _sudo=_sudo,
    )
    systemd.service(
        name=f"Restart {name} systemd service",
        service=name,
        restarted=True,
        _if=restart_if,
        _sudo=_sudo,
    )
