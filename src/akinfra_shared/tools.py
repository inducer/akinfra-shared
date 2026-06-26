import contextlib
import os
import re
import subprocess
import tempfile
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from importlib import resources
from io import BytesIO
from pathlib import Path
from typing import cast
from urllib.request import urlopen

from minijinja import Environment
from pyinfra import host
from pyinfra.api import deploy
from pyinfra.api.host import Host
from pyinfra.facts.deb import DebPackage
from pyinfra.facts.files import FindLinks
from pyinfra.facts.server import Arch, LinuxName
from pyinfra.operations import apt, files, pipx, server, systemd

type HostData = Mapping[str, object]
type HostWithData = tuple[str, HostData] | str
type Inventory = Mapping[str, Sequence[HostWithData]]


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
        with contextlib.suppress(ValueError):
            epoch = int(epoch_part)

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


def ensure_uv(*, _su_user: str | None = None):
    # pipx is now part of default set
    # apt.packages(
    #     packages=["pipx"],
    # )
    pipx.packages(packages=["uv"], _su_user=_su_user)


def install_service(
            name: str,
            content: str,
            *,
            restart_if: Callable[[], bool] | None = None
        ):
    files.put(
        name=f"Install {name} systemd service file",
        dest=f"/etc/systemd/system/{name}.service",
        src=BytesIO(content.encode()),
    )
    systemd.service(
        name=f"Enable {name} systemd service",
        service=name,
        running=True,
        enabled=True,
        daemon_reload=True,
    )
    systemd.service(
        name=f"Restart {name} systemd service",
        service=name,
        restarted=True,
        _if=restart_if,
    )


@deploy("Deploy Nginx")
def deploy_nginx(package_name: str):
    sites_files: list[Path] = list(resources
            .files(package_name)
            .joinpath(f"data/nginx/{host.name}")
            .glob("*.sites")
    )
    if not sites_files:
        return

    nginx_use_full = host.data.get("nginx_use_full", False)
    nginx_package_name = "nginx-full" if nginx_use_full else "nginx"
    nginx_status = host.get_fact(DebPackage, nginx_package_name)
    if nginx_status is None:
        apt.packages(
            packages=[nginx_package_name],
        )
    else:
        needed_ver = {
            # https://security-tracker.debian.org/tracker/CVE-2026-42945
            "Debian": "1.30.1-2",
            "Ubuntu": "1.24.0-2ubuntu7.8",
        }[host.get_fact(LinuxName)]

        installed = parse_debian_version(nginx_status["version"])
        needed = parse_debian_version(needed_ver)
        if installed < needed:
            apt.packages(
                packages=[
                    f"{nginx_package_name}={needed_ver}",
                    f"nginx-common={needed_ver}",
                    *([f"nginx={needed_ver}"] if nginx_use_full else [])
                ],
                update=True,
            )

    files.file(
        name="Remove wreckage from past bugs",
        path="/etc/sites-available/mysites",
        present=False,
    )

    def to_sites_av(p: Path):
        return f"/etc/nginx/sites-available/{p.stem}"

    def to_sites_en(p: Path):
        return f"/etc/nginx/sites-enabled/{p.stem}"

    sites_en_ops = [
        files.put(
            name=f"Install Nginx site {sfile.stem}",
            dest=to_sites_av(sfile),
            src=BytesIO(sfile.read_text().encode()),
            )
        for sfile in sites_files
    ]
    sites_av_names = [to_sites_av(sfile) for sfile in sites_files]
    for link in host.get_fact(FindLinks, "/etc/nginx/sites-enabled"):
        if not (
            # ours
            link in sites_av_names
            # managed via Jitsi Meet package
            or "meet." in link
        ):
            files.link(
                name=f"Remove {link}",
                path=link,
                present=False,
            )
    files.link(
        name="Remove nginx default site",
        path="/etc/nginx/sites-enabled/default",
        present=False,
    )
    sites_av_ops = [files.link(
            name=f"Enable Nginx site {sfile.stem}",
            path=to_sites_en(sfile),
            target=to_sites_av(sfile),
        ) for sfile in sites_files]
    # TODO: Listen snippets
    server.service(
        name="Reload Nginx",
        service="nginx",
        reloaded=True,
        _if=lambda: any(sop.did_change() for sop in [*sites_en_ops, *sites_av_ops]),
    )
    server.service(
        name="Enable/start Nginx",
        service="nginx",
        enabled=True,
        running=True,
    )


def download_and_dearmor_gpg_key(url: str) -> bytes:
    with urlopen(url) as response:
        armored_data = response.read()

    with tempfile.NamedTemporaryFile(delete=False) as tmp_armored:
        tmp_armored.write(armored_data)
        tmp_armored_path = tmp_armored.name

    try:
        process = subprocess.Popen(
            ["gpg", "--dearmor", "-q", "-o", "-", tmp_armored_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        stdout, stderr = process.communicate()

        if process.returncode != 0:
            raise RuntimeError(f"GPG dearmor failed: {stderr.decode().strip()}")

        return stdout

    finally:
        if os.path.exists(tmp_armored_path):
            os.remove(tmp_armored_path)


def host_deb_arch():
    return {
        "x86_64": "amd64",
        "aarch64": "arm64",
    }[host.get_fact(Arch)]


timer_service_content = """[Unit]
After=network.target

[Service]
Type=oneshot
User={user}
ExecStart={command}
"""

timer_content = """[Unit]
[Timer]
{when}
Persistent={persistent}

[Install]
WantedBy=timers.target
"""


def deploy_systemd_timer(base_name: str, command: str, user: str, when: str, persistent: bool = True):
    files.put(
        name=f"Install {base_name} unit",
        src=BytesIO(timer_service_content.format(user=user, command=command).encode()),
        dest=f"/etc/systemd/system/{base_name}.service"
    )

    files.put(
        name=f"Install {base_name} timer",
        dest=f"/etc/systemd/system/{base_name}.timer",
        src=BytesIO(
            timer_content.format(when=when, persistent=str(persistent).lower()).encode()),
    )

    systemd.service(
        name=f"Activate {base_name} timer",
        service=f"{base_name}.timer",
        enabled=True,
        running=True,
        daemon_reload=True,
    )
