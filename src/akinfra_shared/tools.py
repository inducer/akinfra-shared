import os
import subprocess
from collections.abc import Mapping, Sequence
from typing import TypeAlias, cast


HostData: TypeAlias = Mapping[str, object]
HostWithData: TypeAlias = tuple[str, HostData]
Inventory: TypeAlias = Mapping[str, Sequence[HostWithData]]


def get_bitwarden_cmd():
    return [
        "flatpak", "run", "--command=bw",
        f"--env=BW_SESSION={os.environ['BW_SESSION']}",
        "com.bitwarden.desktop",
    ]


def get_bitwarden_password(search_term_or_id: str) -> str:
    return subprocess.check_output(
        [*get_bitwarden_cmd(), "get", "password", search_term_or_id],
        text=True
    ).strip()


def sudo_from_bitwarden(inventory: Inventory) -> Inventory:
    def add_sudo_password(hwd: HostWithData) -> HostWithData:
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
