from collections.abc import Sequence
from typing import Callable

from akinfra_shared.tools import (
    get_bitwarden_password,
    get_bitwarden_username,
    needs_sudo,
)
from pyinfra import host
from pyinfra.operations import apt, files, systemd


def restart_valkey(if_: Sequence[Callable[[], bool]]):
    systemd.service(
        name="Restart valkey",
        service="valkey-server",
        restarted=True,
        _if=lambda: any(func() for func in if_),
        _sudo=needs_sudo(host),
    )


def set_up_valkey():
    apt.packages(
        packages=["valkey-server", "valkey-tools"],
        _sudo=needs_sudo(host),
    )
    vk_listen_change = files.line(
        name="Adjust valkey listen on any interface",
        path="/etc/valkey/valkey.conf",
        line="^bind .*$",
        replace="bind * -::*",
        _sudo=needs_sudo(host),
    ).did_change
    vk_default_change = files.line(
        name="Adjust valkey default user",
        path="/etc/valkey/valkey.conf",
        line="^user default.*$",
        replace="user default on "
            f">{get_bitwarden_password(host.data.valkey_default_password_id)} "
            "sanitize-payload ~* &* +@all",
        _sudo=needs_sudo(host),
    ).did_change

    restart_valkey([vk_listen_change, vk_default_change])


def add_valkey_user(user: str, password_id: str, all_commands: bool = False):
    bw_user = get_bitwarden_username(password_id)
    bw_password = get_bitwarden_password(password_id)
    assert user == bw_user

    vk_user_change = files.block(
        name=f"Set up valkey {user} user",
        path="/etc/valkey/valkey.conf",
        content=(
            f"user {user} on >{bw_password} ~* &* +@all"
            if all_commands else
            f"user {user} on >{bw_password} ~* &* +@all -@dangerous +keys +flushdb +flushall"
        ),

        marker=f"# {{mark}} VALKEY {user} PYINFRA BLOCK",
        _sudo=needs_sudo(host),
    ).did_change
    restart_valkey([vk_user_change])
