from dataclasses import dataclass, field
from io import BytesIO

from pyinfra.api.deploy import deploy
from pyinfra.context import host
from pyinfra.operations import apt, files

from akinfra_shared.tools import get_bitwarden_notes, get_bitwarden_password, render_template


@dataclass(frozen=True, kw_only=True)
class ResticRoot:
    path: str
    excludes: list[str]


@dataclass(frozen=True, kw_only=True)
class ResticServerAuthInfo:
    user: str
    password_id: str


@dataclass(frozen=True, kw_only=True)
class ResticTarget:
    name: str
    cert_id: str

    server_auth: ResticServerAuthInfo | None

    host: str
    path: str
    port: int = 8000

    password_id: str

    allow_users: list[str] = field(default_factory=list)


@dataclass(frozen=True, kw_only=True)
class ResticConfig:
    targets: list[ResticTarget]
    roots: list[ResticRoot]


RESTIC_GENERIC_EXCLUDES = [
    "/boot",
    ".cache",
    ".cargo",
    "/swapfile",
    "/var/lib/docker",
    "/var/lib/containers",
    "/var/lib/postgresql",
    "/var/cache",
    "/var/lib/apt/lists",
    "/usr",
    ".local/share/containers",
    ".venv",
    ".npm",
]


@deploy("Deploy restic backup task")
def deploy_restic_backup() -> None:
    if not hasattr(host.data, "restic_config"):
        return

    config = host.data.restic_config
    assert isinstance(config, ResticConfig)

    backup_script = "/etc/restic-backup.sh"
    apt.packages(
        name="Install package",
        packages=["restic"],
    )
    default_target: str | None = None
    target_to_url: dict[str, str] = {}
    for target in config.targets:
        access = ""
        auth = target.server_auth
        if auth:
            server_pw_file = f"/etc/restic-repo-password-{target.name}"
            access = f"{auth.user}:$(cat {server_pw_file})@"
            files.put(
                name=f"Store repo password for target {target.name}",
                dest=server_pw_file,
                mode="600",
                src=BytesIO(get_bitwarden_password(
                    auth.password_id).encode()),
            )
        target_to_url[target.name] = (
            f"rest:https://{access}{target.host}:{target.port}{target.path}")
        if default_target is None:
            default_target = target.name

        files.put(
            name="Store password",
            dest=f"/etc/restic-password-{target.name}",
            mode="600",
            src=BytesIO(get_bitwarden_password(
                target.password_id).encode()),
        )
        files.put(
            name=f"Store restic cert pub key for target {target.name}",
            dest=f"/etc/restic-public-key-{target.name}.pem",
            mode="644",
            src=BytesIO(get_bitwarden_notes(target.cert_id).encode()),
        )

        sudoers_file = f"/etc/sudoers.d/restic-backup-{target.name}"
        if target.allow_users:
            lines = "\n".join(
                f"{user} ALL=(ALL) NOPASSWD: {backup_script} {target.name}"
                for user in target.allow_users
            ) + "\n"
            files.put(
                name=f"Store allow users for target {target.name}",
                dest=sudoers_file,
                mode="440",
                src=BytesIO(lines.encode()),
            )
        else:
            files.file(
                path=sudoers_file,
                present=False,
            )
    assert default_target

    script_content = render_template(
        "restic-backup.sh.jinja",
        module_name="akinfra_shared",
        template_vars={
            "target_to_url": target_to_url,
            "default_target": default_target,
            "roots": config.roots,
        })
    files.put(
        name="Store backup script",
        dest=backup_script,
        mode="755",
        src=BytesIO(script_content.encode()),
    )
    files.link(
        name="Add backup script to cron",
        # NB: Cannot have a file extension, or else it won't get run.
        path="/etc/cron.daily/restic-backup",
        target=backup_script,
    )
