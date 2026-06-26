from io import BytesIO
from typing import ClassVar

from pydantic import BaseModel, ConfigDict
from pyinfra.api.deploy import deploy
from pyinfra.context import host
from pyinfra.operations import apt, files

from akinfra_shared.tools import get_bitwarden_password, render_template


class ResticRoot(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(extra="forbid")

    path: str
    excludes: list[str]


class ResticConfig(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(extra="forbid")

    user: str
    host: str
    path: str

    password_id: str
    repo_password_id: str

    roots: list[ResticRoot]
    port: int = 8000


RESTIC_CERT = """
-----BEGIN CERTIFICATE-----
MIID9DCCAtygAwIBAgIUY21my1hwK+Kun6rgtY0t2M9gYAAwDQYJKoZIhvcNAQEL
BQAwfjELMAkGA1UEBhMCVVMxEDAOBgNVBAgMB0lsaW5vaXMxEjAQBgNVBAcMCUNo
YW1wYWlnbjEXMBUGA1UECgwOVGlrZXIubmV0IEdtYkgxDzANBgNVBAsMBkJhY2t1
cDEfMB0GCSqGSIb3DQEJARYQaW5mb3JtQHRpa2VyLm5ldDAeFw0yNDA1MTgxOTMx
MzBaFw0zNDA1MTYxOTMxMzBaMH4xCzAJBgNVBAYTAlVTMRAwDgYDVQQIDAdJbGlu
b2lzMRIwEAYDVQQHDAlDaGFtcGFpZ24xFzAVBgNVBAoMDlRpa2VyLm5ldCBHbWJI
MQ8wDQYDVQQLDAZCYWNrdXAxHzAdBgkqhkiG9w0BCQEWEGluZm9ybUB0aWtlci5u
ZXQwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCm8/+cQBGHcek+ZqCn
ZFYjXJrT5MoJSWMI0NRduI8EateGZkuW6THsZsHZ1wpHMyCqTGV2J7VJaNIsQwsg
WTH9P8aQwgAf3yJqVTeu9jbQLx3iGfWEuR11dKmffk+pT7yM2NpaFCJca8egajJ8
Bz+0dNCiG8e8By4jTtxpt+taOulaT4f9KupQiXdhBswlkOeS6jopbD7fGgfLfYsB
WI1qn2hZrCR1YQCuw8CifsE/CUVLhJaYOQvPZhxybEOD2OmfOPXUm6ibNrSGQ+t6
aQXFd3eUJN7PACKtbbHjhY8O2vvztVmstVN5F/lshcwqcSuN4ZP7PoeTKBRHXsGI
nlZFAgMBAAGjajBoMB0GA1UdDgQWBBT2cv3msrrzB6+FRRkZ6lXV8P74WzAfBgNV
HSMEGDAWgBT2cv3msrrzB6+FRRkZ6lXV8P74WzAPBgNVHRMBAf8EBTADAQH/MBUG
A1UdEQQOMAyHBH8AAAGHBAohAgIwDQYJKoZIhvcNAQELBQADggEBACKqoyczcmDF
tthpPrAfc+DDq0hXkG/wKX/WT4ird8PAFe6q4ZJBIqewqYqNcIlIC4nkmavJWhhX
GzVjl6YIAPMWQvEv5NvszWYMowDnZ6tLJZ/hOfGSQvHQBCfHOPgHTNtMhB+oAYVy
YC4JvqVscTQ/Pp+8v3/8bPecV0bxFv3jgocDIAfRzVjBgvC40zTnKpHmYOZ14PhB
eRAPNqks/p5RwCu5SzW4XHluRL5upUGIMCj+kdcM/HrDf6kD+Bsy7F9ByIjGgPzA
bXzYILKbIH/c4S5Qr1dKfXpm2krGRe12oynVT+9Z8jZV/zOYAjKRTciql+xyIzlM
T5bhZSxCzY4=
-----END CERTIFICATE-----
"""


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
]


@deploy("Deploy restic backup task")
def deploy_restic_backup() -> None:
    if not hasattr(host.data, "restic_config"):
        return

    config = ResticConfig.model_validate(host.data.restic_config)

    apt.packages(
        name="Install package",
        packages=["restic"],
    )
    script_content = render_template(
        "restic-backup.sh.jinja",
        module_name="akinfra_shared",
        template_vars={
            "user": config.user,
            "host": config.host,
            "port": config.port,
            "path": config.path,
            "roots": config.roots,
        })
    backup_script = "/etc/restic-backup.sh"
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
    files.put(
        name="Store password",
        dest="/etc/restic-password",
        mode="600",
        src=BytesIO(get_bitwarden_password(
            config.password_id).encode()),
    )
    files.put(
        name="Store repo password",
        dest="/etc/restic-repo-password",
        mode="600",
        src=BytesIO(get_bitwarden_password(
            config.repo_password_id).encode()),
    )
    files.put(
        name="Store restic cert pub key",
        dest="/etc/restic-public-key.pem",
        mode="644",
        src=BytesIO(RESTIC_CERT.encode()),
    )
