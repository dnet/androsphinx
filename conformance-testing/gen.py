# /// script
# requires-python = ">=3.13"
# dependencies = [
#     "click",
#     "cryptography",
#     "pysodium",
#     "pyyaml",
#     "tomlkit",
# ]
# ///

from base64 import b64encode

import click
import tomlkit  # tomllib is read-only, this is required for writing
import yaml
from pysodium import crypto_sign_keypair
from pathlib import Path
from cryptography.x509 import load_pem_x509_certificates
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.x509.oid import ExtensionOID
from cryptography import x509


@click.command()
@click.option(
    "--cert",
    required=True,
    help="Path to the PEM-encoded certificate (chain)",
    type=click.File(mode="rb"),
)
@click.option(
    "--key",
    required=True,
    help="Path to the PEM-encoded private key matching the leaf certificate",
    type=click.File(mode="rb"),
)
@click.option(
    "--sslkeylogfile",
    required=False,
    help="Path to SSLKEYLOGFILE for TLS (Pre)MasterSecret logging",
    type=click.File(mode="ab"),
)
@click.option("--oracles", default=5, type=int, help="Number of oracles to create")
@click.option("--threshold", default=3, type=int, help="Threshold to set in client")
def gen(cert, key, oracles, threshold, sslkeylogfile):
    """Generates a test environment"""
    certs = load_pem_x509_certificates(cert.read())
    pkey = load_pem_private_key(key.read(), None)
    leaf = next(cert for cert in certs if cert.public_key() == pkey.public_key())
    names = leaf.extensions.get_extension_for_oid(
        ExtensionOID.SUBJECT_ALTERNATIVE_NAME
    ).value.get_values_for_type(x509.DNSName)
    wildcard = next(name for name in names if name.startswith("*."))
    suffix = wildcard[1:]
    services = {}
    servers = {}
    basedir = Path(__file__).parent / "output"
    basedir.mkdir()
    for n in range(1, oracles + 1):
        pk, sk = crypto_sign_keypair()
        prefix = f"oracle{n}"
        host = prefix + suffix
        server = {
            "ltsigkey": b64encode(pk).decode("ascii"),
            "host": host,
            "port": 2355,
        }
        servers[prefix] = server
        volume = f"{prefix}-data"
        voldir = basedir / volume
        voldir.mkdir()
        (voldir / "ltsigkey").write_bytes(sk)
        services[prefix] = {
            "build": "..",
            "ports": [f"2355{n}:2355"],
            "volumes": [
                f"{Path(v).absolute()}:/cert/{k}.pem:ro"
                for k, v in [("key", key.name), ("cert", cert.name)]
            ]
            + [f"{voldir.absolute()}:/sphinx"]
            + (
                [f"{Path(sslkeylogfile.name).absolute()}:/sslkeylogfile"]
                if sslkeylogfile
                else []
            ),
            "networks": {"default": {"aliases": [host]}},
        }
        if sslkeylogfile:
            services[prefix]["environment"] = {"SSLKEYLOGFILE": "/sslkeylogfile"}
    client = {
        "servers": servers,
        "client": {
            "verbose": True,
            "threshold": threshold,
            "datadir": "/sphinx",
            "validate_password": True,
        },
    }
    (basedir / "client-config.toml").write_text(tomlkit.dumps(client))
    compose_root = {"services": services}
    (basedir / "compose.yaml").write_text(yaml.dump(compose_root))


if __name__ == "__main__":
    gen()
