#!/usr/bin/env python3
"""
grc_fixtures.py - Shared Synthetic Audit Fixtures for Offline & Mock Execution
==============================================================================

Classification: Internal Compliance & Engineering Specification
Zero External Dependencies: 100% Python 3 Standard Library.

Decouples synthetic mock fixture generators from `scripts/grc_test.py` so that
production engines (`scripts/grc_ami.py`) can run in `--mock` mode without
importing the test runner or `unittest`.
"""

import hashlib
import shutil
import subprocess
import tempfile
import uuid
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from grc_common import sha256_file, utc_now_iso


def generate_mock_ebs_volume(snapshot_id: Optional[str] = None) -> str:
    """Generates a deterministic or synthetic AWS EBS volume identifier."""
    if snapshot_id:
        digest = hashlib.sha256(snapshot_id.encode("utf-8")).hexdigest()[:17]
        return f"vol-{digest}"
    return f"vol-{uuid.uuid4().hex[:17]}"


def generate_mock_ami_metadata(ami_id: str, region: str = "us-east-1") -> Dict[str, Any]:
    """Generates realistic synthetic AWS EC2 AMI metadata for `--mock` mode."""
    snap_id = f"snap-{hashlib.sha256(ami_id.encode('utf-8')).hexdigest()[:17]}"
    kms_arn = f"arn:aws:kms:{region}:123456789012:key/c01d-m0un-t001-f1p5-1402k3y00000"
    return {
        "image_id": ami_id,
        "name": f"rhel-9-hardened-golden-image-{ami_id[:8]}",
        "owner_id": "123456789012",
        "architecture": "x86_64",
        "creation_date": utc_now_iso(),
        "state": "available",
        "root_device_name": "/dev/sda1",
        "root_snapshot_id": snap_id,
        "root_volume_size_gb": 40,
        "encrypted": True,
        "kms_key_id": kms_arn,
        "virtualization_type": "hvm",
        "ena_support": True,
        "block_devices": [
            {
                "DeviceName": "/dev/sda1",
                "Ebs": {
                    "SnapshotId": snap_id,
                    "VolumeSize": 40,
                    "Encrypted": True,
                    "KmsKeyId": kms_arn,
                    "VolumeType": "gp3",
                },
            }
        ],
    }


def create_mock_rootfs(mount_path: Path) -> None:
    """Populates a synthetic Linux root filesystem fixture for offline cold-mount tests."""
    etc_dir = mount_path / "etc"
    etc_dir.mkdir(parents=True, exist_ok=True)
    os_release_content = (
        'NAME="Red Hat Enterprise Linux"\n'
        'VERSION="9.2 (Plow)"\n'
        'ID="rhel"\n'
        'ID_LIKE="fedora"\n'
        'VERSION_ID="9.2"\n'
        'PLATFORM_ID="platform:el9"\n'
        'PRETTY_NAME="Red Hat Enterprise Linux 9.2 (Plow)"\n'
        'ANSI_COLOR="0;31"\n'
        'CPE_NAME="cpe:/o:redhat:enterprise_linux:9::baseos"\n'
        'HOME_URL="https://www.redhat.com/"\n'
        'BUG_REPORT_URL="https://bugzilla.redhat.com/"\n'
    )
    (etc_dir / "os-release").write_text(os_release_content, encoding="utf-8")

    # Sample library directories with mock shared objects
    lib_dir = mount_path / "usr" / "lib64"
    lib_dir.mkdir(parents=True, exist_ok=True)
    (lib_dir / "libssl.so.3").touch()
    (lib_dir / "libcrypto.so.3").touch()


def create_synthetic_scratch_bundle(dest_bundle: Path) -> Tuple[str, Path]:
    """
    Creates a temporary Git repository in /tmp with intentional compliance flaws,
    tags it at v1.0.0 (with GPG signing explicitly disabled for portability),
    and exports it as a standalone Git packfile bundle.
    Returns (sha256_checksum, bundle_path).
    """
    temp_repo = Path(tempfile.mkdtemp(prefix="grc_test_repo_"))
    git_base = ["git", "-c", "commit.gpgsign=false", "-c", "tag.gpgsign=false"]
    try:
        init_res = subprocess.run(
            ["git", "init", "-b", "main"],
            cwd=temp_repo,
            capture_output=True,
            text=True,
        )
        if init_res.returncode != 0:
            subprocess.run(["git", "init"], cwd=temp_repo, check=True, capture_output=True)
            subprocess.run(["git", "checkout", "-b", "main"], cwd=temp_repo, check=True, capture_output=True)

        subprocess.run(["git", "config", "user.name", "GRCx Test Harness"], cwd=temp_repo, check=True)
        subprocess.run(["git", "config", "user.email", "test@grc-x.internal"], cwd=temp_repo, check=True)

        # 1. Sample app.py with hardcoded secret and weak crypto
        app_code = (
            "import hashlib\n"
            "SECRET_KEY = 'hardcoded_test_secret_key'\n"
            "def hash_token(data):\n"
            "    return hashlib.md5(data.encode()).hexdigest()\n"
        )
        (temp_repo / "app.py").write_text(app_code, encoding="utf-8")

        # 2. Sample requirements.txt with deprecated pycrypto
        reqs = "pycrypto==2.6.1\nrequests==2.31.0\n"
        (temp_repo / "requirements.txt").write_text(reqs, encoding="utf-8")

        # 3. Commit and tag (with GPG signing disabled so host gitconfig never breaks tests)
        subprocess.run(["git", "add", "."], cwd=temp_repo, check=True, capture_output=True)
        subprocess.run(
            git_base + ["commit", "-m", "feat: test release candidate"],
            cwd=temp_repo,
            check=True,
            capture_output=True,
        )
        subprocess.run(
            git_base + ["tag", "-a", "v1.0.0", "-m", "Release v1.0.0"],
            cwd=temp_repo,
            check=True,
            capture_output=True,
        )

        # 4. Create Git bundle
        dest_bundle.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run(
            ["git", "bundle", "create", str(dest_bundle), "--all"],
            cwd=temp_repo,
            check=True,
            capture_output=True,
        )

        # 5. Compute SHA-256
        sha256 = sha256_file(dest_bundle)
        return sha256, dest_bundle
    finally:
        shutil.rmtree(temp_repo, ignore_errors=True)


def populate_fips_positive_fixture(workspace: Path) -> None:
    """
    Populates a multi-language synthetic workspace exhibiting ONLY approved
    FIPS 140-3 conformance indicators (zero FAIL findings expected).
    """
    workspace.mkdir(parents=True, exist_ok=True)
    (workspace / "etc" / "default").mkdir(parents=True, exist_ok=True)
    (workspace / "etc" / "crypto-policies").mkdir(parents=True, exist_ok=True)
    (workspace / "conf").mkdir(parents=True, exist_ok=True)
    (workspace / "src").mkdir(parents=True, exist_ok=True)

    (workspace / "etc" / "default" / "grub").write_text(
        'GRUB_CMDLINE_LINUX="crashkernel=auto fips=1"\n',
        encoding="utf-8",
    )
    (workspace / "etc" / "crypto-policies" / "config").write_text("FIPS\n", encoding="utf-8")
    (workspace / "conf" / "openssl.cnf").write_text(
        "openssl_conf = openssl_init\n"
        "[openssl_init]\nproviders = provider_sect\n"
        "[provider_sect]\nfips = fips_sect\n"
        "[fips_sect]\nactivate = 1\n",
        encoding="utf-8",
    )
    (workspace / "conf" / "java.security").write_text(
        "security.provider.1=org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider\n",
        encoding="utf-8",
    )
    (workspace / "Dockerfile").write_text(
        "FROM cgr.dev/chainguard/python:latest-fips\n"
        "ENV GOLANG_FIPS=1\n",
        encoding="utf-8",
    )
    (workspace / "Cargo.toml").write_text(
        '[package]\nname = "clean-fips"\nversion = "0.1.0"\n\n'
        '[dependencies]\naws-lc-rs = { version = "1.9.3", features = ["fips"] }\n',
        encoding="utf-8",
    )
    (workspace / "Cargo.lock").write_text(
        '[[package]]\nname = "aws-lc-rs"\nversion = "1.9.3"\n',
        encoding="utf-8",
    )
    (workspace / "pom.xml").write_text(
        "<project><dependencies><dependency>"
        "<groupId>org.bouncycastle</groupId>"
        "<artifactId>bc-fips</artifactId>"
        "<version>2.0.0</version>"
        "</dependency></dependencies></project>\n",
        encoding="utf-8",
    )
    (workspace / "src" / "approved.py").write_text(
        '"""Comments mentioning hashlib.md5() must never trigger false positives."""\n'
        "import hashlib, hmac, secrets\n"
        "from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519\n"
        "from cryptography.hazmat.primitives.ciphers.aead import AESGCM\n\n"
        "def run_approved(key: bytes, payload: bytes) -> bytes:\n"
        "    nonce = secrets.token_bytes(12)\n"
        "    ct = AESGCM(key).encrypt(nonce, payload, None)\n"
        "    digest = hashlib.sha256(ct).digest()\n"
        "    mac = hmac.new(key, digest, hashlib.sha256).digest()\n"
        "    _rsa = rsa.generate_private_key(public_exponent=65537, key_size=3072)\n"
        "    _ec = ec.generate_private_key(ec.SECP256R1())\n"
        "    _ed = ed25519.Ed25519PrivateKey.generate()\n"
        "    return mac\n",
        encoding="utf-8",
    )
    (workspace / "src" / "approved.go").write_text(
        "//go:debug fips140=only\n"
        "package main\n"
        'import (\n  "crypto/cipher"\n  "crypto/elliptic"\n  "crypto/rand"\n  "crypto/rsa"\n  "crypto/sha256"\n  "crypto/tls"\n)\n'
        "func ok(block cipher.Block) {\n"
        "  _ = sha256.Sum256([]byte(\"ok\"))\n"
        "  _, _ = cipher.NewGCM(block)\n"
        "  _, _ = rsa.GenerateKey(rand.Reader, 3072)\n"
        "  _ = elliptic.P256()\n"
        "  _ = &tls.Config{MinVersion: tls.VersionTLS13}\n"
        "}\n",
        encoding="utf-8",
    )
    (workspace / "src" / "Approved.java").write_text(
        "import java.security.MessageDigest;\nimport javax.crypto.Cipher;\nimport javax.net.ssl.SSLContext;\n"
        "public class Approved {\n"
        "  public void run() throws Exception {\n"
        '    CryptoServicesRegistrar.setApprovedOnlyMode(true);\n'
        '    MessageDigest.getInstance("SHA-256");\n'
        '    Cipher.getInstance("AES/GCM/NoPadding");\n'
        '    SSLContext.getInstance("TLSv1.3");\n'
        "  }\n}\n",
        encoding="utf-8",
    )
    (workspace / "src" / "approved.js").write_text(
        "const crypto = require('crypto');\n"
        "crypto.setFips(1);\n"
        "const digest = crypto.createHash('sha256').update('data').digest('hex');\n"
        "const mac = crypto.createHmac('sha256', Buffer.alloc(32)).update(digest).digest('hex');\n",
        encoding="utf-8",
    )
    (workspace / "src" / "approved.c").write_text(
        "#include <openssl/evp.h>\n#include <openssl/provider.h>\n"
        "void init_fips(void) {\n"
        '  OSSL_PROVIDER_load(NULL, "fips");\n'
        "  EVP_default_properties_enable_fips(NULL, 1);\n"
        "  const EVP_MD *md = EVP_sha256();\n"
        "  const EVP_CIPHER *c = EVP_aes_256_gcm();\n"
        "  (void)md; (void)c;\n"
        "}\n",
        encoding="utf-8",
    )
    (workspace / "src" / "approved.rs").write_text(
        "use sha2::Sha256;\n"
        "pub fn hash_ok() { let _ = sha2::Sha256::new(); }\n",
        encoding="utf-8",
    )
    (workspace / "src" / "Approved.cs").write_text(
        "using System.Security.Cryptography;\n"
        "public class Approved {\n"
        "  public void Run(byte[] key) {\n"
        "    using var h = SHA256.Create();\n"
        "    using var gcm = new AesGcm(key);\n"
        "    using var rsa = RSA.Create(3072);\n"
        "  }\n}\n",
        encoding="utf-8",
    )


def populate_fips_negative_fixture(workspace: Path) -> None:
    """
    Populates a multi-language synthetic workspace containing intentional
    algorithm, cipher-mode, parameter, TLS, and approved-mode violations.
    """
    workspace.mkdir(parents=True, exist_ok=True)
    (workspace / "etc" / "default").mkdir(parents=True, exist_ok=True)
    (workspace / "etc" / "crypto-policies").mkdir(parents=True, exist_ok=True)
    (workspace / "src").mkdir(parents=True, exist_ok=True)

    (workspace / "etc" / "default" / "grub").write_text(
        'GRUB_CMDLINE_LINUX="console=tty0 fips=0"\n',
        encoding="utf-8",
    )
    (workspace / "etc" / "crypto-policies" / "config").write_text("LEGACY\n", encoding="utf-8")
    (workspace / "App.config").write_text(
        '<configuration><runtime><enforceFIPSPolicy enabled="false"/></runtime></configuration>\n',
        encoding="utf-8",
    )
    (workspace / "requirements.txt").write_text("pycryptodome==3.20.0\n", encoding="utf-8")
    (workspace / "pom.xml").write_text(
        "<project><dependencies><dependency>"
        "<groupId>org.bouncycastle</groupId>"
        "<artifactId>bc-fips</artifactId>"
        "<version>1.0.2.5</version>"
        "</dependency></dependencies></project>\n",
        encoding="utf-8",
    )
    (workspace / "src" / "bad.py").write_text(
        "import hashlib, random\n"
        "from cryptography.hazmat.primitives.asymmetric import rsa, ec\n"
        "from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes\n\n"
        "def bad(key: bytes) -> None:\n"
        "    _ = hashlib.md5(b'payload').hexdigest()\n"
        "    _ = Cipher(algorithms.AES(key), modes.ECB())\n"
        "    _ = rsa.generate_private_key(public_exponent=65537, key_size=1024)\n"
        "    _ = ec.generate_private_key(ec.SECP256K1())\n"
        "    secret_token = random.randint(1000, 9999)\n"
        "    _ = secret_token\n",
        encoding="utf-8",
    )
    (workspace / "src" / "bad.go").write_text(
        "//go:debug fips140=off\n"
        "package main\n"
        'import (\n  "crypto/des"\n  "crypto/md5"\n  "crypto/tls"\n)\n'
        "func bad() {\n"
        "  _ = md5.Sum([]byte(\"x\"))\n"
        "  _, _ = des.NewCipher(make([]byte, 8))\n"
        "  _ = &tls.Config{MinVersion: tls.VersionTLS10, InsecureSkipVerify: true}\n"
        "}\n",
        encoding="utf-8",
    )
    (workspace / "src" / "Bad.java").write_text(
        "import java.security.MessageDigest;\nimport javax.crypto.Cipher;\nimport javax.net.ssl.SSLContext;\n"
        "public class Bad {\n"
        "  public void bad() throws Exception {\n"
        '    MessageDigest.getInstance("MD5");\n'
        '    Cipher.getInstance("AES/ECB/PKCS5Padding");\n'
        '    SSLContext.getInstance("TLSv1.1");\n'
        "  }\n}\n",
        encoding="utf-8",
    )
    (workspace / "src" / "bad.js").write_text(
        "const crypto = require('crypto');\n"
        "crypto.setFips(0);\n"
        "crypto.createHash('md5').update('x').digest('hex');\n"
        "crypto.createCipheriv('rc4', Buffer.alloc(16), '');\n",
        encoding="utf-8",
    )
    (workspace / "src" / "bad.c").write_text(
        "#include <openssl/evp.h>\n"
        "void bad_c(void) {\n"
        "  FIPS_mode_set(0);\n"
        "  const EVP_MD *m = EVP_md5();\n"
        "  const EVP_CIPHER *c = EVP_aes_128_ecb();\n"
        "  (void)m; (void)c;\n"
        "}\n",
        encoding="utf-8",
    )
    (workspace / "src" / "bad.rs").write_text(
        "pub fn bad_rs() {\n"
        "  let _ = md5::Md5::new();\n"
        "  let _ = chacha20poly1305::ChaCha20Poly1305::new();\n"
        "}\n",
        encoding="utf-8",
    )
    (workspace / "src" / "Bad.cs").write_text(
        "using System.Security.Cryptography;\n"
        "public class Bad {\n"
        "  public void Run() {\n"
        "    using var m = MD5.Create();\n"
        "    using var r = RSA.Create(1024);\n"
        "  }\n}\n",
        encoding="utf-8",
    )

