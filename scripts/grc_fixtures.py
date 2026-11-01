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
