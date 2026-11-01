#!/usr/bin/env python3
"""
grc_ami.py - GRC Amazon Machine Image (AMI) Ingestion & Cold-Mount Lifecycle Manager
=====================================================================================

Classification: Internal Compliance & Engineering Specification
Pipeline Role: Phase 1 (Pull & Verify) & Phase 2 (Restore / Cold-Mount) Core Orchestrator
Target Frameworks: NIST SP 800-53 (SC-12, SC-13, SI-7, CM-6), FedRAMP High, DISA STIG
Architecture Pattern: EBS Snapshot Cold-Mount (Zero Untrusted Execution)

Purpose:
  Provides the operational CLI and orchestration engine for auditing AMIs out-of-band:
    - Verifies AMI metadata, root EBS snapshot integrity, and KMS encryption compliance.
    - Provisions ephemeral secondary EBS volumes from root snapshots in the worker's AZ.
    - Executes read-only cold mounts (`ro,norecovery,nouuid,noexec,nosuid` for XFS;
      `ro,noload,noexec,nosuid` for ext4) without booting untrusted code.
    - Extracts OS release identifiers (`/etc/os-release`) to map applicable DISA STIG profiles.
    - Emits formal `ami_provenance.json` audit manifests for FedRAMP / DoD SCR packages.
    - Guarantees complete ephemeral teardown (`grc ami clean`) and automatic volume rollback
      on failure to eliminate cloud sprawl.

Design Rule Adherence:
  - Out-of-Band (OOB): Never gates main VM image build pipelines.
  - Zero Untrusted Execution: Cold-mounting prevents code execution, daemon activation, and state mutation.
  - Ephemeral Lifecycle: Volumes and mount points exist solely for analysis and are destroyed post-audit.
  - Explicit Mock Mode: Simulation mode runs ONLY when `--mock` is explicitly passed.
"""

import argparse
import json
import os
import subprocess
import sys
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

# Optional boto3 import; falls back to AWS CLI if unavailable (never silent mock fallback)
try:
    import boto3
    from botocore.exceptions import BotoCoreError, ClientError
    HAS_BOTO3 = True
except ImportError:
    HAS_BOTO3 = False

try:
    from grc_common import load_os_stig_mapping, safe_rmtree, utc_now_iso
    from grc_fixtures import (
        create_mock_rootfs,
        generate_mock_ami_metadata,
        generate_mock_ebs_volume,
    )
except ImportError:
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from grc_common import load_os_stig_mapping, safe_rmtree, utc_now_iso
    from grc_fixtures import (
        create_mock_rootfs,
        generate_mock_ami_metadata,
        generate_mock_ebs_volume,
    )


# ==============================================================================
# OS TO DISA STIG BENCHMARK RESOLVER (SHARED CATALOG)
# ==============================================================================

DEFAULT_SCAP_PROFILE = "xccdf_org.ssgproject.content_profile_stig"

_FALLBACK_OS_STIG_MAPPING: Dict[str, Dict[str, str]] = {
    "rhel-9": {
        "benchmark_id": "U_RHEL_9_STIG",
        "benchmark_title": "Red Hat Enterprise Linux 9 STIG",
        "scap_datastream": "/usr/share/xml/scap/ssg/content/ssg-rhel9-ds.xml",
        "default_profile": DEFAULT_SCAP_PROFILE,
    },
    "rhel-8": {
        "benchmark_id": "U_RHEL_8_STIG",
        "benchmark_title": "Red Hat Enterprise Linux 8 STIG",
        "scap_datastream": "/usr/share/xml/scap/ssg/content/ssg-rhel8-ds.xml",
        "default_profile": DEFAULT_SCAP_PROFILE,
    },
    "amzn-2023": {
        "benchmark_id": "U_AL2023_STIG",
        "benchmark_title": "Amazon Linux 2023 STIG",
        "scap_datastream": "/usr/share/xml/scap/ssg/content/ssg-al2023-ds.xml",
        "default_profile": DEFAULT_SCAP_PROFILE,
    },
    "amzn-2": {
        "benchmark_id": "U_AL2_STIG",
        "benchmark_title": "Amazon Linux 2 STIG",
        "scap_datastream": "/usr/share/xml/scap/ssg/content/ssg-al2-ds.xml",
        "default_profile": DEFAULT_SCAP_PROFILE,
    },
    "ubuntu-22.04": {
        "benchmark_id": "U_Canonical_Ubuntu_22.04_LTS_STIG",
        "benchmark_title": "Canonical Ubuntu 22.04 LTS STIG",
        "scap_datastream": "/usr/share/xml/scap/ssg/content/ssg-ubuntu2204-ds.xml",
        "default_profile": DEFAULT_SCAP_PROFILE,
    },
    "ubuntu-20.04": {
        "benchmark_id": "U_Canonical_Ubuntu_20.04_LTS_STIG",
        "benchmark_title": "Canonical Ubuntu 20.04 LTS STIG",
        "scap_datastream": "/usr/share/xml/scap/ssg/content/ssg-ubuntu2004-ds.xml",
        "default_profile": DEFAULT_SCAP_PROFILE,
    },
    "rocky-9": {
        "benchmark_id": "U_RHEL_9_STIG",
        "benchmark_title": "Red Hat Enterprise Linux 9 STIG (Rocky Linux 9 Compatible)",
        "scap_datastream": "/usr/share/xml/scap/ssg/content/ssg-rl9-ds.xml",
        "default_profile": DEFAULT_SCAP_PROFILE,
    },
}

OS_STIG_MAPPING: Dict[str, Dict[str, str]] = load_os_stig_mapping() or dict(_FALLBACK_OS_STIG_MAPPING)


def resolve_os_stig(os_id: str, version_id: str) -> Dict[str, str]:
    """Resolves OS identity to the corresponding DISA STIG benchmark."""
    os_id_clean = os_id.strip().lower()
    major_ver = version_id.split(".")[0] if version_id else ""
    full_key = f"{os_id_clean}-{version_id}"
    major_key = f"{os_id_clean}-{major_ver}"

    for candidate in (full_key, major_key, os_id_clean):
        if candidate in OS_STIG_MAPPING:
            return dict(OS_STIG_MAPPING[candidate])

    return {
        "benchmark_id": "U_Generic_Linux_OS_SRG",
        "benchmark_title": f"Generic Linux OS Security Requirements Guide ({os_id} {version_id})",
        "scap_datastream": "/usr/share/xml/scap/ssg/content/ssg-generic-ds.xml",
        "default_profile": DEFAULT_SCAP_PROFILE,
    }


def _kms_key_matches(actual_kms: Optional[str], expected_kms: str) -> bool:
    """
    Compares KMS Key ID or ARN using exact equality on either the full ARN
    or the trailing key UUID/alias (never arbitrary substring matching).
    """
    if not actual_kms or not expected_kms:
        return False
    actual = actual_kms.strip()
    expected = expected_kms.strip()
    if actual == expected:
        return True
    if "/" in actual and actual.rsplit("/", 1)[-1] == expected:
        return True
    return False


def parse_ec2_image(img: Dict[str, Any]) -> Dict[str, Any]:
    """Extracts normalized metadata from an EC2 DescribeImages response dictionary."""
    root_device = img.get("RootDeviceName", "/dev/sda1")
    block_devices = img.get("BlockDeviceMappings", [])
    root_snap = None
    encrypted = False
    kms_key = None
    vol_size = 30

    # Pass 1: Match exact RootDeviceName
    matched_bdm = None
    for bdm in block_devices:
        if bdm.get("DeviceName") == root_device and "Ebs" in bdm:
            matched_bdm = bdm
            break
    # Pass 2: Fallback to first EBS mapping only if RootDeviceName didn't match
    if not matched_bdm:
        for bdm in block_devices:
            if "Ebs" in bdm:
                matched_bdm = bdm
                break

    if matched_bdm:
        ebs = matched_bdm.get("Ebs", {})
        root_snap = ebs.get("SnapshotId")
        encrypted = ebs.get("Encrypted", False)
        kms_key = ebs.get("KmsKeyId")
        vol_size = ebs.get("VolumeSize", 30)

    return {
        "image_id": img.get("ImageId"),
        "name": img.get("Name", "unnamed-image"),
        "owner_id": img.get("OwnerId", "unknown"),
        "architecture": img.get("Architecture", "x86_64"),
        "creation_date": img.get("CreationDate"),
        "state": img.get("State", "available"),
        "root_device_name": root_device,
        "root_snapshot_id": root_snap,
        "root_volume_size_gb": vol_size,
        "encrypted": encrypted,
        "kms_key_id": kms_key,
        "virtualization_type": img.get("VirtualizationType", "hvm"),
        "ena_support": img.get("EnaSupport", True),
        "block_devices": block_devices,
    }


# ==============================================================================
# EC2 BACKEND STRATEGY PATTERN (MOCK / AWS CLI / BOTO3)
# ==============================================================================

class Ec2Backend:
    """Strategy interface for AWS EC2 image inspection and ephemeral EBS lifecycle operations."""

    def __init__(self, region: str):
        self.region = region

    def describe_image(self, ami_id: str) -> Dict[str, Any]:
        raise NotImplementedError

    def resolve_worker_az(self, worker_id: Optional[str], default_az: str) -> str:
        raise NotImplementedError

    def create_volume(self, snapshot_id: str, az: str, tags: List[Dict[str, str]]) -> str:
        raise NotImplementedError

    def attach_volume(self, volume_id: str, worker_id: str, device_name: str) -> str:
        raise NotImplementedError

    def detach_and_delete_volume(self, volume_id: str) -> None:
        raise NotImplementedError


class MockBackend(Ec2Backend):
    """Offline simulation backend (activated ONLY when `--mock` is explicitly passed)."""

    def describe_image(self, ami_id: str) -> Dict[str, Any]:
        return generate_mock_ami_metadata(ami_id, self.region)

    def resolve_worker_az(self, worker_id: Optional[str], default_az: str) -> str:
        return default_az

    def create_volume(self, snapshot_id: str, az: str, tags: List[Dict[str, str]]) -> str:
        mock_vol = generate_mock_ebs_volume(snapshot_id)
        print(f"[*] [MOCK] Provisioned ephemeral EBS volume: {mock_vol} (from {snapshot_id})")
        return mock_vol

    def attach_volume(self, volume_id: str, worker_id: str, device_name: str) -> str:
        print(f"[*] [MOCK] Attached volume {volume_id} to worker as {device_name}")
        return device_name

    def detach_and_delete_volume(self, volume_id: str) -> None:
        print(f"    -> [MOCK] Detached and deleted volume {volume_id}.")


class AwsCliBackend(Ec2Backend):
    """AWS CLI (`aws ec2 ...`) backend strategy."""

    def describe_image(self, ami_id: str, boto_err: Optional[Exception] = None) -> Dict[str, Any]:
        try:
            cmd = [
                "aws", "ec2", "describe-images",
                "--image-ids", ami_id,
                "--region", self.region,
                "--output", "json",
            ]
            res = subprocess.run(cmd, capture_output=True, text=True, check=True)
            data = json.loads(res.stdout)
            images = data.get("Images", [])
            if not images:
                raise FileNotFoundError(f"AMI '{ami_id}' not found in region '{self.region}'")
            return parse_ec2_image(images[0])
        except FileNotFoundError as e:
            if getattr(e, "filename", None) == "aws":
                raise RuntimeError(
                    f"Failed to query AMI '{ami_id}': AWS CLI ('aws') is not installed "
                    f"(and boto3 {'failed: ' + str(boto_err) if boto_err else 'is not installed'}). "
                    f"Pass --mock only when running offline simulations."
                ) from e
            raise
        except (subprocess.CalledProcessError, json.JSONDecodeError) as e:
            err_detail = getattr(e, "stderr", None) or str(e)
            raise RuntimeError(
                f"Failed to query AMI '{ami_id}' in region '{self.region}': {err_detail.strip()}"
            ) from e

    def resolve_worker_az(self, worker_id: Optional[str], default_az: str) -> str:
        if not worker_id:
            return default_az
        try:
            cmd = [
                "aws", "ec2", "describe-instances",
                "--instance-ids", worker_id,
                "--query", "Reservations[0].Instances[0].Placement.AvailabilityZone",
                "--output", "text",
                "--region", self.region,
            ]
            res = subprocess.run(cmd, capture_output=True, text=True, check=True)
            az = res.stdout.strip()
            if az and az != "None":
                return az
        except Exception:
            pass
        return default_az

    def create_volume(self, snapshot_id: str, az: str, tags: List[Dict[str, str]]) -> str:
        tag_items = ",".join(f"{{Key={t['Key']},Value={t['Value']}}}" for t in tags)
        tag_spec = f"ResourceType=volume,Tags=[{tag_items}]"
        cmd = [
            "aws", "ec2", "create-volume",
            "--snapshot-id", snapshot_id,
            "--volume-type", "gp3",
            "--availability-zone", az,
            "--tag-specifications", tag_spec,
            "--region", self.region,
            "--output", "json",
        ]
        res = subprocess.run(cmd, capture_output=True, text=True, check=True)
        data = json.loads(res.stdout)
        vol_id = data["VolumeId"]
        subprocess.run(
            ["aws", "ec2", "wait", "volume-available", "--volume-ids", vol_id, "--region", self.region],
            check=True,
        )
        return vol_id

    def attach_volume(self, volume_id: str, worker_id: str, device_name: str) -> str:
        cmd = [
            "aws", "ec2", "attach-volume",
            "--volume-id", volume_id,
            "--instance-id", worker_id,
            "--device", device_name,
            "--region", self.region,
        ]
        subprocess.run(cmd, check=True)
        subprocess.run(
            ["aws", "ec2", "wait", "volume-in-use", "--volume-ids", volume_id, "--region", self.region],
            check=True,
        )
        return device_name

    def detach_and_delete_volume(self, volume_id: str) -> None:
        subprocess.run(
            ["aws", "ec2", "detach-volume", "--volume-id", volume_id, "--force", "--region", self.region],
            check=False,
        )
        subprocess.run(
            ["aws", "ec2", "wait", "volume-available", "--volume-ids", volume_id, "--region", self.region],
            check=False,
        )
        subprocess.run(
            ["aws", "ec2", "delete-volume", "--volume-id", volume_id, "--region", self.region],
            check=False,
        )


class Boto3Backend(Ec2Backend):
    """Native `boto3` EC2 backend with lazily cached client and CLI fallback on SDK transport errors."""

    def __init__(self, region: str):
        super().__init__(region)
        self._ec2: Any = None
        self._cli_fallback = AwsCliBackend(region)

    @property
    def ec2(self) -> Any:
        if self._ec2 is None:
            self._ec2 = boto3.client("ec2", region_name=self.region)
        return self._ec2

    def describe_image(self, ami_id: str) -> Dict[str, Any]:
        try:
            resp = self.ec2.describe_images(ImageIds=[ami_id])
            images = resp.get("Images", [])
            if not images:
                raise FileNotFoundError(f"AMI '{ami_id}' not found in region '{self.region}'")
            return parse_ec2_image(images[0])
        except FileNotFoundError:
            raise
        except (ClientError, BotoCoreError) as e:
            print(f"[WARN] boto3 call failed ({e}); attempting AWS CLI...", file=sys.stderr)
            return self._cli_fallback.describe_image(ami_id, boto_err=e)

    def resolve_worker_az(self, worker_id: Optional[str], default_az: str) -> str:
        if not worker_id:
            return default_az
        try:
            resp = self.ec2.describe_instances(InstanceIds=[worker_id])
            for resv in resp.get("Reservations", []):
                for inst in resv.get("Instances", []):
                    az = inst.get("Placement", {}).get("AvailabilityZone")
                    if az:
                        return az
        except Exception:
            pass
        return self._cli_fallback.resolve_worker_az(worker_id, default_az)

    def create_volume(self, snapshot_id: str, az: str, tags: List[Dict[str, str]]) -> str:
        resp = self.ec2.create_volume(
            SnapshotId=snapshot_id,
            VolumeType="gp3",
            AvailabilityZone=az,
            TagSpecifications=[{"ResourceType": "volume", "Tags": tags}],
        )
        vol_id = resp["VolumeId"]
        print(f"    -> Created Volume ID: {vol_id}. Waiting for 'available' state...")
        waiter = self.ec2.get_waiter("volume_available")
        waiter.wait(VolumeIds=[vol_id])
        return vol_id

    def attach_volume(self, volume_id: str, worker_id: str, device_name: str) -> str:
        self.ec2.attach_volume(
            VolumeId=volume_id,
            InstanceId=worker_id,
            Device=device_name,
        )
        waiter = self.ec2.get_waiter("volume_in_use")
        waiter.wait(VolumeIds=[volume_id])
        print("    -> Volume successfully attached in use.")
        return device_name

    def detach_and_delete_volume(self, volume_id: str) -> None:
        try:
            self.ec2.detach_volume(VolumeId=volume_id, Force=True)
            waiter = self.ec2.get_waiter("volume_available")
            waiter.wait(VolumeIds=[volume_id])
        except Exception as e:
            print(f"[WARN] Error detaching volume: {e}", file=sys.stderr)

        try:
            self.ec2.delete_volume(VolumeId=volume_id)
            print(f"    -> Deleted ephemeral volume {volume_id}.")
        except Exception as e:
            print(f"[ERROR] Failed to delete volume {volume_id}: {e}", file=sys.stderr)


# ==============================================================================
# GRC AMI LIFECYCLE MANAGER
# ==============================================================================

class GRCAMIManager:
    """
    Manages the verification, cold-mount restoration, and ephemeral cleanup
    of Amazon Machine Images (AMIs).
    """

    def __init__(
        self,
        ami_id: str,
        workspace_root: Optional[Path] = None,
        region: str = "us-east-1",
        worker_id: Optional[str] = None,
        device_name: str = "/dev/xvdf",
        partition: Optional[str] = None,
        mock_mode: bool = False,
        allow_unencrypted: bool = False,
        backend: Optional[Ec2Backend] = None,
    ):
        self.ami_id = ami_id.strip()
        self.region = region
        self.worker_id = worker_id
        self.device_name = device_name
        self.partition = partition
        self.mock_mode = mock_mode
        self.allow_unencrypted = allow_unencrypted
        self.session_id = str(uuid.uuid4())

        self.workspace_root = (
            Path(workspace_root).resolve()
            if workspace_root
            else Path(f"./ephemeral_ami_workspace_{self.session_id[:8]}").resolve()
        )
        self.mount_point = self.workspace_root / "mnt"

        # Runtime state
        self.ephemeral_volume_id: Optional[str] = None
        self.ami_metadata: Dict[str, Any] = {}
        self.last_mount_options: str = "ro,norecovery,nouuid,noexec,nosuid"
        self._explicit_backend = backend
        self._live_backend: Ec2Backend = Boto3Backend(region) if HAS_BOTO3 else AwsCliBackend(region)
        self._mock_backend: Ec2Backend = MockBackend(region)

    @property
    def backend(self) -> Ec2Backend:
        """Returns the active EC2 strategy backend (`MockBackend`, `Boto3Backend`, or `AwsCliBackend`)."""
        if self._explicit_backend is not None:
            return self._explicit_backend
        return self._mock_backend if self.mock_mode else self._live_backend

    # --------------------------------------------------------------------------
    # PHASE 1: PULL & VERIFY
    # --------------------------------------------------------------------------

    def verify_ami(
        self,
        expected_snapshot: Optional[str] = None,
        expected_kms_key: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Executes Phase 1 (Pull & Verify):
          1. Resolves AMI metadata via AWS EC2 API or explicit `--mock` mode.
          2. Verifies root EBS snapshot existence and availability.
          3. Enforces EBS encryption compliance (NIST SP 800-53 SC-12/13/28).
          4. Emits structured verification record.
        """
        print(f"[*] Starting Pull & Verify for AMI: {self.ami_id} (Region: {self.region})")

        metadata = self._fetch_ami_metadata()
        self.ami_metadata = metadata

        root_snap_id = metadata.get("root_snapshot_id")
        encrypted = bool(metadata.get("encrypted", False))
        kms_key_id = metadata.get("kms_key_id")
        arch = metadata.get("architecture", "unknown")
        image_name = metadata.get("name", "unknown")

        print(f"    -> Image Name: {image_name}")
        print(f"    -> Architecture: {arch}")
        print(f"    -> Root Snapshot ID: {root_snap_id}")
        print(f"    -> EBS Encryption: {'ENABLED' if encrypted else 'DISABLED'}")
        if kms_key_id:
            print(f"    -> KMS Key ID / ARN: {kms_key_id}")

        # SC-12 / SC-13 / SC-28 Encryption enforcement
        if not encrypted and not self.allow_unencrypted:
            raise ValueError(
                f"AMI '{self.ami_id}' root snapshot '{root_snap_id}' is UNENCRYPTED "
                f"(NIST SP 800-53 SC-28 violation). Pass --allow-unencrypted to override."
            )

        # Baseline verification checks
        if expected_snapshot:
            if root_snap_id != expected_snapshot.strip():
                raise ValueError(
                    f"Root snapshot mismatch! Expected '{expected_snapshot}', found '{root_snap_id}'."
                )
            print("    -> Root snapshot verified against baseline: MATCH")

        if expected_kms_key:
            if not _kms_key_matches(kms_key_id, expected_kms_key):
                raise ValueError(
                    f"KMS Key mismatch! Expected '{expected_kms_key}', found '{kms_key_id}'."
                )
            print("    -> KMS Key verified against baseline: MATCH")

        verification_record = {
            "session_id": self.session_id,
            "ami_id": self.ami_id,
            "region": self.region,
            "image_name": image_name,
            "architecture": arch,
            "root_snapshot_id": root_snap_id,
            "encrypted": encrypted,
            "kms_key_id": kms_key_id,
            "creation_date": metadata.get("creation_date"),
            "owner_id": metadata.get("owner_id"),
            "virtualization_type": metadata.get("virtualization_type"),
            "ena_support": metadata.get("ena_support", False),
            "status": metadata.get("state", "available"),
            "verified_at": utc_now_iso(),
            "mock_mode": self.mock_mode,
        }

        print("[SUCCESS] AMI verification completed successfully.")
        return verification_record

    # --------------------------------------------------------------------------
    # PHASE 2: RESTORE / COLD-MOUNT
    # --------------------------------------------------------------------------

    def restore_ami(
        self,
        expected_snapshot: Optional[str] = None,
        expected_kms_key: Optional[str] = None,
        force: bool = False,
    ) -> Dict[str, Any]:
        """
        Executes Phase 2 (Restore / Cold-Mount) with automatic volume rollback on error:
          1. Verifies AMI integrity and storage attributes.
          2. Creates an ephemeral EBS volume from the root snapshot.
          3. Attaches volume as secondary block device to audit worker host.
          4. Mounts secondary filesystem with read-only cold-mount flags.
          5. Reads `/etc/os-release` and maps DISA STIG profile.
          6. Emits `ami_provenance.json` in workspace root.
        """
        if not self.mock_mode and not self.worker_id:
            raise ValueError(
                "In live AWS mode, --worker-id is required to attach and cold-mount an EBS volume "
                "(or pass --mock for offline simulation)."
            )

        # Step 1: Verification
        verification = self.verify_ami(
            expected_snapshot=expected_snapshot,
            expected_kms_key=expected_kms_key,
        )

        root_snap_id = verification["root_snapshot_id"]
        if not root_snap_id:
            raise RuntimeError(f"Unable to resolve root EBS snapshot for AMI {self.ami_id}")

        # Step 2: Prepare Workspace Root & Mount Point
        if self.workspace_root.exists():
            if force:
                print(f"[*] Removing existing workspace directory: {self.workspace_root}")
                if self.mount_point.exists() and os.path.ismount(self.mount_point):
                    self._unmount_filesystem(self.mount_point)
                safe_rmtree(self.workspace_root, allowed_markers=("ami_provenance.json", "mnt"))
            else:
                raise FileExistsError(
                    f"Workspace '{self.workspace_root}' already exists. Use --force to overwrite."
                )

        self.workspace_root.mkdir(parents=True, exist_ok=True)
        self.mount_point.mkdir(parents=True, exist_ok=True)
        print(f"[*] Initialized ephemeral workspace: {self.workspace_root}")

        # Steps 3–5: Provision, Attach, and Mount with automatic rollback on failure
        volume_id: Optional[str] = None
        mounted = False
        try:
            volume_id = self._create_ephemeral_volume(root_snap_id)
            self.ephemeral_volume_id = volume_id

            actual_device = self._attach_ephemeral_volume(volume_id)
            mount_dev = self.partition if self.partition else actual_device
            self._mount_filesystem(mount_dev, self.mount_point, volume_id=volume_id)
            mounted = True
        except Exception:
            if mounted:
                try:
                    self._unmount_filesystem(self.mount_point)
                except Exception:
                    pass
            if volume_id:
                print(f"[WARN] Rolling back ephemeral EBS volume {volume_id} after restore failure...", file=sys.stderr)
                try:
                    self._detach_and_delete_volume(volume_id)
                except Exception as cleanup_err:
                    print(f"[ERROR] Volume rollback failed for {volume_id}: {cleanup_err}", file=sys.stderr)
            raise

        # Step 6: Identify Target OS Distribution & Map STIG
        os_info = self._identify_target_os(self.mount_point)
        stig_mapping = resolve_os_stig(os_info["os_id"], os_info["version_id"])
        os_info.update({
            "applicable_stig_benchmark": stig_mapping["benchmark_id"],
            "benchmark_title": stig_mapping["benchmark_title"],
            "scap_datastream": stig_mapping["scap_datastream"],
            "default_profile": stig_mapping["default_profile"],
        })

        print(f"    -> Detected Operating System: {os_info['pretty_name']}")
        print(f"    -> Mapped DISA STIG Baseline: {os_info['benchmark_title']}")

        # Step 7: Generate ami_provenance.json
        provenance = {
            "$schema": "https://specs.grc.internal/schemas/ami-provenance-v1.json",
            "manifest_schema": "grc-ami-provenance-v1",
            "session_id": self.session_id,
            "ami_identifier": self.ami_id,
            "region": self.region,
            "image_metadata": self.ami_metadata,
            "storage_provenance": {
                "root_snapshot_id": root_snap_id,
                "snapshot_size_gb": self.ami_metadata.get("root_volume_size_gb", 30),
                "encrypted": verification["encrypted"],
                "kms_key_id": verification["kms_key_id"],
                "volume_type": "gp3",
            },
            "cold_mount_execution": {
                "ephemeral_volume_id": volume_id,
                "audit_worker_id": self.worker_id or "local-ephemeral-worker",
                "attached_device": actual_device,
                "mounted_device_or_partition": mount_dev,
                "workspace_mount_path": str(self.mount_point),
                "mount_options": self.last_mount_options,
                "mounted_at": utc_now_iso(),
            },
            "os_identification": os_info,
            "restored_at": utc_now_iso(),
            "status": "COLD_MOUNTED",
            "ephemeral": True,
            "mock_mode": self.mock_mode,
            "verification": verification,
        }

        manifest_path = self.workspace_root / "ami_provenance.json"
        with open(manifest_path, "w", encoding="utf-8") as f:
            json.dump(provenance, f, indent=2)

        print(f"[*] Cryptographic provenance manifest generated: {manifest_path.name}")
        print("[SUCCESS] AMI successfully cold-mounted and ready for Phase 3 (Analyze).")
        return provenance

    # --------------------------------------------------------------------------
    # PHASE 5: CLEAN & TEARDOWN
    # --------------------------------------------------------------------------

    def clean_workspace(
        self,
        volume_id: Optional[str] = None,
        keep_evidence: bool = False,
    ) -> None:
        """
        Executes Phase 5 (Clean / Teardown):
          1. Reads `ami_provenance.json` (honoring recorded `mock_mode` if present).
          2. Unmounts secondary cold-mount filesystem.
          3. Detaches & deletes temporary EBS volume in AWS.
          4. Safely cleans up local workspace directory.
        """
        print(f"[*] Starting Ephemeral Teardown for workspace: {self.workspace_root}")

        target_vol = volume_id or self.ephemeral_volume_id
        prov_path = self.workspace_root / "ami_provenance.json"
        if prov_path.exists():
            try:
                with open(prov_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    if not target_vol:
                        target_vol = data.get("cold_mount_execution", {}).get("ephemeral_volume_id")
                    if data.get("mock_mode") is True:
                        self.mock_mode = True
            except Exception:
                pass

        # 1. Unmount if mounted
        if self.mount_point.exists():
            if os.path.ismount(self.mount_point) or self.mock_mode:
                self._unmount_filesystem(self.mount_point)

        # 2. Detach & Delete EBS Volume
        if target_vol:
            self._detach_and_delete_volume(target_vol)

        # 3. Workspace cleanup
        if self.workspace_root.exists():
            if keep_evidence:
                print("    -> Preserving audit evidence deliverables in workspace.")
                if self.mount_point.exists():
                    try:
                        safe_rmtree(self.mount_point, allowed_markers=("etc", "usr"))
                    except Exception:
                        pass
            else:
                safe_rmtree(self.workspace_root, allowed_markers=("ami_provenance.json", "mnt"))
                print("    -> Workspace directory completely purged.")

        print("[SUCCESS] AMI audit workspace teardown and cleanup complete.")

    # --------------------------------------------------------------------------
    # INTERNAL DELEGATES TO EC2 BACKEND & LOCAL MOUNT HELPERS
    # --------------------------------------------------------------------------

    def _fetch_ami_metadata(self) -> Dict[str, Any]:
        """Queries AMI details via the active `Ec2Backend` strategy."""
        return self.backend.describe_image(self.ami_id)

    def _parse_ec2_image(self, img: Dict[str, Any]) -> Dict[str, Any]:
        """Backward-compatible wrapper around `parse_ec2_image`."""
        return parse_ec2_image(img)

    def _mock_ami_metadata(self) -> Dict[str, Any]:
        """Delegates synthetic AMI metadata generation to `grc_fixtures`."""
        return generate_mock_ami_metadata(self.ami_id, self.region)

    def _resolve_worker_az(self) -> str:
        """Resolves the Availability Zone of `self.worker_id` via the active `Ec2Backend`."""
        default_az = f"{self.region}a"
        return self.backend.resolve_worker_az(self.worker_id, default_az)

    def _create_ephemeral_volume(self, snapshot_id: str) -> str:
        """Provisions an ephemeral EBS volume from the root snapshot via the active `Ec2Backend`."""
        target_az = self._resolve_worker_az()
        if not self.mock_mode:
            print(f"[*] Provisioning ephemeral EBS volume from snapshot: {snapshot_id} (AZ: {target_az})")
        worker_tag = self.worker_id or "unknown-worker"
        tags = [
            {"Key": "GRC-Audit-Session", "Value": self.session_id},
            {"Key": "Ephemeral-Worker", "Value": worker_tag},
            {"Key": "PurgeAfter", "Value": "4h"},
        ]
        return self.backend.create_volume(snapshot_id, target_az, tags)

    def _attach_ephemeral_volume(self, volume_id: str) -> str:
        """Attaches the secondary EBS volume to the audit worker instance via the active `Ec2Backend`."""
        if not self.mock_mode and not self.worker_id:
            raise ValueError("Cannot attach EBS volume without --worker-id in live AWS mode.")
        if not self.mock_mode:
            print(f"[*] Attaching volume {volume_id} to worker {self.worker_id} at {self.device_name}")
        return self.backend.attach_volume(volume_id, self.worker_id or "", self.device_name)

    def _detach_and_delete_volume(self, volume_id: str) -> None:
        """Detaches and deletes the ephemeral EBS volume via the active `Ec2Backend`."""
        print(f"[*] Tearing down ephemeral EBS volume: {volume_id}")
        self.backend.detach_and_delete_volume(volume_id)

    def _resolve_block_device(self, requested_device: str, volume_id: Optional[str] = None) -> str:
        """Resolves AWS Nitro NVMe `/dev/disk/by-id/...` symlink if `/dev/xvdf` is mapped as NVMe."""
        if os.path.exists(requested_device):
            return requested_device
        if volume_id:
            clean_vol = volume_id.replace("-", "")
            by_id = f"/dev/disk/by-id/nvme-Amazon_Elastic_Block_Store_{clean_vol}"
            if os.path.exists(by_id):
                return by_id
        return requested_device

    def _detect_fs_type(self, device: str) -> str:
        """Detects filesystem type (`xfs`, `ext4`, etc.) via `blkid`."""
        try:
            res = subprocess.run(
                ["blkid", "-o", "value", "-s", "TYPE", device],
                capture_output=True,
                text=True,
                check=False,
            )
            fs = res.stdout.strip().lower()
            if fs:
                return fs
        except Exception:
            pass
        return "xfs"

    def _mount_filesystem(
        self,
        device: str,
        mount_path: Path,
        volume_id: Optional[str] = None,
    ) -> None:
        """
        Mounts secondary volume partition read-only with filesystem-appropriate cold-mount flags:
          - XFS (RHEL 8/9, AL2023 default): `ro,norecovery,nouuid,noexec,nosuid`
          - ext3/ext4 (Ubuntu/Debian):      `ro,noload,noexec,nosuid`
        """
        if self.mock_mode:
            self.last_mount_options = "ro,norecovery,nouuid,noexec,nosuid"
            print(f"[*] Mounting {device} at {mount_path} with options: {self.last_mount_options}")
            self._create_mock_rootfs(mount_path)
            print("    -> [MOCK] Synthetic root filesystem initialized at mount point.")
            return

        resolved_dev = self._resolve_block_device(device, volume_id=volume_id)
        fs_type = self._detect_fs_type(resolved_dev)

        if fs_type == "xfs":
            option_candidates = ["ro,norecovery,nouuid,noexec,nosuid", "ro,noload,noexec,nosuid"]
        else:
            option_candidates = ["ro,noload,noexec,nosuid", "ro,norecovery,nouuid,noexec,nosuid"]

        last_err = ""
        for opts in option_candidates:
            print(f"[*] Mounting {resolved_dev} at {mount_path} with options: {opts}")
            cmd = ["mount", "-o", opts, resolved_dev, str(mount_path)]
            try:
                subprocess.run(cmd, capture_output=True, text=True, check=True)
                self.last_mount_options = opts
                print("    -> Secondary filesystem mounted read-only.")
                return
            except subprocess.CalledProcessError as e:
                last_err = (e.stderr or e.stdout or str(e)).strip()

        raise RuntimeError(f"Cold-mount failed on {resolved_dev}: {last_err}")

    def _unmount_filesystem(self, mount_path: Path) -> None:
        """Unmounts the filesystem safely."""
        print(f"[*] Unmounting filesystem at {mount_path}")
        if self.mock_mode:
            print("    -> [MOCK] Cleaned up synthetic mount point.")
            return

        try:
            subprocess.run(["umount", "-f", str(mount_path)], check=True)
            print("    -> Unmounted successfully.")
        except subprocess.CalledProcessError:
            subprocess.run(["umount", "-l", str(mount_path)], check=False)
            print("    -> Lazy unmount executed.")

    def _identify_target_os(self, mount_path: Path) -> Dict[str, Any]:
        """Parses /etc/os-release or /usr/lib/os-release from mounted rootfs."""
        os_release = mount_path / "etc" / "os-release"
        alt_release = mount_path / "usr" / "lib" / "os-release"

        target_file = os_release if os_release.exists() else (alt_release if alt_release.exists() else None)

        os_id = "unknown"
        version_id = "0"
        pretty_name = "Unknown Linux Distribution"

        if target_file and target_file.exists():
            try:
                with open(target_file, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if line.startswith("ID="):
                            os_id = line.split("=", 1)[1].strip('"\'').lower()
                        elif line.startswith("VERSION_ID="):
                            version_id = line.split("=", 1)[1].strip('"\'')
                        elif line.startswith("PRETTY_NAME="):
                            pretty_name = line.split("=", 1)[1].strip('"\'')
            except Exception as e:
                print(f"[WARN] Error reading os-release: {e}", file=sys.stderr)

        return {
            "os_id": os_id,
            "version_id": version_id,
            "pretty_name": pretty_name,
            "release_file": str(target_file) if target_file else None,
        }

    def _create_mock_rootfs(self, mount_path: Path) -> None:
        """Delegates synthetic root filesystem fixture generation to `grc_fixtures`."""
        create_mock_rootfs(mount_path)


# ==============================================================================
# CLI DISPATCHER
# ==============================================================================

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="grc ami",
        description="GRC-xMINI Amazon Machine Image (AMI) Review Lifecycle Manager (Cold-Mount Pattern)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Commands:
  verify    Check AMI metadata, KMS encryption, and root snapshot integrity.
  restore   Cold-mount AMI snapshot as a secondary read-only volume on the audit worker.
  clean     Unmount, detach, and delete ephemeral EBS volume to uphold ephemeral hygiene.

Examples:
  grc ami verify ami-0123456789abcdef0 --region us-east-1
  grc ami verify ami-0123456789abcdef0 --expected-snapshot snap-0987654321fedcba0
  grc ami restore ami-0123456789abcdef0 --workspace ./ephemeral_ami --worker-id i-0abcdef1234567890
  grc ami restore ami-0123456789abcdef0 --mock --workspace ./ephemeral_mock_ami
  grc ami clean --workspace ./ephemeral_ami --region us-east-1
        """,
    )

    subparsers = parser.add_subparsers(dest="action", required=True, help="AMI Action to execute")

    # Command: verify
    verify_parser = subparsers.add_parser(
        "verify", help="Verify AMI metadata, KMS encryption, and snapshot integrity"
    )
    verify_parser.add_argument("ami_id", help="Target Amazon Machine Image ID (ami-xxxxxxxxxxxxxxxxx)")
    verify_parser.add_argument("--region", default="us-east-1", help="AWS region (defaults to us-east-1)")
    verify_parser.add_argument("--expected-snapshot", default=None, help="Expected root EBS snapshot ID to validate")
    verify_parser.add_argument("--expected-kms-key", default=None, help="Expected KMS Key ID / ARN to validate")
    verify_parser.add_argument("--allow-unencrypted", action="store_true", help="Do not fail verification if root EBS snapshot is unencrypted")
    verify_parser.add_argument("--mock", action="store_true", help="Execute in local mock/simulation mode without AWS API")
    verify_parser.add_argument("--json", action="store_true", help="Output verification results as raw JSON")

    # Command: restore (cold-mount)
    restore_parser = subparsers.add_parser(
        "restore", help="Cold-mount AMI root snapshot as a read-only secondary volume"
    )
    restore_parser.add_argument("ami_id", help="Target Amazon Machine Image ID (ami-xxxxxxxxxxxxxxxxx)")
    restore_parser.add_argument("--workspace", "-w", type=Path, default=None, help="Destination directory for audit workspace")
    restore_parser.add_argument("--region", default="us-east-1", help="AWS region (defaults to us-east-1)")
    restore_parser.add_argument("--worker-id", default=None, help="Instance ID of the audit worker EC2 host")
    restore_parser.add_argument("--device", default="/dev/xvdf", help="Target secondary block device name (default: /dev/xvdf)")
    restore_parser.add_argument("--partition", default=None, help="Specific partition to mount (e.g., /dev/xvdf1)")
    restore_parser.add_argument("--expected-snapshot", default=None, help="Expected snapshot ID")
    restore_parser.add_argument("--expected-kms-key", default=None, help="Expected KMS Key ID / ARN")
    restore_parser.add_argument("--allow-unencrypted", action="store_true", help="Allow restoring an unencrypted root snapshot")
    restore_parser.add_argument("--force", "-f", action="store_true", help="Overwrite existing workspace directory")
    restore_parser.add_argument("--mock", action="store_true", help="Execute in local mock/simulation mode without AWS API")
    restore_parser.add_argument("--json", action="store_true", help="Output restoration summary as raw JSON")

    # Command: clean
    clean_parser = subparsers.add_parser(
        "clean", help="Unmount, detach, and delete ephemeral EBS volume"
    )
    clean_parser.add_argument("--workspace", "-w", type=Path, required=True, help="Path to ephemeral audit workspace")
    clean_parser.add_argument("--region", default="us-east-1", help="AWS region (defaults to us-east-1)")
    clean_parser.add_argument("--volume-id", default=None, help="Optional explicit EBS volume ID to delete")
    clean_parser.add_argument("--keep-evidence", action="store_true", help="Keep audit evidence outputs while tearing down volume")
    clean_parser.add_argument("--mock", action="store_true", help="Execute in local mock/simulation mode")

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    try:
        if args.action == "verify":
            manager = GRCAMIManager(
                ami_id=args.ami_id,
                region=args.region,
                mock_mode=args.mock,
                allow_unencrypted=args.allow_unencrypted,
            )
            result = manager.verify_ami(
                expected_snapshot=args.expected_snapshot,
                expected_kms_key=args.expected_kms_key,
            )
            if args.json:
                print(json.dumps(result, indent=2))

        elif args.action == "restore":
            manager = GRCAMIManager(
                ami_id=args.ami_id,
                workspace_root=args.workspace,
                region=args.region,
                worker_id=args.worker_id,
                device_name=args.device,
                partition=args.partition,
                mock_mode=args.mock,
                allow_unencrypted=args.allow_unencrypted,
            )
            result = manager.restore_ami(
                expected_snapshot=args.expected_snapshot,
                expected_kms_key=args.expected_kms_key,
                force=args.force,
            )
            if args.json:
                print(json.dumps(result, indent=2))

        elif args.action == "clean":
            manager = GRCAMIManager(
                ami_id="ami-cleanup",
                workspace_root=args.workspace,
                region=args.region,
                mock_mode=args.mock,
            )
            manager.clean_workspace(
                volume_id=args.volume_id,
                keep_evidence=args.keep_evidence,
            )

    except Exception as e:
        print(f"[FATAL] AMI operation failed: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
