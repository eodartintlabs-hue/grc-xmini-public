#!/usr/bin/env python3
"""
grc_bundle.py - GRC Bundle Verification, Restoration, and Workspace Ingestion Engine
=====================================================================================

Classification: Internal Compliance & Engineering Specification
Pipeline Role: Phase 1 (Pull & Verify) & Phase 2 (Restore) Core Orchestrator
Target Frameworks: NIST SP 800-53 (SI-7, CM-6, SC-12), FedRAMP, DISA STIG

Purpose:
  Provides the operational CLI implementation for GRC-xMINI ("The GRC eXperience"):
    - Verifies cryptographic integrity (SHA-256) of incoming release bundles.
    - Validates bundle structure via `git bundle verify`.
    - Restores and unpacks the Git bundle into an isolated, ephemeral workspace.
    - Generates cryptographic provenance manifests (Bundle Identifier, commit hash, tree hash).
    - Prepares the workspace for Phase 3 (Analyze) containerized security scanning.
    - Provides safe workspace teardown to uphold ephemeral hygiene rules.

Design Rule Adherence:
  - Out-of-Band (OOB): Operates on exported bundles without gating main deployment pipelines.
  - Ephemeral Lifecycle: Workspaces are created on-demand and wiped after evidence generation.
  - Read-Only Ingestion: Preserves immutable integrity of audit inputs.
"""

import argparse
import json
import os
import re
import subprocess
import sys
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    from grc_common import safe_rmtree, sha256_file, utc_now_iso
except ImportError:
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from grc_common import safe_rmtree, sha256_file, utc_now_iso

_HEX_HASH_RE = re.compile(r"^[0-9a-fA-F]{40}([0-9a-fA-F]{24})?$")


# ==============================================================================
# CRYPTOGRAPHIC INTEGRITY & WORKSPACE CLEANUP UTILITIES
# ==============================================================================

def compute_sha256(file_path: Path, block_size: int = 65536) -> str:
    """Computes the hex-encoded SHA-256 checksum of a file in chunks."""
    return sha256_file(file_path, block_size=block_size)


def clean_ephemeral_workspace(
    workspace_root: Path,
    bundle_path: Optional[Path] = None,
    remove_bundle: bool = False,
) -> None:
    """
    Executes guarded workspace teardown without requiring an existing bundle instance:
      1. Verifies the target workspace is not a protected system/repo path and contains
         an ephemeral marker (`bundle_provenance.json` or `.git`) before removal.
      2. Optionally deletes the processed bundle file if `remove_bundle=True` and the
         bundle file exists (refusing to delete `.py` scripts).
    """
    ws_resolved = Path(workspace_root).resolve()
    if ws_resolved.exists():
        print(f"[*] Destroying ephemeral workspace: {ws_resolved}")
        safe_rmtree(ws_resolved, allowed_markers=("bundle_provenance.json", ".git"))
        print("    -> Workspace directory deleted.")

    if remove_bundle and bundle_path is not None:
        b_resolved = Path(bundle_path).resolve()
        if b_resolved == Path(__file__).resolve() or b_resolved.suffix == ".py":
            raise ValueError(f"Refusing to delete Python script as bundle: {b_resolved}")
        if b_resolved.exists():
            print(f"[*] Deleting processed bundle: {b_resolved}")
            b_resolved.unlink()
            print("    -> Bundle file deleted.")
        else:
            print(f"[WARN] Bundle file slated for deletion does not exist: {b_resolved}", file=sys.stderr)

    print("[SUCCESS] Ephemeral cleanup complete.")


# ==============================================================================
# GIT BUNDLE RESTORATION & VERIFICATION ENGINE
# ==============================================================================

class GRCBundleManager:
    """Manages the verification, extraction, and provenance recording of Git bundles."""

    def __init__(self, bundle_path: Path, workspace_root: Optional[Path] = None):
        self.bundle_path = Path(bundle_path).resolve()
        if not self.bundle_path.exists():
            raise FileNotFoundError(f"Target bundle file does not exist: {self.bundle_path}")

        self.workspace_root = (
            Path(workspace_root).resolve()
            if workspace_root
            else self.bundle_path.parent / "ephemeral_workspace"
        )
        self.session_id = str(uuid.uuid4())
        self.bundle_sha256 = ""

    def verify_bundle(self, expected_sha256: Optional[str] = None) -> Dict[str, Any]:
        """
        Executes Phase 1 (Pull & Verify):
          1. Calculates and records SHA-256 checksum.
          2. Compares against expected checksum if supplied.
          3. Executes `git bundle verify` to inspect Git object integrity.
        """
        print(f"[*] Starting Pull & Verify for bundle: {self.bundle_path.name}")
        self.bundle_sha256 = compute_sha256(self.bundle_path)
        print(f"    -> SHA-256 Digest: {self.bundle_sha256}")

        checksum_verified = True
        if expected_sha256:
            expected_clean = expected_sha256.strip().lower()
            if self.bundle_sha256.lower() != expected_clean:
                checksum_verified = False
                raise ValueError(
                    f"Bundle cryptographic integrity verification failed: "
                    f"expected {expected_clean}, computed {self.bundle_sha256}"
                )
            print("    -> Cryptographic checksum verified against session baseline: MATCH")

        # Execute git bundle verify
        try:
            result = subprocess.run(
                ["git", "bundle", "verify", str(self.bundle_path)],
                capture_output=True,
                text=True,
                check=True,
            )
            raw_verify_output = f"{result.stdout or ''}\n{result.stderr or ''}".strip()
            print("    -> Git bundle object verification: VALID")
        except subprocess.CalledProcessError as e:
            err_msg = (e.stderr or e.stdout or str(e)).strip()
            raise RuntimeError(f"Git bundle verification failed: {err_msg}")

        # Parse available references from verification output
        refs = self._parse_bundle_refs(raw_verify_output)

        return {
            "session_id": self.session_id,
            "bundle_file": str(self.bundle_path),
            "bundle_size_bytes": self.bundle_path.stat().st_size,
            "bundle_sha256": self.bundle_sha256,
            "checksum_verified": checksum_verified,
            "git_bundle_valid": True,
            "contained_references": refs,
            "verified_at": utc_now_iso(),
        }

    def restore_bundle(
        self,
        target_ref: Optional[str] = None,
        expected_sha256: Optional[str] = None,
        force: bool = False,
        read_only: bool = False,
    ) -> Dict[str, Any]:
        """
        Executes Phase 2 (Restore):
          1. Verifies bundle integrity.
          2. Prepares isolated ephemeral workspace directory.
          3. Clones the Git repository from the bundle file.
          4. Checks out the designated tag or branch.
          5. Captures commit provenance and creates `bundle_provenance.json`.
        """
        if target_ref and target_ref.strip().startswith("-"):
            raise ValueError(f"Invalid target git reference (must not start with '-'): {target_ref}")

        # Step 1: Verification
        verification = self.verify_bundle(expected_sha256=expected_sha256)

        # Step 2: Clean/Prepare Destination Workspace
        if self.workspace_root.exists():
            if force:
                print(f"[*] Removing existing workspace directory: {self.workspace_root}")
                safe_rmtree(self.workspace_root, allowed_markers=("bundle_provenance.json", ".git"))
            else:
                raise FileExistsError(
                    f"Workspace destination '{self.workspace_root}' already exists. "
                    f"Use --force to overwrite."
                )

        self.workspace_root.mkdir(parents=True, exist_ok=True)
        print(f"[*] Extracting bundle into ephemeral workspace: {self.workspace_root}")

        # Step 3: Clone from bundle file
        try:
            subprocess.run(
                ["git", "clone", str(self.bundle_path), str(self.workspace_root)],
                capture_output=True,
                text=True,
                check=True,
            )
            print("    -> Cloned bundle repository successfully.")
        except subprocess.CalledProcessError as e:
            err_msg = (e.stderr or e.stdout or str(e)).strip()
            raise RuntimeError(f"Failed to extract Git bundle: {err_msg}")

        # Step 4: Checkout target tag/branch if specified
        if target_ref:
            try:
                subprocess.run(
                    ["git", "-C", str(self.workspace_root), "checkout", target_ref, "--"],
                    capture_output=True,
                    text=True,
                    check=True,
                )
                print(f"    -> Checked out reference: {target_ref}")
            except subprocess.CalledProcessError as e:
                err_msg = (e.stderr or e.stdout or str(e)).strip()
                raise RuntimeError(f"Failed to checkout ref '{target_ref}': {err_msg}")

        # Step 5: Gather commit metadata
        commit_info = self._get_commit_metadata(self.workspace_root)
        print(f"    -> Checked out Commit: {commit_info['commit_hash'][:8]} ({commit_info['ref']})")
        print(f"    -> Author: {commit_info['author_name']} <{commit_info['author_email']}>")
        print(f"    -> Subject: {commit_info['subject']}")

        # Step 6: Create Bundle Provenance Manifest
        provenance = {
            "manifest_schema": "grc-bundle-provenance-v1",
            "session_id": self.session_id,
            "bundle_identifier": self.bundle_sha256,
            "bundle_source_path": str(self.bundle_path),
            "bundle_size_bytes": self.bundle_path.stat().st_size,
            "bundle_sha256": self.bundle_sha256,
            "workspace_path": str(self.workspace_root),
            "checked_out_ref": target_ref or commit_info["ref"],
            "commit_metadata": commit_info,
            "restored_at": utc_now_iso(),
            "status": "RESTORED",
            "ephemeral": True,
            "verification": verification,
        }

        manifest_path = self.workspace_root / "bundle_provenance.json"
        with open(manifest_path, "w", encoding="utf-8") as f:
            json.dump(provenance, f, indent=2)
        print(f"[*] Provenance manifest generated: {manifest_path.name}")

        # Optional: Set read-only permissions on source files to prevent scanner mutation
        if read_only:
            self._apply_read_only(self.workspace_root)
            print("    -> Applied read-only filesystem permissions across source tree.")

        print("[SUCCESS] Bundle successfully restored and ready for Phase 3 (Analyze).")
        return provenance

    def clean_workspace(self, remove_bundle: bool = False) -> None:
        """Delegates workspace teardown to `clean_ephemeral_workspace`."""
        clean_ephemeral_workspace(
            workspace_root=self.workspace_root,
            bundle_path=self.bundle_path,
            remove_bundle=remove_bundle,
        )

    # --------------------------------------------------------------------------
    # INTERNAL HELPERS
    # --------------------------------------------------------------------------

    def _parse_bundle_refs(self, verify_output: str) -> List[Dict[str, str]]:
        refs = []
        for line in verify_output.splitlines():
            line = line.strip()
            # Standard git bundle verify output lists refs like:
            # <sha1-or-sha256> refs/heads/main
            parts = line.split()
            if len(parts) >= 2 and _HEX_HASH_RE.match(parts[0]):
                refs.append({"commit": parts[0], "ref": parts[1]})
        return refs

    def _get_commit_metadata(self, repo_path: Path) -> Dict[str, Any]:
        fmt = "%H%x00%h%x00%an%x00%ae%x00%ad%x00%s%x00%D"
        try:
            res = subprocess.run(
                ["git", "-C", str(repo_path), "log", "-1", f"--format={fmt}"],
                capture_output=True,
                text=True,
                check=True,
            )
            parts = res.stdout.strip().split("\x00")
            return {
                "commit_hash": parts[0] if len(parts) > 0 else "",
                "short_hash": parts[1] if len(parts) > 1 else "",
                "author_name": parts[2] if len(parts) > 2 else "",
                "author_email": parts[3] if len(parts) > 3 else "",
                "author_date": parts[4] if len(parts) > 4 else "",
                "subject": parts[5] if len(parts) > 5 else "",
                "ref": parts[6] if (len(parts) > 6 and parts[6]) else "HEAD",
            }
        except subprocess.CalledProcessError:
            return {
                "commit_hash": "UNKNOWN",
                "short_hash": "UNKNOWN",
                "author_name": "UNKNOWN",
                "author_email": "UNKNOWN",
                "author_date": "UNKNOWN",
                "subject": "UNKNOWN",
                "ref": "HEAD",
            }

    def _apply_read_only(self, path: Path) -> None:
        """Makes source files read-only while keeping directories traversable and preserving .github/."""
        for root, dirs, files in os.walk(path):
            # Prune .git directory only (not .github or .gitlab)
            dirs[:] = [d for d in dirs if d != ".git"]
            if ".git" in Path(root).parts:
                continue
            for f in files:
                f_path = Path(root) / f
                try:
                    f_path.chmod(0o444)
                except OSError:
                    pass


# ==============================================================================
# CLI DISPATCHER
# ==============================================================================

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="grc bundle",
        description="GRC-xMINI Bundle Lifecycle Manager (Pull, Verify, Restore, and Clean)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Commands:
  restore   Verify and extract a Git bundle into an ephemeral workspace.
  verify    Check SHA-256 integrity and validate Git bundle objects without extracting.
  clean     Tear down the ephemeral workspace and delete bundle to uphold ephemeral hygiene.

Examples:
  grc bundle restore /path/to/release.bundle --workspace ./workspace
  grc bundle restore release-v1.0.0.bundle --expected-sha256 a1b2c3... --ref v1.0.0
  grc bundle verify /path/to/release.bundle
  grc bundle clean --workspace ./workspace --delete-bundle release-v1.0.0.bundle
        """,
    )

    subparsers = parser.add_subparsers(dest="action", required=True, help="Action to execute")

    # Command: restore
    restore_parser = subparsers.add_parser(
        "restore", help="Verify and extract Git bundle into ephemeral workspace"
    )
    restore_parser.add_argument(
        "bundle",
        type=Path,
        help="Path to the target Git bundle file (.bundle)",
    )
    restore_parser.add_argument(
        "--workspace",
        "-w",
        type=Path,
        default=None,
        help="Destination directory for workspace restoration (defaults to <bundle_dir>/ephemeral_workspace)",
    )
    restore_parser.add_argument(
        "--ref",
        "-r",
        default=None,
        help="Specific tag or branch reference to checkout (e.g., v1.0.0, main)",
    )
    restore_parser.add_argument(
        "--expected-sha256",
        "-s",
        default=None,
        help="Expected SHA-256 hash recorded during Pull & Verify to enforce strict integrity",
    )
    restore_parser.add_argument(
        "--force",
        "-f",
        action="store_true",
        help="Overwrite workspace directory if it already exists",
    )
    restore_parser.add_argument(
        "--read-only",
        action="store_true",
        help="Apply read-only permissions across source tree after extraction",
    )
    restore_parser.add_argument(
        "--json",
        action="store_true",
        help="Output restoration summary as raw JSON",
    )

    # Command: verify
    verify_parser = subparsers.add_parser(
        "verify", help="Verify SHA-256 and Git bundle integrity without extracting"
    )
    verify_parser.add_argument(
        "bundle",
        type=Path,
        help="Path to the Git bundle file (.bundle)",
    )
    verify_parser.add_argument(
        "--expected-sha256",
        "-s",
        default=None,
        help="Expected SHA-256 hash to validate against",
    )
    verify_parser.add_argument(
        "--json",
        action="store_true",
        help="Output verification results as raw JSON",
    )

    # Command: clean
    clean_parser = subparsers.add_parser(
        "clean", help="Teardown ephemeral workspace and delete bundle"
    )
    clean_parser.add_argument(
        "--workspace",
        "-w",
        type=Path,
        required=True,
        help="Path to the ephemeral workspace to destroy",
    )
    clean_parser.add_argument(
        "--delete-bundle",
        type=Path,
        default=None,
        help="Optional path to the bundle file to delete post-review",
    )

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    try:
        if args.action == "verify":
            manager = GRCBundleManager(args.bundle)
            result = manager.verify_bundle(expected_sha256=args.expected_sha256)
            if args.json:
                print(json.dumps(result, indent=2))
            else:
                print(f"[SUCCESS] Bundle verification passed for: {args.bundle.name}")

        elif args.action == "restore":
            manager = GRCBundleManager(args.bundle, workspace_root=args.workspace)
            result = manager.restore_bundle(
                target_ref=args.ref,
                expected_sha256=args.expected_sha256,
                force=args.force,
                read_only=args.read_only,
            )
            if args.json:
                print(json.dumps(result, indent=2))

        elif args.action == "clean":
            clean_ephemeral_workspace(
                workspace_root=args.workspace,
                bundle_path=args.delete_bundle,
                remove_bundle=bool(args.delete_bundle),
            )

    except Exception as e:
        print(f"[FATAL] Operation failed: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
