#!/usr/bin/env python3
"""
fips_discovery.py - Static Cryptographic Discovery, CBOM & FIPS 140-3 Assessment Engine
=======================================================================================

Classification: Internal Security Assessment & Engineering Specification
Pipeline Role: Engine #8 — Source/Config Crypto Discovery, Algorithm Policy, CMVP Mapping & CBOM
Target Frameworks: NIST SP 800-53 Rev. 5 (SC-13, SC-12, SC-8(1), SC-28(1), IA-7, SC-23, CM-6),
                   NIST FIPS 140-3 (SP 800-140C/D), NIST SP 800-131A Rev. 2, FIPS 186-5, SP 800-52 Rev. 2
Zero External Dependencies: 100% Python 3 Standard Library (Python 3.9+).

Framing:
  FIPS 140-3 validates cryptographic modules through NIST CMVP; applications and source
  repositories are not themselves validated or certified. This engine evaluates static
  evidence of whether security-relevant cryptography is routed through a FIPS 140-3
  validated module, configured for approved-mode intent, using approved algorithms and
  parameters. Where static inspection cannot decide, findings emit
  `CANNOT_DETERMINE_STATICALLY` or `NEEDS_REVIEW`, never `PASS`.
"""

import argparse
import ast
import datetime
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import uuid
from pathlib import Path, PurePosixPath
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

try:
    from crypto_lib_scan import (
        SKIP_DIRS,
        CryptoScanner,
        DependencyExtractor,
        load_crypto_catalog,
    )
    from grc_common import (
        CMVP_CATALOG_PATH,
        FIPS_ALGORITHM_POLICY_PATH,
        REPO_ROOT,
        RULES_DIR,
        SEVERITY_RANK,
        get_catalog_descriptor,
        make_finding_id,
        sha256_file,
        split_aoc,
        utc_now_iso,
        utc_now_str,
        utc_today,
        validate_finding_envelope,
        version_lt,
    )
except ImportError:
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from crypto_lib_scan import (
        SKIP_DIRS,
        CryptoScanner,
        DependencyExtractor,
        load_crypto_catalog,
    )
    from grc_common import (
        CMVP_CATALOG_PATH,
        FIPS_ALGORITHM_POLICY_PATH,
        REPO_ROOT,
        RULES_DIR,
        SEVERITY_RANK,
        get_catalog_descriptor,
        make_finding_id,
        sha256_file,
        split_aoc,
        utc_now_iso,
        utc_now_str,
        utc_today,
        validate_finding_envelope,
        version_lt,
    )

ENGINE_NAME = "FIPSDiscovery"
ENGINE_VERSION = "1.5.2"
CRYPTO_CATALOG_PATH = RULES_DIR / "crypto_catalog.json"
PROVENANCE_FILENAMES = frozenset({"bundle_provenance.json", "ami_provenance.json", "fips_provenance.json"})

ASSESSED_CONTROLS = [
    "SC-13",
    "SC-12",
    "SC-8",
    "SC-8(1)",
    "SC-28",
    "SC-28(1)",
    "IA-7",
    "SC-23",
    "SI-7",
    "SI-17",
    "CM-6",
]
ASSESSED_AOCS = ["AOC-03", "AOC-05", "AOC-09", "AOC-12"]

_SECURITY_VAR_RE = re.compile(
    r"(token|secret|key|apikey|api_key|nonce|iv|salt|otp|passwd|password|session|csrf|auth|seed)",
    re.IGNORECASE,
)
_NONSEC_HINT_RE = re.compile(
    r"(etag|cache_key|cachekey|checksum_nonsec|shard_key|bucket_hash|avatar_hash|color_hash)",
    re.IGNORECASE,
)
_SECRET_ASSIGN_REDACT_RE = re.compile(
    r"""((?:key|secret|password|passwd|token|api_key)\s*[:=]\s*)(['"][^'"]{6,}['"])""",
    re.IGNORECASE,
)


def _redact_snippet(line: str) -> str:
    """Redacts potential literal secret values while preserving cryptographic API syntax."""
    s = line.strip()
    s = _SECRET_ASSIGN_REDACT_RE.sub(r'\1"<REDACTED>"', s)
    return s[:500]


def _strip_c_style_comments(source: str) -> List[str]:
    """
    Strips `//` and `/* ... */` comments while preserving exact 1-based line numbers
    for Go, Java, Kotlin, JS/TS, C/C++, Rust, and C#.
    """
    out_chars: List[str] = []
    i = 0
    n = len(source)
    in_block = False
    in_str: Optional[str] = None
    while i < n:
        ch = source[i]
        nxt = source[i + 1] if i + 1 < n else ""
        if in_block:
            if ch == "*" and nxt == "/":
                in_block = False
                out_chars.append("  ")
                i += 2
            else:
                out_chars.append("\n" if ch == "\n" else " ")
                i += 1
            continue
        if in_str:
            out_chars.append(ch)
            if ch == "\\" and i + 1 < n:
                out_chars.append(nxt)
                i += 2
                continue
            if ch == in_str:
                in_str = None
            i += 1
            continue
        if ch in ('"', "'", "`"):
            in_str = ch
            out_chars.append(ch)
            i += 1
            continue
        if ch == "/" and nxt == "/":
            while i < n and source[i] != "\n":
                i += 1
            continue
        if ch == "/" and nxt == "*":
            in_block = True
            out_chars.append("  ")
            i += 2
            continue
        out_chars.append(ch)
        i += 1
    return "".join(out_chars).splitlines()


# ==============================================================================
# CATALOG LOADERS, STALENESS & SIGNATURE INTEGRITY CHECKS
# ==============================================================================

def load_algorithm_policy(path: Optional[Path] = None) -> Dict[str, Any]:
    target = Path(path) if path else FIPS_ALGORITHM_POLICY_PATH
    if target.is_file():
        return json.loads(target.read_text(encoding="utf-8"))
    raise FileNotFoundError(f"Algorithm policy catalog not found: {target}")


def load_cmvp_catalog(path: Optional[Path] = None) -> Dict[str, Any]:
    target = Path(path) if path else CMVP_CATALOG_PATH
    if target.is_file():
        return json.loads(target.read_text(encoding="utf-8"))
    raise FileNotFoundError(f"CMVP reference catalog not found: {target}")


def check_cmvp_staleness(
    cmvp_data: Dict[str, Any],
    threshold_days: Optional[int] = None,
    today: Optional[datetime.date] = None,
) -> Optional[str]:
    """Returns a warning string if `cmvp_catalog.json` exceeds its staleness threshold."""
    meta = cmvp_data.get("catalog_metadata", {})
    limit = threshold_days if threshold_days is not None else int(meta.get("staleness_threshold_days", 90))
    retrieved_str = str(meta.get("retrieved_at") or meta.get("last_updated") or "")
    if len(retrieved_str) < 10:
        return "CMVP catalog metadata lacks a parseable 'retrieved_at' date; refresh before formal assessment."
    try:
        retrieved_dt = datetime.date.fromisoformat(retrieved_str[:10])
    except ValueError:
        return f"CMVP catalog 'retrieved_at' ('{retrieved_str}') is invalid."
    ref_day = today or utc_today()
    age_days = (ref_day - retrieved_dt).days
    if age_days > limit:
        return (
            f"CMVP reference snapshot is {age_days} days old (retrieved {retrieved_dt.isoformat()}, "
            f"threshold {limit} days). Verify certificate statuses against NIST CMVP before relying on module mappings."
        )
    return None


def verify_catalog_authenticity(catalog_path: Path) -> Dict[str, str]:
    """
    Checks SHA-256 digest and optional detached cryptographic signature (.sig / .bundle)
    when `cosign` or `ssh-keygen` is installed on the host.
    """
    sha = sha256_file(catalog_path) if catalog_path.is_file() else ""
    sig_bundle = catalog_path.with_suffix(catalog_path.suffix + ".sigstore.json")
    ssh_sig = catalog_path.with_suffix(catalog_path.suffix + ".sshsig")
    cosign_bin = shutil.which("cosign")
    ssh_keygen_bin = shutil.which("ssh-keygen")

    if sig_bundle.is_file() and cosign_bin:
        res = subprocess.run(
            [cosign_bin, "verify-blob", "--bundle", str(sig_bundle), str(catalog_path)],
            capture_output=True,
            text=True,
        )
        status = "VERIFIED_COSIGN" if res.returncode == 0 else "FAILED_COSIGN"
        note = "Verified Sigstore bundle via cosign." if res.returncode == 0 else res.stderr.strip()
        return {"sha256": sha, "signature_status": status, "note": note}

    if ssh_sig.is_file() and ssh_keygen_bin:
        return {
            "sha256": sha,
            "signature_status": "DETACHED_SSHSIG_PRESENT",
            "note": "Detached SSH signature file present; provide trusted allowed_signers to verify publisher identity.",
        }

    return {
        "sha256": sha,
        "signature_status": "CHECKSUM_ONLY",
        "note": (
            "SHA-256 recorded for local integrity; no detached publisher signature (.sigstore.json / .sshsig) "
            "or host verifier configured."
        ),
    }


# ==============================================================================
# INTERNAL DISCOVERY HIT & CBOM ASSET MODELS
# ==============================================================================

class CryptoAssetRecord:
    """Represents a discovered cryptographic asset for CycloneDX 1.6 CBOM & policy evaluation."""

    def __init__(
        self,
        asset_type: str,  # "algorithm" | "protocol" | "related-crypto-material" | "certificate"
        name: str,
        language: str,
        file_path: str,
        line_start: Optional[int],
        api: str,
        detection_method: str,
        confidence: str,
        mode: Optional[str] = None,
        key_bits: Optional[int] = None,
        curve: Optional[str] = None,
        purpose: str = "unknown",
        snippet: str = "",
        extra: Optional[Dict[str, Any]] = None,
    ):
        self.asset_type = asset_type
        self.name = name.lower().strip()
        self.language = language
        self.file_path = file_path.replace("\\", "/").lstrip("./")
        self.line_start = line_start
        self.api = api
        self.detection_method = detection_method
        self.confidence = confidence
        self.mode = mode.upper() if mode else None
        self.key_bits = key_bits
        self.curve = curve
        self.purpose = purpose
        self.snippet = _redact_snippet(snippet) if snippet else ""
        self.extra = extra or {}


# ==============================================================================
# PYTHON AST ANALYZER (Zero Regex on .py Source)
# ==============================================================================

class _PythonCryptoVisitor(ast.NodeVisitor):
    """AST visitor inspecting Python cryptographic API calls, modes, key sizes, and TLS flags."""

    def __init__(self, rel_path: str, source_lines: List[str]):
        self.rel_path = rel_path
        self.source_lines = source_lines
        self.imports: Dict[str, str] = {}
        self.assets: List[CryptoAssetRecord] = []
        self.config_signals: List[Dict[str, Any]] = []
        self._scope_names: List[str] = []
        self._handled_call_ids: Set[int] = set()

    def _line_text(self, lineno: Optional[int]) -> str:
        if lineno and 1 <= lineno <= len(self.source_lines):
            return self.source_lines[lineno - 1]
        return ""

    def _resolve_attr(self, node: ast.AST) -> str:
        parts: List[str] = []
        cur: Optional[ast.AST] = node
        while isinstance(cur, ast.Attribute):
            parts.append(cur.attr)
            cur = cur.value
        if isinstance(cur, ast.Name):
            root = self.imports.get(cur.id, cur.id)
            parts.append(root)
            return ".".join(reversed(parts))
        if isinstance(cur, ast.Call):
            inner = self._resolve_attr(cur.func)
            if inner:
                parts.append(inner)
                return ".".join(reversed(parts))
        return ""

    @staticmethod
    def _const_str(node: Optional[ast.AST]) -> Optional[str]:
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        return None

    @staticmethod
    def _const_int(node: Optional[ast.AST]) -> Optional[int]:
        if isinstance(node, ast.Constant) and isinstance(node.value, int) and not isinstance(node.value, bool):
            return int(node.value)
        return None

    @staticmethod
    def _const_bool(node: Optional[ast.AST]) -> Optional[bool]:
        if isinstance(node, ast.Constant) and isinstance(node.value, bool):
            return node.value
        return None

    @staticmethod
    def _is_constant_bytes(node: Optional[ast.AST]) -> bool:
        if isinstance(node, ast.Constant) and isinstance(node.value, (bytes, str)):
            return True
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mult):
            return _PythonCryptoVisitor._is_constant_bytes(node.left) or _PythonCryptoVisitor._is_constant_bytes(node.right)
        return False

    def _kwarg(self, call: ast.Call, name: str) -> Optional[ast.AST]:
        for kw in call.keywords:
            if kw.arg == name:
                return kw.value
        return None

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            bound = alias.asname or alias.name.split(".")[0]
            if alias.asname:
                self.imports[bound] = alias.name
            else:
                self.imports[bound] = bound
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        mod = node.module or ""
        for alias in node.names:
            bound = alias.asname or alias.name
            full = f"{mod}.{alias.name}" if mod else alias.name
            self.imports[bound] = full
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._scope_names.append(node.name)
        self.generic_visit(node)
        self._scope_names.pop()

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._scope_names.append(node.name)
        self.generic_visit(node)
        self._scope_names.pop()

    def visit_Assign(self, node: ast.Assign) -> None:
        target_names: List[str] = []
        for t in node.targets:
            if isinstance(t, ast.Name):
                target_names.append(t.id)
            elif isinstance(t, ast.Attribute):
                target_names.append(t.attr)
                resolved_lhs = self._resolve_attr(t)
                # Detect ctx.verify_mode = ssl.CERT_NONE or ctx.check_hostname = False
                if t.attr == "verify_mode":
                    rhs_name = self._resolve_attr(node.value)
                    if rhs_name.endswith("CERT_NONE"):
                        self.assets.append(CryptoAssetRecord(
                            asset_type="protocol",
                            name="tls-cert-verification-disabled",
                            language="python",
                            file_path=self.rel_path,
                            line_start=node.lineno,
                            api=f"{resolved_lhs} = ssl.CERT_NONE",
                            detection_method="ast",
                            confidence="HIGH",
                            snippet=self._line_text(node.lineno),
                            extra={"tls_check": "cert_verification_disabled"},
                        ))
                elif t.attr == "check_hostname" and self._const_bool(node.value) is False:
                    self.assets.append(CryptoAssetRecord(
                        asset_type="protocol",
                        name="tls-hostname-verification-disabled",
                        language="python",
                        file_path=self.rel_path,
                        line_start=node.lineno,
                        api=f"{resolved_lhs} = False",
                        detection_method="ast",
                        confidence="HIGH",
                        snippet=self._line_text(node.lineno),
                        extra={"tls_check": "cert_verification_disabled"},
                    ))
                elif t.attr == "minimum_version":
                    rhs_name = self._resolve_attr(node.value)
                    self._record_python_tls_version(rhs_name, node.lineno)

        scope_pushed = "|".join(target_names)
        if scope_pushed:
            self._scope_names.append(scope_pushed)
        self.generic_visit(node)
        if scope_pushed:
            self._scope_names.pop()

    def _record_python_tls_version(self, proto_symbol: str, lineno: int) -> None:
        sym_u = proto_symbol.upper()
        ver = None
        if any(x in sym_u for x in ("SSLv2", "SSLV2")):
            ver = "sslv2"
        elif any(x in sym_u for x in ("SSLv3", "SSLV3")):
            ver = "sslv3"
        elif any(x in sym_u for x in ("TLSV1_1", "PROTOCOL_TLSV1_1")):
            ver = "tls1.1"
        elif any(x in sym_u for x in ("TLSV1_2", "PROTOCOL_TLSV1_2")):
            ver = "tls1.2"
        elif any(x in sym_u for x in ("TLSV1_3", "PROTOCOL_TLSV1_3")):
            ver = "tls1.3"
        elif sym_u.endswith("TLSV1") or sym_u.endswith("PROTOCOL_TLSV1"):
            ver = "tls1.0"
        if ver:
            self.assets.append(CryptoAssetRecord(
                asset_type="protocol",
                name=ver,
                language="python",
                file_path=self.rel_path,
                line_start=lineno,
                api=proto_symbol,
                detection_method="ast",
                confidence="HIGH",
                snippet=self._line_text(lineno),
            ))

    def visit_Call(self, node: ast.Call) -> None:
        if id(node) in self._handled_call_ids:
            self.generic_visit(node)
            return
        fq = self._resolve_attr(node.func)
        lineno = node.lineno
        snippet = self._line_text(lineno)
        context_str = " ".join(self._scope_names)

        # 1. Detect getattr(ssl, "FIPS_mode", lambda: 0)() or ssl.FIPS_mode()
        if isinstance(node.func, ast.Call) and self._resolve_attr(node.func.func) == "getattr":
            g_args = node.func.args
            if (
                len(g_args) >= 2
                and self._resolve_attr(g_args[0]) == "ssl"
                and self._const_str(g_args[1]) == "FIPS_mode"
            ):
                self.config_signals.append({
                    "kind": "python_fips_mode_unenforced",
                    "path": self.rel_path,
                    "line": lineno,
                    "snippet": snippet,
                })
        elif fq == "getattr" and len(node.args) >= 2:
            if self._resolve_attr(node.args[0]) == "ssl" and self._const_str(node.args[1]) == "FIPS_mode":
                # Handled on outer call if invoked directly; skip duplicate
                pass

        # 2. hashlib.*
        if fq.startswith("hashlib."):
            fn = fq.split(".", 1)[1]
            alg = None
            if fn == "new" and node.args:
                raw_alg = self._const_str(node.args[0])
                if raw_alg:
                    alg = raw_alg.lower().replace("_", "-").replace("sha-", "sha")
            elif fn in (
                "md5", "sha1", "sha224", "sha256", "sha384", "sha512",
                "sha3_224", "sha3_256", "sha3_384", "sha3_512",
                "shake_128", "shake_256", "blake2b", "blake2s",
            ):
                alg = fn.replace("sha3_", "sha3-").replace("shake_", "shake")
            elif fn == "pbkdf2_hmac" and len(node.args) >= 4:
                iters = self._const_int(node.args[3])
                salt_const = self._is_constant_bytes(node.args[2])
                self.assets.append(CryptoAssetRecord(
                    asset_type="algorithm",
                    name="pbkdf2",
                    language="python",
                    file_path=self.rel_path,
                    line_start=lineno,
                    api=fq,
                    detection_method="ast",
                    confidence="HIGH",
                    purpose="kdf",
                    snippet=snippet,
                    extra={"iterations": iters, "static_salt": salt_const},
                ))

            if alg:
                ufs_node = self._kwarg(node, "usedforsecurity")
                ufs = self._const_bool(ufs_node)
                purpose = "hashing"
                if ufs is False or _NONSEC_HINT_RE.search(context_str):
                    purpose = "non_security"
                elif ufs is None:
                    purpose = "unknown"
                self.assets.append(CryptoAssetRecord(
                    asset_type="algorithm",
                    name=alg,
                    language="python",
                    file_path=self.rel_path,
                    line_start=lineno,
                    api=fq,
                    detection_method="ast",
                    confidence="HIGH",
                    purpose=purpose,
                    snippet=snippet,
                    extra={"usedforsecurity": ufs},
                ))

        # 3. hmac.new / hmac.digest
        elif fq in ("hmac.new", "hmac.HMAC", "hmac.digest"):
            digest_node = self._kwarg(node, "digestmod") or self._kwarg(node, "digest")
            if digest_node is None:
                if fq == "hmac.digest" and len(node.args) >= 3:
                    digest_node = node.args[2]
                elif len(node.args) >= 3:
                    digest_node = node.args[2]
            d_str = self._const_str(digest_node)
            if not d_str and digest_node is not None:
                attr = self._resolve_attr(digest_node)
                if attr.startswith("hashlib."):
                    d_str = attr.split(".", 1)[1]
            norm_d = (d_str or "md5").lower().replace("_", "").replace("-", "")
            mac_name = f"hmac-{norm_d}"
            self.assets.append(CryptoAssetRecord(
                asset_type="algorithm",
                name=mac_name,
                language="python",
                file_path=self.rel_path,
                line_start=lineno,
                api=fq,
                detection_method="ast",
                confidence="HIGH",
                purpose="hmac",
                snippet=snippet,
            ))

        # 4. ssl contexts & requests(..., verify=False)
        elif fq in ("ssl.SSLContext", "ssl.wrap_socket"):
            if node.args:
                proto = self._resolve_attr(node.args[0])
                self._record_python_tls_version(proto, lineno)
        elif fq == "ssl._create_unverified_context":
            self.assets.append(CryptoAssetRecord(
                asset_type="protocol",
                name="tls-cert-verification-disabled",
                language="python",
                file_path=self.rel_path,
                line_start=lineno,
                api=fq,
                detection_method="ast",
                confidence="HIGH",
                snippet=snippet,
                extra={"tls_check": "cert_verification_disabled"},
            ))
        elif fq == "ssl.create_default_context":
            self.assets.append(CryptoAssetRecord(
                asset_type="protocol",
                name="tls1.2",
                language="python",
                file_path=self.rel_path,
                line_start=lineno,
                api=fq,
                detection_method="ast",
                confidence="HIGH",
                snippet=snippet,
            ))
        elif fq.startswith(("requests.", "httpx.")) and fq.split(".", 1)[1] in (
            "get", "post", "put", "delete", "patch", "head", "request", "Client", "AsyncClient"
        ):
            v_node = self._kwarg(node, "verify")
            if self._const_bool(v_node) is False:
                self.assets.append(CryptoAssetRecord(
                    asset_type="protocol",
                    name="tls-cert-verification-disabled",
                    language="python",
                    file_path=self.rel_path,
                    line_start=lineno,
                    api=f"{fq}(verify=False)",
                    detection_method="ast",
                    confidence="HIGH",
                    snippet=snippet,
                    extra={"tls_check": "cert_verification_disabled"},
                ))

        # 5. cryptography.hazmat.* & Crypto / Cryptodome
        elif "Cipher" in fq or "algorithms." in fq or fq.endswith((
            "AESGCM", "AESCCM", "ChaCha20Poly1305", "TripleDES", "ARC4", "Blowfish", "CAST5", "IDEA", "ChaCha20"
        )):
            tail = fq.split(".")[-1]
            cmap = {
                "TripleDES": ("3des", None),
                "DES3": ("3des", None),
                "DES": ("des", None),
                "ARC4": ("rc4", None),
                "ARC2": ("rc2", None),
                "Blowfish": ("blowfish", None),
                "CAST5": ("cast5", None),
                "CAST": ("cast5", None),
                "IDEA": ("idea", None),
                "ChaCha20": ("chacha20", None),
                "ChaCha20Poly1305": ("chacha20", "POLY1305"),
                "Salsa20": ("salsa20", None),
                "AESGCM": ("aes", "GCM"),
                "AESCCM": ("aes", "CCM"),
                "AES": ("aes", None),
            }
            # PyCrypto/PyCryptodome `DES.new(...)`, `AES.new(..., AES.MODE_ECB)`
            if tail == "new" and len(fq.split(".")) >= 2:
                mod_cls = fq.split(".")[-2]
                if mod_cls in cmap:
                    alg_name, def_mode = cmap[mod_cls]
                    mode = def_mode
                    if len(node.args) >= 2:
                        m_attr = self._resolve_attr(node.args[1])
                        if "MODE_ECB" in m_attr:
                            mode = "ECB"
                        elif "MODE_GCM" in m_attr:
                            mode = "GCM"
                        elif "MODE_CBC" in m_attr:
                            mode = "CBC"
                    static_iv = False
                    iv_kw = self._kwarg(node, "iv") or self._kwarg(node, "nonce")
                    if iv_kw is not None and self._is_constant_bytes(iv_kw):
                        static_iv = True
                    elif len(node.args) >= 3 and self._is_constant_bytes(node.args[2]):
                        static_iv = True
                    self.assets.append(CryptoAssetRecord(
                        asset_type="algorithm",
                        name=alg_name,
                        language="python",
                        file_path=self.rel_path,
                        line_start=lineno,
                        api=fq,
                        detection_method="ast",
                        confidence="HIGH",
                        mode=mode,
                        purpose="encryption",
                        snippet=snippet,
                        extra={"static_iv": static_iv},
                    ))
                elif mod_cls in ("MD2", "MD4", "MD5", "SHA", "SHA1", "RIPEMD160", "SHA256", "SHA384", "SHA512"):
                    h_name = "sha1" if mod_cls == "SHA" else mod_cls.lower()
                    self.assets.append(CryptoAssetRecord(
                        asset_type="algorithm",
                        name=h_name,
                        language="python",
                        file_path=self.rel_path,
                        line_start=lineno,
                        api=fq,
                        detection_method="ast",
                        confidence="HIGH",
                        purpose="hashing",
                        snippet=snippet,
                    ))
            elif tail == "Cipher" and node.args:
                alg_arg = node.args[0]
                mode_arg = node.args[1] if len(node.args) >= 2 else None
                alg_tail = (
                    self._resolve_attr(alg_arg.func).split(".")[-1]
                    if isinstance(alg_arg, ast.Call)
                    else self._resolve_attr(alg_arg).split(".")[-1]
                )
                if isinstance(alg_arg, ast.Call):
                    self._handled_call_ids.add(id(alg_arg))
                mode_name: Optional[str] = None
                static_iv = False
                if isinstance(mode_arg, ast.Call):
                    self._handled_call_ids.add(id(mode_arg))
                    m_tail = self._resolve_attr(mode_arg.func).split(".")[-1].upper()
                    if m_tail in ("ECB", "GCM", "CBC", "CTR", "CFB", "OFB", "XTS"):
                        mode_name = m_tail
                    if mode_arg.args and self._is_constant_bytes(mode_arg.args[0]):
                        static_iv = True
                if alg_tail in cmap:
                    alg_name, def_mode = cmap[alg_tail]
                    self.assets.append(CryptoAssetRecord(
                        asset_type="algorithm",
                        name=alg_name,
                        language="python",
                        file_path=self.rel_path,
                        line_start=lineno,
                        api=fq,
                        detection_method="ast",
                        confidence="HIGH",
                        mode=mode_name or def_mode,
                        purpose="encryption",
                        snippet=snippet,
                        extra={"static_iv": static_iv},
                    ))
            elif tail in cmap:
                alg_name, mode = cmap[tail]
                self.assets.append(CryptoAssetRecord(
                    asset_type="algorithm",
                    name=alg_name,
                    language="python",
                    file_path=self.rel_path,
                    line_start=lineno,
                    api=fq,
                    detection_method="ast",
                    confidence="HIGH",
                    mode=mode,
                    purpose="encryption",
                    snippet=snippet,
                ))

        elif fq.endswith(("modes.ECB", ".ECB")):
            self.assets.append(CryptoAssetRecord(
                asset_type="algorithm",
                name="aes",
                language="python",
                file_path=self.rel_path,
                line_start=lineno,
                api=fq,
                detection_method="ast",
                confidence="HIGH",
                mode="ECB",
                purpose="encryption",
                snippet=snippet,
            ))
        elif fq.endswith(("modes.GCM", "modes.CBC", "modes.CTR", ".GCM", ".CBC", ".CTR")):
            mode_name = fq.split(".")[-1].upper()
            static_iv = bool(node.args and self._is_constant_bytes(node.args[0]))
            if static_iv:
                self.assets.append(CryptoAssetRecord(
                    asset_type="algorithm",
                    name="aes",
                    language="python",
                    file_path=self.rel_path,
                    line_start=lineno,
                    api=fq,
                    detection_method="ast",
                    confidence="HIGH",
                    mode=mode_name,
                    purpose="encryption",
                    snippet=snippet,
                    extra={"static_iv": True},
                ))

        # 6. Asymmetric key generation (RSA / DSA / DH / EC)
        elif fq.endswith("rsa.generate_private_key") or fq.endswith("RSA.generate"):
            bits = self._const_int(self._kwarg(node, "key_size"))
            if bits is None and node.args:
                bits = self._const_int(node.args[0])
            self.assets.append(CryptoAssetRecord(
                asset_type="algorithm",
                name="rsa",
                language="python",
                file_path=self.rel_path,
                line_start=lineno,
                api=fq,
                detection_method="ast",
                confidence="HIGH",
                key_bits=bits,
                purpose="signature",
                snippet=snippet,
            ))
        elif fq.endswith("dsa.generate_private_key") or fq.endswith("DSA.generate"):
            self.assets.append(CryptoAssetRecord(
                asset_type="algorithm",
                name="dsa",
                language="python",
                file_path=self.rel_path,
                line_start=lineno,
                api=fq,
                detection_method="ast",
                confidence="HIGH",
                purpose="signature",
                snippet=snippet,
            ))
        elif fq.endswith("dh.generate_parameters"):
            bits = self._const_int(self._kwarg(node, "key_size"))
            if bits is None and len(node.args) >= 2:
                bits = self._const_int(node.args[1])
            self.assets.append(CryptoAssetRecord(
                asset_type="algorithm",
                name="dh",
                language="python",
                file_path=self.rel_path,
                line_start=lineno,
                api=fq,
                detection_method="ast",
                confidence="HIGH",
                key_bits=bits,
                purpose="key_agreement",
                snippet=snippet,
            ))
        elif fq.endswith("ec.generate_private_key") and node.args:
            curve_attr = self._resolve_attr(node.args[0])
            curve_tail = curve_attr.split(".")[-1].lower()
            self.assets.append(CryptoAssetRecord(
                asset_type="algorithm",
                name="ecdsa",
                language="python",
                file_path=self.rel_path,
                line_start=lineno,
                api=fq,
                detection_method="ast",
                confidence="HIGH",
                curve=curve_tail,
                purpose="signature",
                snippet=snippet,
            ))
        elif fq.endswith((
            "Ed25519PrivateKey.generate",
            "Ed448PrivateKey.generate",
            "X25519PrivateKey.generate",
            "X448PrivateKey.generate",
        )):
            cls_name = fq.split(".")[-2]
            alg_map = {
                "Ed25519PrivateKey": ("ed25519", "ed25519", "signature"),
                "Ed448PrivateKey": ("ed448", "ed448", "signature"),
                "X25519PrivateKey": ("ecdh", "x25519", "key_agreement"),
                "X448PrivateKey": ("ecdh", "x448", "key_agreement"),
            }
            a_name, c_name, purp = alg_map[cls_name]
            self.assets.append(CryptoAssetRecord(
                asset_type="algorithm",
                name=a_name,
                language="python",
                file_path=self.rel_path,
                line_start=lineno,
                api=fq,
                detection_method="ast",
                confidence="HIGH",
                curve=c_name,
                purpose=purp,
                snippet=snippet,
            ))
        elif fq.endswith("PBKDF2HMAC"):
            iters = self._const_int(self._kwarg(node, "iterations"))
            salt_const = self._is_constant_bytes(self._kwarg(node, "salt"))
            self.assets.append(CryptoAssetRecord(
                asset_type="algorithm",
                name="pbkdf2",
                language="python",
                file_path=self.rel_path,
                line_start=lineno,
                api=fq,
                detection_method="ast",
                confidence="HIGH",
                purpose="kdf",
                snippet=snippet,
                extra={"iterations": iters, "static_salt": salt_const},
            ))

        # 7. PRNG vs CSPRNG
        elif fq.startswith("random.") and fq.split(".", 1)[1] in (
            "random", "randint", "randrange", "choice", "choices", "getrandbits", "randbytes"
        ):
            if _SECURITY_VAR_RE.search(context_str) or _SECURITY_VAR_RE.search(snippet):
                self.assets.append(CryptoAssetRecord(
                    asset_type="algorithm",
                    name="unapproved-prng",
                    language="python",
                    file_path=self.rel_path,
                    line_start=lineno,
                    api=fq,
                    detection_method="ast",
                    confidence="HIGH",
                    purpose="rng",
                    snippet=snippet,
                ))
        elif fq in ("os.urandom", "secrets.token_bytes", "secrets.token_hex", "secrets.token_urlsafe", "secrets.randbits"):
            self.assets.append(CryptoAssetRecord(
                asset_type="algorithm",
                name="drbg",
                language="python",
                file_path=self.rel_path,
                line_start=lineno,
                api=fq,
                detection_method="ast",
                confidence="HIGH",
                purpose="rng",
                snippet=snippet,
            ))

        self.generic_visit(node)


# ==============================================================================
# MULTI-ECOSYSTEM LEXICAL & CONFIG ANALYZERS
# ==============================================================================

class WorkspaceCryptoScanner:
    """Scans source and infrastructure/configuration files across all target ecosystems."""

    def __init__(self, workspace_root: Path):
        self.workspace_root = Path(workspace_root).resolve()
        self.assets: List[CryptoAssetRecord] = []
        self.config_signals: List[Dict[str, Any]] = []
        self.ecosystems_seen: Set[str] = set()
        self.surface_counts: Dict[str, int] = {
            "python": 0,
            "polyglot_source": 0,
            "manifests": 0,
            "deploy_iac": 0,
            "os_config": 0,
        }
        self.workspace_files_total: int = 0

    def scan(self) -> None:
        for root, dirs, files in os.walk(self.workspace_root):
            dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
            r_path = Path(root)
            for fname in sorted(files):
                if fname in PROVENANCE_FILENAMES:
                    continue
                fpath = r_path / fname
                if fpath.is_symlink():
                    continue
                self.workspace_files_total += 1
                rel = str(fpath.relative_to(self.workspace_root)).replace("\\", "/")
                self._dispatch_file(fpath, rel, fname)

    def _dispatch_file(self, fpath: Path, rel: str, fname: str) -> None:
        flc = fname.lower()
        rel_lc = rel.lower()
        is_manifest = (
            DependencyExtractor._resolve_parser(fname) is not None
            or fname.startswith("libcrypto.")
            or fname.startswith("libssl.")
            or fname == "openssl"
        )
        if is_manifest:
            self.surface_counts["manifests"] += 1

        # Config / Host / IaC checks first
        if rel_lc.endswith("etc/default/grub") or flc == "grub":
            if not is_manifest:
                self.surface_counts["os_config"] += 1
            self._scan_grub(fpath, rel)
            return
        if rel_lc.endswith("etc/crypto-policies/config"):
            if not is_manifest:
                self.surface_counts["os_config"] += 1
            self._scan_crypto_policy(fpath, rel)
            return
        if flc.endswith(".cnf") or ("openssl" in flc and flc.endswith(".conf")):
            if not is_manifest:
                self.surface_counts["os_config"] += 1
            self._scan_openssl_cnf(fpath, rel)
            return
        if flc == "java.security" or flc.endswith(".security"):
            if not is_manifest:
                self.surface_counts["os_config"] += 1
            self._scan_java_security(fpath, rel)
            return
        if flc == "dockerfile" or flc.startswith("dockerfile.") or flc == "containerfile":
            if not is_manifest:
                self.surface_counts["deploy_iac"] += 1
            self._scan_dockerfile(fpath, rel)
            return
        if flc.endswith(".pkr.hcl") or flc.endswith(".tf"):
            if not is_manifest:
                self.surface_counts["deploy_iac"] += 1
            self._scan_iac_hcl(fpath, rel)
            return
        counted_deploy = False
        if flc in ("app.config", "web.config") or flc.endswith(".config"):
            if not is_manifest and not counted_deploy:
                self.surface_counts["deploy_iac"] += 1
                counted_deploy = True
            self._scan_dotnet_config(fpath, rel)
        if flc == "nginx.conf" or ("nginx" in rel_lc and flc.endswith(".conf")):
            if not is_manifest and not counted_deploy:
                self.surface_counts["deploy_iac"] += 1
                counted_deploy = True
            self._scan_nginx_conf(fpath, rel)
            return
        if flc.endswith((".yaml", ".yml")):
            if not is_manifest and not counted_deploy:
                self.surface_counts["deploy_iac"] += 1
                counted_deploy = True
            self._scan_yaml_config(fpath, rel)

        # Source code analyzers
        if flc.endswith(".py"):
            if not is_manifest:
                self.surface_counts["python"] += 1
            self.ecosystems_seen.add("pypi")
            self._scan_python(fpath, rel)
        elif flc.endswith(".go"):
            if not is_manifest:
                self.surface_counts["polyglot_source"] += 1
            self.ecosystems_seen.add("go")
            self._scan_go(fpath, rel)
        elif flc.endswith((".java", ".kt")):
            if not is_manifest:
                self.surface_counts["polyglot_source"] += 1
            self.ecosystems_seen.add("maven")
            self._scan_java(fpath, rel)
        elif flc.endswith((".js", ".mjs", ".cjs", ".ts", ".tsx")):
            if not is_manifest:
                self.surface_counts["polyglot_source"] += 1
            self.ecosystems_seen.add("npm")
            self._scan_js_ts(fpath, rel)
        elif flc.endswith((".c", ".cc", ".cpp", ".cxx", ".h", ".hpp")):
            if not is_manifest:
                self.surface_counts["polyglot_source"] += 1
            self.ecosystems_seen.add("system")
            self._scan_c_cpp(fpath, rel)
        elif flc.endswith(".rs"):
            if not is_manifest:
                self.surface_counts["polyglot_source"] += 1
            self.ecosystems_seen.add("cargo")
            self._scan_rust(fpath, rel)
        elif flc.endswith(".cs"):
            if not is_manifest:
                self.surface_counts["polyglot_source"] += 1
            self.ecosystems_seen.add("nuget")
            self._scan_csharp(fpath, rel)
        elif flc.endswith(".sh"):
            if not is_manifest and not counted_deploy:
                self.surface_counts["deploy_iac"] += 1
            self._scan_shell(fpath, rel)

    def _read_text(self, fpath: Path) -> Optional[str]:
        try:
            if fpath.stat().st_size > 4 * 1024 * 1024:
                return None
            return fpath.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            return None

    # ------------------------------------------------------------------
    # Python AST
    # ------------------------------------------------------------------
    def _scan_python(self, fpath: Path, rel: str) -> None:
        text = self._read_text(fpath)
        if text is None:
            return
        lines = text.splitlines()
        try:
            tree = ast.parse(text, filename=rel)
        except SyntaxError:
            return
        visitor = _PythonCryptoVisitor(rel, lines)
        visitor.visit(tree)
        self.assets.extend(visitor.assets)
        self.config_signals.extend(visitor.config_signals)

    # ------------------------------------------------------------------
    # Go Lexical
    # ------------------------------------------------------------------
    def _scan_go(self, fpath: Path, rel: str) -> None:
        text = self._read_text(fpath)
        if text is None:
            return
        raw_lines = text.splitlines()
        # Check //go:debug directives before stripping comments
        for idx, rline in enumerate(raw_lines, start=1):
            m_dbg = re.search(r"//go:debug\s+fips140=(on|only|off)", rline)
            if m_dbg:
                mode_val = m_dbg.group(1)
                self.config_signals.append({
                    "kind": "go_fips_enabled" if mode_val in ("on", "only") else "go_fips_disabled",
                    "path": rel,
                    "line": idx,
                    "snippet": rline.strip(),
                    "detail": f"fips140={mode_val}",
                })

        clean_lines = _strip_c_style_comments(text)
        for idx, line in enumerate(clean_lines, start=1):
            raw = raw_lines[idx - 1]
            # Standard & x/crypto calls / imports
            if re.search(r'\bmd5\.(New|Sum)\b|"crypto/md5"', line):
                self.assets.append(CryptoAssetRecord("algorithm", "md5", "go", rel, idx, "crypto/md5", "lexical", "HIGH", purpose="hashing", snippet=raw))
            if re.search(r'\bsha1\.(New|Sum)\b|"crypto/sha1"', line):
                purpose = "hmac" if "hmac.New" in line else "hashing"
                self.assets.append(CryptoAssetRecord("algorithm", "hmac-sha1" if purpose == "hmac" else "sha1", "go", rel, idx, "crypto/sha1", "lexical", "HIGH", purpose=purpose, snippet=raw))
            if re.search(r'\bsha256\.(New|Sum256|Sum224)\b', line):
                self.assets.append(CryptoAssetRecord("algorithm", "sha256", "go", rel, idx, "crypto/sha256", "lexical", "HIGH", purpose="hashing", snippet=raw))
            if re.search(r'\bsha512\.(New|Sum512|Sum384)\b', line):
                self.assets.append(CryptoAssetRecord("algorithm", "sha512", "go", rel, idx, "crypto/sha512", "lexical", "HIGH", purpose="hashing", snippet=raw))
            if re.search(r'\bdes\.NewTripleDESCipher\b', line):
                self.assets.append(CryptoAssetRecord("algorithm", "3des", "go", rel, idx, "crypto/des.NewTripleDESCipher", "lexical", "HIGH", purpose="encryption", snippet=raw))
            elif re.search(r'\bdes\.NewCipher\b|"crypto/des"', line):
                self.assets.append(CryptoAssetRecord("algorithm", "des", "go", rel, idx, "crypto/des", "lexical", "HIGH", purpose="encryption", snippet=raw))
            if re.search(r'\brc4\.NewCipher\b|"crypto/rc4"', line):
                self.assets.append(CryptoAssetRecord("algorithm", "rc4", "go", rel, idx, "crypto/rc4", "lexical", "HIGH", purpose="encryption", snippet=raw))
            if re.search(r'"golang\.org/x/crypto/(chacha20poly1305|chacha20)"|\bchacha20poly1305\.New', line):
                self.assets.append(CryptoAssetRecord("algorithm", "chacha20", "go", rel, idx, "golang.org/x/crypto/chacha20poly1305", "lexical", "HIGH", purpose="encryption", snippet=raw))
            if re.search(r'"golang\.org/x/crypto/blowfish"|\bblowfish\.NewCipher', line):
                self.assets.append(CryptoAssetRecord("algorithm", "blowfish", "go", rel, idx, "golang.org/x/crypto/blowfish", "lexical", "HIGH", purpose="encryption", snippet=raw))
            if re.search(r'"golang\.org/x/crypto/salsa20"|\bsalsa20\.XORKeyStream', line):
                self.assets.append(CryptoAssetRecord("algorithm", "salsa20", "go", rel, idx, "golang.org/x/crypto/salsa20", "lexical", "HIGH", purpose="encryption", snippet=raw))
            if re.search(r'"golang\.org/x/crypto/ripemd160"', line):
                self.assets.append(CryptoAssetRecord("algorithm", "ripemd160", "go", rel, idx, "golang.org/x/crypto/ripemd160", "lexical", "HIGH", purpose="hashing", snippet=raw))
            if re.search(r'"golang\.org/x/crypto/md4"', line):
                self.assets.append(CryptoAssetRecord("algorithm", "md4", "go", rel, idx, "golang.org/x/crypto/md4", "lexical", "HIGH", purpose="hashing", snippet=raw))
            if re.search(r'\bcipher\.NewGCM\b', line):
                self.assets.append(CryptoAssetRecord("algorithm", "aes", "go", rel, idx, "cipher.NewGCM", "lexical", "HIGH", mode="GCM", purpose="encryption", snippet=raw))
            m_rsa = re.search(r'\brsa\.GenerateKey\s*\([^,]+,\s*(\d+)\s*\)', line)
            if m_rsa:
                self.assets.append(CryptoAssetRecord("algorithm", "rsa", "go", rel, idx, "rsa.GenerateKey", "lexical", "HIGH", key_bits=int(m_rsa.group(1)), purpose="signature", snippet=raw))
            m_ec = re.search(r'\belliptic\.(P224|P256|P384|P521)\s*\(', line)
            if m_ec:
                c_name = f"p-{m_ec.group(1)[1:]}"
                self.assets.append(CryptoAssetRecord("algorithm", "ecdsa", "go", rel, idx, f"elliptic.{m_ec.group(1)}", "lexical", "HIGH", curve=c_name, purpose="signature", snippet=raw))
            if re.search(r'InsecureSkipVerify\s*:\s*true\b', line):
                self.assets.append(CryptoAssetRecord("protocol", "tls-cert-verification-disabled", "go", rel, idx, "tls.Config.InsecureSkipVerify", "lexical", "HIGH", snippet=raw, extra={"tls_check": "cert_verification_disabled"}))
            m_tls = re.search(r'\btls\.Version(SSL30|TLS10|TLS11|TLS12|TLS13)\b', line)
            if m_tls:
                vmap = {"SSL30": "sslv3", "TLS10": "tls1.0", "TLS11": "tls1.1", "TLS12": "tls1.2", "TLS13": "tls1.3"}
                self.assets.append(CryptoAssetRecord("protocol", vmap[m_tls.group(1)], "go", rel, idx, f"tls.Version{m_tls.group(1)}", "lexical", "HIGH", snippet=raw))
            if re.search(r'\brand\.(Int|Intn|Read|Uint64|Uint32)\b', line) and _SECURITY_VAR_RE.search(line) and "crypto/rand" not in text:
                self.assets.append(CryptoAssetRecord("algorithm", "unapproved-prng", "go", rel, idx, "math/rand", "lexical", "MEDIUM", purpose="rng", snippet=raw))

    # ------------------------------------------------------------------
    # Java / Kotlin Lexical
    # ------------------------------------------------------------------
    def _scan_java(self, fpath: Path, rel: str) -> None:
        text = self._read_text(fpath)
        if text is None:
            return
        raw_lines = text.splitlines()
        clean_lines = _strip_c_style_comments(text)
        for idx, line in enumerate(clean_lines, start=1):
            raw = raw_lines[idx - 1]
            # MessageDigest.getInstance("...")
            m_md = re.search(r'MessageDigest\.getInstance\s*\(\s*"([^"]+)"', line)
            if m_md:
                alg = m_md.group(1).lower().replace("-", "")
                alg = {"sha3256": "sha3-256", "sha3384": "sha3-384", "sha3512": "sha3-512"}.get(alg, alg)
                self.assets.append(CryptoAssetRecord("algorithm", alg, "java", rel, idx, "MessageDigest.getInstance", "lexical", "HIGH", purpose="hashing", snippet=raw))
            if re.search(r'DigestUtils\.(md5|md5Hex)\b', line):
                self.assets.append(CryptoAssetRecord("algorithm", "md5", "java", rel, idx, "DigestUtils.md5", "lexical", "HIGH", purpose="hashing", snippet=raw))
            if re.search(r'DigestUtils\.(sha1|sha1Hex)\b', line):
                self.assets.append(CryptoAssetRecord("algorithm", "sha1", "java", rel, idx, "DigestUtils.sha1", "lexical", "HIGH", purpose="hashing", snippet=raw))

            # Cipher.getInstance("...")
            m_cip = re.search(r'Cipher\.getInstance\s*\(\s*"([^"]+)"', line)
            if m_cip:
                spec = m_cip.group(1)
                parts = spec.split("/")
                base_alg = parts[0].strip().lower()
                mode = parts[1].strip().upper() if len(parts) >= 2 else ("ECB" if base_alg == "aes" else None)
                alg_map = {"desede": "3des", "tripledes": "3des", "arcfour": "rc4", "chacha20-poly1305": "chacha20"}
                canon_alg = alg_map.get(base_alg, base_alg)
                self.assets.append(CryptoAssetRecord("algorithm", canon_alg, "java", rel, idx, f'Cipher.getInstance("{spec}")', "lexical", "HIGH", mode=mode, purpose="encryption", snippet=raw))

            # Mac.getInstance("...")
            m_mac = re.search(r'Mac\.getInstance\s*\(\s*"([^"]+)"', line)
            if m_mac:
                raw_m = m_mac.group(1).lower().replace("-", "")
                if raw_m.startswith("hmac"):
                    mac_alg = f"hmac-{raw_m[4:]}"
                    self.assets.append(CryptoAssetRecord("algorithm", mac_alg, "java", rel, idx, "Mac.getInstance", "lexical", "HIGH", purpose="hmac", snippet=raw))

            # KeyPairGenerator + .initialize(bits)
            m_kpg = re.search(r'\.initialize\s*\(\s*(\d{3,4})\b', line)
            if m_kpg and ("RSA" in text or "KeyPairGenerator" in text):
                self.assets.append(CryptoAssetRecord("algorithm", "rsa", "java", rel, idx, "KeyPairGenerator.initialize", "lexical", "MEDIUM", key_bits=int(m_kpg.group(1)), purpose="signature", snippet=raw))

            # ECGenParameterSpec
            m_ec = re.search(r'ECGenParameterSpec\s*\(\s*"([^"]+)"', line)
            if m_ec:
                self.assets.append(CryptoAssetRecord("algorithm", "ecdsa", "java", rel, idx, "ECGenParameterSpec", "lexical", "HIGH", curve=m_ec.group(1).lower(), purpose="signature", snippet=raw))

            # SSLContext.getInstance
            m_ssl = re.search(r'SSLContext\.getInstance\s*\(\s*"([^"]+)"', line)
            if m_ssl:
                p_raw = m_ssl.group(1).lower()
                pmap = {"ssl": "sslv3", "sslv3": "sslv3", "tlsv1": "tls1.0", "tlsv1.0": "tls1.0", "tlsv1.1": "tls1.1", "tlsv1.2": "tls1.2", "tlsv1.3": "tls1.3"}
                if p_raw in pmap:
                    self.assets.append(CryptoAssetRecord("protocol", pmap[p_raw], "java", rel, idx, f'SSLContext.getInstance("{m_ssl.group(1)}")', "lexical", "HIGH", snippet=raw))

            if re.search(r'\bnew\s+Random\s*\(', line) and _SECURITY_VAR_RE.search(line):
                self.assets.append(CryptoAssetRecord("algorithm", "unapproved-prng", "java", rel, idx, "java.util.Random", "lexical", "MEDIUM", purpose="rng", snippet=raw))

            if "CryptoServicesRegistrar.setApprovedOnlyMode(true)" in line or "BouncyCastleFipsProvider" in line:
                self.config_signals.append({
                    "kind": "java_fips_enabled",
                    "path": rel,
                    "line": idx,
                    "snippet": raw.strip(),
                })

    # ------------------------------------------------------------------
    # JavaScript / TypeScript Lexical
    # ------------------------------------------------------------------
    def _scan_js_ts(self, fpath: Path, rel: str) -> None:
        text = self._read_text(fpath)
        if text is None:
            return
        raw_lines = text.splitlines()
        clean_lines = _strip_c_style_comments(text)
        for idx, line in enumerate(clean_lines, start=1):
            raw = raw_lines[idx - 1]
            m_hash = re.search(r"""createHash\s*\(\s*['"]([^'"]+)['"]""", line)
            if m_hash:
                alg = m_hash.group(1).lower().replace("-", "")
                alg = {"sha3256": "sha3-256", "sha3384": "sha3-384", "sha3512": "sha3-512"}.get(alg, alg)
                self.assets.append(CryptoAssetRecord("algorithm", alg, "javascript", rel, idx, "crypto.createHash", "lexical", "HIGH", purpose="hashing", snippet=raw))

            m_hmac = re.search(r"""createHmac\s*\(\s*['"]([^'"]+)['"]""", line)
            if m_hmac:
                h_alg = m_hmac.group(1).lower().replace("-", "")
                self.assets.append(CryptoAssetRecord("algorithm", f"hmac-{h_alg}", "javascript", rel, idx, "crypto.createHmac", "lexical", "HIGH", purpose="hmac", snippet=raw))

            if re.search(r"""\bcreateCipher\s*\(""", line):
                self.assets.append(CryptoAssetRecord("algorithm", "md5", "javascript", rel, idx, "crypto.createCipher", "lexical", "HIGH", purpose="encryption", snippet=raw))

            m_civ = re.search(r"""createCipheriv\s*\(\s*['"]([^'"]+)['"]""", line)
            if m_civ:
                spec = m_civ.group(1).lower()
                if "ecb" in spec:
                    self.assets.append(CryptoAssetRecord("algorithm", "aes", "javascript", rel, idx, "crypto.createCipheriv", "lexical", "HIGH", mode="ECB", purpose="encryption", snippet=raw))
                elif spec.startswith(("des-ede", "des3")):
                    self.assets.append(CryptoAssetRecord("algorithm", "3des", "javascript", rel, idx, "crypto.createCipheriv", "lexical", "HIGH", purpose="encryption", snippet=raw))
                elif spec.startswith("des"):
                    self.assets.append(CryptoAssetRecord("algorithm", "des", "javascript", rel, idx, "crypto.createCipheriv", "lexical", "HIGH", purpose="encryption", snippet=raw))
                elif "rc4" in spec:
                    self.assets.append(CryptoAssetRecord("algorithm", "rc4", "javascript", rel, idx, "crypto.createCipheriv", "lexical", "HIGH", purpose="encryption", snippet=raw))
                elif spec.startswith("bf"):
                    self.assets.append(CryptoAssetRecord("algorithm", "blowfish", "javascript", rel, idx, "crypto.createCipheriv", "lexical", "HIGH", purpose="encryption", snippet=raw))
                elif "chacha20" in spec:
                    self.assets.append(CryptoAssetRecord("algorithm", "chacha20", "javascript", rel, idx, "crypto.createCipheriv", "lexical", "HIGH", purpose="encryption", snippet=raw))
                elif spec.startswith("aes") and "gcm" in spec:
                    self.assets.append(CryptoAssetRecord("algorithm", "aes", "javascript", rel, idx, "crypto.createCipheriv", "lexical", "HIGH", mode="GCM", purpose="encryption", snippet=raw))

            m_cjs = re.search(r'\bCryptoJS\.(MD5|SHA1|DES|TripleDES|RC4|SHA256|AES)\b', line)
            if m_cjs:
                cmap = {"MD5": "md5", "SHA1": "sha1", "DES": "des", "TripleDES": "3des", "RC4": "rc4", "SHA256": "sha256", "AES": "aes"}
                self.assets.append(CryptoAssetRecord("algorithm", cmap[m_cjs.group(1)], "javascript", rel, idx, f"CryptoJS.{m_cjs.group(1)}", "lexical", "HIGH", snippet=raw))

            if re.search(r'rejectUnauthorized\s*:\s*false\b', line) or re.search(r"""NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['"]0['"]""", line):
                self.assets.append(CryptoAssetRecord("protocol", "tls-cert-verification-disabled", "javascript", rel, idx, "rejectUnauthorized: false", "lexical", "HIGH", snippet=raw, extra={"tls_check": "cert_verification_disabled"}))

            m_set_fips = re.search(r'\bcrypto\.setFips\s*\(\s*(true|false|1|0)\s*\)', line)
            if m_set_fips:
                enabled = m_set_fips.group(1) in ("true", "1")
                self.config_signals.append({
                    "kind": "node_fips_enabled" if enabled else "node_fips_disabled",
                    "path": rel,
                    "line": idx,
                    "snippet": raw.strip(),
                })

            if "Math.random()" in line and _SECURITY_VAR_RE.search(line):
                self.assets.append(CryptoAssetRecord("algorithm", "unapproved-prng", "javascript", rel, idx, "Math.random", "lexical", "MEDIUM", purpose="rng", snippet=raw))

    # ------------------------------------------------------------------
    # C / C++ Lexical
    # ------------------------------------------------------------------
    def _scan_c_cpp(self, fpath: Path, rel: str) -> None:
        text = self._read_text(fpath)
        if text is None:
            return
        raw_lines = text.splitlines()
        clean_lines = _strip_c_style_comments(text)
        for idx, line in enumerate(clean_lines, start=1):
            raw = raw_lines[idx - 1]
            if re.search(r'\b(EVP_md5|MD5_Init|MD5)\s*\(', line):
                self.assets.append(CryptoAssetRecord("algorithm", "md5", "c_cpp", rel, idx, "OpenSSL MD5", "lexical", "HIGH", purpose="hashing", snippet=raw))
            if re.search(r'\b(EVP_sha1|SHA1_Init|SHA1)\s*\(', line):
                self.assets.append(CryptoAssetRecord("algorithm", "sha1", "c_cpp", rel, idx, "OpenSSL SHA1", "lexical", "HIGH", purpose="hashing", snippet=raw))
            if re.search(r'\bEVP_sha(256|384|512)\s*\(', line):
                m = re.search(r'EVP_sha(256|384|512)', line)
                if m:
                    self.assets.append(CryptoAssetRecord("algorithm", f"sha{m.group(1)}", "c_cpp", rel, idx, f"EVP_sha{m.group(1)}", "lexical", "HIGH", purpose="hashing", snippet=raw))
            if re.search(r'\bEVP_des_ede3', line):
                self.assets.append(CryptoAssetRecord("algorithm", "3des", "c_cpp", rel, idx, "EVP_des_ede3", "lexical", "HIGH", purpose="encryption", snippet=raw))
            elif re.search(r'\b(EVP_des_|DES_set_key|DES_ecb_encrypt)\b', line):
                self.assets.append(CryptoAssetRecord("algorithm", "des", "c_cpp", rel, idx, "OpenSSL DES", "lexical", "HIGH", purpose="encryption", snippet=raw))
            if re.search(r'\b(EVP_rc4|RC4_set_key)\b', line):
                self.assets.append(CryptoAssetRecord("algorithm", "rc4", "c_cpp", rel, idx, "OpenSSL RC4", "lexical", "HIGH", purpose="encryption", snippet=raw))
            if re.search(r'\bEVP_aes_(128|192|256)_ecb\s*\(', line):
                self.assets.append(CryptoAssetRecord("algorithm", "aes", "c_cpp", rel, idx, "EVP_aes_*_ecb", "lexical", "HIGH", mode="ECB", purpose="encryption", snippet=raw))
            if re.search(r'\bEVP_aes_(128|192|256)_gcm\s*\(', line):
                self.assets.append(CryptoAssetRecord("algorithm", "aes", "c_cpp", rel, idx, "EVP_aes_*_gcm", "lexical", "HIGH", mode="GCM", purpose="encryption", snippet=raw))
            if re.search(r'OSSL_PROVIDER_load\s*\([^,]+,\s*"fips"\s*\)', line) or re.search(r'EVP_default_properties_enable_fips\s*\([^,]+,\s*1\s*\)', line):
                self.config_signals.append({"kind": "openssl_fips_enabled", "path": rel, "line": idx, "snippet": raw.strip()})
            if re.search(r'FIPS_mode_set\s*\(\s*0\s*\)', line) or re.search(r'EVP_default_properties_enable_fips\s*\([^,]+,\s*0\s*\)', line):
                self.config_signals.append({"kind": "openssl_fips_disabled", "path": rel, "line": idx, "snippet": raw.strip()})
            elif re.search(r'FIPS_mode_set\s*\(\s*1\s*\)', line):
                self.config_signals.append({"kind": "openssl_1x_fips_api", "path": rel, "line": idx, "snippet": raw.strip()})

    # ------------------------------------------------------------------
    # Rust Lexical
    # ------------------------------------------------------------------
    def _scan_rust(self, fpath: Path, rel: str) -> None:
        text = self._read_text(fpath)
        if text is None:
            return
        raw_lines = text.splitlines()
        clean_lines = _strip_c_style_comments(text)
        for idx, line in enumerate(clean_lines, start=1):
            raw = raw_lines[idx - 1]
            if re.search(r'\bmd5::(Md5|compute)\b', line):
                self.assets.append(CryptoAssetRecord("algorithm", "md5", "rust", rel, idx, "md5::Md5", "lexical", "HIGH", purpose="hashing", snippet=raw))
            if re.search(r'\bsha1::Sha1\b', line):
                self.assets.append(CryptoAssetRecord("algorithm", "sha1", "rust", rel, idx, "sha1::Sha1", "lexical", "HIGH", purpose="hashing", snippet=raw))
            if re.search(r'\bsha2::Sha(256|384|512)\b', line):
                m = re.search(r'Sha(256|384|512)', line)
                if m:
                    self.assets.append(CryptoAssetRecord("algorithm", f"sha{m.group(1)}", "rust", rel, idx, f"sha2::Sha{m.group(1)}", "lexical", "HIGH", purpose="hashing", snippet=raw))
            if re.search(r'\bchacha20poly1305::ChaCha20Poly1305\b', line):
                self.assets.append(CryptoAssetRecord("algorithm", "chacha20", "rust", rel, idx, "chacha20poly1305", "lexical", "HIGH", purpose="encryption", snippet=raw))
            if re.search(r'\bdes::(Des|TdesEde3)\b', line):
                is_3 = "Tdes" in line
                self.assets.append(CryptoAssetRecord("algorithm", "3des" if is_3 else "des", "rust", rel, idx, "des crate", "lexical", "HIGH", purpose="encryption", snippet=raw))
            if "danger_accept_invalid_certs" in line:
                self.assets.append(CryptoAssetRecord("protocol", "tls-cert-verification-disabled", "rust", rel, idx, "danger_accept_invalid_certs", "lexical", "HIGH", snippet=raw, extra={"tls_check": "cert_verification_disabled"}))

    # ------------------------------------------------------------------
    # .NET / C# Lexical
    # ------------------------------------------------------------------
    def _scan_csharp(self, fpath: Path, rel: str) -> None:
        text = self._read_text(fpath)
        if text is None:
            return
        raw_lines = text.splitlines()
        clean_lines = _strip_c_style_comments(text)
        for idx, line in enumerate(clean_lines, start=1):
            raw = raw_lines[idx - 1]
            if re.search(r'\b(MD5\.Create|new\s+MD5CryptoServiceProvider)\b', line):
                self.assets.append(CryptoAssetRecord("algorithm", "md5", "csharp", rel, idx, "System.Security.Cryptography.MD5", "lexical", "HIGH", purpose="hashing", snippet=raw))
            if re.search(r'\b(SHA1\.Create|new\s+SHA1Managed|new\s+SHA1CryptoServiceProvider)\b', line):
                self.assets.append(CryptoAssetRecord("algorithm", "sha1", "csharp", rel, idx, "System.Security.Cryptography.SHA1", "lexical", "HIGH", purpose="hashing", snippet=raw))
            if re.search(r'\bSHA(256|384|512)\.Create\b', line):
                m = re.search(r'SHA(256|384|512)', line)
                if m:
                    self.assets.append(CryptoAssetRecord("algorithm", f"sha{m.group(1)}", "csharp", rel, idx, f"SHA{m.group(1)}.Create", "lexical", "HIGH", purpose="hashing", snippet=raw))
            if re.search(r'\b(TripleDES\.Create|new\s+TripleDESCryptoServiceProvider)\b', line):
                self.assets.append(CryptoAssetRecord("algorithm", "3des", "csharp", rel, idx, "TripleDES", "lexical", "HIGH", purpose="encryption", snippet=raw))
            elif re.search(r'\b(DES\.Create|new\s+DESCryptoServiceProvider)\b', line):
                self.assets.append(CryptoAssetRecord("algorithm", "des", "csharp", rel, idx, "DES", "lexical", "HIGH", purpose="encryption", snippet=raw))
            if re.search(r'\bRC2\.Create\b', line):
                self.assets.append(CryptoAssetRecord("algorithm", "rc2", "csharp", rel, idx, "RC2.Create", "lexical", "HIGH", purpose="encryption", snippet=raw))
            if "CipherMode.ECB" in line:
                self.assets.append(CryptoAssetRecord("algorithm", "aes", "csharp", rel, idx, "CipherMode.ECB", "lexical", "HIGH", mode="ECB", purpose="encryption", snippet=raw))
            if re.search(r'\bnew\s+AesGcm\b', line):
                self.assets.append(CryptoAssetRecord("algorithm", "aes", "csharp", rel, idx, "AesGcm", "lexical", "HIGH", mode="GCM", purpose="encryption", snippet=raw))
            m_rsa = re.search(r'\bRSA\.Create\s*\(\s*(\d{3,4})\s*\)', line)
            if m_rsa:
                self.assets.append(CryptoAssetRecord("algorithm", "rsa", "csharp", rel, idx, "RSA.Create", "lexical", "HIGH", key_bits=int(m_rsa.group(1)), purpose="signature", snippet=raw))
            if re.search(r'ServerCertificateCustomValidationCallback\s*=.*=>\s*true\b', line):
                self.assets.append(CryptoAssetRecord("protocol", "tls-cert-verification-disabled", "csharp", rel, idx, "ServerCertificateCustomValidationCallback", "lexical", "HIGH", snippet=raw, extra={"tls_check": "cert_verification_disabled"}))

    # ------------------------------------------------------------------
    # Config & Infrastructure Detectors (AOC-12 & AOC-05)
    # ------------------------------------------------------------------
    def _scan_grub(self, fpath: Path, rel: str) -> None:
        text = self._read_text(fpath)
        if text is None:
            return
        found_cmdline = False
        for idx, raw_line in enumerate(text.splitlines(), start=1):
            line = raw_line.split("#", 1)[0].strip()
            if not line or "GRUB_CMDLINE_LINUX" not in line:
                continue
            found_cmdline = True
            if re.search(r'\bfips=0\b', line):
                self.config_signals.append({
                    "kind": "kernel_fips_disabled",
                    "path": rel,
                    "line": idx,
                    "snippet": raw_line.strip(),
                    "evidence_tag": f"{rel}:fips=0",
                })
            elif re.search(r'\bfips=1\b', line):
                self.config_signals.append({
                    "kind": "kernel_fips_enabled",
                    "path": rel,
                    "line": idx,
                    "snippet": raw_line.strip(),
                    "evidence_tag": f"{rel}:fips=1",
                })
            else:
                self.config_signals.append({
                    "kind": "kernel_fips_missing",
                    "path": rel,
                    "line": idx,
                    "snippet": raw_line.strip(),
                    "evidence_tag": f"{rel}:missing_fips=1",
                })
        if not found_cmdline and text.strip():
            self.config_signals.append({
                "kind": "kernel_fips_missing",
                "path": rel,
                "line": 1,
                "snippet": text.splitlines()[0].strip(),
                "evidence_tag": f"{rel}:missing_fips=1",
            })

    def _scan_crypto_policy(self, fpath: Path, rel: str) -> None:
        text = self._read_text(fpath)
        if text is None:
            return
        for idx, raw_line in enumerate(text.splitlines(), start=1):
            line = raw_line.split("#", 1)[0].strip()
            if not line:
                continue
            upper = line.upper()
            if upper == "FIPS" or upper.startswith("FIPS:"):
                self.config_signals.append({
                    "kind": "crypto_policy_fips",
                    "path": rel,
                    "line": idx,
                    "snippet": raw_line.strip(),
                    "policy": upper,
                    "evidence_tag": f"{rel}:{upper}",
                })
            else:
                self.config_signals.append({
                    "kind": "crypto_policy_non_fips",
                    "path": rel,
                    "line": idx,
                    "snippet": raw_line.strip(),
                    "policy": upper,
                    "evidence_tag": f"{rel}:{upper}",
                })

    def _scan_openssl_cnf(self, fpath: Path, rel: str) -> None:
        text = self._read_text(fpath)
        if text is None:
            return
        # Only inspect actual OpenSSL config files (having openssl_conf, providers, fips_sect, or default_properties)
        if not re.search(r'(openssl_conf|provider_sect|fips_sect|default_properties|fipsmodule\.cnf)', text):
            return
        section = ""
        fips_sect_line: Optional[int] = None
        fips_activated = False
        default_props_fips = False
        first_active_line = 1

        for idx, raw_line in enumerate(text.splitlines(), start=1):
            line = raw_line.split("#", 1)[0].strip()
            if not line:
                continue
            if first_active_line == 1:
                first_active_line = idx
            if line.startswith("[") and line.endswith("]"):
                section = line[1:-1].strip().lower()
                if section == "fips_sect":
                    fips_sect_line = idx
                continue
            if section == "fips_sect" and re.match(r'^activate\s*=\s*(1|yes|true)\b', line, re.IGNORECASE):
                fips_activated = True
                fips_sect_line = fips_sect_line or idx
            if re.search(r'default_properties\s*=\s*["\']?[^"\']*fips\s*=\s*yes', line, re.IGNORECASE):
                default_props_fips = True
                fips_sect_line = fips_sect_line or idx

        if fips_activated or default_props_fips:
            self.config_signals.append({
                "kind": "openssl_fips_enabled",
                "path": rel,
                "line": fips_sect_line or first_active_line,
                "snippet": "[fips_sect] activate = 1" if fips_activated else "default_properties = fips=yes",
                "evidence_tag": f"{rel}:fips_activated",
            })
        else:
            self.config_signals.append({
                "kind": "openssl_fips_disabled",
                "path": rel,
                "line": first_active_line,
                "snippet": text.splitlines()[first_active_line - 1].strip(),
                "evidence_tag": f"{rel}:missing_fips_activation",
            })

    def _scan_java_security(self, fpath: Path, rel: str) -> None:
        text = self._read_text(fpath)
        if text is None or "security.provider." not in text:
            return
        providers: List[Tuple[int, str, int, str]] = []
        for idx, raw_line in enumerate(text.splitlines(), start=1):
            line = raw_line.split("#", 1)[0].strip()
            m = re.match(r'^security\.provider\.(\d+)\s*=\s*(.+)$', line)
            if m:
                providers.append((int(m.group(1)), m.group(2).strip(), idx, raw_line.strip()))
        if not providers:
            return
        providers.sort(key=lambda x: x[0])
        fips_keywords = ("bouncycastlefipsprovider", "sunpkcs11-nss-fips", "openjceplusfips", "ibmjcefips", "bcfips")
        top_prio, top_prov, top_line, top_raw = providers[0]
        if any(k in top_prov.lower() for k in fips_keywords):
            self.config_signals.append({
                "kind": "java_fips_enabled",
                "path": rel,
                "line": top_line,
                "snippet": top_raw,
                "evidence_tag": f"{rel}:security.provider.{top_prio}={top_prov}",
            })
        else:
            self.config_signals.append({
                "kind": "java_fips_disabled",
                "path": rel,
                "line": top_line,
                "snippet": top_raw,
                "provider": top_prov,
                "evidence_tag": f"{rel}:security.provider.{top_prio}={top_prov}",
            })

    def _scan_dockerfile(self, fpath: Path, rel: str) -> None:
        text = self._read_text(fpath)
        if text is None:
            return

        # Reconstruct logical backslash-continued commands alongside raw per-line directives
        logical_cmds: List[Tuple[int, str]] = []
        buf_parts: List[str] = []
        buf_start = 1
        for idx, raw_line in enumerate(text.splitlines(), start=1):
            stripped_comment = raw_line.split("#", 1)[0].strip()
            if not stripped_comment:
                if buf_parts:
                    logical_cmds.append((buf_start, " ".join(buf_parts)))
                    buf_parts = []
                continue
            if not buf_parts:
                buf_start = idx
            if stripped_comment.endswith("\\"):
                buf_parts.append(stripped_comment[:-1].strip())
            else:
                buf_parts.append(stripped_comment)
                logical_cmds.append((buf_start, " ".join(buf_parts)))
                buf_parts = []
        if buf_parts:
            logical_cmds.append((buf_start, " ".join(buf_parts)))

        has_sys_openssl_py = False
        sys_py_line = 1
        has_pypi_wheel_py = False
        pypi_wheel_line = 1

        for idx, line in logical_cmds:
            m_from = re.match(r'^FROM\s+(?:--platform=[^\s]+\s+)?([^\s]+)', line, re.IGNORECASE)
            if m_from:
                self.config_signals.append({
                    "kind": "dockerfile_base_image",
                    "path": rel,
                    "line": idx,
                    "image": m_from.group(1),
                    "snippet": line,
                })
            if re.search(r'GODEBUG\s*=\s*["\']?[^"\']*fips140=(on|only)', line):
                self.config_signals.append({"kind": "go_fips_enabled", "path": rel, "line": idx, "snippet": line})
            elif re.search(r'GODEBUG\s*=\s*["\']?[^"\']*fips140=off', line):
                self.config_signals.append({"kind": "go_fips_disabled", "path": rel, "line": idx, "snippet": line})
            if "GOEXPERIMENT=boringcrypto" in line:
                self.config_signals.append({"kind": "go_boringcrypto_enabled", "path": rel, "line": idx, "snippet": line})
            if "--enable-fips" in line or "--force-fips" in line:
                self.config_signals.append({"kind": "node_fips_enabled", "path": rel, "line": idx, "snippet": line})

            if re.search(r'\b(dnf|yum|microdnf|apt-get|apt|apk|zypper)\b.*\b(python3?-cryptography|py3-cryptography)\b', line, re.IGNORECASE) or (
                re.search(r'--no-binary(?:\s+|=)(?::all:|.*\bcryptography\b)', line, re.IGNORECASE)
            ) or re.search(r'\bPIP_NO_BINARY\s*=\s*["\']?(?::all:|[^"\']*\bcryptography\b)', line, re.IGNORECASE):
                has_sys_openssl_py = True
                sys_py_line = idx
            elif re.search(r'\bpip3?\s+install\b', line, re.IGNORECASE):
                has_pypi_wheel_py = True
                pypi_wheel_line = idx

        if has_sys_openssl_py:
            self.config_signals.append({
                "kind": "dockerfile_python_system_openssl",
                "path": rel,
                "line": sys_py_line,
                "evidence_tag": f"{rel}:system-openssl-linked",
            })
        elif has_pypi_wheel_py:
            self.config_signals.append({
                "kind": "dockerfile_python_pypi_wheel",
                "path": rel,
                "line": pypi_wheel_line,
                "evidence_tag": f"{rel}:pypi-wheel-install",
            })

    def _scan_iac_hcl(self, fpath: Path, rel: str) -> None:
        text = self._read_text(fpath)
        if text is None:
            return
        for idx, raw_line in enumerate(text.splitlines(), start=1):
            line = raw_line.split("#", 1)[0].strip()
            if not line:
                continue
            if re.search(r'\bfips=0\b', line):
                self.config_signals.append({
                    "kind": "kernel_fips_disabled",
                    "path": rel,
                    "line": idx,
                    "snippet": raw_line.strip(),
                    "evidence_tag": f"{rel}:fips=0",
                })
            if re.search(r'update-crypto-policies\s+--set\s+(DEFAULT|LEGACY|FUTURE)\b', line):
                m = re.search(r'--set\s+(DEFAULT|LEGACY|FUTURE)', line)
                pol = m.group(1) if m else "DEFAULT"
                self.config_signals.append({
                    "kind": "crypto_policy_non_fips",
                    "path": rel,
                    "line": idx,
                    "snippet": raw_line.strip(),
                    "policy": pol,
                    "evidence_tag": f"{rel}:{pol}",
                })
            if re.search(r'TLSv1_(0|1)|TLS-1-(0|1)|SSLv3', line):
                self.assets.append(CryptoAssetRecord("protocol", "tls1.0", "hcl", rel, idx, "IaC TLS Policy", "config", "HIGH", snippet=raw_line))

    def _scan_shell(self, fpath: Path, rel: str) -> None:
        text = self._read_text(fpath)
        if text is None:
            return
        for idx, raw_line in enumerate(text.splitlines(), start=1):
            line = raw_line.split("#", 1)[0].strip()
            if not line:
                continue
            if re.search(r'grubby\b.*\bfips=0\b', line):
                self.config_signals.append({"kind": "kernel_fips_disabled", "path": rel, "line": idx, "snippet": raw_line.strip(), "evidence_tag": f"{rel}:fips=0"})
            if re.search(r'update-crypto-policies\s+--set\s+(DEFAULT|LEGACY)\b', line):
                self.config_signals.append({"kind": "crypto_policy_non_fips", "path": rel, "line": idx, "snippet": raw_line.strip(), "policy": "DEFAULT", "evidence_tag": f"{rel}:DEFAULT"})

    def _scan_dotnet_config(self, fpath: Path, rel: str) -> None:
        text = self._read_text(fpath)
        if text is None:
            return
        for idx, raw_line in enumerate(text.splitlines(), start=1):
            m = re.search(r'<enforceFIPSPolicy\s+enabled\s*=\s*"(true|false)"', raw_line, re.IGNORECASE)
            if m:
                enabled = m.group(1).lower() == "true"
                self.config_signals.append({
                    "kind": "dotnet_fips_enabled" if enabled else "dotnet_fips_disabled",
                    "path": rel,
                    "line": idx,
                    "snippet": raw_line.strip(),
                })

    def _scan_nginx_conf(self, fpath: Path, rel: str) -> None:
        text = self._read_text(fpath)
        if text is None:
            return
        for idx, raw_line in enumerate(text.splitlines(), start=1):
            line = raw_line.split("#", 1)[0].strip()
            if line.startswith("ssl_protocols"):
                if re.search(r'\b(SSLv2|SSLv3|TLSv1|TLSv1\.1)(?=\s|;)', line):
                    self.assets.append(CryptoAssetRecord("protocol", "tls1.0", "nginx", rel, idx, "ssl_protocols", "config", "HIGH", snippet=raw_line))
                elif re.search(r'\bTLSv1\.(2|3)\b', line):
                    self.assets.append(CryptoAssetRecord("protocol", "tls1.2", "nginx", rel, idx, "ssl_protocols", "config", "HIGH", snippet=raw_line))
            if line.startswith("ssl_ciphers"):
                if re.search(r'(^|[:\s!])(?!\!)(RC4|3DES|DES|MD5|aNULL|eNULL|EXPORT)\b', line, re.IGNORECASE):
                    self.assets.append(CryptoAssetRecord("protocol", "tls-unapproved-ciphersuite", "nginx", rel, idx, "ssl_ciphers", "config", "HIGH", snippet=raw_line, extra={"tls_check": "non_approved_cipher_suite"}))

    def _scan_yaml_config(self, fpath: Path, rel: str) -> None:
        text = self._read_text(fpath)
        if text is None:
            return
        for idx, raw_line in enumerate(text.splitlines(), start=1):
            line = raw_line.split("#", 1)[0].strip()
            if not line:
                continue
            if re.search(r'GODEBUG.*fips140=(on|only)', line):
                self.config_signals.append({"kind": "go_fips_enabled", "path": rel, "line": idx, "snippet": raw_line.strip()})
            if re.search(r'minVersion\s*:\s*["\']?VersionTLS1[01]["\']?', line) or re.search(r'tlsMinimumProtocolVersion\s*:\s*["\']?TLSv1_[01]["\']?', line):
                self.assets.append(CryptoAssetRecord("protocol", "tls1.0", "yaml", rel, idx, "K8s TLS minVersion", "config", "HIGH", snippet=raw_line))


# ==============================================================================
# PHASE 3 & 4 EVALUATION ENGINE (Policy + CMVP + Approved Mode)
# ==============================================================================

class FIPSAssessmentEngine:
    """Evaluates discovered source/config assets and dependencies against NIST & CMVP catalogs."""

    def __init__(
        self,
        workspace_root: Path,
        policy_path: Optional[Path] = None,
        cmvp_path: Optional[Path] = None,
        crypto_catalog_path: Optional[Path] = None,
        staleness_days: Optional[int] = None,
    ):
        self.workspace_root = Path(workspace_root).resolve()
        self.policy_path = Path(policy_path) if policy_path else FIPS_ALGORITHM_POLICY_PATH
        self.cmvp_path = Path(cmvp_path) if cmvp_path else CMVP_CATALOG_PATH
        self.crypto_catalog_path = Path(crypto_catalog_path) if crypto_catalog_path else CRYPTO_CATALOG_PATH

        self.policy = load_algorithm_policy(self.policy_path)
        self.cmvp = load_cmvp_catalog(self.cmvp_path)
        self.crypto_catalog = load_crypto_catalog(self.crypto_catalog_path)
        self.staleness_warning = check_cmvp_staleness(self.cmvp, threshold_days=staleness_days)
        self.cmvp_integrity = verify_catalog_authenticity(self.cmvp_path)

        self.ws_scanner = WorkspaceCryptoScanner(self.workspace_root)
        self.dependencies: List[Tuple[str, str, str, str]] = []
        self.cargo_features: Dict[str, Set[str]] = {}
        self.findings: List[Dict[str, Any]] = []
        self.cmvp_mappings: List[Dict[str, Any]] = []
        self.mode_flags: Set[str] = set()
        self.mode_evidence_by_flag: Dict[str, List[str]] = {}
        self.mode_signal_records: List[Dict[str, str]] = []

    def run(self) -> Dict[str, Any]:
        self.ws_scanner.scan()
        self.dependencies = DependencyExtractor.extract_from_workspace(self.workspace_root)
        self.cargo_features = DependencyExtractor.extract_cargo_features(self.workspace_root)

        cargo_files = [
            p.relative_to(self.workspace_root).as_posix()
            for p in sorted(self.workspace_root.rglob("Cargo.toml"))
            if not (set(p.relative_to(self.workspace_root).parts) & SKIP_DIRS)
        ]
        cargo_path = cargo_files[0] if len(cargo_files) == 1 else "Cargo.toml"

        # Register Cargo 'fips' feature signals
        for crate, feats in self.cargo_features.items():
            if crate in ("aws-lc-rs", "aws-lc-fips-sys", "rustls", "boring") and "fips" in feats:
                c_match = cargo_path
                if len(cargo_files) > 1:
                    for cand_rel in cargo_files:
                        try:
                            if crate in (self.workspace_root / cand_rel).read_text(encoding="utf-8", errors="ignore").lower():
                                c_match = cand_rel
                                break
                        except OSError:
                            pass
                self.ws_scanner.config_signals.append({
                    "kind": "rust_fips_feature",
                    "path": c_match,
                    "line": 1,
                    "snippet": f'{crate} features = {sorted(feats)}',
                    "evidence_tag": f"{c_match}:{crate}[fips]",
                })

        self._evaluate_config_signals()
        self._evaluate_assets()
        self._evaluate_dependencies_and_cmvp()

        # Sort findings deterministically by severity rank, determination, path, line
        det_order = {"FAIL": 0, "WARN": 1, "NEEDS_REVIEW": 2, "CANNOT_DETERMINE_STATICALLY": 3, "PASS": 4}
        self.findings.sort(
            key=lambda f: (
                det_order.get(f["determination"], 9),
                SEVERITY_RANK.get(str(f.get("severity") or "INFO"), 9),
                f["location"].get("path", ""),
                f["location"].get("line_start") or 0,
                f["rule_id"],
            )
        )
        return self.build_envelope()

    def _record_mode_flag(self, flag: str, tag: str, path: str = "") -> None:
        self.mode_flags.add(flag)
        self.mode_evidence_by_flag.setdefault(flag, []).append(tag)
        self.mode_signal_records.append({
            "flag": flag,
            "tag": tag,
            "path": path.replace("\\", "/").lstrip("./"),
        })

    # ------------------------------------------------------------------
    # Phase 4 Approved-Mode Config Evaluation (AOC-12)
    # ------------------------------------------------------------------
    def _evaluate_config_signals(self) -> None:
        base_img_rules = self.cmvp.get("base_image_mappings", [])
        certs_db = self.cmvp.get("certificates", {})

        for sig in self.ws_scanner.config_signals:
            kind = sig["kind"]
            path = sig["path"]
            line = sig.get("line", 1)
            snippet = _redact_snippet(sig.get("snippet", ""))
            tag = sig.get("evidence_tag", f"{path}:{line}")

            if kind == "kernel_fips_disabled":
                self._record_mode_flag("kernel_fips_disabled", tag, path=path)
                self._add_finding(
                    rule_id="fips-cfg:kernel-fips-disabled",
                    aoc_str="AOC-12: Lack of FIPS Mode",
                    controls=["SC-13", "CM-6"],
                    determination="FAIL",
                    determination_detail="APPROVED_MODE_DISABLED",
                    severity="HIGH",
                    subject={"kind": "config_setting", "name": "grub:fips"},
                    location={"kind": "file", "path": path, "line_start": line},
                    detection={"method": "config", "confidence": "HIGH"},
                    title="Kernel FIPS mode explicitly disabled (fips=0)",
                    message=f"Bootloader/kernel configuration in '{path}' explicitly sets fips=0.",
                    remediation="Configure kernel command line with fips=1 (e.g., fips-mode-setup --enable) and rebuild initramfs.",
                    snippet=snippet,
                    references=["NIST SP 800-53 Rev. 5 SC-13", "NIST FIPS 140-3"],
                    fips_ext={"approved_mode_evidence": [tag]},
                )
            elif kind == "kernel_fips_missing":
                self._record_mode_flag("kernel_fips_disabled", tag, path=path)
                self._add_finding(
                    rule_id="fips-cfg:kernel-fips-missing",
                    aoc_str="AOC-12: Lack of FIPS Mode",
                    controls=["SC-13", "CM-6"],
                    determination="FAIL",
                    determination_detail="APPROVED_MODE_MISSING",
                    severity="HIGH",
                    subject={"kind": "config_setting", "name": "grub:fips"},
                    location={"kind": "file", "path": path, "line_start": line},
                    detection={"method": "config", "confidence": "HIGH"},
                    title="Kernel command line omits fips=1 boot parameter",
                    message=f"GRUB bootloader configuration in '{path}' does not enable kernel FIPS mode (fips=1).",
                    remediation="Enable OS kernel FIPS mode via 'fips-mode-setup --enable' so GRUB_CMDLINE_LINUX includes fips=1.",
                    snippet=snippet,
                    references=["NIST SP 800-53 Rev. 5 SC-13"],
                    fips_ext={"approved_mode_evidence": [tag]},
                )
            elif kind == "kernel_fips_enabled":
                self._record_mode_flag("kernel_fips_enabled", tag, path=path)
                self._add_finding(
                    rule_id="fips-cfg:kernel-fips-enabled",
                    aoc_str="AOC-12: Lack of FIPS Mode",
                    controls=["SC-13", "CM-6"],
                    determination="PASS",
                    determination_detail="CONFORMANT_INDICATOR",
                    subject={"kind": "config_setting", "name": "grub:fips"},
                    location={"kind": "file", "path": path, "line_start": line},
                    detection={"method": "config", "confidence": "HIGH"},
                    title="Kernel FIPS boot parameter (fips=1) configured",
                    message=f"Bootloader configuration in '{path}' includes fips=1.",
                    snippet=snippet,
                    fips_ext={"approved_mode_evidence": [tag]},
                )

            elif kind == "crypto_policy_non_fips":
                pol = sig.get("policy", "DEFAULT")
                self._record_mode_flag("crypto_policy_disabled", tag, path=path)
                self._add_finding(
                    rule_id="fips-cfg:crypto-policy-non-fips",
                    aoc_str="AOC-12: Lack of FIPS Mode",
                    controls=["SC-13", "CM-6"],
                    determination="FAIL",
                    determination_detail="APPROVED_MODE_DISABLED",
                    severity="HIGH",
                    subject={"kind": "config_setting", "name": "crypto-policies:config"},
                    location={"kind": "file", "path": path, "line_start": line},
                    detection={"method": "config", "confidence": "HIGH"},
                    title=f"System cryptographic policy set to non-FIPS profile ({pol})",
                    message=f"System-wide crypto-policies configuration in '{path}' is set to '{pol}' instead of 'FIPS'.",
                    remediation="Set system-wide crypto policy to 'FIPS' (or 'FIPS:OSPP') using 'update-crypto-policies --set FIPS'.",
                    snippet=snippet,
                    references=["NIST SP 800-53 Rev. 5 SC-13", "NIST SP 800-52 Rev. 2"],
                    fips_ext={"approved_mode_evidence": [tag]},
                )
            elif kind == "crypto_policy_fips":
                self._record_mode_flag("openssl_fips_enabled", tag, path=path)
                self._add_finding(
                    rule_id="fips-cfg:crypto-policy-fips",
                    aoc_str="AOC-12: Lack of FIPS Mode",
                    controls=["SC-13", "CM-6"],
                    determination="PASS",
                    determination_detail="CONFORMANT_INDICATOR",
                    subject={"kind": "config_setting", "name": "crypto-policies:config"},
                    location={"kind": "file", "path": path, "line_start": line},
                    detection={"method": "config", "confidence": "HIGH"},
                    title="System cryptographic policy set to FIPS profile",
                    message=f"System-wide crypto-policies configuration in '{path}' enforces FIPS profile.",
                    snippet=snippet,
                    fips_ext={"approved_mode_evidence": [tag]},
                )

            elif kind == "openssl_fips_disabled":
                self._record_mode_flag("openssl_fips_disabled", tag, path=path)
                self._add_finding(
                    rule_id="fips-cfg:openssl-fips-not-activated",
                    aoc_str="AOC-12: Lack of FIPS Mode",
                    controls=["SC-13", "CM-6"],
                    determination="FAIL",
                    determination_detail="APPROVED_MODE_DISABLED",
                    severity="HIGH",
                    subject={"kind": "config_setting", "name": "openssl.cnf:fips_sect"},
                    location={"kind": "file", "path": path, "line_start": line},
                    detection={"method": "config", "confidence": "HIGH"},
                    title="OpenSSL FIPS provider not activated in configuration",
                    message=f"OpenSSL configuration in '{path}' does not activate [fips_sect] (activate = 1) or set default_properties = fips=yes.",
                    remediation="Include fipsmodule.cnf, enable 'fips = fips_sect' under [provider_sect], set '[fips_sect] activate = 1', and enforce 'default_properties = fips=yes'.",
                    snippet=snippet,
                    references=["NIST SP 800-53 Rev. 5 SC-13", "NIST FIPS 140-3"],
                    fips_ext={"approved_mode_evidence": [tag]},
                )
            elif kind == "openssl_fips_enabled":
                self._record_mode_flag("openssl_fips_enabled", tag, path=path)
                self._add_finding(
                    rule_id="fips-cfg:openssl-fips-activated",
                    aoc_str="AOC-12: Lack of FIPS Mode",
                    controls=["SC-13", "CM-6"],
                    determination="PASS",
                    determination_detail="CONFORMANT_INDICATOR",
                    subject={"kind": "config_setting", "name": "openssl.cnf:fips_sect"},
                    location={"kind": "file", "path": path, "line_start": line},
                    detection={"method": "config", "confidence": "HIGH"},
                    title="OpenSSL 3 FIPS provider activation indicator detected",
                    message=f"OpenSSL FIPS provider activation configured in '{path}'.",
                    snippet=snippet,
                    fips_ext={"approved_mode_evidence": [tag]},
                )
            elif kind == "openssl_1x_fips_api":
                self._add_finding(
                    rule_id="fips-cfg:openssl-1x-historical-api",
                    aoc_str="AOC-12: Lack of FIPS Mode",
                    controls=["SC-13"],
                    determination="FAIL",
                    determination_detail="FAIL_HISTORICAL_CERT",
                    severity="HIGH",
                    subject={"kind": "code_pattern", "name": "fips_mode_set"},
                    location={"kind": "file", "path": path, "line_start": line},
                    detection={"method": "lexical", "confidence": "HIGH"},
                    title="Legacy OpenSSL 1.x FIPS_mode_set() API detected (Historical 140-2)",
                    message="FIPS_mode_set(1) belongs to the End-of-Life OpenSSL 1.0.2 FIPS Object Module, whose FIPS 140-2 certificate (#1747) is Historical.",
                    remediation="Migrate to OpenSSL 3.x provider APIs: OSSL_PROVIDER_load(NULL, \"fips\") and EVP_default_properties_enable_fips(NULL, 1).",
                    snippet=snippet,
                    references=["NIST CMVP FIPS 140-2 Sunset (2026-09-21)", "NIST SP 800-53 Rev. 5 SC-13"],
                    fips_ext={"cmvp_cert": "1747", "cert_standard": "FIPS 140-2", "cert_status": "Historical"},
                )

            elif kind == "java_fips_disabled":
                prov = sig.get("provider", "sun.security.provider.Sun")
                self._record_mode_flag("java_fips_disabled", tag, path=path)
                self._add_finding(
                    rule_id="fips-cfg:java-security-non-fips-provider",
                    aoc_str="AOC-12: Lack of FIPS Mode",
                    controls=["SC-13", "CM-6"],
                    determination="FAIL",
                    determination_detail="APPROVED_MODE_DISABLED",
                    severity="HIGH",
                    subject={"kind": "config_setting", "name": "java.security:security.provider.1"},
                    location={"kind": "file", "path": path, "line_start": line},
                    detection={"method": "config", "confidence": "HIGH"},
                    title=f"Java security.provider.1 configured to non-FIPS provider ({prov})",
                    message=f"Java security configuration in '{path}' registers unvalidated provider '{prov}' at highest priority without a validated FIPS provider.",
                    remediation="Configure a CMVP-validated JCA/JCE provider (e.g., BouncyCastleFipsProvider 2.0.x or SunPKCS11-NSS-FIPS) as security.provider.1 in approved-only mode.",
                    snippet=snippet,
                    references=["NIST SP 800-53 Rev. 5 SC-13", "NIST FIPS 140-3"],
                    fips_ext={"approved_mode_evidence": [tag]},
                )
            elif kind == "java_fips_enabled":
                self._record_mode_flag("java_fips_enabled", tag, path=path)
                self._add_finding(
                    rule_id="fips-cfg:java-security-fips-provider",
                    aoc_str="AOC-12: Lack of FIPS Mode",
                    controls=["SC-13", "CM-6"],
                    determination="PASS",
                    determination_detail="CONFORMANT_INDICATOR",
                    subject={"kind": "config_setting", "name": "java.security:security.provider.1"},
                    location={"kind": "file", "path": path, "line_start": line},
                    detection={"method": "config", "confidence": "HIGH"},
                    title="Java FIPS cryptographic provider configuration indicator detected",
                    message=f"FIPS provider or approved-only mode registration found in '{path}'.",
                    snippet=snippet,
                    fips_ext={"approved_mode_evidence": [tag]},
                )

            elif kind == "python_fips_mode_unenforced":
                self._add_finding(
                    rule_id="fips-cfg:python-fips-mode-unenforced",
                    aoc_str="AOC-12: Lack of FIPS Mode",
                    controls=["SC-13"],
                    determination="FAIL",
                    determination_detail="APPROVED_MODE_DISABLED",
                    severity="MEDIUM",
                    subject={"kind": "code_pattern", "name": "ssl.fips_mode"},
                    location={"kind": "file", "path": path, "line_start": line},
                    detection={"method": "ast", "confidence": "HIGH"},
                    title="Python ssl.FIPS_mode fallback defaults to disabled (0) without enforcement",
                    message="Code probes ssl.FIPS_mode with a default fallback of 0 (disabled) and uses an OpenSSL 1.x attribute removed in OpenSSL 3 / modern Python.",
                    remediation="Link Python against a CMVP-validated OpenSSL 3 FIPS provider (openssl.cnf [fips_sect] activate = 1) and fail closed when FIPS provider self-checks are absent.",
                    snippet=snippet,
                    references=["NIST SP 800-53 Rev. 5 SC-13"],
                    fips_ext={"approved_mode_evidence": [f"{path}:FIPS_mode_fallback_0"]},
                )

            elif kind in ("go_fips_enabled", "go_boringcrypto_enabled"):
                self._record_mode_flag(kind, tag, path=path)
                self._add_finding(
                    rule_id="fips-cfg:go-fips-enabled",
                    aoc_str="AOC-12: Lack of FIPS Mode",
                    controls=["SC-13"],
                    determination="PASS",
                    determination_detail="CONFORMANT_INDICATOR",
                    subject={"kind": "config_setting", "name": "go:fips140"},
                    location={"kind": "file", "path": path, "line_start": line},
                    detection={"method": "config", "confidence": "HIGH"},
                    title="Go FIPS 140 cryptographic module mode indicator enabled",
                    message=f"Go FIPS mode configuration detected in '{path}'.",
                    snippet=snippet,
                    fips_ext={"approved_mode_evidence": [tag]},
                )
            elif kind == "go_fips_disabled":
                self._add_finding(
                    rule_id="fips-cfg:go-fips-disabled",
                    aoc_str="AOC-12: Lack of FIPS Mode",
                    controls=["SC-13"],
                    determination="FAIL",
                    determination_detail="APPROVED_MODE_DISABLED",
                    severity="HIGH",
                    subject={"kind": "config_setting", "name": "go:fips140"},
                    location={"kind": "file", "path": path, "line_start": line},
                    detection={"method": "config", "confidence": "HIGH"},
                    title="Go FIPS 140 module explicitly disabled (fips140=off)",
                    message=f"Configuration in '{path}' disables the Go FIPS 140 module.",
                    remediation="Set GODEBUG=fips140=only (or fips140=on) for Go >= 1.24.",
                    snippet=snippet,
                    references=["NIST SP 800-53 Rev. 5 SC-13"],
                    fips_ext={"approved_mode_evidence": [tag]},
                )
            elif kind == "node_fips_enabled":
                self._record_mode_flag("node_fips_enabled", tag, path=path)
                self._add_finding(
                    rule_id="fips-cfg:node-fips-enabled",
                    aoc_str="AOC-12: Lack of FIPS Mode",
                    controls=["SC-13"],
                    determination="PASS",
                    determination_detail="CONFORMANT_INDICATOR",
                    subject={"kind": "config_setting", "name": "node:fips"},
                    location={"kind": "file", "path": path, "line_start": line},
                    detection={"method": "config", "confidence": "HIGH"},
                    title="Node.js FIPS mode flag enabled",
                    message=f"Node.js FIPS configuration detected in '{path}'.",
                    snippet=snippet,
                    fips_ext={"approved_mode_evidence": [tag]},
                )
            elif kind == "node_fips_disabled":
                self._add_finding(
                    rule_id="fips-cfg:node-fips-disabled",
                    aoc_str="AOC-12: Lack of FIPS Mode",
                    controls=["SC-13"],
                    determination="FAIL",
                    determination_detail="APPROVED_MODE_DISABLED",
                    severity="HIGH",
                    subject={"kind": "config_setting", "name": "node:fips"},
                    location={"kind": "file", "path": path, "line_start": line},
                    detection={"method": "lexical", "confidence": "HIGH"},
                    title="Node.js FIPS mode explicitly disabled",
                    message=f"crypto.setFips(false/0) disables OpenSSL FIPS mode in '{path}'.",
                    remediation="Start Node.js with --force-fips against a validated OpenSSL 3 FIPS provider.",
                    snippet=snippet,
                    references=["NIST SP 800-53 Rev. 5 SC-13"],
                )
            elif kind == "rust_fips_feature":
                self._record_mode_flag("rust_fips_feature", tag, path=path)
                self._add_finding(
                    rule_id="fips-cfg:rust-fips-feature",
                    aoc_str="AOC-12: Lack of FIPS Mode",
                    controls=["SC-13"],
                    determination="PASS",
                    determination_detail="CONFORMANT_INDICATOR",
                    subject={"kind": "config_setting", "name": "cargo:fips-feature"},
                    location={"kind": "manifest", "path": path, "line_start": line},
                    detection={"method": "manifest", "confidence": "HIGH"},
                    title="Cargo 'fips' feature enabled for validated Rust cryptographic provider",
                    message=f"Cargo manifest '{path}' enables the 'fips' feature.",
                    snippet=snippet,
                    fips_ext={"approved_mode_evidence": [tag]},
                )
            elif kind == "dotnet_fips_disabled":
                self._add_finding(
                    rule_id="fips-cfg:dotnet-fips-disabled",
                    aoc_str="AOC-12: Lack of FIPS Mode",
                    controls=["SC-13", "CM-6"],
                    determination="FAIL",
                    determination_detail="APPROVED_MODE_DISABLED",
                    severity="HIGH",
                    subject={"kind": "config_setting", "name": "dotnet:enforceFIPSPolicy"},
                    location={"kind": "file", "path": path, "line_start": line},
                    detection={"method": "config", "confidence": "HIGH"},
                    title=".NET enforceFIPSPolicy explicitly disabled",
                    message=f"Configuration in '{path}' sets enforceFIPSPolicy enabled=\"false\".",
                    remediation="Set <enforceFIPSPolicy enabled=\"true\"/> and enable OS FIPS mode.",
                    snippet=snippet,
                    references=["NIST SP 800-53 Rev. 5 SC-13"],
                )
            elif kind == "dotnet_fips_enabled":
                self._record_mode_flag("dotnet_fips_enabled", tag, path=path)
                self._add_finding(
                    rule_id="fips-cfg:dotnet-fips-enabled",
                    aoc_str="AOC-12: Lack of FIPS Mode",
                    controls=["SC-13", "CM-6"],
                    determination="PASS",
                    determination_detail="CONFORMANT_INDICATOR",
                    subject={"kind": "config_setting", "name": "dotnet:enforceFIPSPolicy"},
                    location={"kind": "file", "path": path, "line_start": line},
                    detection={"method": "config", "confidence": "HIGH"},
                    title=".NET enforceFIPSPolicy enabled",
                    message=f"Configuration in '{path}' enables enforceFIPSPolicy.",
                    snippet=snippet,
                    fips_ext={"approved_mode_evidence": [tag]},
                )
            elif kind in ("dockerfile_python_system_openssl", "dockerfile_python_pypi_wheel"):
                self._record_mode_flag(kind, tag, path=path)
            elif kind == "dockerfile_base_image":
                img = sig.get("image", "")
                matched_img = None
                for bm in base_img_rules:
                    if re.search(bm["pattern"], img, re.IGNORECASE):
                        matched_img = bm
                        break
                if matched_img:
                    cert_no = matched_img["cert_number"]
                    cert = certs_db.get(cert_no, {})
                    self._record_mode_flag("os_fips_image", f"{path}:FROM {img}", path=path)
                    self._add_finding(
                        rule_id="fips-cfg:container-fips-base-image",
                        aoc_str="AOC-12: Lack of FIPS Mode",
                        controls=["SC-13", "CM-6"],
                        determination="PASS",
                        determination_detail="CONFORMANT_INDICATOR",
                        subject={"kind": "module", "name": img.lower()},
                        location={"kind": "file", "path": path, "line_start": line},
                        detection={"method": "config", "confidence": "MEDIUM"},
                        title=f"Container base image ships CMVP-validated module ({matched_img['vendor']})",
                        message=matched_img["note"],
                        snippet=snippet,
                        fips_ext={
                            "fips_status": "VALIDATED_MODULE",
                            "module_name": cert.get("module_name", matched_img["vendor"]),
                            "cmvp_cert": cert_no,
                            "cert_standard": cert.get("standard", "FIPS 140-3"),
                            "cert_status": cert.get("status", "Active"),
                            "approved_mode_evidence": [f"{path}:FROM {img}"],
                        },
                    )

    # ------------------------------------------------------------------
    # Phase 3 Algorithm, Parameter & TLS Policy Evaluation
    # ------------------------------------------------------------------
    def _evaluate_assets(self) -> None:
        hashes = self.policy.get("hash_algorithms", {})
        approved_hashes = set(hashes.get("approved", []))
        macs = self.policy.get("mac_algorithms", {})
        approved_macs = set(macs.get("approved", []))
        disallowed_macs = macs.get("disallowed", {})
        ciphers = self.policy.get("symmetric_ciphers", {})
        params = self.policy.get("parameter_rules", {})
        tls_rules = self.policy.get("tls_rules", {})

        for asset in self.ws_scanner.assets:
            loc: Dict[str, Any] = {"kind": "file", "path": asset.file_path}
            if asset.line_start:
                loc["line_start"] = asset.line_start
            det = {"method": asset.detection_method, "confidence": asset.confidence}
            subj_params: Dict[str, Any] = {}
            if asset.mode:
                subj_params["mode"] = asset.mode
            if asset.key_bits is not None:
                subj_params["key_bits"] = asset.key_bits
            if asset.curve:
                subj_params["curve"] = asset.curve
            if asset.purpose:
                subj_params["purpose"] = asset.purpose

            # 1. TLS / Protocol checks
            if asset.asset_type == "protocol":
                tchk = asset.extra.get("tls_check")
                if tchk == "cert_verification_disabled":
                    r = tls_rules["cert_verification_disabled"]
                    self._add_finding(
                        rule_id=r["rule_id"],
                        aoc_str=r["aoc"],
                        controls=r["controls"],
                        determination="FAIL",
                        severity=r["severity"],
                        subject={"kind": "protocol", "name": asset.name},
                        location=loc,
                        detection=det,
                        title=r["title"],
                        message=f"{r['message']} ({asset.api})",
                        remediation=r["remediation"],
                        snippet=asset.snippet,
                        references=r["references"],
                    )
                elif tchk == "non_approved_cipher_suite":
                    r = tls_rules["non_approved_cipher_suite"]
                    self._add_finding(
                        rule_id=r["rule_id"],
                        aoc_str=r["aoc"],
                        controls=r["controls"],
                        determination="FAIL",
                        severity=r["severity"],
                        subject={"kind": "protocol", "name": asset.name},
                        location=loc,
                        detection=det,
                        title=r["title"],
                        message=r["message"],
                        remediation=r["remediation"],
                        snippet=asset.snippet,
                        references=r["references"],
                    )
                elif asset.name in tls_rules["deprecated_protocol"]["disallowed_versions"]:
                    r = tls_rules["deprecated_protocol"]
                    self._add_finding(
                        rule_id=r["rule_id"],
                        aoc_str=r["aoc"],
                        controls=r["controls"],
                        determination="FAIL",
                        severity=r["severity"],
                        subject={"kind": "protocol", "name": asset.name},
                        location=loc,
                        detection=det,
                        title=f"{r['title']}: {asset.name.upper()}",
                        message=r["message"],
                        remediation=r["remediation"],
                        snippet=asset.snippet,
                        references=r["references"],
                    )
                elif asset.name in tls_rules["deprecated_protocol"]["approved_versions"]:
                    self._add_finding(
                        rule_id=f"fips-tls:{asset.name}",
                        aoc_str="AOC-05: Unencrypted Traffic / Deprecated TLS",
                        controls=["SC-8", "SC-8(1)", "SC-13"],
                        determination="PASS",
                        determination_detail="CONFORMANT_INDICATOR",
                        subject={"kind": "protocol", "name": asset.name},
                        location=loc,
                        detection=det,
                        title=f"Approved TLS protocol version configured: {asset.name.upper()}",
                        message=f"{asset.api} negotiates {asset.name.upper()} per NIST SP 800-52 Rev. 2.",
                        snippet=asset.snippet,
                        references=["NIST SP 800-52 Rev. 2 §3.1"],
                    )
                continue

            subj: Dict[str, Any] = {"kind": "algorithm", "name": asset.name}
            if subj_params:
                subj["parameters"] = subj_params

            # 2. Hash algorithms
            if asset.name in hashes and isinstance(hashes[asset.name], dict):
                r = hashes[asset.name]
                if asset.purpose == "non_security":
                    self._add_finding(
                        rule_id=f"{r['rule_id']}:context",
                        aoc_str=r["aoc"],
                        controls=r["controls"],
                        determination="NEEDS_REVIEW",
                        severity="INFO",
                        subject=subj,
                        location=loc,
                        detection=det,
                        title=f"Non-approved hash in non-security context requires review: {asset.name.upper()}",
                        message=(
                            f"{asset.api} invokes {asset.name.upper()} with non-security indicators; "
                            "confirm digest is never used for integrity, authentication, or signatures."
                        ),
                        remediation=r["remediation"],
                        snippet=asset.snippet,
                        references=r["references"],
                    )
                else:
                    self._add_finding(
                        rule_id=r["rule_id"],
                        aoc_str=r["aoc"],
                        controls=r["controls"],
                        determination="FAIL",
                        severity=r["severity"],
                        subject=subj,
                        location=loc,
                        detection=det,
                        title=r["title"],
                        message=r["message"],
                        remediation=r["remediation"],
                        snippet=asset.snippet,
                        references=r["references"],
                    )
                continue

            if asset.name in approved_hashes:
                self._add_finding(
                    rule_id=f"fips-alg:{asset.name}",
                    aoc_str="AOC-03: Weak Encryption Check",
                    controls=["SC-13"],
                    determination="PASS",
                    determination_detail="CONFORMANT_INDICATOR",
                    subject=subj,
                    location=loc,
                    detection=det,
                    title=f"Approved hash function: {asset.name.upper()}",
                    message=f"{asset.api} uses NIST-approved hash function {asset.name.upper()}.",
                    snippet=asset.snippet,
                    references=["NIST SP 800-140C", "FIPS 180-4 / FIPS 202"],
                )
                continue

            # 3. MAC algorithms (HMAC-SHA-1 approved vs HMAC-MD5 disallowed)
            if asset.name in disallowed_macs:
                r = disallowed_macs[asset.name]
                self._add_finding(
                    rule_id=r["rule_id"],
                    aoc_str=r["aoc"],
                    controls=r["controls"],
                    determination="FAIL",
                    severity=r["severity"],
                    subject=subj,
                    location=loc,
                    detection=det,
                    title=r["title"],
                    message=r["message"],
                    remediation=r["remediation"],
                    snippet=asset.snippet,
                    references=r["references"],
                )
                continue
            if asset.name in approved_macs:
                self._add_finding(
                    rule_id=f"fips-alg:{asset.name}",
                    aoc_str="AOC-03: Weak Encryption Check",
                    controls=["SC-13"],
                    determination="PASS",
                    determination_detail="CONFORMANT_INDICATOR",
                    subject=subj,
                    location=loc,
                    detection=det,
                    title=f"Approved MAC algorithm: {asset.name.upper()}",
                    message=f"{asset.api} uses approved HMAC construction (FIPS 198-1 / SP 800-140C).",
                    snippet=asset.snippet,
                    references=["FIPS 198-1", "NIST SP 800-131A Rev. 2 §10"],
                )
                continue

            # 4. Symmetric ciphers & AES modes / static IVs
            if asset.name == "aes":
                aes_pol = ciphers["aes"]
                if asset.mode in aes_pol["disallowed_modes"]:
                    r = aes_pol["disallowed_modes"][asset.mode]
                    self._add_finding(
                        rule_id=r["rule_id"],
                        aoc_str=r["aoc"],
                        controls=r["controls"],
                        determination="FAIL",
                        severity=r["severity"],
                        subject=subj,
                        location=loc,
                        detection=det,
                        title=r["title"],
                        message=r["message"],
                        remediation=r["remediation"],
                        snippet=asset.snippet,
                        references=r["references"],
                    )
                elif asset.extra.get("static_iv"):
                    r = params["static_iv_or_nonce"]
                    self._add_finding(
                        rule_id=r["rule_id"],
                        aoc_str=r["aoc"],
                        controls=r["controls"],
                        determination="FAIL",
                        severity=r["severity"],
                        subject=subj,
                        location=loc,
                        detection=det,
                        title=r["title"],
                        message=r["message"],
                        remediation=r["remediation"],
                        snippet=asset.snippet,
                        references=r["references"],
                    )
                else:
                    mode_lbl = f"-{asset.mode}" if asset.mode else ""
                    self._add_finding(
                        rule_id="fips-alg:aes",
                        aoc_str="AOC-03: Weak Encryption Check",
                        controls=["SC-13", "SC-28(1)"],
                        determination="PASS",
                        determination_detail="CONFORMANT_INDICATOR",
                        subject=subj,
                        location=loc,
                        detection=det,
                        title=f"Approved symmetric cipher: AES{mode_lbl}",
                        message=f"{asset.api} invokes AES{mode_lbl} (FIPS 197 / SP 800-38).",
                        snippet=asset.snippet,
                        references=["FIPS 197", "NIST SP 800-38D"],
                    )
                continue

            if asset.name in ciphers and asset.name != "aes":
                r = ciphers[asset.name]
                self._add_finding(
                    rule_id=r["rule_id"],
                    aoc_str=r["aoc"],
                    controls=r["controls"],
                    determination="FAIL",
                    severity=r["severity"],
                    subject=subj,
                    location=loc,
                    detection=det,
                    title=r["title"],
                    message=r["message"],
                    remediation=r["remediation"],
                    snippet=asset.snippet,
                    references=r["references"],
                )
                continue

            # 5. Asymmetric & parameter checks (RSA, DSA, DH, EC, PBKDF2, PRNG)
            if asset.name == "rsa":
                r = params["rsa_min_bits"]
                if asset.key_bits is not None and asset.key_bits < r["min_bits"]:
                    self._add_finding(
                        rule_id=r["rule_id"],
                        aoc_str=r["aoc"],
                        controls=r["controls"],
                        determination="FAIL",
                        severity=r["severity"],
                        subject=subj,
                        location=loc,
                        detection=det,
                        title=f"{r['title']} ({asset.key_bits} bits)",
                        message=r["message"],
                        remediation=r["remediation"],
                        snippet=asset.snippet,
                        references=r["references"],
                    )
                elif asset.key_bits is not None:
                    self._add_finding(
                        rule_id="fips-alg:rsa",
                        aoc_str="AOC-03: Weak Encryption Check",
                        controls=["SC-12", "SC-13"],
                        determination="PASS",
                        determination_detail="CONFORMANT_INDICATOR",
                        subject=subj,
                        location=loc,
                        detection=det,
                        title=f"Approved RSA modulus size ({asset.key_bits} bits)",
                        message=f"{asset.api} generates {asset.key_bits}-bit RSA key (>= 2048 bits).",
                        snippet=asset.snippet,
                        references=["FIPS 186-5 §5.1"],
                    )
                continue

            if asset.name == "dh":
                r = params["dh_min_bits"]
                if asset.key_bits is not None and asset.key_bits < r["min_bits"]:
                    self._add_finding(
                        rule_id=r["rule_id"],
                        aoc_str=r["aoc"],
                        controls=r["controls"],
                        determination="FAIL",
                        severity=r["severity"],
                        subject=subj,
                        location=loc,
                        detection=det,
                        title=f"{r['title']} ({asset.key_bits} bits)",
                        message=r["message"],
                        remediation=r["remediation"],
                        snippet=asset.snippet,
                        references=r["references"],
                    )
                continue

            if asset.name == "dsa":
                r = params["dsa_disallowed"]
                self._add_finding(
                    rule_id=r["rule_id"],
                    aoc_str=r["aoc"],
                    controls=r["controls"],
                    determination="FAIL",
                    severity=r["severity"],
                    subject=subj,
                    location=loc,
                    detection=det,
                    title=r["title"],
                    message=r["message"],
                    remediation=r["remediation"],
                    snippet=asset.snippet,
                    references=r["references"],
                )
                continue

            if asset.name in ("ecdsa", "ed25519", "ed448", "ecdh") and asset.curve:
                ec_pol = params["ecc_curves"]
                c_lc = asset.curve.lower()
                if c_lc in ec_pol["approved"]:
                    self._add_finding(
                        rule_id=f"fips-alg:{asset.name}",
                        aoc_str="AOC-03: Weak Encryption Check",
                        controls=["SC-12", "SC-13"],
                        determination="PASS",
                        determination_detail="CONFORMANT_INDICATOR",
                        subject=subj,
                        location=loc,
                        detection=det,
                        title=f"Approved elliptic curve / EdDSA parameter: {asset.curve}",
                        message=f"{asset.api} uses NIST-approved curve {asset.curve} (FIPS 186-5).",
                        snippet=asset.snippet,
                        references=["FIPS 186-5"],
                    )
                elif c_lc in ec_pol["legacy_review"]:
                    self._add_finding(
                        rule_id="fips-param:ecc-p224-review",
                        aoc_str="AOC-03: Weak Encryption Check",
                        controls=["SC-12", "SC-13"],
                        determination="NEEDS_REVIEW",
                        severity="INFO",
                        subject=subj,
                        location=loc,
                        detection=det,
                        title=f"Legacy 112-bit elliptic curve requires horizon review: {asset.curve}",
                        message="P-224 provides 112-bit security strength; NIST SP 800-131A transitions favor >= 128-bit curves (P-256/P-384).",
                        remediation="Prefer P-256 or P-384 for new key pairs.",
                        snippet=asset.snippet,
                        references=["NIST SP 800-131A Rev. 2", "FIPS 186-5"],
                    )
                else:
                    r = ec_pol["disallowed_rule"]
                    self._add_finding(
                        rule_id=r["rule_id"],
                        aoc_str=r["aoc"],
                        controls=r["controls"],
                        determination="FAIL",
                        severity=r["severity"],
                        subject=subj,
                        location=loc,
                        detection=det,
                        title=f"{r['title']}: {asset.curve}",
                        message=r["message"],
                        remediation=r["remediation"],
                        snippet=asset.snippet,
                        references=r["references"],
                    )
                continue

            if asset.name == "pbkdf2":
                r = params["pbkdf2_min_iterations"]
                iters = asset.extra.get("iterations")
                static_salt = asset.extra.get("static_salt", False)
                if (iters is not None and iters < r["min_iterations"]) or static_salt:
                    self._add_finding(
                        rule_id=r["rule_id"],
                        aoc_str=r["aoc"],
                        controls=r["controls"],
                        determination="FAIL",
                        severity=r["severity"],
                        subject=subj,
                        location=loc,
                        detection=det,
                        title=r["title"],
                        message=r["message"],
                        remediation=r["remediation"],
                        snippet=asset.snippet,
                        references=r["references"],
                    )
                else:
                    self._add_finding(
                        rule_id="fips-alg:pbkdf2",
                        aoc_str="AOC-03: Weak Encryption Check",
                        controls=["SC-12", "SC-13"],
                        determination="PASS",
                        determination_detail="CONFORMANT_INDICATOR",
                        subject=subj,
                        location=loc,
                        detection=det,
                        title="Approved PBKDF2 key derivation invocation",
                        message="PBKDF2 invoked with compliant or dynamic iteration/salt parameters (SP 800-132).",
                        snippet=asset.snippet,
                        references=["NIST SP 800-132"],
                    )
                continue

            if asset.name == "unapproved-prng":
                r = params["non_approved_rng"]
                self._add_finding(
                    rule_id=r["rule_id"],
                    aoc_str=r["aoc"],
                    controls=r["controls"],
                    determination="FAIL",
                    severity=r["severity"],
                    subject=subj,
                    location=loc,
                    detection=det,
                    title=r["title"],
                    message=f"{r['message']} ({asset.api})",
                    remediation=r["remediation"],
                    snippet=asset.snippet,
                    references=r["references"],
                )
            elif asset.name == "drbg":
                self._add_finding(
                    rule_id="fips-alg:drbg",
                    aoc_str="AOC-03: Weak Encryption Check",
                    controls=["SC-13"],
                    determination="PASS",
                    determination_detail="CONFORMANT_INDICATOR",
                    subject=subj,
                    location=loc,
                    detection=det,
                    title=f"CSPRNG / DRBG interface invoked ({asset.api})",
                    message=f"{asset.api} delegates random bit generation to the OS/runtime CSPRNG.",
                    snippet=asset.snippet,
                    references=["NIST SP 800-90A Rev. 1"],
                )

    # ------------------------------------------------------------------
    # Phase 4 Dependency -> CMVP Module Mapping
    # ------------------------------------------------------------------
    def _scoped_signals_for_manifest(self, manifest_path: str) -> List[Dict[str, str]]:
        """
        Scopes approved-mode and container linkage evidence to the component directory tree
        owning `manifest_path`, while allowing appliance/host `/etc/` OS configs to act as
        deployment-level Operational Environment evidence across components (`H7`).
        """
        m_dir = PurePosixPath(manifest_path.replace("\\", "/").lstrip("./")).parent
        has_local_dockerfile = False
        if m_dir != PurePosixPath("."):
            for r in self.mode_signal_records:
                if r["flag"].startswith("dockerfile_") or r["flag"] == "os_fips_image":
                    s_dir = PurePosixPath(r["path"]).parent if r["path"] else PurePosixPath(".")
                    if s_dir == m_dir or m_dir in s_dir.parents:
                        has_local_dockerfile = True
                        break

        in_scope: List[Dict[str, str]] = []
        for r in self.mode_signal_records:
            flg = r["flag"]
            s_path = PurePosixPath(r["path"]) if r["path"] else PurePosixPath(".")
            s_dir = s_path.parent
            is_container_sig = (
                flg in ("os_fips_image", "dockerfile_python_system_openssl", "dockerfile_python_pypi_wheel")
                or "dockerfile" in s_path.name.lower()
            )
            is_etc_os_sig = ("etc" in s_path.parts) and not is_container_sig

            if is_etc_os_sig:
                in_scope.append(r)
            elif is_container_sig:
                if m_dir == PurePosixPath("."):
                    if s_dir == PurePosixPath("."):
                        in_scope.append(r)
                else:
                    if s_dir == m_dir or m_dir in s_dir.parents or (s_dir == PurePosixPath(".") and not has_local_dockerfile):
                        in_scope.append(r)
            else:
                if m_dir == PurePosixPath(".") or s_dir == m_dir or m_dir in s_dir.parents or s_dir == PurePosixPath("."):
                    in_scope.append(r)
        return in_scope

    def _evaluate_dependencies_and_cmvp(self) -> None:
        certs_db = self.cmvp.get("certificates", {})
        mappings = self.cmvp.get("module_mappings", [])
        crypto_scanner = CryptoScanner(self.crypto_catalog)
        dep_findings = crypto_scanner.evaluate(self.dependencies)

        for df in dep_findings:
            self.ws_scanner.ecosystems_seen.add(df.ecosystem)
            matched_mapping = self._match_cmvp_mapping(df.name, df.version, df.ecosystem, mappings)
            loc = {
                "kind": "file" if df.ecosystem == "system" else "manifest",
                "path": df.source_file.replace("\\", "/").lstrip("./"),
            }
            det_method = "binary" if df.ecosystem == "system" else "manifest"
            has_ver = df.version != "Unknown"
            subj: Dict[str, Any] = {"kind": "module", "name": df.name.lower(), "ecosystem": df.ecosystem}
            if has_ver:
                subj["version"] = df.version

            if matched_mapping:
                cert_ids = matched_mapping.get("cert_numbers", [])
                cert_objs = [certs_db[cid] for cid in cert_ids if cid in certs_db]
                active_140_3 = [c for c in cert_objs if c.get("standard") == "FIPS 140-3" and c.get("status") == "Active"]
                hist_140_2 = [c for c in cert_objs if c.get("standard") == "FIPS 140-2" or c.get("status") == "Historical"]

                scoped_recs = self._scoped_signals_for_manifest(loc["path"])
                scoped_flags = {r["flag"] for r in scoped_recs}
                scoped_evid_by_flag: Dict[str, List[str]] = {}
                for r in scoped_recs:
                    scoped_evid_by_flag.setdefault(r["flag"], []).append(r["tag"])

                req_signals = set(matched_mapping.get("required_mode_signals", []))
                matched_pos = req_signals & scoped_flags
                evid_tags: List[str] = []
                for flg in sorted(matched_pos):
                    for t in scoped_evid_by_flag.get(flg, []):
                        if t not in evid_tags:
                            evid_tags.append(t)

                # For PyCA cryptography, require dynamic/system OpenSSL linkage rather than static PyPI wheels
                if matched_mapping.get("id") == "cryptography-pyca":
                    if "dockerfile_python_pypi_wheel" in scoped_flags and "dockerfile_python_system_openssl" not in scoped_flags:
                        matched_pos = set()
                        evid_tags = []
                    elif "dockerfile_python_system_openssl" in scoped_flags and matched_pos:
                        for t in scoped_evid_by_flag.get("dockerfile_python_system_openssl", []):
                            if t not in evid_tags:
                                evid_tags.append(t)

                # Check if explicit disabled signal contradicts this module in scope
                explicitly_disabled = False
                if "openssl_fips_enabled" in req_signals and "openssl_fips_disabled" in scoped_flags:
                    explicitly_disabled = True
                    evid_tags.extend(scoped_evid_by_flag.get("openssl_fips_disabled", []))
                if "java_fips_enabled" in req_signals and "java_fips_disabled" in scoped_flags:
                    explicitly_disabled = True
                    evid_tags.extend(scoped_evid_by_flag.get("java_fips_disabled", []))

                if not active_140_3 and hist_140_2:
                    c0 = hist_140_2[0]
                    determination = "FAIL"
                    detail = "FAIL_HISTORICAL_CERT"
                    sev: Optional[str] = "HIGH"
                    title = f"Historical FIPS 140-2 module certificate only: {df.name} ({df.version})"
                    msg = (
                        f"'{df.name}' ({df.version}) maps only to {c0['standard']} cert #{c0['cert_number']} "
                        f"({c0['module_name']}), which moved to Historical status on {c0.get('sunset_date', '2026-09-21')}. "
                        f"{matched_mapping.get('condition_note', '')}"
                    )
                elif explicitly_disabled:
                    c0 = active_140_3[0]
                    determination = "FAIL"
                    detail = "APPROVED_MODE_DISABLED"
                    sev = "HIGH"
                    title = f"Capable module present while approved FIPS mode is disabled: {df.name} ({df.version})"
                    msg = (
                        f"'{df.name}' ({df.version}) can leverage {c0['module_name']} (cert #{c0['cert_number']}), "
                        "but workspace configuration explicitly leaves FIPS mode disabled."
                    )
                elif active_140_3 and matched_pos:
                    c0 = active_140_3[0]
                    determination = "PASS"
                    detail = "CONFORMANT_INDICATOR"
                    sev = None
                    title = f"CMVP-validated module alignment & approved-mode intent: {df.name} ({df.version})"
                    msg = (
                        f"'{df.name}' ({df.version}) aligns with Active FIPS 140-3 cert #{c0['cert_number']} "
                        f"({c0['module_name']}) with static approved-mode configuration evidence ({', '.join(evid_tags)}). "
                        "Runtime Operational Environment verification remains required."
                    )
                else:
                    c0 = active_140_3[0] if active_140_3 else {}
                    determination = "CANNOT_DETERMINE_STATICALLY"
                    detail = "CAPABLE_IF_CONFIGURED"
                    sev = "INFO"
                    title = f"Capable cryptographic dependency lacks static approved-mode evidence: {df.name} ({df.version})"
                    msg = (
                        f"'{df.name}' ({df.version}) can bind to {c0.get('module_name', 'a validated module')} "
                        f"(cert #{c0.get('cert_number', 'N/A')}), but static source/manifests do not prove approved-mode activation. "
                        f"{matched_mapping.get('condition_note', '')}"
                    )

                fips_ext: Dict[str, Any] = {
                    "fips_status": "VALIDATED_MODULE" if determination == "PASS" else df.fips_status,
                }
                if c0:
                    fips_ext["module_name"] = c0["module_name"]
                    fips_ext["cmvp_cert"] = c0["cert_number"]
                    fips_ext["cert_standard"] = c0["standard"]
                    fips_ext["cert_status"] = c0["status"]
                    oes = c0.get("tested_operational_environments", [])
                    if oes:
                        fips_ext["operational_environment"] = "; ".join(oes[:2])
                if evid_tags:
                    fips_ext["approved_mode_evidence"] = evid_tags

                self.cmvp_mappings.append({
                    "dependency": df.name,
                    "version": df.version,
                    "ecosystem": df.ecosystem,
                    "manifest": df.source_file,
                    "determination": determination,
                    "determination_detail": detail,
                    "certificates": cert_objs,
                    "approved_mode_evidence": evid_tags,
                    "condition_note": matched_mapping.get("condition_note", ""),
                })

                self._add_finding(
                    rule_id=f"fips-cmvp:{matched_mapping['id']}",
                    aoc_str="AOC-12: Lack of FIPS Mode" if detail != "FAIL_HISTORICAL_CERT" else "AOC-09: Crypto Dependencies on Unsupported Libraries",
                    controls=["SC-13", "IA-7"],
                    determination=determination,
                    determination_detail=detail,
                    severity=sev,
                    subject=subj,
                    location=loc,
                    detection={"method": det_method, "confidence": "HIGH" if has_ver else "MEDIUM"},
                    title=title,
                    message=msg.strip(),
                    remediation=df.remediation if determination in ("FAIL", "WARN") else None,
                    references=["NIST FIPS 140-3", "NIST SP 800-53 Rev. 5 SC-13"],
                    fips_ext=fips_ext,
                )
            else:
                # Unvalidated or unpinned dependency not matching any CMVP certificate
                det = "NEEDS_REVIEW" if df.status == "WARN_UNVERIFIED" else "FAIL"
                detail = "WARN_UNVERIFIED" if df.status == "WARN_UNVERIFIED" else "NOT_VALIDATED"
                sev_unval = "INFO" if det == "NEEDS_REVIEW" else (df.severity if df.severity in ("CRITICAL", "HIGH") else "MEDIUM")
                self.cmvp_mappings.append({
                    "dependency": df.name,
                    "version": df.version,
                    "ecosystem": df.ecosystem,
                    "manifest": df.source_file,
                    "determination": det,
                    "determination_detail": detail,
                    "certificates": [],
                    "approved_mode_evidence": [],
                    "condition_note": df.description,
                })
                self._add_finding(
                    rule_id=f"fips-cmvp:unvalidated:{df.rule_key}",
                    aoc_str="AOC-09: Crypto Dependencies on Unsupported Libraries",
                    controls=["SC-13"],
                    determination=det,
                    determination_detail=detail,
                    severity=sev_unval,
                    subject=subj,
                    location=loc,
                    detection={"method": det_method, "confidence": "HIGH" if has_ver else "MEDIUM"},
                    title=f"No NIST CMVP validation certificate for dependency: {df.name} ({df.version})"[:200],
                    message=df.description,
                    remediation=df.remediation,
                    references=["NIST FIPS 140-3", "NIST SP 800-53 Rev. 5 SC-13"],
                    fips_ext={"fips_status": "NOT_VALIDATED"},
                )

    @staticmethod
    def _match_cmvp_mapping(
        name: str,
        version: str,
        ecosystem: str,
        mappings: List[Dict[str, Any]],
    ) -> Optional[Dict[str, Any]]:
        eco_lc = ecosystem.lower()
        eco_group = CryptoScanner._ECOSYSTEM_ALIASES.get(eco_lc, {eco_lc})
        for m in mappings:
            m_ecos = {str(x).lower() for x in m.get("ecosystems", [])}
            if m_ecos and not (eco_group & m_ecos):
                continue
            if not any(re.match(pat, name, re.IGNORECASE) for pat in m.get("patterns", [])):
                continue
            if version != "Unknown":
                min_v = m.get("min_version")
                max_v_ex = m.get("max_version_exclusive")
                if min_v and version_lt(version, min_v):
                    continue
                if max_v_ex and not version_lt(version, max_v_ex):
                    continue
            else:
                # If version is unknown and this rule has an upper bound (historical 1.x), skip to avoid misclassifying unpinned as 1.x
                if m.get("max_version_exclusive"):
                    continue
            return m
        return None

    def _add_finding(
        self,
        rule_id: str,
        aoc_str: str,
        controls: Sequence[str],
        determination: str,
        subject: Dict[str, Any],
        location: Dict[str, Any],
        detection: Dict[str, Any],
        title: str,
        message: str,
        determination_detail: Optional[str] = None,
        severity: Optional[str] = None,
        remediation: Optional[str] = None,
        snippet: str = "",
        references: Optional[Sequence[str]] = None,
        fips_ext: Optional[Dict[str, Any]] = None,
    ) -> None:
        fid = make_finding_id(
            "fipsdisc",
            rule_id,
            location.get("path", ""),
            location.get("line_start"),
            f"{subject.get('name', '')}:{subject.get('version', '')}",
        )
        rec: Dict[str, Any] = {
            "finding_id": fid,
            "rule_id": rule_id,
            "aoc": split_aoc(aoc_str, default_id="AOC-12"),
            "controls": list(dict.fromkeys(controls)),
            "determination": determination,
            "subject": subject,
            "location": location,
            "detection": detection,
            "title": title[:200],
            "message": message,
        }
        if determination_detail:
            rec["determination_detail"] = determination_detail
        if severity:
            rec["severity"] = severity
        elif determination in ("FAIL", "WARN"):
            rec["severity"] = "MEDIUM"
        if remediation:
            rec["remediation"] = remediation
        elif determination in ("FAIL", "WARN"):
            rec["remediation"] = "Remediate cryptographic usage to use a CMVP-validated module and approved algorithm."

        ev: Dict[str, Any] = {}
        if snippet:
            ev["snippet"] = _redact_snippet(snippet)
        if references:
            ev["references"] = list(references)
        if ev:
            rec["evidence"] = ev

        if fips_ext:
            rec["extensions"] = {"fips": fips_ext}

        self.findings.append(rec)

    # ------------------------------------------------------------------
    # Deliverable Builders (Schema JSON, CycloneDX 1.6 CBOM, SARIF, Markdown)
    # ------------------------------------------------------------------
    def _target_metadata(self) -> Dict[str, str]:
        for pname in ("bundle_provenance.json", "ami_provenance.json"):
            p = self.workspace_root / pname
            if p.is_file():
                try:
                    d = json.loads(p.read_text(encoding="utf-8"))
                    ident = d.get("target_identifier") or d.get("bundle_identifier") or d.get("ami_identifier") or self.workspace_root.name
                    res: Dict[str, str] = {"identifier": str(ident), "provenance_file": pname}
                    c = d.get("commit_sha") or d.get("commit_metadata", {}).get("commit_hash")
                    if c and c != "UNKNOWN":
                        res["commit"] = str(c)
                    ref = d.get("checked_out_ref")
                    if isinstance(ref, str) and ref.strip():
                        res["checked_out_ref"] = ref.strip()
                    return res
                except Exception:
                    pass
        return {"identifier": self.workspace_root.name or "workspace"}

    def _default_evidence_slug(self) -> str:
        """
        Builds a deterministic human-readable evidence folder slug:
        `<bundle-stem>@<ref>` when `bundle_provenance.json` identifies the bundle and checked-out ref.
        """
        bp = self.workspace_root / "bundle_provenance.json"
        if bp.is_file():
            try:
                d = json.loads(bp.read_text(encoding="utf-8"))
                src_path = str(d.get("bundle_source_path") or "").strip()
                checked_ref = str(d.get("checked_out_ref") or "").strip()
                stem = re.sub(r"\.bundle$", "", Path(src_path).name, flags=re.IGNORECASE) if src_path else ""
                if stem and checked_ref:
                    raw_slug = f"{stem}@{checked_ref}"
                elif stem:
                    raw_slug = stem
                else:
                    raw_slug = self._target_metadata()["identifier"]
                return re.sub(r"[^A-Za-z0-9.@_-]+", "_", raw_slug).strip("_") or "fips"
            except Exception:
                pass
        return re.sub(r"[^A-Za-z0-9.@_-]+", "_", self._target_metadata()["identifier"]).strip("_") or "fips"

    def _limitations_list(self) -> List[str]:
        lims = [
            "Static source, manifest, and configuration inspection demonstrates configuration intent only; runtime verification on the deployed host/container is required to confirm FIPS provider self-tests and Operational Environment (OE) alignment.",
            "Python files are analyzed via the Python 'ast' module; Go, Java/Kotlin, JS/TS, C/C++, Rust, and C# files are analyzed with comment-stripping lexical detectors that do not resolve cross-file constants or dynamic reflection.",
        ]
        if self.staleness_warning:
            lims.append(self.staleness_warning)
        return lims

    def files_inspected_summary(self) -> Dict[str, int]:
        sc = self.ws_scanner.surface_counts
        total = sc["python"] + sc["polyglot_source"] + sc["manifests"] + sc["deploy_iac"] + sc["os_config"]
        return {
            "total": total,
            "workspace_files_total": self.ws_scanner.workspace_files_total,
            "python": sc["python"],
            "polyglot_source": sc["polyglot_source"],
            "manifests": sc["manifests"],
            "deploy_iac": sc["deploy_iac"],
            "os_config": sc["os_config"],
        }

    def build_envelope(self) -> Dict[str, Any]:
        envelope: Dict[str, Any] = {
            "schema_version": "1.0.0",
            "engine": {
                "name": ENGINE_NAME,
                "version": ENGINE_VERSION,
                "catalogs": [
                    get_catalog_descriptor(self.policy_path, rel_label="rules/fips_algorithm_policy.json"),
                    get_catalog_descriptor(self.cmvp_path, rel_label="rules/cmvp_catalog.json"),
                    get_catalog_descriptor(self.crypto_catalog_path, rel_label="rules/crypto_catalog.json"),
                ],
            },
            "generated_at": utc_now_iso(),
            "target": self._target_metadata(),
            "scope": {
                "assessed_controls": ASSESSED_CONTROLS,
                "assessed_aocs": ASSESSED_AOCS,
                "ecosystems": sorted(self.ws_scanner.ecosystems_seen),
                "limitations": self._limitations_list(),
                "files_inspected": self.files_inspected_summary(),
            },
            "findings": self.findings,
        }
        errs = validate_finding_envelope(envelope)
        if errs:
            raise ValueError(f"Internal schema invariant violation in FIPSDiscovery: {errs[:3]}")
        return envelope

    def build_cbom_cyclonedx(self) -> Dict[str, Any]:
        """Emits a CycloneDX 1.6 Cryptographic Bill of Materials (`cbom.cdx.json`)."""
        components: List[Dict[str, Any]] = []
        seen_refs: Set[str] = set()

        # 1. Source/config cryptographic assets
        for idx, asset in enumerate(self.ws_scanner.assets, start=1):
            bom_ref = f"crypto-asset:{idx}:{asset.name}:{asset.file_path}:{asset.line_start or 0}"
            if bom_ref in seen_refs:
                continue
            seen_refs.add(bom_ref)

            crypto_props: Dict[str, Any] = {"assetType": asset.asset_type}
            if asset.asset_type == "algorithm":
                alg_props: Dict[str, Any] = {"primitive": asset.purpose}
                if asset.mode:
                    alg_props["mode"] = asset.mode.lower()
                if asset.key_bits is not None:
                    alg_props["parameterSetIdentifier"] = str(asset.key_bits)
                if asset.curve:
                    alg_props["curve"] = asset.curve
                crypto_props["algorithmProperties"] = alg_props
            elif asset.asset_type == "protocol":
                crypto_props["protocolProperties"] = {"type": "tls", "version": asset.name}

            occurrences = [{"location": asset.file_path, **({"line": asset.line_start} if asset.line_start else {})}]
            components.append({
                "type": "cryptographic-asset",
                "bom-ref": bom_ref,
                "name": asset.name,
                "cryptoProperties": crypto_props,
                "evidence": {"occurrences": occurrences},
                "properties": [
                    {"name": "grc:language", "value": asset.language},
                    {"name": "grc:api", "value": asset.api},
                    {"name": "grc:detection_method", "value": asset.detection_method},
                    {"name": "grc:confidence", "value": asset.confidence},
                ],
            })

        # 2. Cryptographic module / library dependencies
        for m in self.cmvp_mappings:
            ref = f"crypto-module:{m['ecosystem']}:{m['dependency']}@{m['version']}"
            if ref in seen_refs:
                continue
            seen_refs.add(ref)
            props = [
                {"name": "grc:ecosystem", "value": m["ecosystem"]},
                {"name": "grc:manifest", "value": m["manifest"]},
                {"name": "grc:fips_determination", "value": m["determination"]},
            ]
            for c in m["certificates"]:
                props.append({"name": "grc:cmvp_cert", "value": f"#{c['cert_number']} ({c['standard']} - {c['status']})"})
            comp: Dict[str, Any] = {
                "type": "library",
                "bom-ref": ref,
                "name": m["dependency"],
                "properties": props,
            }
            if m["version"] != "Unknown":
                comp["version"] = m["version"]
            components.append(comp)

        return {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "serialNumber": f"urn:uuid:{uuid.uuid4()}",
            "version": 1,
            "metadata": {
                "timestamp": utc_now_iso(),
                "tools": {
                    "components": [
                        {
                            "type": "application",
                            "name": "GRC-xMINI FIPSDiscovery",
                            "version": ENGINE_VERSION,
                        }
                    ]
                },
                "component": {
                    "type": "application",
                    "name": self._target_metadata()["identifier"],
                },
            },
            "components": components,
        }

    def build_sarif(self) -> Dict[str, Any]:
        """Emits SARIF 2.1.0 for actionable assessment findings (`FAIL`, `WARN`, `NEEDS_REVIEW`, `CANNOT_DETERMINE_STATICALLY`)."""
        rules_index: Dict[str, Dict[str, Any]] = {}
        results: List[Dict[str, Any]] = []
        level_map = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning", "LOW": "note", "INFO": "note"}

        for f in self.findings:
            if f["determination"] == "PASS":
                continue
            rid = f["rule_id"]
            if rid not in rules_index:
                rules_index[rid] = {
                    "id": rid,
                    "shortDescription": {"text": f["title"]},
                    "help": {"text": f.get("remediation") or f["message"]},
                    "properties": {
                        "tags": ["security", "cryptography", "FIPS-140-3"] + f["controls"],
                    },
                }
            sev = f.get("severity", "INFO")
            loc_obj = f["location"]
            phys_loc: Dict[str, Any] = {
                "artifactLocation": {"uri": loc_obj.get("path", "workspace")},
            }
            if loc_obj.get("line_start"):
                phys_loc["region"] = {"startLine": loc_obj["line_start"]}

            results.append({
                "ruleId": rid,
                "level": level_map.get(sev, "warning") if f["determination"] in ("FAIL", "WARN") else "note",
                "message": {"text": f"[{f['determination']}] {f['message']}"},
                "locations": [{"physicalLocation": phys_loc}],
                "partialFingerprints": {"primaryLocationLineHash": f["finding_id"]},
                "properties": {
                    "determination": f["determination"],
                    "determination_detail": f.get("determination_detail", ""),
                    "controls": f["controls"],
                    "aoc": f["aoc"]["id"],
                    "confidence": f["detection"]["confidence"],
                },
            })

        return {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "GRC-xMINI FIPSDiscovery",
                            "version": ENGINE_VERSION,
                            "informationUri": "https://csrc.nist.gov/projects/cryptographic-module-validation-program",
                            "rules": list(rules_index.values()),
                        }
                    },
                    "results": results,
                }
            ],
        }

    def build_cmvp_mapping_markdown(self) -> str:
        """Generates `cmvp_mapping.md` without using 'compliant' or 'certified' claims."""
        now = utc_now_str()
        tgt = self._target_metadata()["identifier"]
        meta = self.cmvp.get("catalog_metadata", {})

        lines = [
            "# NIST CMVP Cryptographic Module Mapping & Approved-Mode Traceability",
            "",
            f"> **Target Identifier**: `{tgt}`  ",
            f"> **Generated**: `{now}`  ",
            f"> **CMVP Reference Snapshot**: `v{meta.get('version', '1.0.0')}` (Retrieved `{meta.get('retrieved_at', 'N/A')}`)  ",
            "> **Primary Control**: NIST SP 800-53 Rev. 5 `SC-13` (Cryptographic Protection) & `IA-7`  ",
            "",
            "---",
            "",
            "## 1. Module Validation & Configuration Intent Matrix",
            "",
            "> **Assessment Framing**: FIPS 140-3 validates cryptographic modules through NIST CMVP, never whole applications or source repositories. Static mapping identifies candidate CMVP certificates and configuration intent only; runtime Operational Environment (OE) verification is mandatory. Note that all FIPS 140-2 certificates moved to **Historical** status on **2026-09-21**.",
            "",
        ]
        if self.staleness_warning:
            lines.extend([f"> [!WARNING]\n> {self.staleness_warning}", ""])

        if not self.cmvp_mappings:
            lines.append("*No cryptographic library dependencies were detected in workspace manifests or shared objects.*")
        else:
            lines.extend([
                "| Dependency / Module | Version | Ecosystem | Manifest | Determination | Candidate CMVP Cert(s) | Approved-Mode Evidence | Verification Condition |",
                "| :--- | :---: | :---: | :--- | :---: | :--- | :--- | :--- |",
            ])
            for m in self.cmvp_mappings:
                certs_str = (
                    ", ".join(f"`#{c['cert_number']}` ({c['standard']} · {c['status']})" for c in m["certificates"])
                    if m["certificates"]
                    else "*None (`NOT_VALIDATED`)*"
                )
                evid_str = ", ".join(f"`{e}`" for e in m["approved_mode_evidence"]) if m["approved_mode_evidence"] else "*None in repo*"
                note = m["condition_note"].replace("|", "\\|")
                lines.append(
                    f"| **{m['dependency']}** | `{m['version']}` | `{m['ecosystem']}` | `{m['manifest']}` | "
                    f"`{m['determination']}` (`{m['determination_detail']}`) | {certs_str} | {evid_str} | {note} |"
                )

        lines.extend([
            "",
            "---",
            f"*Catalog Integrity (`rules/cmvp_catalog.json`)*: SHA-256 `{self.cmvp_integrity['sha256']}` ({self.cmvp_integrity['signature_status']})",
            "",
        ])
        return "\n".join(lines)

    def build_assessment_markdown(self) -> str:
        """
        Generates `fips_assessment.md` strictly adhering to Handoff §1.1 & §4.5:
        Uses 'conformance indicators' and 'assessment findings' rather than overclaiming 'compliant' or 'certified'.
        """
        now = utc_now_str()
        tgt = self._target_metadata()["identifier"]
        fi = self.files_inspected_summary()
        counts = {
            "FAIL": sum(1 for f in self.findings if f["determination"] == "FAIL"),
            "WARN": sum(1 for f in self.findings if f["determination"] == "WARN"),
            "NEEDS_REVIEW": sum(1 for f in self.findings if f["determination"] == "NEEDS_REVIEW"),
            "CANNOT_DETERMINE_STATICALLY": sum(1 for f in self.findings if f["determination"] == "CANNOT_DETERMINE_STATICALLY"),
            "PASS": sum(1 for f in self.findings if f["determination"] == "PASS"),
        }

        lines = [
            "# Static FIPS 140-3 Cryptographic Conformance Assessment",
            "",
            f"> **Target Identifier**: `{tgt}`  ",
            f"> **Generated**: `{now}`  ",
            f"> **Engine**: `{ENGINE_NAME} v{ENGINE_VERSION}` (Pure Python Stdlib)  ",
            (
                f"> **Files Inspected**: `{fi['total']}` "
                f"(Python: `{fi['python']}`, Polyglot Source: `{fi['polyglot_source']}`, "
                f"Manifests: `{fi['manifests']}`, Deploy/IaC: `{fi['deploy_iac']}`, "
                f"OS Config: `{fi['os_config']}`; Workspace Total: `{fi['workspace_files_total']}`)  "
            ),
            "> **NIST SP 800-53 Rev. 5 Controls**: `SC-13` (Primary), `SC-12`, `SC-8(1)`, `SC-28(1)`, `IA-7`, `SC-23`, `CM-6`  ",
            "",
            "---",
            "",
            "## 1. Scope, Framing & Static Analysis Limitations",
            "",
        ]
        if fi["total"] == 0:
            lines.extend([
                "> [!WARNING]",
                "> **No assessable files found**: Static inspection found `0` assessable cryptographic source, manifest, deploy/IaC, or OS configuration files in the target workspace. Zero findings do not indicate a clean posture.",
                "",
            ])
        lines.extend([
            "* **Module Validation Scope**: FIPS 140-3 validates **cryptographic modules** through the NIST Cryptographic Module Validation Program (CMVP). Applications and source code repositories are **not** module-validated as a whole.",
            "* **Assessment Question**: This assessment evaluates static evidence for the question: *\"Does this code perform all security-relevant cryptography through a FIPS 140-3 validated module, configured in its approved mode, using only approved algorithms and parameters?\"*",
            "* **Historical FIPS 140-2 Sunset**: All FIPS 140-2 module validation certificates transitioned to **Historical** status on **2026-09-21** and are flagged as assessment findings requiring migration to active FIPS 140-3 modules.",
            "* **Indeterminate Static Posture**: Where static source or manifest inspection cannot confirm runtime module linkage, Operational Environment (OE), or approved-mode execution, the determination is recorded as `CANNOT_DETERMINE_STATICALLY` or `NEEDS_REVIEW`, never as a positive pass.",
            "",
            "### Run-Specific Limitations",
        ])
        for lim in self._limitations_list():
            lines.append(f"* {lim}")

        lines.extend([
            "",
            "---",
            "",
            "## 2. Summary by Determination",
            "",
            "| Determination | Count | Assessment Interpretation |",
            "| :--- | :---: | :--- |",
            f"| **`FAIL` (Assessment Findings)** | **{counts['FAIL']}** | Disallowed algorithm/mode/parameter, disabled FIPS configuration, unvalidated library, or Historical 140-2 module |",
            f"| **`WARN` (Assessment Warnings)** | **{counts['WARN']}** | Sub-baseline cryptographic configuration or library warning |",
            f"| **`NEEDS_REVIEW`** | **{counts['NEEDS_REVIEW']}** | Context-dependent primitive or unpinned dependency version requiring human disposition |",
            f"| **`CANNOT_DETERMINE_STATICALLY`** | **{counts['CANNOT_DETERMINE_STATICALLY']}** | Capable module detected, but runtime linkage/OE/approved mode cannot be proven statically |",
            f"| **`PASS` (Conformance Indicators)** | **{counts['PASS']}** | Approved algorithm/parameter or explicit approved-mode configuration indicator |",
            "",
            "---",
            "",
            "## 3. CMVP Module Mapping Summary",
            "",
        ])

        if not self.cmvp_mappings:
            lines.append("*No known cryptographic packages matched in workspace manifests. See `cbom.cdx.json` for source-level primitive usage.*")
        else:
            lines.extend([
                "| Dependency | Version | Determination | Candidate CMVP Cert(s) | Approved-Mode Evidence |",
                "| :--- | :---: | :---: | :--- | :--- |",
            ])
            for m in self.cmvp_mappings:
                c_txt = ", ".join(f"`#{c['cert_number']}` ({c['standard']} · {c['status']})" for c in m["certificates"]) or "None"
                e_txt = ", ".join(f"`{e}`" for e in m["approved_mode_evidence"]) or "None"
                lines.append(f"| **{m['dependency']}** | `{m['version']}` | `{m['determination']}` | {c_txt} | {e_txt} |")

        lines.extend(["", "---", "", "## 4. Actionable Assessment Findings (`FAIL` / `WARN`)", ""])
        actionable = [f for f in self.findings if f["determination"] in ("FAIL", "WARN")]
        if fi["total"] == 0:
            lines.append("*No assessable files found in the target workspace (0 files inspected). A clean assessment result cannot be claimed when nothing was inspected.*")
        elif not actionable:
            lines.append("*No `FAIL` or `WARN` assessment findings were detected in static source or configuration files.*")
        else:
            for idx, f in enumerate(actionable, start=1):
                loc = f["location"]
                loc_str = f"{loc.get('path', 'N/A')}:{loc['line_start']}" if loc.get("line_start") else loc.get("path", "N/A")
                refs = ", ".join(f.get("evidence", {}).get("references", [])) or "NIST SP 800-53 SC-13"
                snip = f.get("evidence", {}).get("snippet", "")
                lines.extend([
                    f"### 4.{idx} [{f['determination']} · {f.get('severity', 'MEDIUM')}] {f['title']}",
                    f"* **Finding ID**: `{f['finding_id']}` | **Rule**: `{f['rule_id']}` | **Confidence**: `{f['detection']['confidence']}` (`{f['detection']['method']}`)",
                    f"* **Location**: `{loc_str}`",
                    f"* **Controls**: `{', '.join(f['controls'])}` | **AOC**: `{f['aoc']['id']}`",
                    f"* **Normative Citation**: {refs}",
                    f"* **Detail**: {f['message']}",
                ])
                if snip:
                    lines.append(f"* **Evidence Snippet**: `{snip.replace('`', '')}`")
                if f.get("remediation"):
                    lines.append(f"* **Remediation**: {f['remediation']}")
                lines.append("")

        lines.extend(["---", "", "## 5. Items Requiring Human or Runtime Verification (`NEEDS_REVIEW` / `CANNOT_DETERMINE_STATICALLY`)", ""])
        indeterminate = [f for f in self.findings if f["determination"] in ("NEEDS_REVIEW", "CANNOT_DETERMINE_STATICALLY")]
        if not indeterminate:
            lines.append("*No indeterminate items pending human or runtime verification.*")
        else:
            lines.extend([
                "| Finding ID | Determination | Location | Subject | Controls | Verification Requirement |",
                "| :--- | :---: | :--- | :--- | :---: | :--- |",
            ])
            for f in indeterminate:
                loc = f["location"]
                loc_str = f"{loc.get('path', 'N/A')}:{loc['line_start']}" if loc.get("line_start") else loc.get("path", "N/A")
                msg_clean = f["message"].replace("|", "\\|")
                lines.append(
                    f"| `{f['finding_id']}` | `{f['determination']}` | `{loc_str}` | "
                    f"`{f['subject']['name']}` | `{', '.join(f['controls'])}` | {msg_clean} |"
                )

        lines.extend(["", "---", "", "## 6. Positive Conformance Indicators (`PASS`)", ""])
        positives = [f for f in self.findings if f["determination"] == "PASS"]
        if not positives:
            lines.append("*No positive conformance indicators recorded.*")
        else:
            lines.extend([
                "| Finding ID | Rule | Location | Subject | Indicator Summary |",
                "| :--- | :--- | :--- | :--- | :--- |",
            ])
            for f in positives:
                loc = f["location"]
                loc_str = f"{loc.get('path', 'N/A')}:{loc['line_start']}" if loc.get("line_start") else loc.get("path", "N/A")
                lines.append(
                    f"| `{f['finding_id']}` | `{f['rule_id']}` | `{loc_str}` | "
                    f"`{f['subject']['name']}` | {f['title'].replace('|', '/')} |"
                )

        lines.extend(["", "---", "", "## 7. Data Catalog Versions & Integrity", ""])
        lines.extend([
            "| Catalog File | Version | Last Updated | SHA-256 Digest |",
            "| :--- | :---: | :---: | :--- |",
        ])
        for cat in self.build_envelope()["engine"]["catalogs"]:
            lines.append(
                f"| `{cat['path']}` | `{cat['version']}` | `{cat.get('last_updated', 'N/A')}` | `{cat.get('sha256', 'N/A')}` |"
            )
        lines.append("")
        return "\n".join(lines)

    def build_provenance(self) -> Dict[str, Any]:
        tgt = self._target_metadata()
        return {
            "schema": "grc-fips-provenance-v1",
            "generated_at": utc_now_iso(),
            "target_identifier": tgt["identifier"],
            "workspace_path": str(self.workspace_root),
            "upstream_provenance_file": tgt.get("provenance_file"),
            "commit_sha": tgt.get("commit", "UNKNOWN"),
            "engine": {"name": ENGINE_NAME, "version": ENGINE_VERSION},
            "files_inspected": self.files_inspected_summary(),
            "catalogs": self.build_envelope()["engine"]["catalogs"],
            "cmvp_authenticity": self.cmvp_integrity,
            "staleness_warning": self.staleness_warning,
        }

    def build_terminal_preview(self, evidence_dir: Optional[Path] = None, dry_run: bool = False) -> str:
        tgt = self._target_metadata()["identifier"]
        fi = self.files_inspected_summary()
        fails = sum(1 for f in self.findings if f["determination"] == "FAIL")
        warns = sum(1 for f in self.findings if f["determination"] == "WARN")
        reviews = sum(1 for f in self.findings if f["determination"] in ("NEEDS_REVIEW", "CANNOT_DETERMINE_STATICALLY"))
        passes = sum(1 for f in self.findings if f["determination"] == "PASS")

        out = [
            "==========================================================================",
            "  GRC-xMINI · FIPS 140-3 Static Cryptographic Conformance Assessment",
            "==========================================================================",
            f"  Target Workspace : {self.workspace_root} ({tgt})",
            f"  Execution Mode   : {'DRY-RUN PREVIEW (no deliverables written)' if dry_run else 'DELIVERABLE GENERATION'}",
            f"  Evidence Output  : {evidence_dir if evidence_dir and not dry_run else '(stdout / preview)'}",
            (
                f"  Files Inspected  : {fi['total']} "
                f"(python={fi['python']}, polyglot_source={fi['polyglot_source']}, "
                f"manifests={fi['manifests']}, deploy_iac={fi['deploy_iac']}, "
                f"os_config={fi['os_config']}; workspace_total={fi['workspace_files_total']})"
            ),
            "--------------------------------------------------------------------------",
            f"  FAIL Findings                  : {fails}",
            f"  WARN Findings                  : {warns}",
            f"  Indeterminate / Needs Review   : {reviews}",
            f"  Conformance Indicators (PASS)  : {passes}",
            f"  CBOM Cryptographic Assets      : {len(self.ws_scanner.assets) + len(self.cmvp_mappings)}",
            "--------------------------------------------------------------------------",
        ]
        if fi["total"] == 0:
            out.append("  [WARN] No assessable files found in workspace (0 files inspected).")
            out.append("--------------------------------------------------------------------------")
        if self.staleness_warning:
            out.append(f"  [WARN] {self.staleness_warning}")
            out.append("--------------------------------------------------------------------------")

        for f in self.findings:
            if f["determination"] == "PASS":
                continue
            loc = f["location"]
            loc_str = f"{loc.get('path', 'N/A')}:{loc['line_start']}" if loc.get("line_start") else loc.get("path", "N/A")
            badge = f"[{f['determination']}]"
            out.append(f"  {badge:<30} {f['rule_id']} @ {loc_str}")
            out.append(f"      {f['title']}")
        out.append("==========================================================================")
        return "\n".join(out)

    def write_deliverables(self, evidence_dir: Path) -> List[str]:
        ev = Path(evidence_dir).resolve()
        ev.mkdir(parents=True, exist_ok=True)

        files_to_write = {
            "fips_findings.json": json.dumps(self.build_envelope(), indent=2) + "\n",
            "cbom.cdx.json": json.dumps(self.build_cbom_cyclonedx(), indent=2) + "\n",
            "fips_findings.sarif": json.dumps(self.build_sarif(), indent=2) + "\n",
            "cmvp_mapping.md": self.build_cmvp_mapping_markdown() + "\n",
            "fips_assessment.md": self.build_assessment_markdown() + "\n",
            "fips_provenance.json": json.dumps(self.build_provenance(), indent=2) + "\n",
        }
        for name, content in files_to_write.items():
            (ev / name).write_text(content, encoding="utf-8")

        # Seal sha256sum across all files in evidence_dir
        manifest_lines: List[str] = []
        for p in sorted(ev.iterdir()):
            if p.is_file() and p.name != "sha256sum" and not p.name.startswith("."):
                manifest_lines.append(f"{sha256_file(p)}  {p.name}")
        (ev / "sha256sum").write_text("\n".join(manifest_lines) + "\n", encoding="utf-8")
        return list(files_to_write.keys()) + ["sha256sum"]


# ==============================================================================
# CLI ENTRY POINT
# ==============================================================================

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="grc fips",
        description="Static FIPS 140-3 Cryptographic Discovery, Algorithm Policy, CMVP & CBOM Engine",
    )
    parser.add_argument(
        "-w", "--workspace",
        default=".",
        help="Path to unpacked bundle, local source checkout, or cold-mounted rootfs (default: .)",
    )
    parser.add_argument(
        "-e", "--evidence",
        default=None,
        help="Output directory for the 6 FIPS deliverables + sha256sum (default: artifacts/pick-up/<timestamp>_fips)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Preview assessment findings in terminal without writing files to disk.",
    )
    parser.add_argument(
        "-f", "--format",
        choices=["all", "terminal", "json", "markdown", "sarif", "cbom", "cmvp"],
        default="all",
        help="Output mode: 'all' writes full deliverable package (unless --dry-run); single format prints or writes -o.",
    )
    parser.add_argument(
        "-o", "--output",
        default=None,
        help="Optional single-file output path when using --format json|markdown|sarif|cbom|cmvp.",
    )
    parser.add_argument("--policy", default=None, help="Custom path to fips_algorithm_policy.json")
    parser.add_argument("--cmvp-catalog", default=None, help="Custom path to cmvp_catalog.json")
    parser.add_argument("--crypto-catalog", default=None, help="Custom path to crypto_catalog.json")
    parser.add_argument(
        "--staleness-days",
        type=int,
        default=None,
        help="Override CMVP snapshot staleness warning threshold in days (default: 90).",
    )
    parser.add_argument(
        "--allow-empty",
        action="store_true",
        help="Return exit code 0 even when 0 assessable files are found in the workspace.",
    )
    parser.add_argument(
        "--fail-on",
        choices=["FAIL", "NEEDS_REVIEW", "never"],
        default="never",
        help="Exit non-zero when matching findings exist ('FAIL', 'NEEDS_REVIEW', or 'never' [default]).",
    )
    return parser


def _compute_exit_code(envelope: Dict[str, Any], allow_empty: bool, fail_on: str) -> int:
    fi_total = envelope.get("scope", {}).get("files_inspected", {}).get("total", 0)
    if fi_total == 0 and not allow_empty:
        return 2
    dets = {str(f.get("determination") or "") for f in envelope.get("findings", [])}
    if fail_on == "FAIL" and (dets & {"FAIL", "WARN"}):
        return 1
    if fail_on == "NEEDS_REVIEW" and (dets & {"FAIL", "WARN", "NEEDS_REVIEW", "CANNOT_DETERMINE_STATICALLY"}):
        return 1
    return 0


def _next_available_evidence_dir(base_dir: Path) -> Path:
    """Appends `_2`, `_3`, ... if an auto-generated evidence folder already exists (`M8`)."""
    if not base_dir.exists():
        return base_dir
    suffix = 2
    while True:
        cand = base_dir.parent / f"{base_dir.name}_{suffix}"
        if not cand.exists():
            return cand
        suffix += 1


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    ws = Path(args.workspace).resolve()
    if not ws.exists():
        print(f"[FATAL] Workspace path does not exist: {ws}", file=sys.stderr)
        sys.exit(1)
    if not ws.is_dir():
        if ws.name.lower().endswith(".bundle"):
            print(
                f"[FATAL] Workspace path is a Git bundle file, not a directory: {ws}\n"
                f"        Restore the bundle first: ./grc bundle restore {ws} -w ./ephemeral_workspace -r <tag> -f --read-only",
                file=sys.stderr,
            )
        else:
            print(f"[FATAL] Workspace path is not a directory: {ws}", file=sys.stderr)
        sys.exit(1)

    engine = FIPSAssessmentEngine(
        workspace_root=ws,
        policy_path=Path(args.policy) if args.policy else None,
        cmvp_path=Path(args.cmvp_catalog) if args.cmvp_catalog else None,
        crypto_catalog_path=Path(args.crypto_catalog) if args.crypto_catalog else None,
        staleness_days=args.staleness_days,
    )
    envelope = engine.run()
    fi_total = envelope["scope"]["files_inspected"]["total"]
    if fi_total == 0:
        print(
            f"[WARN] No assessable files found in workspace '{ws}' "
            f"(0 files inspected across Python, polyglot source, manifests, deploy/IaC, and OS config).",
            file=sys.stderr,
        )

    rc = _compute_exit_code(envelope, allow_empty=args.allow_empty, fail_on=args.fail_on)

    if args.format != "all":
        if args.format == "json":
            rendered = json.dumps(envelope, indent=2)
        elif args.format == "markdown":
            rendered = engine.build_assessment_markdown()
        elif args.format == "sarif":
            rendered = json.dumps(engine.build_sarif(), indent=2)
        elif args.format == "cbom":
            rendered = json.dumps(engine.build_cbom_cyclonedx(), indent=2)
        elif args.format == "cmvp":
            rendered = engine.build_cmvp_mapping_markdown()
        else:
            rendered = engine.build_terminal_preview(dry_run=True)

        if args.output and not args.dry_run:
            out_p = Path(args.output).resolve()
            out_p.parent.mkdir(parents=True, exist_ok=True)
            out_p.write_text(rendered + ("\n" if not rendered.endswith("\n") else ""), encoding="utf-8")
            print(f"[SUCCESS] FIPS deliverable written to: {out_p}")
        else:
            print(rendered)
        if rc != 0:
            sys.exit(rc)
        return

    if args.dry_run:
        print(engine.build_terminal_preview(dry_run=True))
        if rc != 0:
            sys.exit(rc)
        return

    if args.evidence:
        ev_dir = Path(args.evidence).resolve()
    else:
        ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d_%H%M%S")
        tgt_slug = engine._default_evidence_slug()
        ev_dir = _next_available_evidence_dir(REPO_ROOT / "artifacts" / "pick-up" / f"{ts}_{tgt_slug}_fips")

    written = engine.write_deliverables(ev_dir)
    print(engine.build_terminal_preview(evidence_dir=ev_dir, dry_run=False))
    print(f"[SUCCESS] Wrote {len(written)} FIPS assessment deliverables to: {ev_dir}")
    for fname in written:
        print(f"    - {fname}")
    if rc != 0:
        sys.exit(rc)


if __name__ == "__main__":
    main()
