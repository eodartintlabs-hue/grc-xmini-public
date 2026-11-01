#!/usr/bin/env python3
"""
GRCx (The GRC eXperience) — Standalone Scan-to-POA&M Transformation Engine
Engine: scripts/transform_scans.py (v1.3.4 — Sasebo) [LEGACY match mode build]

Purpose:
  Standalone Continuous Monitoring (ConMon) engine for GRC analysts.
  Ingests Tenable (Nessus / Tenable.sc / Tenable.io) or AWS Inspector scan
  results in .csv or .xlsx format and populates the official OPEN and CLOSED
  FedRAMP POA&M Excel templates (.xlsx) using 100% Python 3 Standard Library.

Key Capabilities:
  1. Multi-Format Ingestion (.csv & .xlsx): Auto-detects Tenable vs. AWS Inspector
     exports and maps every finding (1 row per Vulnerability + Asset pair) into
     the 27 official FedRAMP POA&M columns.
  2. Open -> Closed POA&M Delta Reconciliation: Requests the previously filled-out
     OPEN FedRAMP POA&M (.xlsx). Findings still present carry over with their
     immutable Original Detection Date; findings no longer present in the new scan
     (or marked False Positive = Yes) automatically move to the CLOSED FedRAMP
     POA&M template (.xlsx).
  3. Interactive Remediation Plan Drafter ([y/n]): Detects any POA&M entries
     missing a Remediation Plan (Column K) and asks if the analyst wants GRCx to
     auto-draft missing plans with official Tenable or AWS remediation URLs.
  4. SLA Breach & Finding Age Analysis: Reports the exact count of finished POA&M
     entries whose Scheduled Completion Date (SLA) has passed and calculates how
     many days old each entry is from its Original Detection Date.
"""

import argparse
import csv
import datetime
import io
import json
import os
import re
import sys
import zipfile
import xml.etree.ElementTree as ET
from typing import Dict, List, Optional, Set, Tuple

# ---------------------------------------------------------------------------
# Constants & FedRAMP Column Definitions
# ---------------------------------------------------------------------------

# ---- Match mode for this build (no CLI flag needed) ------------------------
# "legacy": Apps Script behavior - match on Weakness Name + Description only.
# "strict": plugin/source ID + host, unscanned hosts kept open for review.
MATCH_MODE = "legacy"

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(SCRIPT_DIR)
DEFAULT_SCANS_DIR = os.path.join(REPO_ROOT, "scans")
SAMPLE_SCANS_DIR = os.path.join(REPO_ROOT, "testing", "sample-scans")
DEFAULT_OPEN_TEMPLATE = os.path.join(REPO_ROOT, "templates", "OPEN FedRAMP-POAM-Template.xlsx")
DEFAULT_CLOSED_TEMPLATE = os.path.join(REPO_ROOT, "templates", "CLOSED LEGACY FedRAMP-POAM-Template.xlsx")
DEFAULT_KEV_CATALOG = os.path.join(REPO_ROOT, "rules", "cisa_kev_catalog.json")

SCAN_EXTENSIONS = (".csv", ".xlsx", ".xlsm")
POAM_EXTENSIONS = (".xlsx", ".xlsm")
MAX_SCAN_FILES = 5

EXCEL_EPOCH = datetime.date(1899, 12, 30)
EXCEL_MAX_CELL_CHARS = 32767
MAIN_NS = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
REL_NS = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"

ET.register_namespace("", MAIN_NS)
ET.register_namespace("r", REL_NS)

# Matches ASCII/Unicode control characters forbidden by the XML 1.0 specification:
# Allowed: #x9 (TAB), #xA (LF), #xD (CR), [#x20-#xD7FF], [#xE000-#xFFFD]
_ILLEGAL_XML_CHARS_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f\ud800-\udfff\ufffe\uffff]")

# 27 logical FedRAMP POA&M fields in canonical order:
# In OPEN FedRAMP-POAM-Template.xlsx:   Columns B .. AB (Row 5+)
# In CLOSED FedRAMP-POAM-Template.xlsx: Columns A .. AA (Row 3+)
POAM_FIELDS = [
    "poam_id",                  # OPEN: B  | CLOSED: A  | POAM ID
    "controls",                 # OPEN: C  | CLOSED: B  | Controls
    "weakness_name",            # OPEN: D  | CLOSED: C  | Weakness Name
    "weakness_description",     # OPEN: E  | CLOSED: D  | Weakness Description
    "detector_source",          # OPEN: F  | CLOSED: E  | Weakness Detector Source
    "source_identifier",        # OPEN: G  | CLOSED: F  | Weakness Source Identifier
    "asset_identifier",         # OPEN: H  | CLOSED: G  | Asset Identifier
    "point_of_contact",         # OPEN: I  | CLOSED: H  | Point of Contact
    "resources_required",       # OPEN: J  | CLOSED: I  | Resources Required
    "remediation_plan",         # OPEN: K  | CLOSED: J  | Remediation Plan / Overall Remediation Plan
    "original_detection_date",  # OPEN: L  | CLOSED: K  | Original Detection Date
    "scheduled_completion_date",# OPEN: M  | CLOSED: L  | Scheduled Completion Date
    "status_date",              # OPEN: N  | CLOSED: M  | Status Date
    "vendor_dependency",        # OPEN: O  | CLOSED: N  | Vendor Dependency
    "last_vendor_checkin",      # OPEN: P  | CLOSED: O  | Last Vendor Check-in Date
    "vendor_product_name",      # OPEN: Q  | CLOSED: P  | Vendor Dependent Product Name
    "original_risk_rating",     # OPEN: R  | CLOSED: Q  | Original Risk Rating
    "adjusted_risk_rating",     # OPEN: S  | CLOSED: R  | Adjusted Risk Rating
    "risk_adjustment",          # OPEN: T  | CLOSED: S  | Risk Adjustment
    "false_positive",           # OPEN: U  | CLOSED: T  | False Positive
    "operational_requirement",  # OPEN: V  | CLOSED: U  | Operational Requirement
    "deviation_rationale",      # OPEN: W  | CLOSED: V  | Deviation Rationale
    "supporting_documents",     # OPEN: X  | CLOSED: W  | Supporting Documents
    "comments",                 # OPEN: Y  | CLOSED: X  | Comments
    "bod_22_01_tracking",       # OPEN: Z  | CLOSED: Y  | Binding Operational Directive 22-01 tracking
    "bod_22_01_due_date",       # OPEN: AA | CLOSED: Z  | Binding Operational Directive 22-01 Due Date
    "cve",                      # OPEN: AB | CLOSED: AA | CVE
]


def col_to_idx(col_str: str) -> int:
    """Convert Excel column letters (e.g., 'A' -> 0, 'Z' -> 25, 'AA' -> 26)."""
    res = 0
    for ch in col_str:
        if "A" <= ch <= "Z":
            res = res * 26 + (ord(ch) - ord("A") + 1)
    return res - 1


def idx_to_col(idx: int) -> str:
    """Convert 0-based column index to Excel column letters (0 -> 'A', 25 -> 'Z', 26 -> 'AA')."""
    res = ""
    n = idx + 1
    while n > 0:
        n, rem = divmod(n - 1, 26)
        res = chr(ord("A") + rem) + res
    return res


# Default layout: the POAM ID is in column A for BOTH the OPEN and CLOSED workbooks
# (fields run A .. AA). The real position is detected from the sheet's header row
# (see detect_poam_id_col) and can be forced with --poam-id-column.
DEFAULT_POAM_ID_COL_IDX = 0
OPEN_COL_LETTERS = [idx_to_col(DEFAULT_POAM_ID_COL_IDX + i) for i in range(len(POAM_FIELDS))]    # A .. AA
CLOSED_COL_LETTERS = [idx_to_col(i) for i in range(0, len(POAM_FIELDS))]                         # A .. AA

# Optional CLI override (column letter of the POAM ID header). None = auto-detect.
POAM_ID_COLUMN_OVERRIDE: Optional[str] = None


def col_letters_from_start(start_idx: int) -> List[str]:
    """Return the 27 POA&M field column letters starting at 0-based column `start_idx`."""
    return [idx_to_col(start_idx + i) for i in range(len(POAM_FIELDS))]


def _norm_header(text: str) -> str:
    return re.sub(r"[^a-z0-9]", "", str(text).lower())


def detect_poam_id_col(rows: List[Dict[str, str]], max_header_row: int = 10) -> Optional[int]:
    """
    Find the 0-based column index of the 'POAM ID' / 'POA&M ID' header within the first
    `max_header_row` rows of a worksheet (rows as returned by read_xlsx_rows).
    """
    for r in rows:
        r_num = int(r.get("_row_num", "0") or 0)
        if r_num == 0 or r_num > max_header_row:
            continue
        for key, val in r.items():
            if key.startswith("_"):
                continue
            if _norm_header(val) in ("poamid", "poamitemid"):
                return col_to_idx(key)
    return None


def resolve_col_letters(rows: List[Dict[str, str]], is_closed_template: bool, label: str = "") -> List[str]:
    """Pick the field column letters for a workbook: CLI override > header detection > default (col A)."""
    if POAM_ID_COLUMN_OVERRIDE:
        return col_letters_from_start(col_to_idx(POAM_ID_COLUMN_OVERRIDE))
    idx = detect_poam_id_col(rows)
    if idx is None:
        print(
            f"[WARNING] Could not find a 'POAM ID' header{' in ' + label if label else ''}; "
            f"assuming the POAM ID is in column {idx_to_col(DEFAULT_POAM_ID_COL_IDX)} "
            f"(use --poam-id-column to override).",
            file=sys.stderr,
        )
        idx = DEFAULT_POAM_ID_COL_IDX
    return col_letters_from_start(idx)

DATE_FIELDS = {
    "original_detection_date",
    "scheduled_completion_date",
    "status_date",
    "last_vendor_checkin",
    "bod_22_01_due_date",
}

SLA_DAYS_BY_RISK = {
    "Critical": 30,
    "High": 30,
    "Moderate": 90,
    "Low": 180,
}

RISK_ORDER = {"Critical": 0, "High": 1, "Moderate": 2, "Low": 3}


# ---------------------------------------------------------------------------
# Date, XML Sanitization & Excel Helper Utilities
# ---------------------------------------------------------------------------

def sanitize_excel_string(val: str, max_len: int = EXCEL_MAX_CELL_CHARS) -> str:
    """
    Strip control characters forbidden by XML 1.0 and enforce Excel's 32,767-character
    per-cell limit so scanner outputs never corrupt sharedStrings.xml.
    """
    if val is None:
        return ""
    cleaned = _ILLEGAL_XML_CHARS_RE.sub("", str(val))
    if len(cleaned) > max_len:
        suffix = "... [truncated]"
        cleaned = cleaned[: max_len - len(suffix)] + suffix
    return cleaned


def register_xml_namespaces(xml_bytes: bytes) -> Dict[str, str]:
    """
    Read all xmlns declarations from an XML byte stream and register their original
    prefixes with ElementTree so serialization never renames them to ns0, ns1, etc.
    """
    ns_map: Dict[str, str] = {}
    try:
        for _, (prefix, uri) in ET.iterparse(io.BytesIO(xml_bytes), events=("start-ns",)):
            p = prefix or ""
            ns_map[p] = uri
            ET.register_namespace(p, uri)
    except ET.ParseError:
        pass
    return ns_map


def serialize_xml_preserving_root_ns(root_el: ET.Element, original_xml_bytes: bytes) -> bytes:
    """
    Serialize an ElementTree root element to UTF-8 XML bytes while preserving all
    original root-element xmlns:<prefix> declarations (such as those referenced
    by mc:Ignorable="x14ac xr ...") that ElementTree omits if unused on child tags.
    """
    register_xml_namespaces(original_xml_bytes)
    xml_out = ET.tostring(root_el, encoding="utf-8", xml_declaration=True)

    # Extract xmlns:prefix="uri" declarations from the original root opening tag
    m_orig_root = re.search(rb"<([A-Za-z0-9_:]+)(\s[^>]*?)?>", original_xml_bytes)
    if not m_orig_root or not m_orig_root.group(2):
        return xml_out

    orig_attrs = m_orig_root.group(2).decode("utf-8", errors="replace")
    orig_xmlns = re.findall(r'(xmlns(?::[A-Za-z0-9_-]+)?="[^"]+")', orig_attrs)
    if not orig_xmlns:
        return xml_out

    root_tag_name = m_orig_root.group(1)
    m_new_root = re.search(rb"<" + re.escape(root_tag_name) + rb"(\s[^>]*?)?>", xml_out)
    if not m_new_root:
        return xml_out

    new_root_str = m_new_root.group(0).decode("utf-8", errors="replace")
    missing_decls = []
    for decl in orig_xmlns:
        prefix_part = decl.split("=", 1)[0]
        if f" {prefix_part}=" not in new_root_str:
            missing_decls.append(decl)

    if missing_decls:
        injected = new_root_str[:-1] + " " + " ".join(missing_decls) + ">"
        xml_out = xml_out[: m_new_root.start()] + injected.encode("utf-8") + xml_out[m_new_root.end() :]

    return xml_out


def resolve_sheet_path(z: zipfile.ZipFile, sheet_index: int = 0) -> str:
    """
    Resolve the archive path of worksheet `sheet_index` via xl/workbook.xml and
    xl/_rels/workbook.xml.rels, handling both relative ('worksheets/sheet1.xml')
    and root-relative ('/xl/worksheets/sheet1.xml') relationship targets.
    """
    ns = {"main": MAIN_NS, "r": REL_NS}
    names = set(z.namelist())
    if "xl/workbook.xml" in names and "xl/_rels/workbook.xml.rels" in names:
        try:
            wb_root = ET.fromstring(z.read("xl/workbook.xml"))
            rels_root = ET.fromstring(z.read("xl/_rels/workbook.xml.rels"))
            rel_map = {
                rel.attrib["Id"]: rel.attrib["Target"]
                for rel in rels_root
                if "Id" in rel.attrib and "Target" in rel.attrib
            }
            sheets = wb_root.findall(".//main:sheet", ns)
            if sheets:
                chosen_sheet = sheets[min(sheet_index, len(sheets) - 1)]
                rid = chosen_sheet.attrib.get(f"{{{REL_NS}}}id", "")
                raw_target = rel_map.get(rid, "")
                if raw_target:
                    clean_target = raw_target.lstrip("/")
                    if not clean_target.startswith("xl/"):
                        clean_target = "xl/" + clean_target
                    if clean_target in names:
                        return clean_target
        except ET.ParseError:
            pass

    if "xl/worksheets/sheet1.xml" in names:
        return "xl/worksheets/sheet1.xml"
    for name in sorted(names):
        if name.startswith("xl/worksheets/sheet") and name.endswith(".xml"):
            return name
    return "xl/worksheets/sheet1.xml"


def split_cell_ref(cell_ref: str) -> Tuple[str, int]:
    """Split 'AB12' into ('AB', 12)."""
    m = re.match(r"^([A-Z]+)(\d+)$", cell_ref.upper())
    if not m:
        return ("A", 1)
    return m.group(1), int(m.group(2))


def date_to_excel_serial(d: datetime.date) -> int:
    """Convert Python date to Excel serial integer (1900 date system)."""
    return (d - EXCEL_EPOCH).days


def excel_serial_to_date(serial_val: float) -> Optional[datetime.date]:
    """Convert Excel serial number to Python date."""
    try:
        days = int(round(float(serial_val)))
        if 10000 <= days <= 90000:
            return EXCEL_EPOCH + datetime.timedelta(days=days)
    except (ValueError, TypeError):
        pass
    return None


def parse_any_date(val: str, fallback: Optional[datetime.date] = None) -> Optional[datetime.date]:
    """Parse Excel serial dates, ISO timestamps, or common US/International date strings."""
    if val is None:
        return fallback
    s = str(val).strip()
    if not s or s.lower() in ("n/a", "none", "null", "-"):
        return fallback

    # Check if numeric Excel serial date
    if re.match(r"^\d+(\.\d+)?$", s):
        d = excel_serial_to_date(float(s))
        if d:
            return d

    # Strip trailing time / timezone component if ISO-like
    s_clean = re.sub(r"[T\s]\d{1,2}:\d{2}(:\d{2})?(\.\d+)?(Z|[+-]\d{2}:?\d{2}|\s*[A-Z]{2,4})?$", "", s).strip()

    date_formats = [
        "%Y-%m-%d",
        "%m/%d/%Y",
        "%m/%d/%y",
        "%Y/%m/%d",
        "%d-%b-%Y",
        "%d-%b-%y",
        "%b %d, %Y",
        "%B %d, %Y",
        "%d/%m/%Y",
    ]
    for fmt in date_formats:
        try:
            return datetime.datetime.strptime(s_clean, fmt).date()
        except ValueError:
            continue

    # Try matching YYYY-MM-DD anywhere inside the string
    m_iso = re.search(r"(\d{4})-(\d{2})-(\d{2})", s)
    if m_iso:
        try:
            return datetime.date(int(m_iso.group(1)), int(m_iso.group(2)), int(m_iso.group(3)))
        except ValueError:
            pass

    return fallback


def format_date_iso(d: Optional[datetime.date]) -> str:
    """Format date as YYYY-MM-DD or empty string."""
    return d.strftime("%Y-%m-%d") if d else ""


MONTH_ABBRS = (
    "", "JAN", "FEB", "MAR", "APR", "MAY", "JUN",
    "JUL", "AUG", "SEP", "OCT", "NOV", "DEC"
)


def format_poam_id(date_obj: datetime.date, seq: int) -> str:
    """
    Format POA&M ID following dynamic FedRAMP standard YYYY-MMM-##### (e.g., 2026-SEP-00347).
    """
    month_abbr = MONTH_ABBRS[date_obj.month] if 1 <= date_obj.month <= 12 else "GEN"
    return f"{date_obj.year:04d}-{month_abbr}-{seq:05d}"


def normalize_risk(raw_risk: str) -> Optional[str]:
    """
    Normalize scanner severity strings into FedRAMP Risk Ratings:
    Critical, High, Moderate, Low (or None for Informational/None).
    """
    if not raw_risk:
        return None
    s = str(raw_risk).strip().lower()
    if s in ("critical", "crit", "4", "cat i", "cat 1", "very high"):
        return "Critical"
    if s in ("high", "3"):
        return "High"
    if s in ("moderate", "medium", "med", "2", "cat ii", "cat 2"):
        return "Moderate"
    if s in ("low", "1", "cat iii", "cat 3"):
        return "Low"
    if s in ("info", "informational", "none", "0", "passed", "open"):
        return None
    return None


def compute_sla_date(detection_date: datetime.date, risk_rating: str, adjusted_risk: str = "", risk_adj_approved: str = "") -> datetime.date:
    """Calculate FedRAMP Scheduled Completion Date from Original Detection Date and Risk Rating."""
    effective_risk = risk_rating
    if str(risk_adj_approved).strip().lower() == "yes" and adjusted_risk in SLA_DAYS_BY_RISK:
        effective_risk = adjusted_risk
    days = SLA_DAYS_BY_RISK.get(effective_risk, 90)
    return detection_date + datetime.timedelta(days=days)


# ---------------------------------------------------------------------------
# Pure-Python Standard Library .xlsx Reader
# ---------------------------------------------------------------------------

def read_xlsx_rows(xlsx_path: str, sheet_index: int = 0) -> List[Dict[str, str]]:
    """
    Stream-read an .xlsx worksheet into a list of dicts keyed by column letter ('A', 'B', ..., 'AB')
    using ET.iterparse so large Tenable.sc / Inspector workbooks load with minimal memory overhead.
    Each dict also includes '_row_num' (1-based Excel row index).
    """
    si_tag = f"{{{MAIN_NS}}}si"
    t_tag = f"{{{MAIN_NS}}}t"
    row_tag = f"{{{MAIN_NS}}}row"
    c_tag = f"{{{MAIN_NS}}}c"
    v_tag = f"{{{MAIN_NS}}}v"
    is_tag = f"{{{MAIN_NS}}}is"

    rows_out: List[Dict[str, str]] = []

    with zipfile.ZipFile(xlsx_path, "r") as z:
        shared_strings: List[str] = []
        if "xl/sharedStrings.xml" in z.namelist():
            with z.open("xl/sharedStrings.xml") as ss_stream:
                for _, elem in ET.iterparse(ss_stream, events=("end",)):
                    if elem.tag == si_tag:
                        texts = [t.text or "" for t in elem.iter(t_tag)]
                        shared_strings.append("".join(texts))
                        elem.clear()

        target = resolve_sheet_path(z, sheet_index=sheet_index)
        if target not in z.namelist():
            return []

        with z.open(target) as sheet_stream:
            for _, elem in ET.iterparse(sheet_stream, events=("end",)):
                if elem.tag == row_tag:
                    r_num = int(elem.attrib.get("r", "0"))
                    row_dict: Dict[str, str] = {"_row_num": str(r_num)}
                    for c in elem.findall(c_tag):
                        c_ref = c.attrib.get("r", "")
                        col_let, _ = split_cell_ref(c_ref)
                        c_type = c.attrib.get("t", "")
                        v = c.find(v_tag)
                        is_elem = c.find(is_tag)
                        val = ""
                        if v is not None and v.text is not None:
                            if c_type == "s":
                                try:
                                    idx = int(v.text)
                                    val = shared_strings[idx] if 0 <= idx < len(shared_strings) else v.text
                                except ValueError:
                                    val = v.text
                            else:
                                val = v.text
                        elif is_elem is not None:
                            val = "".join([t.text or "" for t in is_elem.iter(t_tag)])
                        row_dict[col_let] = val.strip()
                    rows_out.append(row_dict)
                    elem.clear()

    return rows_out


# ---------------------------------------------------------------------------
# Generic Scan File Reader (.csv or .xlsx) & Scanner Auto-Detection
# ---------------------------------------------------------------------------

def load_scan_records(scan_path: str) -> List[Dict[str, str]]:
    """
    Load a Tenable or AWS Inspector scan export from either .csv or .xlsx
    into a list of column-header -> value dictionaries.
    """
    ext = os.path.splitext(scan_path)[1].lower()
    if ext in (".xlsx", ".xlsm"):
        raw_rows = read_xlsx_rows(scan_path)
        if not raw_rows:
            return []
        # Find header row (first non-empty row with >= 3 populated columns)
        header_row = None
        header_idx = 0
        for i, r in enumerate(raw_rows):
            non_empty = [k for k, v in r.items() if k != "_row_num" and v]
            if len(non_empty) >= 3:
                header_row = r
                header_idx = i
                break
        if not header_row:
            return []
        col_to_header = {
            col: val.strip()
            for col, val in header_row.items()
            if col != "_row_num" and val.strip()
        }
        records: List[Dict[str, str]] = []
        for r in raw_rows[header_idx + 1:]:
            rec = {}
            has_val = False
            for col, hdr in col_to_header.items():
                v = r.get(col, "").strip()
                if v:
                    has_val = True
                rec[hdr] = v
            if has_val:
                records.append(rec)
        return records
    else:
        # CSV reader (with UTF-8-SIG BOM handling)
        with open(scan_path, "r", encoding="utf-8-sig", errors="replace", newline="") as f:
            reader = csv.DictReader(f)
            out = []
            for row in reader:
                clean_row = {(k or "").strip(): (v or "").strip() for k, v in row.items() if k}
                if any(clean_row.values()):
                    out.append(clean_row)
            return out


def detect_scanner_type(records: List[Dict[str, str]], explicit_scanner: Optional[str] = None) -> str:
    """Detect whether the input scan is 'tenable' or 'inspector'."""
    if explicit_scanner and explicit_scanner.lower() in ("tenable", "inspector", "aws", "nessus"):
        return "tenable" if explicit_scanner.lower() in ("tenable", "nessus") else "inspector"
    if not records:
        return "tenable"
    headers_lower = {k.lower() for k in records[0].keys()}
    tenable_markers = {"plugin id", "plugin", "plugin name", "synopsis", "plugin output", "see also"}
    inspector_markers = {"finding arn", "arn", "vulnerability id", "resource id", "fix available", "inspector score", "package manager"}
    t_hits = len(headers_lower & tenable_markers)
    i_hits = len(headers_lower & inspector_markers)
    if i_hits > t_hits:
        return "inspector"
    return "tenable"


def get_first_field(row: Dict[str, str], candidates: List[str], default: str = "") -> str:
    """Case-insensitive lookup across candidate column names."""
    lower_map = {k.lower().strip(): v for k, v in row.items()}
    for cand in candidates:
        val = lower_map.get(cand.lower().strip(), "")
        if val != "":
            return val.strip()
    return default


def infer_nist_controls(weakness_name: str, description: str, cve: str = "") -> str:
    """
    Infer suggested NIST SP 800-53 Rev 5 controls based on finding characteristics
    (and CVE identifiers). Analysts can override this column in the OPEN POA&M, and
    carried-over items preserve analyst-curated control mappings.
    """
    text = f"{weakness_name} {description} {cve}".lower()
    controls = ["RA-5", "SI-2"]
    if any(k in text for k in ("tls", "ssl", "certificate", "cipher", "rc4", "3des", "cbc", "cleartext")):
        controls.append("SC-8")
        controls.append("SC-13")
    elif any(k in text for k in ("fips", "openssl", "crypto", "md5", "sha-1", "sha1")):
        controls.append("SC-13")
    if any(k in text for k in ("unencrypted", "encryption at rest", "ebs", "s3", "kms")):
        controls.append("SC-28")
        controls.append("SC-8")
    if any(k in text for k in ("ssh", "password", "authentication", "credential", "default account")):
        controls.append("IA-2")
        controls.append("AC-6")
    if any(k in text for k in ("cis ", "stig", "configuration", "permission", "world-writable")):
        controls.append("CM-6")
    # Preserve order while deduplicating
    seen = set()
    dedup = []
    for c in controls:
        if c not in seen:
            seen.add(c)
            dedup.append(c)
    return ", ".join(dedup)


def load_cisa_kev_catalog(catalog_path: Optional[str] = None) -> Dict[str, Dict[str, str]]:
    """
    Load a local CISA Known Exploited Vulnerabilities (KEV) JSON catalog
    (default: rules/cisa_kev_catalog.json) into a CVE -> metadata dict.
    """
    path = catalog_path or DEFAULT_KEV_CATALOG
    if not path or not os.path.isfile(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        vulns = data.get("vulnerabilities", []) if isinstance(data, dict) else []
        out: Dict[str, Dict[str, str]] = {}
        for item in vulns:
            if not isinstance(item, dict):
                continue
            cid = str(item.get("cveID", "")).strip().upper()
            if cid:
                out[cid] = {
                    "dateAdded": str(item.get("dateAdded", "")).strip(),
                    "dueDate": str(item.get("dueDate", "")).strip(),
                }
        return out
    except (OSError, ValueError, TypeError):
        return {}


def resolve_bod_22_01_status(
    row: Dict[str, str],
    cves_str: str,
    det_date: datetime.date,
    kev_catalog: Dict[str, Dict[str, str]],
) -> Tuple[str, str]:
    """
    Determine BOD 22-01 tracking ('Yes' or '') and BOD 22-01 Due Date ('YYYY-MM-DD' or ''):
      - Never conflates Tenable/Inspector 'Exploit Available' with CISA KEV.
      - Checks explicit KEV/BOD 22-01 columns and matches CVEs against the local CISA KEV catalog.
      - Uses explicit 'BOD 22-01 Due Date' / 'KEV Due Date' column or CISA's catalog 'dueDate'
        (or det_date + 14d when detected after CISA's catalog dateAdded).
    """
    explicit_kev_raw = get_first_field(
        row,
        ["CISA KEV", "KEV", "BOD 22-01", "Known Exploited Vulnerability", "CISA Known Exploited"],
    )
    explicit_due_raw = get_first_field(
        row,
        ["BOD 22-01 Due Date", "KEV Due Date", "CISA KEV Due Date"],
    )
    explicit_is_kev = explicit_kev_raw.strip().lower() in ("yes", "true", "1", "kev")
    explicit_is_not_kev = explicit_kev_raw.strip().lower() in ("no", "false", "0")

    cves = [c.strip().upper() for c in cves_str.split(",") if c.strip()]
    matched_kev_meta: Optional[Dict[str, str]] = None
    for c in cves:
        if c in kev_catalog:
            matched_kev_meta = kev_catalog[c]
            break

    is_kev = explicit_is_kev or (matched_kev_meta is not None and not explicit_is_not_kev)
    if not is_kev:
        return ("", "")

    # 1. Explicit due date column in scan export
    if explicit_due_raw:
        parsed_explicit_due = parse_any_date(explicit_due_raw)
        if parsed_explicit_due:
            return ("Yes", format_date_iso(parsed_explicit_due))

    # 2. CISA KEV catalog dueDate / dateAdded logic (BOD 22-01 authoritative catalog dueDate)
    if matched_kev_meta:
        cat_due = parse_any_date(matched_kev_meta.get("dueDate", ""))
        if cat_due:
            return ("Yes", format_date_iso(cat_due))
        cat_added = parse_any_date(matched_kev_meta.get("dateAdded", ""))
        if cat_added:
            return ("Yes", format_date_iso(cat_added + datetime.timedelta(days=14)))

    # 3. Fallback when marked CISA KEV = Yes in CSV without catalog entry
    return ("Yes", format_date_iso(det_date + datetime.timedelta(days=14)))


def extract_cves(raw_cve_text: str, fallback_text: str = "") -> str:
    """Extract and deduplicate CVE-YYYY-NNNN+ identifiers."""
    combined = f"{raw_cve_text} {fallback_text}"
    matches = re.findall(r"CVE-\d{4}-\d{4,7}", combined, flags=re.IGNORECASE)
    seen = set()
    out = []
    for m in matches:
        up = m.upper()
        if up not in seen:
            seen.add(up)
            out.append(up)
    return ", ".join(out)


def extract_urls(text: str) -> List[str]:
    """Extract HTTP/HTTPS URLs from scanner fields."""
    if not text:
        return []
    urls = re.findall(r"https?://[^\s,;\)\"'>]+", text)
    seen = set()
    out = []
    for u in urls:
        u_clean = u.rstrip(".")
        if u_clean not in seen:
            seen.add(u_clean)
            out.append(u_clean)
    return out


def extract_base_asset(asset_str: str) -> str:
    """Normalize asset identifier (strip port/protocol or resource type suffix) for matching."""
    if not asset_str:
        return ""
    first_line = asset_str.strip().splitlines()[0].strip()
    base = re.sub(r"\s*\([^\)]*\)\s*$", "", first_line).strip()
    return base.lower()


def extract_row_asset_aliases(row: Dict[str, str]) -> List[str]:
    """
    Extract all non-empty normalized asset identifiers (IP, DNS, FQDN, Host, Resource ID)
    present on a single scan row.
    """
    candidate_cols = [
        "Host",
        "IP Address",
        "DNS Name",
        "FQDN",
        "Asset",
        "NetBIOS Name",
        "Resource ID",
        "Instance ID",
        "Asset Identifier",
        "Asset ID",
    ]
    aliases: List[str] = []
    seen: Set[str] = set()
    for col in candidate_cols:
        raw_val = get_first_field(row, [col])
        if raw_val:
            norm = extract_base_asset(raw_val)
            if norm and norm not in seen:
                seen.add(norm)
                aliases.append(norm)
    return aliases


def collect_scanned_assets(records: List[Dict[str, str]]) -> Tuple[Set[str], Dict[str, Set[str]]]:
    """
    Inspect ALL rows in the scan export (including Informational / None rows such as
    Tenable Plugin 19506 'Nessus Scan Information') BEFORE severity filtering to build:
      1. `scanned_assets`: Every asset identifier confirmed scanned in this run.
      2. `asset_alias_map`: Maps any identifier of a host (e.g. IP) to all co-occurring
         identifiers on the same scan row (e.g. DNS Name / FQDN / Instance ID).
    """
    scanned_assets: Set[str] = set()
    asset_alias_map: Dict[str, Set[str]] = {}

    for row in records:
        aliases = extract_row_asset_aliases(row)
        if not aliases:
            continue
        for a in aliases:
            scanned_assets.add(a)
            bucket = asset_alias_map.setdefault(a, set())
            bucket.update(aliases)

    return scanned_assets, asset_alias_map


# ---------------------------------------------------------------------------
# Normalization of Tenable & AWS Inspector Rows -> Logical POA&M Entries
# ---------------------------------------------------------------------------

def normalize_scan_rows(
    records: List[Dict[str, str]],
    scanner_type: str,
    scan_filename: str,
    today: datetime.date,
    default_poc: str,
    kev_catalog: Optional[Dict[str, Dict[str, str]]] = None,
    strict_fedramp_risk: bool = False,
) -> List[Dict[str, object]]:
    """
    Convert raw Tenable or AWS Inspector rows into normalized POA&M entry dicts.
    Enforces 1 POA&M row per unique (Vulnerability + Asset) combination.
    """
    grouped: Dict[Tuple[str, str], Dict[str, object]] = {}
    kev_db = kev_catalog if kev_catalog is not None else load_cisa_kev_catalog()

    for row in records:
        row_aliases = extract_row_asset_aliases(row)
        if scanner_type == "tenable":
            raw_risk = get_first_field(row, ["Risk", "Severity", "Risk Factor", "VPR Severity"])
            risk = normalize_risk(raw_risk)
            if not risk:
                continue
            if strict_fedramp_risk and risk == "Critical":
                risk = "High"

            plugin_id = get_first_field(row, ["Plugin ID", "Plugin", "PluginID"])
            if plugin_id.endswith(".0"):
                plugin_id = plugin_id[:-2]
            name = get_first_field(row, ["Name", "Plugin Name", "Title"], default=f"Tenable Plugin {plugin_id}")
            synopsis = get_first_field(row, ["Synopsis"])
            desc = get_first_field(row, ["Description", "Summary"])
            plugin_out = get_first_field(row, ["Plugin Output", "Output"])
            full_desc = desc or synopsis or name
            if synopsis and desc and synopsis not in desc:
                full_desc = f"{synopsis}\n\n{desc}"
            if plugin_out:
                snippet = plugin_out[:400] + ("..." if len(plugin_out) > 400 else "")
                full_desc = f"{full_desc}\n\n[Scanner Evidence]: {snippet}"

            host = get_first_field(row, ["Host", "IP Address", "DNS Name", "FQDN", "Asset", "NetBIOS Name"], default="unknown-host")
            port = get_first_field(row, ["Port"])
            proto = get_first_field(row, ["Protocol"])
            solution = get_first_field(row, ["Solution", "Remediation", "Recommendation"])
            see_also = get_first_field(row, ["See Also", "References", "URL"])
            raw_cve = get_first_field(row, ["CVE", "CVEs"])
            cves = extract_cves(raw_cve, f"{name} {desc}")

            # Note: Never use 'Plugin Publication Date' here (that is when Tenable authored the plugin, not host detection)
            first_seen_str = get_first_field(row, ["First Discovered", "First Seen", "Discovery Date", "Original Detection Date"])
            last_seen_str = get_first_field(row, ["Last Observed", "Last Seen", "Status Date"])
            det_date = parse_any_date(first_seen_str) or parse_any_date(last_seen_str, fallback=today) or today
            stat_date = parse_any_date(last_seen_str, fallback=today) or today

            is_kev, kev_due_str = resolve_bod_22_01_status(row, cves, det_date, kev_db)

            source_id = plugin_id or cves.split(",")[0].strip() or name
            asset_base = extract_base_asset(host) or host.strip().lower()
            asset_display = f"{host} ({port}/{proto.upper()})" if (port and port != "0" and proto) else host
            detector_source = "Tenable Nessus"
            vendor_dep = "No"
            vendor_prod = ""

        else:
            # AWS Inspector
            raw_risk = get_first_field(row, ["Severity", "Original Risk Rating", "Risk"])
            risk = normalize_risk(raw_risk)
            if not risk:
                continue
            if strict_fedramp_risk and risk == "Critical":
                risk = "High"

            vuln_id = get_first_field(row, ["Vulnerability ID", "CVE", "Plugin ID", "Finding ID"])
            finding_arn = get_first_field(row, ["Finding ARN", "ARN"])
            title = get_first_field(row, ["Title", "Finding Title", "Weakness Name"], default=vuln_id or "AWS Inspector Finding")
            desc = get_first_field(row, ["Description", "Weakness Description"], default=title)
            pkg = get_first_field(row, ["Affected Packages", "Package", "Package Name", "Vulnerable Package"])
            file_path = get_first_field(row, ["File Path", "Package Path"])
            full_desc = desc
            if pkg:
                full_desc += f"\n\nAffected Package(s): {pkg}"
            if file_path:
                full_desc += f" ({file_path})"

            resource_id = get_first_field(row, ["Resource ID", "Instance ID", "Asset Identifier", "Asset ID", "AWS Account ID"], default="aws-resource")
            resource_type = get_first_field(row, ["Resource Type"])
            asset_base = extract_base_asset(resource_id) or resource_id.strip().lower()
            asset_display = f"{resource_id} ({resource_type})" if resource_type and resource_type not in resource_id else resource_id

            solution = get_first_field(row, ["Remediation", "Recommendation", "Remediation Plan", "Fixed Version"])
            fix_avail = get_first_field(row, ["Fix Available", "FixAvailable"])
            pkg_mgr = get_first_field(row, ["Package Manager", "Vendor", "Platform"])
            see_also = get_first_field(row, ["Vendor Advisory", "Reference URLs", "URL", "See Also"])
            raw_cve = get_first_field(row, ["CVE", "Vulnerability ID"])
            cves = extract_cves(raw_cve, f"{title} {desc}")

            first_seen_str = get_first_field(row, ["First Observed At", "First Seen", "Created At", "Original Detection Date"])
            last_seen_str = get_first_field(row, ["Last Observed At", "Last Seen", "Updated At", "Status Date"])
            det_date = parse_any_date(first_seen_str, fallback=today) or today
            stat_date = parse_any_date(last_seen_str, fallback=today) or today

            is_kev, kev_due_str = resolve_bod_22_01_status(row, cves, det_date, kev_db)

            source_id = vuln_id or finding_arn or cves.split(",")[0].strip() or title
            name = title
            detector_source = "AWS Inspector"
            if fix_avail.lower() == "no":
                vendor_dep = "Yes"
                vendor_prod = pkg_mgr or "Upstream OS / Package Maintainer"
            else:
                vendor_dep = "No"
                vendor_prod = ""

        # Deduplication key: 1 row per (Vulnerability Source ID + Base Asset Identifier)
        dedup_key = (source_id.strip().lower(), asset_base.strip().lower())

        if dedup_key in grouped:
            existing = grouped[dedup_key]
            # Merge additional port/protocol on the same asset if different
            curr_asset = str(existing["asset_identifier"])
            if asset_display not in curr_asset.split("\n"):
                existing["asset_identifier"] = f"{curr_asset}\n{asset_display}"
            existing_aliases: Set[str] = set(existing.get("_asset_aliases", set()))
            existing_aliases.update(row_aliases or [asset_base])
            existing["_asset_aliases"] = existing_aliases

            needs_sla_recalc = False
            # Keep earliest detection date
            if det_date < existing["_det_date_obj"]:
                existing["_det_date_obj"] = det_date
                existing["original_detection_date"] = format_date_iso(det_date)
                needs_sla_recalc = True
            # Keep highest severity if multiple records for same vuln+asset
            if RISK_ORDER.get(risk, 99) < RISK_ORDER.get(str(existing["original_risk_rating"]), 99):
                existing["original_risk_rating"] = risk
                needs_sla_recalc = True
            # Recompute SLA date whenever detection date or severity changed during merge
            if needs_sla_recalc:
                new_sla = compute_sla_date(existing["_det_date_obj"], str(existing["original_risk_rating"]))
                existing["_sla_date_obj"] = new_sla
                existing["scheduled_completion_date"] = format_date_iso(new_sla)
            continue

        sla_date = compute_sla_date(det_date, risk)
        controls = infer_nist_controls(name, full_desc, cves)

        grouped[dedup_key] = {
            "_dedup_key": dedup_key,
            "_asset_aliases": set(row_aliases or [asset_base]),
            "_scanner_type": scanner_type,
            "_raw_solution": solution,
            "_see_also": see_also,
            "_det_date_obj": det_date,
            "_sla_date_obj": sla_date,
            "_stat_date_obj": stat_date,
            "poam_id": "",
            "controls": controls,
            "weakness_name": name,
            "weakness_description": full_desc,
            "detector_source": detector_source,
            "source_identifier": source_id,
            "asset_identifier": asset_display,
            "point_of_contact": default_poc,
            "resources_required": "",
            "remediation_plan": solution,
            "original_detection_date": format_date_iso(det_date),
            "scheduled_completion_date": format_date_iso(sla_date),
            "status_date": format_date_iso(stat_date),
            "vendor_dependency": vendor_dep,
            "last_vendor_checkin": "",
            "vendor_product_name": vendor_prod,
            "original_risk_rating": risk,
            "adjusted_risk_rating": "",
            "risk_adjustment": "No",
            "false_positive": "No",
            "operational_requirement": "No",
            "deviation_rationale": "",
            "supporting_documents": scan_filename,
            "comments": "",
            "bod_22_01_tracking": is_kev,
            "bod_22_01_due_date": kev_due_str,
            "cve": cves,
        }

    return list(grouped.values())


def merge_scan_entries(entry_lists: List[List[Dict[str, object]]]) -> List[Dict[str, object]]:
    """
    Combine normalized POA&M findings across up to 5 scan files.
    Enforces 1 POA&M row per unique (Vulnerability + Asset) combination,
    preserving earliest detection dates, highest risk ratings, and aggregating
    asset identifiers, aliases, and supporting document filenames.
    """
    if not entry_lists:
        return []
    if len(entry_lists) == 1:
        return entry_lists[0]

    grouped: Dict[Tuple[str, str], Dict[str, object]] = {}

    for entries in entry_lists:
        for entry in entries:
            dedup_key = entry.get("_dedup_key")
            if not dedup_key:
                continue

            if dedup_key not in grouped:
                item = dict(entry)
                item["_asset_aliases"] = set(entry.get("_asset_aliases", set()))
                grouped[dedup_key] = item
            else:
                existing = grouped[dedup_key]

                # Merge asset_identifier (different port, protocol, or display format)
                curr_asset = str(existing.get("asset_identifier", ""))
                new_asset = str(entry.get("asset_identifier", ""))
                if new_asset and new_asset not in curr_asset.split("\n"):
                    existing["asset_identifier"] = f"{curr_asset}\n{new_asset}" if curr_asset else new_asset

                # Merge asset aliases
                existing_aliases: Set[str] = set(existing.get("_asset_aliases", set()))
                existing_aliases.update(entry.get("_asset_aliases", set()))
                existing["_asset_aliases"] = existing_aliases

                # Merge supporting documents (scan filenames)
                curr_supp = str(existing.get("supporting_documents", ""))
                new_supp = str(entry.get("supporting_documents", ""))
                if new_supp:
                    existing_parts = [p.strip() for p in curr_supp.split(",") if p.strip()]
                    for np in [p.strip() for p in new_supp.split(",") if p.strip()]:
                        if np not in existing_parts:
                            existing_parts.append(np)
                    existing["supporting_documents"] = ", ".join(existing_parts)

                # Keep earliest detection date
                det_date = entry.get("_det_date_obj")
                needs_sla_recalc = False
                if det_date and (not existing.get("_det_date_obj") or det_date < existing["_det_date_obj"]):
                    existing["_det_date_obj"] = det_date
                    existing["original_detection_date"] = format_date_iso(det_date)
                    needs_sla_recalc = True

                # Keep highest severity
                new_risk = str(entry.get("original_risk_rating", ""))
                curr_risk = str(existing.get("original_risk_rating", ""))
                if RISK_ORDER.get(new_risk, 99) < RISK_ORDER.get(curr_risk, 99):
                    existing["original_risk_rating"] = new_risk
                    needs_sla_recalc = True

                # Recalculate SLA date if detection date or risk changed
                if needs_sla_recalc and existing.get("_det_date_obj"):
                    new_sla = compute_sla_date(existing["_det_date_obj"], str(existing["original_risk_rating"]))
                    existing["_sla_date_obj"] = new_sla
                    existing["scheduled_completion_date"] = format_date_iso(new_sla)

                # Merge remediation info if existing was blank
                if not str(existing.get("remediation_plan", "")).strip() and str(entry.get("remediation_plan", "")).strip():
                    existing["remediation_plan"] = entry["remediation_plan"]
                if not str(existing.get("_raw_solution", "")).strip() and str(entry.get("_raw_solution", "")).strip():
                    existing["_raw_solution"] = entry["_raw_solution"]
                if not str(existing.get("_see_also", "")).strip() and str(entry.get("_see_also", "")).strip():
                    existing["_see_also"] = entry["_see_also"]

                # Merge CVEs
                cve_existing = set(c.strip() for c in str(existing.get("cve", "")).split(",") if c.strip())
                cve_new = set(c.strip() for c in str(entry.get("cve", "")).split(",") if c.strip())
                merged_cves = sorted(cve_existing.union(cve_new))
                if merged_cves:
                    existing["cve"] = ", ".join(merged_cves)

                # Merge BOD 22-01 status
                if str(entry.get("bod_22_01_tracking", "")).strip().lower() == "yes":
                    existing["bod_22_01_tracking"] = "Yes"
                    if entry.get("bod_22_01_due_date"):
                        if not existing.get("bod_22_01_due_date") or entry["bod_22_01_due_date"] < existing["bod_22_01_due_date"]:
                            existing["bod_22_01_due_date"] = entry["bod_22_01_due_date"]

    return list(grouped.values())


# ---------------------------------------------------------------------------
# Reading Previous OPEN & CLOSED FedRAMP POA&M Workbooks
# ---------------------------------------------------------------------------

def load_existing_poam_workbook(xlsx_path: str, is_closed_template: bool = False) -> List[Dict[str, object]]:
    """
    Parse an existing OPEN or CLOSED FedRAMP POA&M .xlsx file and return its populated rows.
    """
    if not xlsx_path or not os.path.isfile(xlsx_path):
        return []

    rows = read_xlsx_rows(xlsx_path, sheet_index=0)
    col_letters = resolve_col_letters(rows, is_closed_template, label=os.path.basename(xlsx_path))
    min_data_row = 3 if is_closed_template else 5

    entries: List[Dict[str, object]] = []
    for r in rows:
        r_num = int(r.get("_row_num", "0"))
        if r_num < min_data_row:
            continue

        entry: Dict[str, object] = {}
        for field_name, col_let in zip(POAM_FIELDS, col_letters):
            val = r.get(col_let, "").strip()
            if field_name == "source_identifier" and val.endswith(".0"):
                val = val[:-2]
            entry[field_name] = val

        # Never treat a repeated header row as data
        if _norm_header(str(entry.get("poam_id", ""))) == "poamid":
            continue

        # Check if this row is actually populated with a POA&M entry
        if not any([
            entry.get("poam_id"),
            entry.get("weakness_name"),
            entry.get("source_identifier"),
            entry.get("asset_identifier"),
        ]):
            continue

        # Normalize date fields from Excel serial numbers into YYYY-MM-DD strings and date objects
        det_d = parse_any_date(str(entry.get("original_detection_date", "")))
        sla_d = parse_any_date(str(entry.get("scheduled_completion_date", "")))
        stat_d = parse_any_date(str(entry.get("status_date", "")))
        chk_d = parse_any_date(str(entry.get("last_vendor_checkin", "")))
        bod_d = parse_any_date(str(entry.get("bod_22_01_due_date", "")))

        risk = normalize_risk(str(entry.get("original_risk_rating", ""))) or str(entry.get("original_risk_rating", "Moderate"))
        entry["original_risk_rating"] = risk

        if det_d and not sla_d:
            sla_d = compute_sla_date(
                det_d,
                risk,
                str(entry.get("adjusted_risk_rating", "")),
                str(entry.get("risk_adjustment", "")),
            )

        entry["_det_date_obj"] = det_d
        entry["_sla_date_obj"] = sla_d
        entry["_stat_date_obj"] = stat_d
        entry["original_detection_date"] = format_date_iso(det_d) if det_d else str(entry.get("original_detection_date", ""))
        entry["scheduled_completion_date"] = format_date_iso(sla_d) if sla_d else str(entry.get("scheduled_completion_date", ""))
        entry["status_date"] = format_date_iso(stat_d) if stat_d else str(entry.get("status_date", ""))
        entry["last_vendor_checkin"] = format_date_iso(chk_d) if chk_d else ""
        entry["bod_22_01_due_date"] = format_date_iso(bod_d) if bod_d else ""

        src_key = str(entry.get("source_identifier") or entry.get("cve") or entry.get("weakness_name") or "").strip().lower()
        asset_key = extract_base_asset(str(entry.get("asset_identifier", "")))
        entry["_dedup_key"] = (src_key, asset_key)
        entries.append(entry)

    return entries


# ---------------------------------------------------------------------------
# Delta Reconciliation: Previous OPEN POA&M vs. New Scan Results
# ---------------------------------------------------------------------------

def _merge_carry_over(scan_item: Dict[str, object], matched_prev: Dict[str, object], today: datetime.date) -> Dict[str, object]:
    """Build a carried-over OPEN entry: fresh scan data + immutable analyst fields from the previous POA&M row."""
    # Carry-over Open item: preserve immutable Original Detection Date, POAM ID, and analyst fields
    merged = dict(scan_item)
    merged["poam_id"] = matched_prev.get("poam_id") or merged["poam_id"]
    if matched_prev.get("controls"):
        merged["controls"] = matched_prev["controls"]
    if matched_prev.get("point_of_contact"):
        merged["point_of_contact"] = matched_prev["point_of_contact"]
    if matched_prev.get("resources_required"):
        merged["resources_required"] = matched_prev["resources_required"]
    # Preserve existing analyst Remediation Plan if present; if blank, leave blank so GRCx can offer to draft
    if matched_prev.get("remediation_plan"):
        merged["remediation_plan"] = matched_prev["remediation_plan"]
    else:
        merged["remediation_plan"] = ""

    # Original Detection Date never changes!
    orig_det_obj = matched_prev.get("_det_date_obj") or scan_item.get("_det_date_obj") or today
    merged["_det_date_obj"] = orig_det_obj
    merged["original_detection_date"] = format_date_iso(orig_det_obj)

    # Carry over Risk Adjustments / Deviations
    for carry_field in [
        "vendor_dependency",
        "last_vendor_checkin",
        "vendor_product_name",
        "adjusted_risk_rating",
        "risk_adjustment",
        "false_positive",
        "operational_requirement",
        "deviation_rationale",
        "supporting_documents",
        "comments",
        "bod_22_01_tracking",
        "bod_22_01_due_date",
    ]:
        if matched_prev.get(carry_field):
            merged[carry_field] = matched_prev[carry_field]

    # Recalculate or preserve Scheduled Completion Date based on immutable Original Detection Date
    sla_obj = compute_sla_date(
        orig_det_obj,
        str(merged.get("original_risk_rating", "Moderate")),
        str(merged.get("adjusted_risk_rating", "")),
        str(merged.get("risk_adjustment", "")),
    )
    merged["_sla_date_obj"] = sla_obj
    merged["scheduled_completion_date"] = format_date_iso(sla_obj)
    merged["status_date"] = format_date_iso(today)
    merged["_stat_date_obj"] = today
    merged["_is_carry_over"] = True
    merged["_unverified_host"] = False
    return merged


def reconcile_poam_entries(
    prev_open_entries: List[Dict[str, object]],
    new_scan_entries: List[Dict[str, object]],
    today: datetime.date,
    prev_closed_entries: Optional[List[Dict[str, object]]] = None,
    scanned_assets: Optional[Set[str]] = None,
    asset_alias_map: Optional[Dict[str, Set[str]]] = None,
    close_unscanned_hosts: bool = False,
) -> Tuple[List[Dict[str, object]], List[Dict[str, object]], Dict[str, int]]:
    """
    Reconcile previous OPEN POA&M rows with new scan findings:
      - Carry-Over Open: In Previous OPEN and still present in New Scan (and not False Positive = Yes)
      - Newly Detected Open: In New Scan only (numbered sequentially after the max ID across BOTH
        previous OPEN and previous CLOSED workbooks so POA&M IDs are never reused)
      - Moved to Closed: In Previous OPEN, absent from New Scan AND its asset was confirmed
        scanned (present in `scanned_assets`), or marked False Positive = Yes
      - Unverified (Asset Not in Scan): In Previous OPEN, absent from New Scan, and its asset
        was NOT observed anywhere in the scan -> retained in OPEN and flagged for review.
    """
    prev_by_key: Dict[Tuple[str, str], List[Dict[str, object]]] = {}
    prev_by_alt_key: Dict[Tuple[str, str], List[Dict[str, object]]] = {}

    # Compute highest existing POA&M ID across BOTH previous OPEN and previous CLOSED workbooks
    max_poam_seq = 0
    uses_typed_prefix = False
    max_by_prefix: Dict[str, int] = {"VULN": 0, "COMP": 0, "PENT": 0}
    for p in list(prev_open_entries) + list(prev_closed_entries or []):
        pid = str(p.get("poam_id", "")).strip()
        m_typed = re.match(r"^(VULN|COMP|PENT)-(\d+)$", pid, flags=re.IGNORECASE)
        if m_typed:
            uses_typed_prefix = True
            pfx = m_typed.group(1).upper()
            seq_num = int(m_typed.group(2))
            max_by_prefix[pfx] = max(max_by_prefix.get(pfx, 0), seq_num)
            max_poam_seq = max(max_poam_seq, seq_num)
        else:
            m_dyn = re.match(r"^\d{4}-[A-Za-z]{3}-(\d+)$", pid)
            m_leg = re.match(r"^POAM-\d{4}-(\d+)$", pid, flags=re.IGNORECASE)
            if m_dyn:
                max_poam_seq = max(max_poam_seq, int(m_dyn.group(1)))
            elif m_leg:
                max_poam_seq = max(max_poam_seq, int(m_leg.group(1)))
            else:
                m_seq = re.search(r"(\d+)$", pid)
                if m_seq:
                    max_poam_seq = max(max_poam_seq, int(m_seq.group(1)))

    for p in prev_open_entries:
        k = p["_dedup_key"]
        prev_by_key.setdefault(k, []).append(p)
        wname = str(p.get("weakness_name", "")).strip().lower()
        asset_k = k[1]
        if wname:
            prev_by_alt_key.setdefault((wname, asset_k), []).append(p)

    matched_prev_ids: Set[int] = set()
    final_open: List[Dict[str, object]] = []
    newly_closed: List[Dict[str, object]] = []

    carry_over_count = 0
    new_open_count = 0
    unverified_unscanned_count = 0

    def find_unclaimed_prev(
        src_id: str,
        wname: str,
        candidate_assets: Set[str],
    ) -> Optional[Dict[str, object]]:
        """Find an unclaimed previous OPEN entry by primary (source_id, asset) or fallback (weakness_name, asset)."""
        for a in candidate_assets:
            for cand in prev_by_key.get((src_id, a), []):
                if id(cand) not in matched_prev_ids:
                    return cand
        if wname:
            for a in candidate_assets:
                for cand in prev_by_alt_key.get((wname, a), []):
                    if id(cand) not in matched_prev_ids:
                        return cand
        return None

    for scan_item in new_scan_entries:
        s_src, s_asset = scan_item["_dedup_key"]
        s_wname = str(scan_item.get("weakness_name", "")).strip().lower()
        item_aliases: Set[str] = {s_asset}
        item_aliases.update(scan_item.get("_asset_aliases", set()))
        if asset_alias_map and s_asset in asset_alias_map:
            item_aliases.update(asset_alias_map[s_asset])

        matched_prev = find_unclaimed_prev(s_src, s_wname, item_aliases)

        if matched_prev is not None:
            matched_prev_ids.add(id(matched_prev))

            # If marked False Positive == Yes in previous POA&M, move to CLOSED
            if str(matched_prev.get("false_positive", "")).strip().lower() == "yes":
                closed_copy = dict(matched_prev)
                closed_copy["status_date"] = format_date_iso(today)
                closed_copy["_stat_date_obj"] = today
                prev_comment = str(closed_copy.get("comments", "")).strip()
                note = f"[Closed {format_date_iso(today)}: Approved False Positive moved to Closed POA&M]"
                closed_copy["comments"] = f"{prev_comment}\n{note}".strip() if prev_comment else note
                newly_closed.append(closed_copy)
                continue

            merged = _merge_carry_over(scan_item, matched_prev, today)

            final_open.append(merged)
            carry_over_count += 1
        else:
            # Newly detected Open POA&M item
            new_item = dict(scan_item)
            if uses_typed_prefix:
                w_lower = str(new_item.get("weakness_name", "")).lower()
                is_comp = (not str(new_item.get("cve", "")).strip()) or any(
                    kw in w_lower for kw in ("cipher", "tls", "stig", "cis ", "compliance", "policy", "banner", "configuration")
                )
                pfx = "COMP" if is_comp else "VULN"
                max_by_prefix[pfx] = max_by_prefix.get(pfx, 0) + 1
                new_item["poam_id"] = f"{pfx}-{max_by_prefix[pfx]:05d}"
            else:
                max_poam_seq += 1
                new_item["poam_id"] = format_poam_id(today, max_poam_seq)
            new_item["_is_carry_over"] = False
            new_item["_unverified_host"] = False
            final_open.append(new_item)
            new_open_count += 1

    # Evaluate previous OPEN entries that did not appear in the new scan:
    for p in prev_open_entries:
        if id(p) in matched_prev_ids:
            continue

        # Approved False Positives always move to CLOSED
        if str(p.get("false_positive", "")).strip().lower() == "yes":
            closed_item = dict(p)
            closed_item["status_date"] = format_date_iso(today)
            closed_item["_stat_date_obj"] = today
            prev_comment = str(closed_item.get("comments", "")).strip()
            note = f"[Closed {format_date_iso(today)}: Approved False Positive moved to Closed POA&M]"
            closed_item["comments"] = f"{prev_comment}\n{note}".strip() if prev_comment else note
            newly_closed.append(closed_item)
            continue

        _, p_asset = p["_dedup_key"]
        p_aliases: Set[str] = {p_asset}
        if asset_alias_map and p_asset in asset_alias_map:
            p_aliases.update(asset_alias_map[p_asset])

        # Was this asset actually scanned in the current export?
        asset_was_scanned = (
            close_unscanned_hosts
            or (scanned_assets is not None and bool(p_aliases & scanned_assets))
        )

        if asset_was_scanned:
            closed_item = dict(p)
            closed_item["status_date"] = format_date_iso(today)
            closed_item["_stat_date_obj"] = today
            prev_comment = str(closed_item.get("comments", "")).strip()
            note = f"[Closed {format_date_iso(today)}: Verified remediated — asset scanned and finding no longer present]"
            closed_item["comments"] = f"{prev_comment}\n{note}".strip() if prev_comment else note
            newly_closed.append(closed_item)
        else:
            # Asset was NOT seen in the scan at all -> do NOT blindly close; retain in OPEN and flag for review!
            unverified_item = dict(p)
            unverified_item["_is_carry_over"] = True
            unverified_item["_unverified_host"] = True
            prev_comment = str(unverified_item.get("comments", "")).strip()
            review_note = (
                f"[Review Required {format_date_iso(today)}: Asset '{p.get('asset_identifier', p_asset)}' was not observed "
                f"in the latest scan — retained in OPEN POA&M pending host/scope verification]"
            )
            if review_note not in prev_comment:
                unverified_item["comments"] = f"{prev_comment}\n{review_note}".strip() if prev_comment else review_note
            final_open.append(unverified_item)
            carry_over_count += 1
            unverified_unscanned_count += 1

    stats = {
        "carry_over_open": carry_over_count,
        "new_open": new_open_count,
        "unverified_unscanned_open": unverified_unscanned_count,
        "total_open": len(final_open),
        "moved_to_closed": len(newly_closed),
    }
    return final_open, newly_closed, stats


def legacy_match_key(name: object, desc: object) -> str:
    """
    Apps Script-compatible key: lower-cased, trimmed Weakness Name + Weakness Description
    (the old scripts used `${name}|||${desc}`). Volatile text GRCx appends to descriptions
    ([Scanner Evidence] output, Affected Package lists) is stripped and whitespace collapsed
    so the same vulnerability produces the same key from run to run.
    """
    n = re.sub(r"\s+", " ", str(name or "")).strip().lower()
    d = str(desc or "")
    d = re.split(r"\[scanner evidence\]", d, flags=re.IGNORECASE)[0]
    d = re.split(r"affected package\(s\):", d, flags=re.IGNORECASE)[0]
    d = re.sub(r"\s+", " ", d).strip().lower()
    return f"{n}|||{d}"


def reconcile_poam_entries_legacy(
    prev_open_entries: List[Dict[str, object]],
    new_scan_entries: List[Dict[str, object]],
    today: datetime.date,
    prev_closed_entries: Optional[List[Dict[str, object]]] = None,
    scanned_assets: Optional[Set[str]] = None,
    asset_alias_map: Optional[Dict[str, Set[str]]] = None,
    close_unscanned_hosts: bool = False,
) -> Tuple[List[Dict[str, object]], List[Dict[str, object]], Dict[str, int]]:
    """
    Reproduces the original Google Apps Script logic ("Closed Entries" + "Persisting Entries"):
      - Matching is by Weakness Name + Description only (no host / plugin ID).
      - A previous OPEN entry whose name+description appears ANYWHERE in the scan STAYS open.
      - A previous OPEN entry whose name+description is absent from the scan is CLOSED, even if
        its host was not in the scan (scanned_assets / close_unscanned_hosts are ignored).
      - A scan finding whose name+description already exists in the previous OPEN POA&M is NOT
        a new item (it is the same vulnerability); everything else is new.
    Approved False Positives (False Positive = Yes) still move to CLOSED, as in strict mode.
    """
    max_poam_seq = 0
    uses_typed_prefix = False
    max_by_prefix: Dict[str, int] = {"VULN": 0, "COMP": 0, "PENT": 0}
    for p in list(prev_open_entries) + list(prev_closed_entries or []):
        pid = str(p.get("poam_id", "")).strip()
        m_typed = re.match(r"^(VULN|COMP|PENT)-(\d+)$", pid, flags=re.IGNORECASE)
        if m_typed:
            uses_typed_prefix = True
            pfx = m_typed.group(1).upper()
            seq_num = int(m_typed.group(2))
            max_by_prefix[pfx] = max(max_by_prefix.get(pfx, 0), seq_num)
            max_poam_seq = max(max_poam_seq, seq_num)
        else:
            m_dyn = re.match(r"^\d{4}-[A-Za-z]{3}-(\d+)$", pid)
            m_leg = re.match(r"^POAM-\d{4}-(\d+)$", pid, flags=re.IGNORECASE)
            if m_dyn:
                max_poam_seq = max(max_poam_seq, int(m_dyn.group(1)))
            elif m_leg:
                max_poam_seq = max(max_poam_seq, int(m_leg.group(1)))
            else:
                m_seq = re.search(r"(\d+)$", pid)
                if m_seq:
                    max_poam_seq = max(max_poam_seq, int(m_seq.group(1)))

    scan_by_key: Dict[str, List[Dict[str, object]]] = {}
    for se in new_scan_entries:
        scan_by_key.setdefault(legacy_match_key(se.get("weakness_name"), se.get("weakness_description")), []).append(se)
    prev_keys = {
        legacy_match_key(p.get("weakness_name"), p.get("weakness_description"))
        for p in prev_open_entries
        if str(p.get("weakness_name", "")).strip() or str(p.get("weakness_description", "")).strip()
    }

    final_open: List[Dict[str, object]] = []
    newly_closed: List[Dict[str, object]] = []
    carry_over_count = 0
    new_open_count = 0

    for p in prev_open_entries:
        key = legacy_match_key(p.get("weakness_name"), p.get("weakness_description"))
        fp_yes = str(p.get("false_positive", "")).strip().lower() == "yes"
        candidates = scan_by_key.get(key, [])

        if fp_yes or not candidates:
            closed_item = dict(p)
            closed_item["status_date"] = format_date_iso(today)
            closed_item["_stat_date_obj"] = today
            prev_comment = str(closed_item.get("comments", "")).strip()
            if fp_yes:
                note = f"[Closed {format_date_iso(today)}: Approved False Positive moved to Closed POA&M]"
            else:
                note = f"[Closed {format_date_iso(today)}: Not present in latest scan (legacy name+description match)]"
            closed_item["comments"] = f"{prev_comment}\n{note}".strip() if prev_comment else note
            newly_closed.append(closed_item)
            continue

        # STAY: prefer the scan row for the same (plugin/source id, host); otherwise any row with the same name+description
        exact = next((c for c in candidates if c.get("_dedup_key") == p.get("_dedup_key")), None)
        scan_item = exact or candidates[0]
        merged = _merge_carry_over(scan_item, p, today)
        if exact is None:
            # Keep this POA&M row's own host / source identity instead of the other host's
            for f in ("asset_identifier", "source_identifier"):
                merged[f] = p.get(f, merged.get(f, ""))
            merged["_dedup_key"] = p.get("_dedup_key", merged.get("_dedup_key"))
            merged["_asset_aliases"] = {extract_base_asset(str(p.get("asset_identifier", "")))}
        final_open.append(merged)
        carry_over_count += 1

    claimed_new_keys: Set[str] = set()
    for key, items in scan_by_key.items():
        if key in prev_keys or key in claimed_new_keys:
            continue
        for se in items:  # all hosts for a genuinely new vulnerability become new rows
            new_item = dict(se)
            if uses_typed_prefix:
                w_lower = str(new_item.get("weakness_name", "")).lower()
                is_comp = (not str(new_item.get("cve", "")).strip()) or any(
                    kw in w_lower for kw in ("cipher", "tls", "stig", "cis ", "compliance", "policy", "banner", "configuration")
                )
                pfx = "COMP" if is_comp else "VULN"
                max_by_prefix[pfx] = max_by_prefix.get(pfx, 0) + 1
                new_item["poam_id"] = f"{pfx}-{max_by_prefix[pfx]:05d}"
            else:
                max_poam_seq += 1
                new_item["poam_id"] = format_poam_id(today, max_poam_seq)
            new_item["_is_carry_over"] = False
            new_item["_unverified_host"] = False
            final_open.append(new_item)
            new_open_count += 1
        claimed_new_keys.add(key)

    stats = {
        "carry_over_open": carry_over_count,
        "new_open": new_open_count,
        "unverified_unscanned_open": 0,
        "total_open": len(final_open),
        "moved_to_closed": len(newly_closed),
    }
    return final_open, newly_closed, stats



# ---------------------------------------------------------------------------
# Remediation Plan URL Drafter (Tenable & AWS Inspector)
# ---------------------------------------------------------------------------

def build_remediation_plan_with_urls(entry: Dict[str, object]) -> str:
    """
    Construct a detailed FedRAMP Remediation Plan containing official Tenable or
    AWS remediation reference URLs for findings missing a remediation plan.
    """
    detector = str(entry.get("detector_source", "")).lower()
    scanner_type = str(entry.get("_scanner_type", "")).lower()
    is_tenable = "tenable" in detector or "nessus" in detector or scanner_type == "tenable"

    source_id = str(entry.get("source_identifier", "")).strip()
    cve_str = str(entry.get("cve", "")).strip()
    cves = [c.strip() for c in cve_str.split(",") if c.strip().startswith("CVE-")]
    raw_solution = str(entry.get("_raw_solution", "")).strip()
    see_also = str(entry.get("_see_also", "")).strip()
    weakness_name = str(entry.get("weakness_name", "identified vulnerability")).strip()

    urls: List[str] = []

    if is_tenable:
        # Official Tenable Nessus Plugin Remediation URL
        if source_id and re.match(r"^\d+$", source_id):
            urls.append(f"https://www.tenable.com/plugins/nessus/{source_id}")
        else:
            urls.append("https://www.tenable.com/plugins/search")
        for u in extract_urls(see_also):
            if u not in urls:
                urls.append(u)
        for c in cves[:2]:
            nvd_url = f"https://nvd.nist.gov/vuln/detail/{c}"
            if nvd_url not in urls:
                urls.append(nvd_url)

        base_action = (
            raw_solution
            if raw_solution
            else f"Apply the vendor-supplied security update or configuration hardening to remediate '{weakness_name}' and verify closure via follow-on Tenable credentialed scan."
        )
        url_block = "\n".join(f"• {u}" for u in urls)
        return (
            f"Remediation Action: {base_action}\n\n"
            f"Official Tenable & Vendor Remediation References:\n{url_block}"
        )
    else:
        # Official AWS Inspector & ALAS / CVE Remediation URLs
        if source_id.upper().startswith("ALAS"):
            alas_id = source_id.upper().replace(" ", "")
            urls.append(f"https://explore.alas.aws.amazon.com/{alas_id}.html")
        for u in extract_urls(see_also):
            if u not in urls:
                urls.append(u)
        for c in cves[:2]:
            aws_cve_url = f"https://explore.alas.aws.amazon.com/CVE/{c}.html"
            nvd_url = f"https://nvd.nist.gov/vuln/detail/{c}"
            if aws_cve_url not in urls:
                urls.append(aws_cve_url)
            if nvd_url not in urls:
                urls.append(nvd_url)
        inspector_doc_url = "https://docs.aws.amazon.com/inspector/latest/user/findings-understanding.html"
        if inspector_doc_url not in urls:
            urls.append(inspector_doc_url)

        base_action = (
            raw_solution
            if raw_solution
            else f"Update the affected package/image or apply the AWS-recommended security patch for '{weakness_name}', redeploy the hardened AMI/container, and verify closure in AWS Inspector."
        )
        url_block = "\n".join(f"• {u}" for u in urls)
        return (
            f"Remediation Action: {base_action}\n\n"
            f"Official AWS Inspector & Advisory Remediation References:\n{url_block}"
        )


# ---------------------------------------------------------------------------
# Pure-Python Standard Library .xlsx Template Writer
# ---------------------------------------------------------------------------

def discover_template_styles(
    zin: zipfile.ZipFile,
    s_root: ET.Element,
    start_row: int,
    is_closed_template: bool,
    field_cols: Optional[Dict[str, str]] = None,
) -> Dict[str, str]:
    """
    Inspect the template's existing data row (`start_row`) and `xl/styles.xml` before
    rebuilding rows so style indices (`default`, `date`, `sla`, and `row_ht`) are
    discovered dynamically from the template rather than blindly hard-coded.
    """
    ns = {"main": MAIN_NS}
    date_num_fmts = {"14", "15", "16", "17", "22", "164", "165", "166"}
    style_is_date: Dict[str, bool] = {}

    if "xl/styles.xml" in zin.namelist():
        try:
            st_root = ET.fromstring(zin.read("xl/styles.xml"))
            cell_xfs = st_root.find("main:cellXfs", ns)
            if cell_xfs is not None:
                for idx, xf in enumerate(cell_xfs.findall("main:xf", ns)):
                    nf = xf.attrib.get("numFmtId", "0")
                    style_is_date[str(idx)] = nf in date_num_fmts
        except ET.ParseError:
            pass

    default_style = "2"
    date_style = "2" if is_closed_template else "21"
    sla_style = "2" if is_closed_template else "22"
    row_ht = "15.75" if is_closed_template else "18.0"

    sheet_data = s_root.find("main:sheetData", ns)
    if sheet_data is not None:
        for r_el in sheet_data.findall("main:row", ns):
            r_num = int(r_el.attrib.get("r", "0"))
            if r_num == start_row:
                if r_el.attrib.get("ht"):
                    row_ht = r_el.attrib["ht"]
                cell_styles = {}
                for c_el in r_el.findall("main:c", ns):
                    col_let, _ = split_cell_ref(c_el.attrib.get("r", ""))
                    if "s" in c_el.attrib:
                        cell_styles[col_let] = c_el.attrib["s"]
                if not is_closed_template:
                    fc = field_cols or dict(zip(POAM_FIELDS, OPEN_COL_LETTERS))
                    default_style = cell_styles.get(fc["poam_id"], default_style)
                    l_style = cell_styles.get(fc["original_detection_date"], "")
                    m_style = cell_styles.get(fc["scheduled_completion_date"], "")
                    if l_style and style_is_date.get(l_style, True):
                        date_style = l_style
                    if m_style and style_is_date.get(m_style, True):
                        sla_style = m_style
                else:
                    # In CLOSED template, Row 3 is an example row (s="4") and Row 4+ uses s="2"
                    default_style = cell_styles.get((field_cols or {}).get("poam_id", "A"), default_style)
                break

        if is_closed_template:
            # Prefer Row 4's clean data cell style in CLOSED template if present
            for r_el in sheet_data.findall("main:row", ns):
                if int(r_el.attrib.get("r", "0")) == start_row + 1:
                    for c_el in r_el.findall("main:c", ns):
                        col_let, _ = split_cell_ref(c_el.attrib.get("r", ""))
                        if col_let == (field_cols or {}).get("poam_id", "A") and "s" in c_el.attrib:
                            default_style = c_el.attrib["s"]
                            date_style = default_style
                            sla_style = default_style
                            break
                    break

    return {
        "default": default_style,
        "date": date_style,
        "sla": sla_style,
        "row_ht": row_ht,
        "date_is_numeric": "1" if (not is_closed_template and style_is_date.get(date_style, True)) else "0",
    }


def write_poam_workbook(
    template_path: str,
    output_path: str,
    entries: List[Dict[str, object]],
    is_closed_template: bool = False,
    strict_fedramp_risk: bool = False,
) -> None:
    """
    Populate either the OPEN FedRAMP POA&M template (Row 5+, Cols B..AB) or the
    CLOSED LEGACY FedRAMP POA&M template (Row 3+, Cols A..AA) while preserving
    all native XML namespaces, formatting, styles, drawings, and data validations.
    """
    ns = {"main": MAIN_NS, "r": REL_NS}
    start_row = 3 if is_closed_template else 5

    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)

    # Detect where the POAM ID column sits in THIS template so output lines up with its headers
    col_letters = resolve_col_letters(
        read_xlsx_rows(template_path, sheet_index=0), is_closed_template, label=os.path.basename(template_path)
    )
    first_col_idx = col_to_idx(col_letters[0])
    L = dict(zip(POAM_FIELDS, col_letters))  # field name -> column letter in this template

    with zipfile.ZipFile(template_path, "r") as zin:
        target_sheet_path = resolve_sheet_path(zin, sheet_index=0)

        # Load sharedStrings.xml with full namespace preservation
        shared_strings: List[str] = []
        ss_index_map: Dict[str, int] = {}
        orig_ss_bytes = b""
        if "xl/sharedStrings.xml" in zin.namelist():
            orig_ss_bytes = zin.read("xl/sharedStrings.xml")
            register_xml_namespaces(orig_ss_bytes)
            ss_root = ET.fromstring(orig_ss_bytes)
            for si in ss_root.findall("main:si", ns):
                texts = [t.text or "" for t in si.findall(".//main:t", ns)]
                full_str = "".join(texts)
                if full_str not in ss_index_map:
                    ss_index_map[full_str] = len(shared_strings)
                shared_strings.append(full_str)
        else:
            ss_root = ET.Element(f"{{{MAIN_NS}}}sst", {"count": "0", "uniqueCount": "0"})

        def get_or_add_shared_string(raw_s_val: str) -> int:
            s_val = sanitize_excel_string(raw_s_val)
            if s_val in ss_index_map:
                return ss_index_map[s_val]
            idx = len(shared_strings)
            shared_strings.append(s_val)
            ss_index_map[s_val] = idx
            si_el = ET.SubElement(ss_root, f"{{{MAIN_NS}}}si")
            t_el = ET.SubElement(si_el, f"{{{MAIN_NS}}}t")
            if s_val.startswith(" ") or s_val.endswith(" ") or "\n" in s_val or "\t" in s_val:
                t_el.set("{http://www.w3.org/XML/1998/namespace}space", "preserve")
            t_el.text = s_val
            return idx

        # Parse target worksheet XML with full namespace preservation
        sheet_xml_bytes = zin.read(target_sheet_path)
        register_xml_namespaces(sheet_xml_bytes)
        s_root = ET.fromstring(sheet_xml_bytes)
        sheet_data = s_root.find("main:sheetData", ns)

        # Discover cell styles and row height from template before removing rows >= start_row
        tpl_styles = discover_template_styles(zin, s_root, start_row, is_closed_template, L)
        default_style = tpl_styles["default"]
        date_style = tpl_styles["date"]
        sla_style = tpl_styles["sla"]
        row_ht = tpl_styles["row_ht"]
        store_numeric_dates = tpl_styles["date_is_numeric"] == "1"

        # Keep header rows (< start_row) intact, remove existing blank/template rows >= start_row
        existing_rows = list(sheet_data.findall("main:row", ns))
        for r_el in existing_rows:
            r_num = int(r_el.attrib.get("r", "0"))
            if r_num >= start_row:
                sheet_data.remove(r_el)

        # Build populated rows + a buffer of clean blank formatted rows
        total_rows_to_write = max(len(entries) + 25, 100)
        last_written_row = start_row + total_rows_to_write - 1

        for offset in range(total_rows_to_write):
            r_num = start_row + offset
            row_attribs = {"r": str(r_num), "ht": row_ht, "customHeight": "1"}
            r_el = ET.SubElement(sheet_data, f"{{{MAIN_NS}}}row", row_attribs)

            entry = entries[offset] if offset < len(entries) else None

            # Any margin columns left of the POAM ID column (none when the ID is in column A)
            for pad_idx in range(first_col_idx):
                ET.SubElement(r_el, f"{{{MAIN_NS}}}c", {"r": f"{idx_to_col(pad_idx)}{r_num}", "s": default_style})

            for field_name, col_let in zip(POAM_FIELDS, col_letters):
                cell_ref = f"{col_let}{r_num}"

                if is_closed_template:
                    c_style = default_style
                else:
                    if field_name == "scheduled_completion_date":
                        c_style = sla_style
                    elif field_name in DATE_FIELDS:
                        c_style = date_style
                    else:
                        c_style = default_style

                c_el = ET.SubElement(r_el, f"{{{MAIN_NS}}}c", {"r": cell_ref, "s": c_style})

                if not is_closed_template and field_name == "scheduled_completion_date":
                    f_el = ET.SubElement(c_el, f"{{{MAIN_NS}}}f")
                    det_c = f"{L['original_detection_date']}{r_num}"
                    orr_c = f"{L['original_risk_rating']}{r_num}"
                    adj_c = f"{L['adjusted_risk_rating']}{r_num}"
                    flg_c = f"{L['risk_adjustment']}{r_num}"
                    if strict_fedramp_risk:
                        f_el.text = (
                            f'IF(OR({adj_c}="N/A",ISBLANK({adj_c}),{flg_c}<>"Yes"),'
                            f'IF({orr_c}="High",{det_c}+30,'
                            f'IF({orr_c}="Moderate",{det_c}+90,IF({orr_c}="Low",{det_c}+180,""))),'
                            f'IF({adj_c}="High",{det_c}+30,'
                            f'IF({adj_c}="Moderate",{det_c}+90,IF({adj_c}="Low",{det_c}+180,""))))'
                        )
                    else:
                        f_el.text = (
                            f'IF(OR({adj_c}="N/A",ISBLANK({adj_c}),{flg_c}<>"Yes"),'
                            f'IF(OR({orr_c}="Critical",{orr_c}="High"),{det_c}+30,'
                            f'IF({orr_c}="Moderate",{det_c}+90,IF({orr_c}="Low",{det_c}+180,""))),'
                            f'IF(OR({adj_c}="Critical",{adj_c}="High"),{det_c}+30,'
                            f'IF({adj_c}="Moderate",{det_c}+90,IF({adj_c}="Low",{det_c}+180,""))))'
                        )
                    if entry is not None:
                        d_obj = parse_any_date(str(entry.get(field_name, "")))
                        if d_obj:
                            v_el = ET.SubElement(c_el, f"{{{MAIN_NS}}}v")
                            v_el.text = str(date_to_excel_serial(d_obj))
                    continue

                if entry is None:
                    continue

                raw_val = str(entry.get(field_name, "")).strip()
                if not raw_val:
                    continue

                if field_name in DATE_FIELDS:
                    d_obj = parse_any_date(raw_val)
                    if d_obj and store_numeric_dates:
                        v_el = ET.SubElement(c_el, f"{{{MAIN_NS}}}v")
                        v_el.text = str(date_to_excel_serial(d_obj))
                    else:
                        str_val = format_date_iso(d_obj) if d_obj else raw_val
                        c_el.set("t", "s")
                        v_el = ET.SubElement(c_el, f"{{{MAIN_NS}}}v")
                        v_el.text = str(get_or_add_shared_string(str_val))
                elif field_name == "source_identifier" and re.match(r"^\d+$", raw_val):
                    v_el = ET.SubElement(c_el, f"{{{MAIN_NS}}}v")
                    v_el.text = raw_val
                else:
                    c_el.set("t", "s")
                    v_el = ET.SubElement(c_el, f"{{{MAIN_NS}}}v")
                    v_el.text = str(get_or_add_shared_string(raw_val))

        # Update <dimension ref="..."/> if present on worksheet
        dim_el = s_root.find("main:dimension", ns)
        if dim_el is not None:
            dim_el.set("ref", f"A1:{col_letters[-1]}{last_written_row}")

        # In OPEN template, unless --strict-fedramp-risk is enabled, allow 'Critical' in Risk Rating dropdowns
        if not is_closed_template and not strict_fedramp_risk:
            dvs = s_root.find("main:dataValidations", ns)
            if dvs is not None:
                for dv in dvs.findall("main:dataValidation", ns):
                    sqref = dv.attrib.get("sqref", "")
                    f1 = dv.find("main:formula1", ns)
                    if f1 is not None and f1.text:
                        if f"{L['original_risk_rating']}{start_row}" in sqref:
                            dv.set("prompt", "Low, Moderate, High, Critical")
                            f1.text = '"Low,Moderate,High,Critical"'
                        elif f"{L['adjusted_risk_rating']}{start_row}" in sqref:
                            dv.set("prompt", "Low, Moderate, High, Critical, N/A")
                            f1.text = '"Low,Moderate,High,Critical,N/A"'

        # Update sharedStrings count attributes
        ss_root.set("count", str(len(shared_strings)))
        ss_root.set("uniqueCount", str(len(shared_strings)))

        # Ensure fullCalcOnLoad="1" on <calcPr> in xl/workbook.xml so Excel recalculates formulas on open
        updated_wb_bytes: Optional[bytes] = None
        if "xl/workbook.xml" in zin.namelist():
            orig_wb_bytes = zin.read("xl/workbook.xml")
            register_xml_namespaces(orig_wb_bytes)
            wb_root = ET.fromstring(orig_wb_bytes)
            calc_pr = wb_root.find("main:calcPr", ns)
            if calc_pr is None:
                calc_pr = ET.SubElement(wb_root, f"{{{MAIN_NS}}}calcPr")
            calc_pr.set("fullCalcOnLoad", "1")
            updated_wb_bytes = serialize_xml_preserving_root_ns(wb_root, orig_wb_bytes)

        # Write updated archive
        with zipfile.ZipFile(output_path, "w", zipfile.ZIP_DEFLATED) as zout:
            for item in zin.infolist():
                if item.filename == target_sheet_path:
                    xml_bytes = serialize_xml_preserving_root_ns(s_root, sheet_xml_bytes)
                    zout.writestr(item, xml_bytes)
                elif item.filename == "xl/sharedStrings.xml":
                    ss_bytes = (
                        serialize_xml_preserving_root_ns(ss_root, orig_ss_bytes)
                        if orig_ss_bytes
                        else ET.tostring(ss_root, encoding="utf-8", xml_declaration=True)
                    )
                    zout.writestr(item, ss_bytes)
                elif item.filename == "xl/workbook.xml" and updated_wb_bytes is not None:
                    zout.writestr(item, updated_wb_bytes)
                elif item.filename == "xl/calcChain.xml":
                    # Omit stale calcChain.xml so Excel recalculates cleanly on open
                    continue
                else:
                    zout.writestr(item, zin.read(item.filename))


# ---------------------------------------------------------------------------
# SLA Breach & Age Analysis + Terminal & Markdown Reporting
# ---------------------------------------------------------------------------

def analyze_and_report_sla(
    open_entries: List[Dict[str, object]],
    closed_entries_moved: List[Dict[str, object]],
    all_closed_entries: List[Dict[str, object]],
    stats: Dict[str, int],
    today: datetime.date,
    open_out_path: str,
    closed_out_path: str,
    summary_md_path: Optional[str] = None,
    dry_run: bool = False,
    source_scan_paths: Optional[List[str]] = None,
) -> Dict[str, object]:
    """
    Calculate finding age (days from Original Detection Date) and SLA breach status
    (Scheduled Completion Date < Today) for all finished OPEN POA&M entries.
    """
    overdue_entries = []
    within_sla_entries = []
    unverified_entries = [e for e in open_entries if e.get("_unverified_host")]

    for e in open_entries:
        det_d = e.get("_det_date_obj") or parse_any_date(str(e.get("original_detection_date", ""))) or today
        sla_d = e.get("_sla_date_obj") or parse_any_date(str(e.get("scheduled_completion_date", ""))) or today
        age_days = max(0, (today - det_d).days)
        days_past_sla = (today - sla_d).days  # Positive if overdue, negative if days remaining

        e["_age_days"] = age_days
        e["_days_past_sla"] = days_past_sla
        e["_is_overdue"] = sla_d < today

        if sla_d < today:
            overdue_entries.append(e)
        else:
            within_sla_entries.append(e)

    # Sort open entries by overdue status first, then age descending
    sorted_open = sorted(
        open_entries,
        key=lambda x: (0 if x.get("_is_overdue") else 1, -int(x.get("_age_days", 0))),
    )

    mode_banner = " [DRY-RUN PREVIEW — NO FILES WRITTEN]" if dry_run else ""
    print("\n" + "=" * 96)
    print(f"  GRCx (v1.3.4 — Sasebo) · FEDRAMP POA&M TRANSFORMATION & SLA AGING REPORT{mode_banner}")
    print("=" * 96)
    print(f"  Analysis Reference Date : {format_date_iso(today)}")
    if source_scan_paths:
        scan_display = ", ".join(os.path.basename(p) for p in source_scan_paths)
        print(f"  Source Scan File(s)     : {scan_display} ({len(source_scan_paths)} file{'s' if len(source_scan_paths) > 1 else ''})")
    print(f"  Finished OPEN POA&M     : {open_out_path}{' (dry-run)' if dry_run else ''}")
    print(f"  Finished CLOSED POA&M   : {closed_out_path}{' (dry-run)' if dry_run else ''}")
    print("-" * 96)
    print(f"  • Total Active OPEN POA&M Entries   : {len(open_entries)}  "
          f"({stats['carry_over_open']} Carried Over, {stats['new_open']} Newly Detected)")
    if stats.get("unverified_unscanned_open", 0) > 0:
        print(f"  • Unverified (Host Not in Scan)     : {stats['unverified_unscanned_open']}  "
              f"(Retained in OPEN & flagged for host/scope review)")
    print(f"  • Entries Moved OPEN -> CLOSED      : {len(closed_entries_moved)}  "
          f"(Total in Closed Workbook: {len(all_closed_entries)})")
    print(f"  • OPEN Entries w/ PASSED SLA Date   : {len(overdue_entries)} of {len(open_entries)} "
          f"({'ACTION REQUIRED — SLA BREACH' if overdue_entries else 'ALL WITHIN SLA'})")
    print("=" * 96)

    if sorted_open:
        print("\n  ITEMIZED OPEN POA&M AGING & SLA STATUS:")
        print(f"  {'POAM ID':<15} | {'Risk':<8} | {'Orig. Detected':<14} | {'Age (Days Old)':<16} | {'SLA Due Date':<12} | {'SLA Status'}")
        print("  " + "-" * 92)
        for e in sorted_open:
            pid = str(e.get("poam_id", ""))[:15]
            risk = str(e.get("original_risk_rating", ""))[:8]
            det_s = str(e.get("original_detection_date", ""))
            sla_s = str(e.get("scheduled_completion_date", ""))
            age_d = int(e.get("_age_days", 0))
            past_d = int(e.get("_days_past_sla", 0))
            unv_tag = " [HOST NOT IN SCAN]" if e.get("_unverified_host") else ""
            if e.get("_is_overdue"):
                sla_status = f"🚨 PASSED SLA ({past_d} days overdue){unv_tag}"
            else:
                sla_status = f"✅ Within SLA ({abs(past_d)} days remaining){unv_tag}"
            print(f"  {pid:<15} | {risk:<8} | {det_s:<14} | {f'{age_d} days old':<16} | {sla_s:<12} | {sla_status}")
    else:
        print("\n  [✓] Zero Open POA&M findings remain in the workbook.")

    if unverified_entries:
        print("\n  [!] FLAGGED FOR REVIEW — PREVIOUS OPEN ITEMS WHOSE ASSET WAS NOT OBSERVED IN THIS SCAN:")
        for u in unverified_entries:
            print(f"    • {u.get('poam_id', 'N/A')} | {u.get('weakness_name', '')[:45]} | Asset: {u.get('asset_identifier', '')} (Retained in OPEN)")

    if closed_entries_moved:
        print("\n  ENTRIES MOVED FROM OPEN -> CLOSED FEDRAMP POA&M IN THIS CYCLE:")
        for c in closed_entries_moved:
            print(f"    • {c.get('poam_id', 'N/A')} | {c.get('weakness_name', '')[:45]} | Asset: {c.get('asset_identifier', '')} | Closed: {c.get('status_date', '')}")

    print("=" * 96 + "\n")

    if summary_md_path and not dry_run:
        os.makedirs(os.path.dirname(os.path.abspath(summary_md_path)), exist_ok=True)
        lines = [
            "# GRCx FedRAMP POA&M Scan Transformation & SLA Aging Report",
            "",
            f"- **Transformation Date**: `{format_date_iso(today)}`",
        ]
        if source_scan_paths:
            scans_formatted = ", ".join(f"`{os.path.basename(p)}`" for p in source_scan_paths)
            lines.append(f"- **Source Scan File(s)**: {scans_formatted} ({len(source_scan_paths)} file{'s' if len(source_scan_paths) > 1 else ''})")
        lines.extend([
            f"- **Generated OPEN FedRAMP POA&M**: `{os.path.basename(open_out_path)}`",
            f"- **Generated CLOSED FedRAMP POA&M**: `{os.path.basename(closed_out_path)}`",
            f"- **Total Active OPEN Entries**: **{len(open_entries)}** (*{stats['carry_over_open']} Carried Over, {stats['new_open']} Newly Detected*)",
            f"- **Unverified (Asset Not Observed in Scan)**: **{stats.get('unverified_unscanned_open', 0)}** (*Retained in OPEN pending review*)",
            f"- **Entries Moved from OPEN to CLOSED**: **{len(closed_entries_moved)}** (*Total Closed Rows: {len(all_closed_entries)}*)",
            f"- **OPEN Entries with Passed SLA Date**: **{len(overdue_entries)}** of **{len(open_entries)}**",
            "",
            "## 1. Itemized OPEN POA&M Aging & SLA Status",
            "",
            "| POAM ID | Weakness Name | Asset Identifier | Risk | Original Detection Date | Age (Days Old) | Scheduled Completion Date (SLA) | SLA Status |",
            "| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |",
        ])
        for e in sorted_open:
            age_d = int(e.get("_age_days", 0))
            past_d = int(e.get("_days_past_sla", 0))
            unv_note = " *(Host Not in Scan)*" if e.get("_unverified_host") else ""
            status_str = (
                f"**PASSED SLA ({past_d} days overdue)**{unv_note}"
                if e.get("_is_overdue")
                else f"Within SLA ({abs(past_d)} days left){unv_note}"
            )
            wname = str(e.get("weakness_name", "")).replace("|", "\\|").replace("\n", " ")
            asset = str(e.get("asset_identifier", "")).replace("|", "\\|").replace("\n", ", ")
            lines.append(
                f"| `{e.get('poam_id')}` | {wname} | `{asset}` | **{e.get('original_risk_rating')}** | "
                f"`{e.get('original_detection_date')}` | **{age_d} days old** | `{e.get('scheduled_completion_date')}` | {status_str} |"
            )

        if closed_entries_moved:
            lines.extend([
                "",
                "## 2. Entries Moved from OPEN to CLOSED POA&M",
                "",
                "| POAM ID | Weakness Name | Asset Identifier | Original Detection Date | Closure Date | Closure Note |",
                "| :--- | :--- | :--- | :--- | :--- | :--- |",
            ])
            for c in closed_entries_moved:
                wname = str(c.get("weakness_name", "")).replace("|", "\\|").replace("\n", " ")
                asset = str(c.get("asset_identifier", "")).replace("|", "\\|").replace("\n", ", ")
                comm = str(c.get("comments", "")).replace("|", "\\|").replace("\n", " ")
                lines.append(
                    f"| `{c.get('poam_id')}` | {wname} | `{asset}` | `{c.get('original_detection_date')}` | `{c.get('status_date')}` | {comm} |"
                )

        with open(summary_md_path, "w", encoding="utf-8") as mf:
            mf.write("\n".join(lines) + "\n")

    return {
        "total_open": len(open_entries),
        "overdue_count": len(overdue_entries),
        "moved_to_closed": len(closed_entries_moved),
        "unverified_unscanned_open": stats.get("unverified_unscanned_open", 0),
    }


# ---------------------------------------------------------------------------
# Drop-In Folder (scans/) File Discovery & Resolution Helpers
# ---------------------------------------------------------------------------

def list_eligible_files(
    directory: str,
    extensions: Tuple[str, ...],
    exclude_paths: Optional[List[str]] = None,
) -> List[str]:
    """
    Return sorted absolute file paths inside `directory` matching `extensions`,
    ignoring hidden dotfiles and temporary Office lock files (~$...).
    """
    if not directory or not os.path.isdir(directory):
        return []
    excl_abs = {os.path.abspath(p) for p in (exclude_paths or []) if p}
    ext_lower = tuple(e.lower() for e in extensions)
    matched: List[str] = []
    try:
        for fname in sorted(os.listdir(directory), key=lambda s: s.lower()):
            if fname.startswith(".") or fname.startswith("~$"):
                continue
            full_p = os.path.abspath(os.path.join(directory, fname))
            if full_p in excl_abs or not os.path.isfile(full_p):
                continue
            if fname.lower().endswith(ext_lower):
                matched.append(full_p)
    except OSError:
        pass
    return matched


def resolve_input_file(
    user_input: str,
    scans_dir: str,
    extensions: Tuple[str, ...],
    numbered_choices: Optional[List[str]] = None,
    fallback_dirs: Optional[List[str]] = None,
) -> Optional[str]:
    """
    Resolve a user-supplied file reference via:
      1. Numbered selection (e.g. '1' or '[1]') from `numbered_choices`
      2. Direct file path (relative to CWD or absolute)
      3. Filename inside `scans_dir` (or `fallback_dirs`) — exact, case-insensitive,
         or filename without extension (e.g. 'my_scan' -> 'scans/my_scan.csv').
    """
    if not user_input:
        return None
    raw = user_input.strip().strip("'\"")
    if not raw:
        return None

    # 1. Check numbered choice selection (e.g., "1" or "[1]")
    if numbered_choices:
        m_num = re.match(r"^\[?\s*(\d+)\s*\]?$", raw)
        if m_num:
            idx = int(m_num.group(1))
            if 1 <= idx <= len(numbered_choices):
                return numbered_choices[idx - 1]

    # 2. Direct path as entered (relative to CWD or absolute)
    expanded = os.path.expanduser(raw)
    if os.path.isfile(expanded):
        return os.path.abspath(expanded)

    # 3. Search inside designated drop-in directory (scans/) then fallback dirs
    search_dirs = [scans_dir] + (fallback_dirs or [])
    ext_lower = tuple(e.lower() for e in extensions)

    for d in search_dirs:
        if not d or not os.path.isdir(d):
            continue
        # 3a. Exact filename join
        candidate = os.path.join(d, raw)
        if os.path.isfile(candidate):
            return os.path.abspath(candidate)

        # 3b. Try appending supported extensions if omitted
        for ext in extensions:
            if not raw.lower().endswith(ext.lower()):
                cand_ext = os.path.join(d, raw + ext)
                if os.path.isfile(cand_ext):
                    return os.path.abspath(cand_ext)

        # 3c. Case-insensitive filename or stem match inside directory
        try:
            entries = sorted(os.listdir(d), key=lambda s: s.lower())
        except OSError:
            continue

        raw_lower = raw.lower()
        for fname in entries:
            if fname.startswith(".") or fname.startswith("~$"):
                continue
            full_p = os.path.join(d, fname)
            if not os.path.isfile(full_p):
                continue
            fname_lower = fname.lower()
            stem_lower, f_ext_lower = os.path.splitext(fname_lower)
            if f_ext_lower not in ext_lower:
                continue
            if fname_lower == raw_lower or stem_lower == raw_lower:
                return os.path.abspath(full_p)

    return None


def display_detected_files(
    scans_dir: str,
    extensions: Tuple[str, ...],
    label: str,
    exclude_paths: Optional[List[str]] = None,
) -> List[str]:
    """
    Display a numbered list of eligible files in `scans_dir` (or sample fallback if empty)
    and return their paths.
    """
    rel_scans = os.path.relpath(scans_dir, REPO_ROOT)
    rel_display = f"{rel_scans}/" if not rel_scans.startswith("..") else scans_dir
    files = list_eligible_files(scans_dir, extensions, exclude_paths=exclude_paths)

    if files:
        print(f"  [*] {label} detected in '{rel_display}':")
        for idx, fpath in enumerate(files, start=1):
            print(f"      [{idx}] {os.path.basename(fpath)}")
        return files

    print(f"  [*] Designated drop-in folder '{rel_display}' is currently empty (drop {'/'.join(extensions)} files into '{rel_display}' any time).")
    sample_files = list_eligible_files(SAMPLE_SCANS_DIR, extensions, exclude_paths=exclude_paths)
    if sample_files:
        print(f"  [*] Sample files available in 'testing/sample-scans/':")
        for idx, fpath in enumerate(sample_files, start=1):
            print(f"      [{idx}] {os.path.basename(fpath)}  (sample)")
        return sample_files
    return []


# ---------------------------------------------------------------------------
# CLI & Interactive Orchestration
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(
        prog="grc transform",
        description=(
            "GRCx Standalone Scan-to-POA&M Transformer (transform_scans.py): "
            "Drop your scan exports (.csv/.xlsx) and previous POA&M (.xlsx) into the "
            "'scans/' folder and pass just the filename (or run interactively to pick "
            "from a numbered list). Reconciles Open -> Closed items, drafts missing "
            "remediation plans with official Tenable/AWS URLs, and reports SLA breaches."
        ),
    )
    parser.add_argument(
        "scan_pos",
        nargs="*",
        default=[],
        metavar="SCAN_FILE",
        help="Optional scan filename(s) in scans/ (up to 5 scans, e.g. 'tenable_scan.csv' or 'scan1.csv scan2.csv') or path.",
    )
    parser.add_argument(
        "--scan", "-s",
        action="append",
        dest="scans",
        default=[],
        help="Scan filename in scans/ (or path to Tenable / AWS Inspector .csv or .xlsx file). May be passed multiple times (up to 5 scans) or as comma-separated filenames.",
    )
    parser.add_argument(
        "--scans-dir",
        default=DEFAULT_SCANS_DIR,
        help="Designated drop-in directory for scan exports and previous POA&M files (default: ./scans/).",
    )
    parser.add_argument(
        "--scanner",
        choices=["auto", "tenable", "inspector"],
        default="auto",
        help="Scanner source type (default: auto-detect from column headers).",
    )
    parser.add_argument(
        "--previous-open", "-p",
        default=None,
        help="Filename in scans/ (or path) of previously filled-out OPEN FedRAMP POA&M (.xlsx) for Open->Closed delta reconciliation (or 'none' for initial baseline).",
    )
    parser.add_argument(
        "--no-previous",
        action="store_true",
        help="Skip prompting for a previously filled-out OPEN FedRAMP POA&M (treat run as an initial baseline).",
    )
    parser.add_argument(
        "--previous-closed",
        default=None,
        help="Optional filename in scans/ (or path) of existing CLOSED FedRAMP POA&M (.xlsx) to append newly closed entries.",
    )
    parser.add_argument(
        "--output-dir", "-o",
        default=None,
        help="Directory where finished OPEN and CLOSED FedRAMP POA&M .xlsx files will be saved (default: evidence/poam-<scan>/).",
    )
    parser.add_argument(
        "--open-template",
        default=DEFAULT_OPEN_TEMPLATE,
        help="Path to base OPEN FedRAMP POA&M template (.xlsx).",
    )
    parser.add_argument(
        "--closed-template",
        default=DEFAULT_CLOSED_TEMPLATE,
        help="Path to base CLOSED LEGACY FedRAMP POA&M template (.xlsx).",
    )
    parser.add_argument(
        "--poc",
        default="Cloud Security / GRC Team",
        help="Default Point of Contact (Column I) for newly detected POA&M items.",
    )
    parser.add_argument(
        "--draft-remediations",
        choices=["ask", "y", "n"],
        default="ask",
        help="Whether to auto-draft missing Remediation Plans with Tenable/AWS URLs ('ask' prompts interactively).",
    )
    parser.add_argument(
        "--include-scanner-solutions",
        action="store_true",
        help="Pre-fill Column K directly from raw scanner Solution text before checking for missing remediation plans.",
    )
    parser.add_argument(
        "--reference-date",
        default=None,
        help="Override reference date (YYYY-MM-DD) for SLA and finding age calculation (default: today).",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Preview Carry-Over, New, Closed, and Unscanned-Host items in the terminal without writing .xlsx or .md files.",
    )
    parser.add_argument(
        "--kev-catalog",
        default=DEFAULT_KEV_CATALOG,
        help="Path to local CISA KEV JSON catalog for BOD 22-01 lookup (default: ./rules/cisa_kev_catalog.json).",
    )
    parser.add_argument(
        "--close-unscanned-hosts",
        action="store_true",
        help="Force auto-closure of absent findings even when their host/asset was not observed in the current scan.",
    )
    parser.add_argument(
        "--strict-fedramp-risk",
        action="store_true",
        help="Use strict 3-tier FedRAMP risk rating (High/Moderate/Low; maps Critical -> High 30d SLA) and preserve original template data validations.",
    )

    parser.add_argument(
        "--match-mode",
        choices=["strict", "legacy"],
        default=MATCH_MODE,
        help=(
            "How previous OPEN entries are matched to the new scan. 'strict' (default): plugin/source ID + host, "
            "with unscanned hosts kept open for review. 'legacy': reproduces the old Google Apps Scripts - match on "
            "Weakness Name + Description only; anything absent from the scan is closed."
        ),
    )
    parser.add_argument(
        "--poam-id-column",
        default=None,
        metavar="COL",
        help="Column letter holding the 'POAM ID' header in the POA&M workbooks/templates (default: auto-detect, falling back to A).",
    )

    args = parser.parse_args()
    global POAM_ID_COLUMN_OVERRIDE
    if args.poam_id_column:
        POAM_ID_COLUMN_OVERRIDE = re.sub(r"[^A-Za-z]", "", args.poam_id_column).upper() or None

    scans_dir = os.path.abspath(args.scans_dir)
    os.makedirs(scans_dir, exist_ok=True)
    fallback_dirs = [SAMPLE_SCANS_DIR, REPO_ROOT]

    today = parse_any_date(args.reference_date) if args.reference_date else datetime.date.today()
    if not today:
        today = datetime.date.today()

    # 1. Resolve Scan Input Paths (from CLI argument or interactive prompt in scans/)
    raw_scan_args: List[str] = []
    if args.scans:
        for s in args.scans:
            for part in s.split(","):
                part_clean = part.strip()
                if part_clean:
                    raw_scan_args.append(part_clean)
    if args.scan_pos:
        for p in args.scan_pos:
            for part in p.split(","):
                part_clean = part.strip()
                if part_clean:
                    raw_scan_args.append(part_clean)

    scan_paths: List[str] = []

    if raw_scan_args:
        if len(raw_scan_args) > MAX_SCAN_FILES:
            print(
                f"[ERROR] At most {MAX_SCAN_FILES} scan files can be transformed at one time (received {len(raw_scan_args)}).",
                file=sys.stderr,
            )
            return 1
        for raw_arg in raw_scan_args:
            resolved = resolve_input_file(
                raw_arg,
                scans_dir=scans_dir,
                extensions=SCAN_EXTENSIONS,
                fallback_dirs=fallback_dirs,
            )
            if not resolved:
                avail = [os.path.basename(p) for p in list_eligible_files(scans_dir, SCAN_EXTENSIONS)]
                avail_hint = f" Available in scans/: {', '.join(avail)}" if avail else " Drop your file into the 'scans/' folder and pass just its filename."
                print(f"[ERROR] Scan file not found: '{raw_arg}' (searched ./scans/ and direct path).{avail_hint}", file=sys.stderr)
                return 1
            if resolved not in scan_paths:
                scan_paths.append(resolved)
    else:
        if sys.stdin.isatty():
            print("\n=== GRCx Standalone FedRAMP POA&M Scan Transformer ===")
            while len(scan_paths) < MAX_SCAN_FILES:
                scan_idx = len(scan_paths) + 1
                label = (
                    "Scan / Workbook files (.csv, .xlsx)"
                    if scan_idx == 1
                    else f"Additional scan files (.csv, .xlsx) [Scan {scan_idx}/{MAX_SCAN_FILES}]"
                )
                choices = display_detected_files(
                    scans_dir=scans_dir,
                    extensions=SCAN_EXTENSIONS,
                    label=label,
                    exclude_paths=scan_paths,
                )
                if scan_idx == 1:
                    prompt_msg = (
                        f"[?] Select scan file by number [1-{len(choices)}] or enter filename in scans/ (.csv/.xlsx): "
                        if choices
                        else "[?] Enter scan filename in scans/ (with or without .csv/.xlsx extension): "
                    )
                else:
                    prompt_msg = (
                        f"[?] Select additional scan file #{scan_idx} by number [1-{len(choices)}] or enter filename in scans/ (.csv/.xlsx): "
                        if choices
                        else f"[?] Enter additional scan file #{scan_idx} filename in scans/ (with or without .csv/.xlsx extension): "
                    )

                user_scan = input(prompt_msg).strip()
                if not user_scan:
                    if scan_paths:
                        break
                    print("[ERROR] A scan file (.csv or .xlsx) is required.", file=sys.stderr)
                    return 1

                if user_scan.lower() in ("cancel", "done", "skip", "n", "no") and scan_paths:
                    break

                live_choices = choices or list_eligible_files(scans_dir, SCAN_EXTENSIONS, exclude_paths=scan_paths)
                resolved = resolve_input_file(
                    user_scan,
                    scans_dir=scans_dir,
                    extensions=SCAN_EXTENSIONS,
                    numbered_choices=live_choices,
                    fallback_dirs=fallback_dirs,
                )
                if not resolved:
                    print(f"[ERROR] Scan file not found in scans/: '{user_scan}'", file=sys.stderr)
                    return 1

                if resolved in scan_paths:
                    print(f"[!] Scan file '{os.path.basename(resolved)}' is already selected.")
                else:
                    scan_paths.append(resolved)
                    print(f"[+] Added scan file [{len(scan_paths)}/{MAX_SCAN_FILES}]: {os.path.basename(resolved)}")

                if len(scan_paths) >= MAX_SCAN_FILES:
                    print(f"\n[*] Maximum of {MAX_SCAN_FILES} scan files reached.")
                    break

                # Ask the user if they'd like to add an additional scan file
                add_more = input("\n[?] Would you like to add an additional scan file to also be transformed? [y/N]: ").strip().lower()
                if not add_more.startswith("y"):
                    break

    if not scan_paths:
        parser.error(
            f"A scan file (.csv or .xlsx) is required (up to {MAX_SCAN_FILES} scans supported). "
            "Drop it in 'scans/' and pass --scan <filename> or run interactively."
        )

    # 2. Request Previously Filled-Out OPEN FedRAMP POA&M Form (if not provided via flag)
    prev_open_path = ""
    if args.previous_open is not None:
        if args.previous_open.strip().lower() not in ("", "none", "null", "false", "-"):
            resolved_prev = resolve_input_file(
                args.previous_open,
                scans_dir=scans_dir,
                extensions=POAM_EXTENSIONS,
                fallback_dirs=fallback_dirs,
            )
            if not resolved_prev:
                print(f"[ERROR] Previous OPEN POA&M file not found in scans/: '{args.previous_open}'", file=sys.stderr)
                return 1
            prev_open_path = resolved_prev
    elif not args.no_previous and sys.stdin.isatty():
        print("")
        poam_choices = display_detected_files(
            scans_dir=scans_dir,
            extensions=POAM_EXTENSIONS,
            label="Previous POA&M workbooks (.xlsx)",
            exclude_paths=scan_paths,
        )
        prev_prompt = (
            f"[?] Select previous OPEN FedRAMP POA&M by number [1-{len(poam_choices)}], enter filename in scans/,\n"
            f"    or press Enter if none (initial baseline): "
            if poam_choices
            else "[?] Enter previous OPEN FedRAMP POA&M filename in scans/ (.xlsx) to reconcile\n"
                 "    Open -> Closed transitions (or press Enter if none / initial baseline): "
        )
        user_prev = input(prev_prompt).strip()
        if user_prev and user_prev.lower() not in ("none", "null", "false", "-"):
            live_poam_choices = poam_choices or list_eligible_files(scans_dir, POAM_EXTENSIONS, exclude_paths=scan_paths)
            resolved_prev = resolve_input_file(
                user_prev,
                scans_dir=scans_dir,
                extensions=POAM_EXTENSIONS,
                numbered_choices=live_poam_choices,
                fallback_dirs=fallback_dirs,
            )
            if not resolved_prev:
                print(f"[ERROR] Previous OPEN POA&M file not found in scans/: '{user_prev}'", file=sys.stderr)
                return 1
            prev_open_path = resolved_prev

    # Also resolve --previous-closed through scans/ if provided
    prev_closed_path = ""
    if args.previous_closed:
        resolved_closed = resolve_input_file(
            args.previous_closed,
            scans_dir=scans_dir,
            extensions=POAM_EXTENSIONS,
            fallback_dirs=fallback_dirs,
        )
        if not resolved_closed:
            print(f"[ERROR] Previous CLOSED POA&M file not found in scans/: '{args.previous_closed}'", file=sys.stderr)
            return 1
        prev_closed_path = resolved_closed

    # 3. Load and Normalize Scan Findings
    per_file_entries: List[List[Dict[str, object]]] = []
    all_scanned_assets: Set[str] = set()
    all_asset_alias_map: Dict[str, Set[str]] = {}
    detected_scanner_types: Set[str] = set()
    total_raw_rows = 0
    kev_catalog = load_cisa_kev_catalog(args.kev_catalog)

    print(f"\n[*] Ingesting findings from {len(scan_paths)} scan file(s)...")
    for idx, spath in enumerate(scan_paths, start=1):
        records = load_scan_records(spath)
        total_raw_rows += len(records)
        stype = detect_scanner_type(records, None if args.scanner == "auto" else args.scanner)
        detected_scanner_types.add(stype)
        scanned_assets, asset_alias_map = collect_scanned_assets(records)
        all_scanned_assets.update(scanned_assets)
        for k, v in asset_alias_map.items():
            all_asset_alias_map.setdefault(k, set()).update(v)

        print(
            f"  [{idx}/{len(scan_paths)}] '{os.path.basename(spath)}': {len(records)} rows "
            f"(Source: {stype.upper()}, Scanned host identifiers: {len(scanned_assets)})"
        )

        entries = normalize_scan_rows(
            records=records,
            scanner_type=stype,
            scan_filename=os.path.basename(spath),
            today=today,
            default_poc=args.poc,
            kev_catalog=kev_catalog,
            strict_fedramp_risk=args.strict_fedramp_risk,
        )
        per_file_entries.append(entries)

    scan_entries = merge_scan_entries(per_file_entries)
    if len(scan_paths) > 1:
        print(
            f"[*] Consolidated into {len(scan_entries)} unique vulnerability + asset findings "
            f"across {len(scan_paths)} scan files (Total scanned host identifiers: {len(all_scanned_assets)})"
        )

    # Unless --include-scanner-solutions is explicitly passed, treat new scan entries without
    # an analyst-approved POA&M remediation plan (or with missing remediation URLs) as needing
    # a remediation plan check so the analyst is prompted whether GRCx should draft them with URLs.
    if not args.include_scanner_solutions:
        for se in scan_entries:
            se["remediation_plan"] = ""

    # 4. Load Previous OPEN & CLOSED POA&M Workbooks and Reconcile Open -> Closed
    prev_open_entries = load_existing_poam_workbook(prev_open_path, is_closed_template=False) if prev_open_path else []
    if prev_open_path:
        print(f"[*] Loaded {len(prev_open_entries)} existing entries from previous OPEN POA&M: {os.path.basename(prev_open_path)}")
    else:
        print(
            "[WARNING] No previous OPEN FedRAMP POA&M provided! Treating this run as an initial baseline: "
            f"POA&M IDs will start at {format_poam_id(today, 1)} (unless --previous-closed is supplied) and no Open -> Closed "
            "reconciliation will occur. Pass -p <filename> to reconcile against an existing POA&M."
        )

    prev_closed_entries = (
        load_existing_poam_workbook(prev_closed_path, is_closed_template=True)
        if prev_closed_path and os.path.isfile(prev_closed_path)
        else []
    )
    if prev_closed_path and prev_closed_entries:
        print(f"[*] Loaded {len(prev_closed_entries)} existing entries from previous CLOSED POA&M: {os.path.basename(prev_closed_path)}")

    reconcile_fn = reconcile_poam_entries_legacy if args.match_mode == "legacy" else reconcile_poam_entries
    print(f"[*] Match mode: {args.match_mode.upper()}")
    final_open, newly_closed, stats = reconcile_fn(
        prev_open_entries=prev_open_entries,
        new_scan_entries=scan_entries,
        today=today,
        prev_closed_entries=prev_closed_entries,
        scanned_assets=all_scanned_assets,
        asset_alias_map=all_asset_alias_map,
        close_unscanned_hosts=args.close_unscanned_hosts,
    )
    all_closed = prev_closed_entries + newly_closed

    # 5. Check for Missing Remediation Plans (Column K) and Prompt User [y/n]
    missing_remediation_entries = [
        e for e in final_open if not str(e.get("remediation_plan", "")).strip()
    ]

    if missing_remediation_entries:
        choice = args.draft_remediations
        if choice == "ask":
            if sys.stdin.isatty():
                ans = input(
                    f"\n[!] {len(missing_remediation_entries)} of {len(final_open)} OPEN POA&M entries are missing a Remediation Plan (Column K).\n"
                    f"    Would you like GRCx to draft missing remediation plans with official Tenable/AWS remediation links? (y/n): "
                ).strip().lower()
                choice = "y" if ans.startswith("y") else "n"
            else:
                print(
                    f"[*] Non-interactive session detected with --draft-remediations=ask: "
                    f"auto-drafting {len(missing_remediation_entries)} missing Remediation Plans "
                    f"(pass --draft-remediations n to leave blank)."
                )
                choice = "y"

        if choice == "y":
            for e in missing_remediation_entries:
                e["remediation_plan"] = build_remediation_plan_with_urls(e)
            stypes_str = "/".join(sorted(s.upper() for s in detected_scanner_types))
            print(f"[+] Drafted {len(missing_remediation_entries)} Remediation Plans with official {stypes_str} remediation URLs.")
        else:
            print(f"[*] Left {len(missing_remediation_entries)} missing Remediation Plans blank per user selection.")

    # 6. Write Finished OPEN and CLOSED FedRAMP POA&M Workbooks (skipped in --dry-run mode)
    if len(scan_paths) == 1:
        scan_stem = os.path.splitext(os.path.basename(scan_paths[0]))[0]
        default_out = f"poam-{scan_stem}"
    else:
        first_stem = os.path.splitext(os.path.basename(scan_paths[0]))[0]
        default_out = f"poam-{first_stem}-and-{len(scan_paths)-1}-more"

    out_dir = args.output_dir or os.path.join(REPO_ROOT, "evidence", default_out)

    open_out_path = os.path.join(out_dir, "OPEN FedRAMP-POAM.xlsx")
    closed_out_path = os.path.join(out_dir, "CLOSED FedRAMP-POAM.xlsx")
    summary_md_path = os.path.join(out_dir, "poam_transform_summary.md")

    if not args.dry_run:
        os.makedirs(out_dir, exist_ok=True)
        write_poam_workbook(
            template_path=args.open_template,
            output_path=open_out_path,
            entries=final_open,
            is_closed_template=False,
            strict_fedramp_risk=args.strict_fedramp_risk,
        )
        write_poam_workbook(
            template_path=args.closed_template,
            output_path=closed_out_path,
            entries=all_closed,
            is_closed_template=True,
            strict_fedramp_risk=args.strict_fedramp_risk,
        )

    # 7. Run SLA Breach & Finding Age Analysis and Print Report
    analyze_and_report_sla(
        open_entries=final_open,
        closed_entries_moved=newly_closed,
        all_closed_entries=all_closed,
        stats=stats,
        today=today,
        open_out_path=open_out_path,
        closed_out_path=closed_out_path,
        summary_md_path=summary_md_path,
        dry_run=args.dry_run,
        source_scan_paths=scan_paths,
    )

    return 0


if __name__ == "__main__":
    sys.exit(main())
