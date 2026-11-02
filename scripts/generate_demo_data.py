#!/usr/bin/env python3
"""
Generate synthetic (fake) test datasets for GRC-xMINI Live Demo:
  1. previous_open_poam.xlsx (160 entries, using attached FedRAMP v3.1 5-tab template)
     - Months: March, May, July, August, October 2026 (POAM IDs: 2026-MAR-00001 .. 2026-OCT-00160)
     - 80 entries match current scan reports (stay OPEN)
     - 80 entries absent from current scan reports (move to CLOSED)
  2. tenable_vulnerability_report.xlsx (80 items total: 40 match previous POAM, 40 new)
  3. qualys_vulnerability_report.xlsx (30 items total: 20 match previous POAM, 10 new)
  4. aws_inspector_report.xlsx (150 items total: 10 match previous POAM, 140 new)
  5. wiz_vulnerability_report.xlsx (70 items total: 10 match previous POAM, 60 new)

Total items in 4 scans: 80 + 30 + 150 + 70 = 330 items
Total matched with previous POAM: 40 + 20 + 10 + 10 = 80 items
Total new items: 40 + 10 + 140 + 60 = 250 items
"""

import datetime
import os
import shutil
import sys
import zipfile
import xml.etree.ElementTree as ET

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(SCRIPT_DIR)
sys.path.insert(0, SCRIPT_DIR)
import transform_scans as ts

TEMPLATE_PATH = "/Users/byronturner-pro/.gemini/antigravity/brain/db2719f8-2b7f-43e7-ad0e-cec59d1baed5/.user_uploaded/media_1793588823783_a09a5375.xlsx"
DROPOFF_DIR = os.path.join(REPO_ROOT, "artifacts", "drop-off")
TEST_SCANS_DIR = "/Users/byronturner-pro/Desktop/GRC-xTEST/scans"

os.makedirs(DROPOFF_DIR, exist_ok=True)
if os.path.isdir(TEST_SCANS_DIR):
    os.makedirs(TEST_SCANS_DIR, exist_ok=True)


def create_xlsx(filepath: str, headers: list, rows: list, sheet_name: str = "Sheet1") -> None:
    """Create a standard, clean OpenXML .xlsx file using Python standard library."""
    shared_strings = []
    ss_map = {}

    def get_ss(s):
        s = str(s if s is not None else "")
        if s in ss_map:
            return ss_map[s]
        idx = len(shared_strings)
        shared_strings.append(s)
        ss_map[s] = idx
        return idx

    MAIN_NS = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
    s_root = ET.Element(f"{{{MAIN_NS}}}worksheet")
    sheet_data = ET.SubElement(s_root, f"{{{MAIN_NS}}}sheetData")

    # Row 1: Headers
    r_el = ET.SubElement(sheet_data, f"{{{MAIN_NS}}}row", {"r": "1"})
    for col_idx, h in enumerate(headers):
        col_let = ts.idx_to_col(col_idx)
        c_el = ET.SubElement(r_el, f"{{{MAIN_NS}}}c", {"r": f"{col_let}1", "t": "s"})
        v_el = ET.SubElement(c_el, f"{{{MAIN_NS}}}v")
        v_el.text = str(get_ss(h))

    # Data Rows
    for row_idx, row in enumerate(rows, start=2):
        r_el = ET.SubElement(sheet_data, f"{{{MAIN_NS}}}row", {"r": str(row_idx)})
        for col_idx, h in enumerate(headers):
            col_let = ts.idx_to_col(col_idx)
            val = row.get(h, "")
            if val != "":
                c_el = ET.SubElement(r_el, f"{{{MAIN_NS}}}c", {"r": f"{col_let}{row_idx}", "t": "s"})
                v_el = ET.SubElement(c_el, f"{{{MAIN_NS}}}v")
                v_el.text = str(get_ss(val))

    sst_root = ET.Element(
        f"{{{MAIN_NS}}}sst",
        {"count": str(len(shared_strings)), "uniqueCount": str(len(shared_strings))},
    )
    for s in shared_strings:
        si = ET.SubElement(sst_root, f"{{{MAIN_NS}}}si")
        t = ET.SubElement(si, f"{{{MAIN_NS}}}t")
        if s.startswith(" ") or s.endswith(" ") or "\n" in s:
            t.set("{http://www.w3.org/XML/1998/namespace}space", "preserve")
        t.text = s

    content_types = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>
  <Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>
  <Override PartName="/xl/sharedStrings.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sharedStrings+xml"/>
  <Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>
</Types>"""

    root_rels = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>
</Relationships>"""

    wb_xml = f"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<workbook xmlns="{MAIN_NS}" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
  <sheets>
    <sheet name="{sheet_name}" sheetId="1" r:id="rId1"/>
  </sheets>
</workbook>"""

    wb_rels = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>
  <Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/sharedStrings" Target="sharedStrings.xml"/>
  <Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>
</Relationships>"""

    styles_xml = f"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<styleSheet xmlns="{MAIN_NS}">
  <fonts count="1"><font><name val="Calibri"/><sz val="11"/></font></fonts>
  <fills count="1"><fill><patternFill patternType="none"/></fill></fills>
  <borders count="1"><border/></borders>
  <cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>
  <cellXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/></cellXfs>
</styleSheet>"""

    os.makedirs(os.path.dirname(os.path.abspath(filepath)), exist_ok=True)
    with zipfile.ZipFile(filepath, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", content_types)
        z.writestr("_rels/.rels", root_rels)
        z.writestr("xl/_rels/workbook.xml.rels", wb_rels)
        z.writestr("xl/workbook.xml", wb_xml)
        z.writestr("xl/styles.xml", styles_xml)
        z.writestr("xl/sharedStrings.xml", ET.tostring(sst_root, encoding="utf-8", xml_declaration=True))
        z.writestr("xl/worksheets/sheet1.xml", ET.tostring(s_root, encoding="utf-8", xml_declaration=True))


VULN_CATALOG = [
    {
        "cve": "CVE-2024-6387",
        "name": "OpenSSH Server RegreSSHion Race Condition",
        "desc": "A signal handler race condition was found in OpenSSH's server (sshd) where a client does not authenticate within LoginGraceTime, allowing remote unauthenticated code execution as root.",
        "sol": "Upgrade OpenSSH to version 9.8p1 or newer, or set LoginGraceTime to 0 in sshd_config.",
        "risk": "Critical",
        "controls": "AC-3, IA-2, SI-2",
        "kev": "Yes",
    },
    {
        "cve": "CVE-2021-44228",
        "name": "Apache Log4j JNDI Remote Code Execution (Log4Shell)",
        "desc": "Apache Log4j2 JNDI features used in configuration, log messages, and parameters do not protect against attacker-controlled LDAP and other JNDI related endpoints.",
        "sol": "Upgrade Log4j to version 2.17.1 or higher, or remove the JndiLookup class from the classpath.",
        "risk": "Critical",
        "controls": "SI-2, SC-8, RA-5",
        "kev": "Yes",
    },
    {
        "cve": "CVE-2023-38408",
        "name": "OpenSSH PKCS#11 Provider Remote Code Execution",
        "desc": "A condition in ssh-agent allows remote code execution via PKCS#11 shared library loading forwarded to untrusted hosts.",
        "sol": "Upgrade OpenSSH to 9.3p2 or later; disable agent forwarding where not strictly required.",
        "risk": "Critical",
        "controls": "AC-3, IA-2, SI-2",
        "kev": "No",
    },
    {
        "cve": "CVE-2023-44487",
        "name": "HTTP/2 Rapid Reset Denial of Service Vulnerability",
        "desc": "The HTTP/2 protocol allows a client to reset streams rapidly with RST_STREAM frames, consuming excessive CPU and leading to denial of service.",
        "sol": "Apply web server patch (NGINX, Apache, Envoy, or HAProxy) and configure HTTP/2 stream limit controls.",
        "risk": "High",
        "controls": "SC-5, SI-2",
        "kev": "Yes",
    },
    {
        "cve": "CVE-2023-48795",
        "name": "SSH Prefix Truncation Attack (Terrapin)",
        "desc": "Bidi-stream manipulation in the SSH transport protocol allows an attacker to inject extension negotiation packets and downgrade integrity controls.",
        "sol": "Upgrade OpenSSH to 9.6p1 or apply vendor backports implementing the 'strict KEX' extension.",
        "risk": "Moderate",
        "controls": "SC-8, SC-13",
        "kev": "No",
    },
    {
        "cve": "CVE-2023-38545",
        "name": "curl SOCKS5 Heap-Based Buffer Overflow",
        "desc": "A heap-based buffer overflow flaw was found in the SOCKS5 proxy handshake within libcurl when copying a long hostname.",
        "sol": "Upgrade libcurl and curl packages to 8.4.0 or newer.",
        "risk": "High",
        "controls": "SI-2, SC-13",
        "kev": "No",
    },
    {
        "cve": "CVE-2022-3602",
        "name": "OpenSSL X.509 Email Address Buffer Overflow",
        "desc": "A 4-byte buffer overflow in X.509 certificate verification occurred in OpenSSL 3.0 during name constraint checking.",
        "sol": "Upgrade OpenSSL to version 3.0.7 or later.",
        "risk": "High",
        "controls": "SC-13, SI-2",
        "kev": "No",
    },
    {
        "cve": "CVE-2021-3156",
        "name": "sudo Baron Samedit Heap-Based Buffer Overflow",
        "desc": "Heap-based buffer overflow in sudo allows privilege escalation to root via command line arguments ending with a backslash character.",
        "sol": "Upgrade sudo to 1.9.5p2 or newer.",
        "risk": "High",
        "controls": "AC-3, AC-6, SI-2",
        "kev": "Yes",
    },
    {
        "cve": "CVE-2023-6246",
        "name": "GNU C Library (glibc) syslog Heap Buffer Overflow",
        "desc": "A heap-based buffer overflow vulnerability in glibc's __vsyslog_internal function allows local privilege escalation to root.",
        "sol": "Update glibc package to vendor patched version.",
        "risk": "High",
        "controls": "SI-2, AC-6",
        "kev": "No",
    },
    {
        "cve": "CVE-2022-0847",
        "name": "Linux Kernel Dirty Pipe Local Privilege Escalation",
        "desc": "Flaw in pipe buffer flags in the Linux kernel allows unprivileged users to overwrite arbitrary read-only files.",
        "sol": "Upgrade Linux kernel to 5.16.11, 5.15.25, 5.10.102 or vendor security update.",
        "risk": "High",
        "controls": "AC-3, SI-2",
        "kev": "Yes",
    },
    {
        "cve": "CVE-2023-39417",
        "name": "PostgreSQL Extension SQL Injection and Privilege Escalation",
        "desc": "PostgreSQL extension installation script flaw allows database users with extension creation permissions to execute arbitrary SQL as superuser.",
        "sol": "Upgrade PostgreSQL to 15.4, 14.9, 13.12, 12.16, or 11.21.",
        "risk": "Moderate",
        "controls": "AC-3, SI-2",
        "kev": "No",
    },
    {
        "cve": "CVE-2022-0543",
        "name": "Redis Lua Sandbox Escape and Remote Code Execution",
        "desc": "A packaging flaw in Debian/Ubuntu packages for Redis exposed package.loadlib in the Lua sandbox environment.",
        "sol": "Upgrade Redis server package to patched release.",
        "risk": "Critical",
        "controls": "SC-7, AC-3, SI-2",
        "kev": "Yes",
    },
    {
        "cve": "CVE-2023-36664",
        "name": "Artifex Ghostscript Command Injection",
        "desc": "Ghostscript permits pipe syntax bypass in file validation functions, allowing execution of arbitrary shell commands.",
        "sol": "Upgrade Ghostscript to 10.01.2 or higher.",
        "risk": "High",
        "controls": "SI-2, SC-18",
        "kev": "Yes",
    },
    {
        "cve": "CVE-2023-27477",
        "name": "Kubernetes API Server Request Smuggling",
        "desc": "Kubernetes apiserver allows aggregation proxy request smuggling when handling hop-by-hop headers.",
        "sol": "Upgrade Kubernetes apiserver to 1.26.3, 1.25.8, 1.24.12, or 1.23.17.",
        "risk": "Moderate",
        "controls": "SC-7, SI-2",
        "kev": "No",
    },
    {
        "cve": "CVE-2023-22809",
        "name": "sudo sudoedit Arbitrary File Editing and Privilege Escalation",
        "desc": "Flaw in sudoedit allows local users to append to arbitrary files via crafted environment variables.",
        "sol": "Upgrade sudo to 1.9.12p2 or apply vendor distribution patch.",
        "risk": "Moderate",
        "controls": "AC-3, AC-6",
        "kev": "No",
    },
    {
        "cve": "CVE-2023-45853",
        "name": "MiniZip in zlib Integer Overflow",
        "desc": "Integer overflow vulnerability in MiniZip through zlib allows denial of service or code execution via crafted ZIP file.",
        "sol": "Update zlib and minizip packages to latest patched versions.",
        "risk": "Low",
        "controls": "SI-2",
        "kev": "No",
    },
    {
        "cve": "CVE-2024-21626",
        "name": "runc Leaky File Descriptors Container Breakout",
        "desc": "Flaw in runc allows container breakout and host filesystem access via inherited file descriptors in working directory.",
        "sol": "Upgrade runc to 1.1.12 or containerd to 1.7.13 / 1.6.28.",
        "risk": "Critical",
        "controls": "SC-7, AC-3, SI-2",
        "kev": "Yes",
    },
    {
        "cve": "CVE-2023-4911",
        "name": "GNU C Library ld.so Looney Tunables Buffer Overflow",
        "desc": "A buffer overflow in the GLIBC_TUNABLES environment variable handling allows local privilege escalation to root.",
        "sol": "Upgrade glibc to vendor patched release.",
        "risk": "High",
        "controls": "AC-6, SI-2",
        "kev": "Yes",
    },
    {
        "cve": "CVE-2024-3094",
        "name": "XZ Utils liblzma Upstream Backdoor Compromise",
        "desc": "Malicious code discovered in upstream tarballs of XZ embedded in liblzma intercepts OpenSSH authentication.",
        "sol": "Downgrade xz-utils to 5.4.x and verify system integrity.",
        "risk": "Critical",
        "controls": "SA-12, SI-2, IA-2",
        "kev": "Yes",
    },
    {
        "cve": "CVE-2023-46604",
        "name": "Apache ActiveMQ OpenWire Protocol Remote Code Execution",
        "desc": "Apache ActiveMQ allows unauthenticated remote attackers to execute arbitrary shell commands via ClassPathXmlApplicationContext.",
        "sol": "Upgrade Apache ActiveMQ to 5.18.3, 5.17.6, or 5.16.7.",
        "risk": "Critical",
        "controls": "SC-7, SI-2",
        "kev": "Yes",
    },
]

ASSETS_POOLS = {
    "tenable": [f"10.100.10.{i}" for i in range(11, 31)] + [f"app-srv-{i:02d}.internal" for i in range(1, 21)],
    "qualys": [f"10.200.20.{i}" for i in range(11, 31)] + [f"db-node-{i:02d}.internal" for i in range(1, 21)],
    "inspector": [f"i-0a{i:08x}deadbeef" for i in range(10, 30)] + [f"arn:aws:ec2:us-east-1:123456789012:instance/i-{i:08x}" for i in range(30, 50)],
    "wiz": [f"vm-prod-workload-{i:02d}" for i in range(1, 21)] + [f"k8s-pod-auth-{i:02d}" for i in range(1, 21)],
}

MONTH_INFO = [
    ("MAR", "2026-03-12", "2026-03-25"),
    ("MAY", "2026-05-08", "2026-05-22"),
    ("JUL", "2026-07-10", "2026-07-28"),
    ("AUG", "2026-08-05", "2026-08-20"),
    ("OCT", "2026-10-02", "2026-10-18"),
]


def generate_all_datasets():
    print("[*] Generating synthetic compliance datasets for Live Demo...")
    today = ts.parse_any_date("2026-11-02")
    kev_db = ts.load_cisa_kev_catalog()

    previous_poam_entries = []

    tenable_all_rows = []
    qualys_all_rows = []
    inspector_all_rows = []
    wiz_all_rows = []

    poam_seq = 1

    # 1. Build the 80 Matched Scan Rows across the 4 scanners:
    # 40 Tenable, 20 Qualys, 10 Inspector, 10 Wiz
    # We build the scan rows FIRST, normalize them with their adapter, and then create
    # the matching POAM entry using the exact parsed fields!

    # 1a. Tenable 40 matched rows
    for i in range(40):
        v_idx = i % len(VULN_CATALOG)
        v = VULN_CATALOG[v_idx]
        plugin_id = str(170000 + i * 10)
        asset = ASSETS_POOLS["tenable"][i % len(ASSETS_POOLS["tenable"])]
        month_idx = i // 8  # 5 groups of 8 = 40 items across 5 months
        month_abbr, det_date_early, det_date_late = MONTH_INFO[month_idx]
        det_date = det_date_early if (i % 2 == 0) else det_date_late

        scan_row = {
            "Plugin ID": plugin_id,
            "CVE": v["cve"],
            "CVSS v3.0 Base Score": "9.8" if v["risk"] == "Critical" else ("8.2" if v["risk"] == "High" else "6.5"),
            "Risk": v["risk"],
            "Host": asset,
            "Protocol": "tcp",
            "Port": "22",
            "Name": f"{v['name']} [Tenable #{plugin_id}]",
            "Synopsis": "",
            "Description": f"{v['desc']} Remediation required to comply with FedRAMP High SLA guidelines.",
            "Solution": v["sol"],
            "See Also": f"https://nvd.nist.gov/vuln/detail/{v['cve']}",
            "First Discovered": det_date,
            "Last Observed": "2026-11-01",
            "Plugin Output": f"Service check on {asset}:22 confirmed vulnerability state.",
            "CISA KEV": v["kev"],
        }
        tenable_all_rows.append(scan_row)

        parsed = ts.TenableAdapter.parse_row(scan_row, {k.lower().strip(): v for k, v in scan_row.items()}, today, kev_db, False)
        pid = f"2026-{month_abbr}-{poam_seq:05d}"
        poam_seq += 1

        poam_entry = {
            "poam_id": pid,
            "controls": v["controls"],
            "weakness_name": parsed["name"],
            "weakness_description": parsed["full_desc"],
            "detector_source": parsed["detector_source"],
            "source_identifier": parsed["source_id"],
            "asset_identifier": parsed["asset_display"],
            "point_of_contact": "SecOps Linux Team",
            "resources_required": "Engineering",
            "remediation_plan": parsed["solution"],
            "original_detection_date": det_date,
            "scheduled_completion_date": ts.format_date_iso(ts.compute_sla_date(ts.parse_any_date(det_date), parsed["risk"])),
            "status_date": "2026-10-31",
            "vendor_dependency": "No",
            "last_vendor_checkin": "",
            "vendor_product_name": "",
            "original_risk_rating": parsed["risk"],
            "adjusted_risk_rating": "",
            "risk_adjustment": "No",
            "false_positive": "No",
            "operational_requirement": "No",
            "deviation_rationale": "",
            "supporting_documents": "tenable_vulnerability_report.xlsx",
            "comments": f"Historical POA&M tracking item from {month_abbr} 2026 cycle.",
            "bod_22_01_tracking": parsed["is_kev"],
            "bod_22_01_due_date": parsed["kev_due_str"],
            "cve": parsed["cves"],
        }
        previous_poam_entries.append(poam_entry)

    # 1b. Qualys 20 matched rows
    for i in range(20):
        v_idx = (i * 3 + 2) % len(VULN_CATALOG)
        v = VULN_CATALOG[v_idx]
        qid = str(380000 + i * 10)
        asset = ASSETS_POOLS["qualys"][i % len(ASSETS_POOLS["qualys"])]
        month_idx = i // 4  # 5 groups of 4 = 20 items across 5 months
        month_abbr, det_date_early, det_date_late = MONTH_INFO[month_idx]
        det_date = det_date_early if (i % 2 == 0) else det_date_late

        scan_row = {
            "QID": qid,
            "Title": f"{v['name']} [Qualys QID {qid}]",
            "Severity": "5" if v["risk"] == "Critical" else ("4" if v["risk"] == "High" else "3"),
            "IP": asset,
            "DNS": f"{asset.replace('.', '-')}.internal",
            "NetBIOS": "CORP-NODE",
            "OS": "Linux 5.15 RHEL-compatible",
            "Port": "443",
            "Protocol": "TCP",
            "Type": "Vuln",
            "Status": "Active",
            "First Detected": det_date,
            "Last Detected": "2026-11-01",
            "Times Detected": "12",
            "CVE ID": v["cve"],
            "Vendor Reference": "RHSA-2024:1092",
            "CVSS3.1 Base": "9.1",
            "Threat": f"{v['desc']} Impact: Remote unauthorized access or privilege elevation.",
            "Impact": "",
            "Solution": v["sol"],
            "Results": f"Qualys detected vulnerable software package during credentialed check on {asset}.",
        }
        qualys_all_rows.append(scan_row)

        parsed = ts.QualysAdapter.parse_row(scan_row, {k.lower().strip(): v for k, v in scan_row.items()}, today, kev_db, False)
        pid = f"2026-{month_abbr}-{poam_seq:05d}"
        poam_seq += 1

        poam_entry = {
            "poam_id": pid,
            "controls": v["controls"],
            "weakness_name": parsed["name"],
            "weakness_description": parsed["full_desc"],
            "detector_source": parsed["detector_source"],
            "source_identifier": parsed["source_id"],
            "asset_identifier": parsed["asset_display"],
            "point_of_contact": "Infrastructure Security Team",
            "resources_required": "DevOps",
            "remediation_plan": parsed["solution"],
            "original_detection_date": det_date,
            "scheduled_completion_date": ts.format_date_iso(ts.compute_sla_date(ts.parse_any_date(det_date), parsed["risk"])),
            "status_date": "2026-10-31",
            "vendor_dependency": "No",
            "last_vendor_checkin": "",
            "vendor_product_name": "",
            "original_risk_rating": parsed["risk"],
            "adjusted_risk_rating": "",
            "risk_adjustment": "No",
            "false_positive": "No",
            "operational_requirement": "No",
            "deviation_rationale": "",
            "supporting_documents": "qualys_vulnerability_report.xlsx",
            "comments": f"Historical POA&M tracking item from {month_abbr} 2026 cycle.",
            "bod_22_01_tracking": parsed["is_kev"],
            "bod_22_01_due_date": parsed["kev_due_str"],
            "cve": parsed["cves"],
        }
        previous_poam_entries.append(poam_entry)

    # 1c. AWS Inspector 10 matched rows
    for i in range(10):
        v_idx = (i * 7 + 1) % len(VULN_CATALOG)
        v = VULN_CATALOG[v_idx]
        vuln_id = v["cve"]
        asset = ASSETS_POOLS["inspector"][i % len(ASSETS_POOLS["inspector"])]
        month_idx = i // 2  # 5 groups of 2 = 10 items across 5 months
        month_abbr, det_date_early, det_date_late = MONTH_INFO[month_idx]
        det_date = det_date_early
        arn = f"arn:aws:inspector2:us-east-1:123456789012:finding/insp-match-{i+1:04d}"

        scan_row = {
            "Finding ARN": arn,
            "Vulnerability ID": vuln_id,
            "Title": f"{v['name']} [Inspector {vuln_id}]",
            "Severity": v["risk"],
            "Resource ID": asset,
            "Resource Type": "AWS::EC2::Instance",
            "AWS Account ID": "123456789012",
            "Description": v["desc"],
            "Remediation": v["sol"],
            "Fix Available": "YES",
            "Package Name": "openssl-libs",
            "File Path": "/usr/lib64/libssl.so.3",
            "Package Manager": "RPM",
            "Vendor Advisory": f"https://explore.alas.aws.amazon.com/CVE/{vuln_id}.html",
            "First Observed At": det_date,
            "Last Observed At": "2026-11-01",
            "CVE": vuln_id,
        }
        inspector_all_rows.append(scan_row)

        parsed = ts.InspectorAdapter.parse_row(scan_row, {k.lower().strip(): v for k, v in scan_row.items()}, today, kev_db, False)
        pid = f"2026-{month_abbr}-{poam_seq:05d}"
        poam_seq += 1

        poam_entry = {
            "poam_id": pid,
            "controls": v["controls"],
            "weakness_name": parsed["name"],
            "weakness_description": parsed["full_desc"],
            "detector_source": parsed["detector_source"],
            "source_identifier": parsed["source_id"],
            "asset_identifier": parsed["asset_display"],
            "point_of_contact": "Cloud Platform Team",
            "resources_required": "CloudOps",
            "remediation_plan": parsed["solution"],
            "original_detection_date": det_date,
            "scheduled_completion_date": ts.format_date_iso(ts.compute_sla_date(ts.parse_any_date(det_date), parsed["risk"])),
            "status_date": "2026-10-31",
            "vendor_dependency": "No",
            "last_vendor_checkin": "",
            "vendor_product_name": "",
            "original_risk_rating": parsed["risk"],
            "adjusted_risk_rating": "",
            "risk_adjustment": "No",
            "false_positive": "No",
            "operational_requirement": "No",
            "deviation_rationale": "",
            "supporting_documents": "aws_inspector_report.xlsx",
            "comments": f"Historical POA&M tracking item from {month_abbr} 2026 cycle.",
            "bod_22_01_tracking": parsed["is_kev"],
            "bod_22_01_due_date": parsed["kev_due_str"],
            "cve": parsed["cves"],
        }
        previous_poam_entries.append(poam_entry)

    # 1d. Wiz 10 matched rows
    for i in range(10):
        v_idx = (i * 11 + 3) % len(VULN_CATALOG)
        v = VULN_CATALOG[v_idx]
        wiz_id = f"WIZ-{v['cve']}"
        asset = ASSETS_POOLS["wiz"][i % len(ASSETS_POOLS["wiz"])]
        month_idx = i // 2  # 5 groups of 2 = 10 items across 5 months
        month_abbr, det_date_early, det_date_late = MONTH_INFO[month_idx]
        det_date = det_date_early

        scan_row = {
            "Wiz ID": wiz_id,
            "Vulnerability ID": wiz_id,
            "Name": f"{v['name']} [Wiz Finding]",
            "Severity": v["risk"],
            "Asset Name": asset,
            "Asset Type": "VirtualMachine",
            "Project Name": "Production Enclave",
            "Resource ID": f"res-{asset}",
            "IP": f"10.150.10.{i+10}",
            "Description": v["desc"],
            "Remediation": v["sol"],
            "Fix Available": "YES",
            "Package Name": "containerd",
            "Fixed Version": "1.7.13",
            "Reference URLs": f"https://www.wiz.io/vulnerability-database/{v['cve']}",
            "First Detected": det_date,
            "Last Detected": "2026-11-01",
            "CVE": v["cve"],
        }
        wiz_all_rows.append(scan_row)

        parsed = ts.WizAdapter.parse_row(scan_row, {k.lower().strip(): v for k, v in scan_row.items()}, today, kev_db, False)
        pid = f"2026-{month_abbr}-{poam_seq:05d}"
        poam_seq += 1

        poam_entry = {
            "poam_id": pid,
            "controls": v["controls"],
            "weakness_name": parsed["name"],
            "weakness_description": parsed["full_desc"],
            "detector_source": parsed["detector_source"],
            "source_identifier": parsed["source_id"],
            "asset_identifier": parsed["asset_display"],
            "point_of_contact": "Cloud Security SecOps",
            "resources_required": "Platform Engineering",
            "remediation_plan": parsed["solution"],
            "original_detection_date": det_date,
            "scheduled_completion_date": ts.format_date_iso(ts.compute_sla_date(ts.parse_any_date(det_date), parsed["risk"])),
            "status_date": "2026-10-31",
            "vendor_dependency": "No",
            "last_vendor_checkin": "",
            "vendor_product_name": "",
            "original_risk_rating": parsed["risk"],
            "adjusted_risk_rating": "",
            "risk_adjustment": "No",
            "false_positive": "No",
            "operational_requirement": "No",
            "deviation_rationale": "",
            "supporting_documents": "wiz_vulnerability_report.xlsx",
            "comments": f"Historical POA&M tracking item from {month_abbr} 2026 cycle.",
            "bod_22_01_tracking": parsed["is_kev"],
            "bod_22_01_due_date": parsed["kev_due_str"],
            "cve": parsed["cves"],
        }
        previous_poam_entries.append(poam_entry)

    assert len(previous_poam_entries) == 80, f"Expected 80 matched entries, got {len(previous_poam_entries)}"

    # 2. Build 80 CLOSED entries for Previous POAM:
    # 5 months x 16 items = 80 closed items.
    # Distributed across the 5 months:
    closed_sources = [
        ("Tenable Nessus", "tenable", "180"),
        ("Qualys VMDR", "qualys", "390"),
        ("AWS Inspector", "inspector", "ALAS2023-"),
        ("Wiz", "wiz", "WIZ-HIST-"),
    ]

    for month_idx, (month_abbr, det_date_early, det_date_late) in enumerate(MONTH_INFO):
        # 16 closed per month: 4 per source
        for src_label, pool_key, id_pfx in closed_sources:
            for j in range(4):
                c_idx = (poam_seq * 13 + j) % len(VULN_CATALOG)
                v = VULN_CATALOG[c_idx]
                pid = f"2026-{month_abbr}-{poam_seq:05d}"
                poam_seq += 1
                asset = ASSETS_POOLS[pool_key][(j + poam_seq) % len(ASSETS_POOLS[pool_key])]
                src_id = f"{id_pfx}{poam_seq:04d}"
                det_date = det_date_early
                sla_date = ts.format_date_iso(ts.compute_sla_date(ts.parse_any_date(det_date), v["risk"]))
                w_name = f"Remediated: {v['name']} [Audit Check #{poam_seq}]"
                w_desc = f"Historical remediation verified: {v['desc']}"

                poam_entry = {
                    "poam_id": pid,
                    "controls": v["controls"],
                    "weakness_name": w_name,
                    "weakness_description": w_desc,
                    "detector_source": src_label,
                    "source_identifier": src_id,
                    "asset_identifier": asset,
                    "point_of_contact": "FedRAMP Security Engineering",
                    "resources_required": "SecOps",
                    "remediation_plan": "Security patch applied and verified remediated during validation cycle.",
                    "original_detection_date": det_date,
                    "scheduled_completion_date": sla_date,
                    "status_date": "2026-10-31",
                    "vendor_dependency": "No",
                    "last_vendor_checkin": "",
                    "vendor_product_name": "",
                    "original_risk_rating": v["risk"],
                    "adjusted_risk_rating": "",
                    "risk_adjustment": "No",
                    "false_positive": "No",
                    "operational_requirement": "No",
                    "deviation_rationale": "",
                    "supporting_documents": "historical_remediation_audit.xlsx",
                    "comments": f"Historical item from {month_abbr} 2026. Successfully resolved by systems engineering.",
                    "bod_22_01_tracking": "No",
                    "bod_22_01_due_date": "",
                    "cve": v["cve"],
                }
                previous_poam_entries.append(poam_entry)

    assert len(previous_poam_entries) == 160, f"Expected 160 previous POAM entries, got {len(previous_poam_entries)}"

    # Sort previous POAM entries by POAM ID ascending (2026-MAR-00001 .. 2026-OCT-00160)
    previous_poam_entries.sort(key=lambda x: x["poam_id"])

    # 3. Add 40 NEW Tenable scan rows (Total = 40 + 40 = 80):
    for i in range(40):
        v_idx = (i * 3 + 1) % len(VULN_CATALOG)
        v = VULN_CATALOG[v_idx]
        plugin_id = str(200500 + i)
        asset = ASSETS_POOLS["tenable"][(i + 5) % len(ASSETS_POOLS["tenable"])]
        cve = v["cve"]
        det_date = "2026-10-25" if i % 2 == 0 else "2026-10-30"
        tenable_all_rows.append({
            "Plugin ID": plugin_id,
            "CVE": cve,
            "CVSS v3.0 Base Score": "9.8" if v["risk"] == "Critical" else ("7.8" if v["risk"] == "High" else "5.3"),
            "Risk": v["risk"],
            "Host": asset,
            "Protocol": "tcp",
            "Port": "443" if i % 2 == 0 else "22",
            "Name": f"Newly Detected: {v['name']} [Scan #{i+1:02d}]",
            "Synopsis": "",
            "Description": f"New scan cycle confirmed: {v['desc']}",
            "Solution": v["sol"],
            "See Also": f"https://nvd.nist.gov/vuln/detail/{cve}",
            "First Discovered": det_date,
            "Last Observed": "2026-11-01",
            "Plugin Output": f"Credentialed packet audit confirmed vulnerable package on {asset}.",
            "CISA KEV": v["kev"],
        })
    assert len(tenable_all_rows) == 80

    # 4. Add 10 NEW Qualys scan rows (Total = 20 + 10 = 30):
    for i in range(10):
        v_idx = (i * 5 + 2) % len(VULN_CATALOG)
        v = VULN_CATALOG[v_idx]
        qid = str(450100 + i)
        asset = ASSETS_POOLS["qualys"][(i + 3) % len(ASSETS_POOLS["qualys"])]
        cve = v["cve"]
        det_date = "2026-10-26" if i % 2 == 0 else "2026-10-31"
        qualys_all_rows.append({
            "QID": qid,
            "Title": f"Newly Detected: {v['name']} [Qualys #{i+1:02d}]",
            "Severity": "5" if v["risk"] == "Critical" else ("4" if v["risk"] == "High" else "3"),
            "IP": asset,
            "DNS": f"{asset.replace('.', '-')}.internal",
            "NetBIOS": "CORP-DB",
            "OS": "Linux 5.15 RHEL-compatible",
            "Port": "5432" if i % 2 == 0 else "443",
            "Protocol": "TCP",
            "Type": "Vuln",
            "Status": "Active",
            "First Detected": det_date,
            "Last Detected": "2026-11-01",
            "Times Detected": "3",
            "CVE ID": cve,
            "Vendor Reference": "RHSA-2024:8812",
            "CVSS3.1 Base": "8.8",
            "Threat": f"New scan finding: {v['desc']}",
            "Impact": "",
            "Solution": v["sol"],
            "Results": f"Qualys sensor check detected unpatched daemon on {asset}.",
        })
    assert len(qualys_all_rows) == 30

    # 5. Add 140 NEW AWS Inspector scan rows (Total = 10 + 140 = 150):
    for i in range(140):
        v_idx = (i * 7 + 3) % len(VULN_CATALOG)
        v = VULN_CATALOG[v_idx]
        vuln_id = f"CVE-2024-{1000 + i}"
        arn = f"arn:aws:inspector2:us-east-1:123456789012:finding/insp-new-{i+1:04d}"
        asset = ASSETS_POOLS["inspector"][(i + 2) % len(ASSETS_POOLS["inspector"])]
        det_date = "2026-10-20" if i % 3 == 0 else ("2026-10-28" if i % 3 == 1 else "2026-11-01")
        inspector_all_rows.append({
            "Finding ARN": arn,
            "Vulnerability ID": vuln_id,
            "Title": f"Newly Detected: {v['name']} [Item #{i+1:03d}]",
            "Severity": v["risk"],
            "Resource ID": asset,
            "Resource Type": "AWS::EC2::Instance" if "instance" in asset or asset.startswith("i-") else "AWS::Lambda::Function",
            "AWS Account ID": "123456789012",
            "Description": f"Amazon Inspector detected vulnerability in container layer/AMI: {v['desc']}",
            "Remediation": v["sol"],
            "Fix Available": "YES" if i % 5 != 0 else "NO",
            "Package Name": "kernel-core" if i % 2 == 0 else "glibc-common",
            "File Path": "/usr/lib64/libc.so.6",
            "Package Manager": "RPM",
            "Vendor Advisory": f"https://explore.alas.aws.amazon.com/CVE/{vuln_id}.html",
            "First Observed At": det_date,
            "Last Observed At": "2026-11-01",
            "CVE": vuln_id,
        })
    assert len(inspector_all_rows) == 150

    # 6. Add 60 NEW Wiz scan rows (Total = 10 + 60 = 70):
    for i in range(60):
        v_idx = (i * 11 + 4) % len(VULN_CATALOG)
        v = VULN_CATALOG[v_idx]
        vuln_id = f"WIZ-CVE-2024-{2000 + i}"
        asset = ASSETS_POOLS["wiz"][(i + 4) % len(ASSETS_POOLS["wiz"])]
        cve = f"CVE-2024-{2000 + i}"
        det_date = "2026-10-22" if i % 2 == 0 else "2026-10-29"
        wiz_all_rows.append({
            "Wiz ID": vuln_id,
            "Vulnerability ID": vuln_id,
            "Name": f"Newly Detected: {v['name']} [Wiz Finding #{i+1:02d}]",
            "Severity": v["risk"],
            "Asset Name": asset,
            "Asset Type": "VirtualMachine" if "workload" in asset else "KubernetesPod",
            "Project Name": "Production Enclave",
            "Resource ID": f"res-{asset}",
            "IP": f"10.150.20.{10 + (i % 50)}",
            "Description": f"Wiz agentless cloud scanner identified workload risk: {v['desc']}",
            "Remediation": v["sol"],
            "Fix Available": "YES",
            "Package Name": "openssl" if i % 2 == 0 else "curl",
            "Fixed Version": "3.0.12-r1",
            "Reference URLs": f"https://www.wiz.io/vulnerability-database/{cve}",
            "First Detected": det_date,
            "Last Detected": "2026-11-01",
            "CVE": cve,
        })
    assert len(wiz_all_rows) == 70

    print("  [✓] Verified exact dataset counts:")
    print(f"      • Previous POAM items: {len(previous_poam_entries)} (80 to stay open, 80 to move to closed)")
    print(f"      • Tenable report items: {len(tenable_all_rows)} (40 matched + 40 new)")
    print(f"      • Qualys report items: {len(qualys_all_rows)} (20 matched + 10 new)")
    print(f"      • AWS Inspector report items: {len(inspector_all_rows)} (10 matched + 140 new)")
    print(f"      • Wiz report items: {len(wiz_all_rows)} (10 matched + 60 new)")
    print(f"      • Total scan findings across all 4 reports: {len(tenable_all_rows) + len(qualys_all_rows) + len(inspector_all_rows) + len(wiz_all_rows)}")

    # 7. Write all 5 Excel workbooks to artifacts/drop-off/:
    out_poam_path = os.path.join(DROPOFF_DIR, "previous_open_poam.xlsx")
    out_tenable_path = os.path.join(DROPOFF_DIR, "tenable_vulnerability_report.xlsx")
    out_qualys_path = os.path.join(DROPOFF_DIR, "qualys_vulnerability_report.xlsx")
    out_inspector_path = os.path.join(DROPOFF_DIR, "aws_inspector_report.xlsx")
    out_wiz_path = os.path.join(DROPOFF_DIR, "wiz_vulnerability_report.xlsx")

    print(f"[*] Populating {out_poam_path} using attached 5-worksheet FedRAMP template...")
    ts.write_poam_workbook(
        template_path=TEMPLATE_PATH,
        output_path=out_poam_path,
        entries=previous_poam_entries,
        is_closed_template=False,
    )

    print(f"[*] Generating {out_tenable_path}...")
    create_xlsx(
        filepath=out_tenable_path,
        headers=list(tenable_all_rows[0].keys()),
        rows=tenable_all_rows,
        sheet_name="Tenable Vulnerabilities",
    )

    print(f"[*] Generating {out_qualys_path}...")
    create_xlsx(
        filepath=out_qualys_path,
        headers=list(qualys_all_rows[0].keys()),
        rows=qualys_all_rows,
        sheet_name="Qualys Vulnerabilities",
    )

    print(f"[*] Generating {out_inspector_path}...")
    create_xlsx(
        filepath=out_inspector_path,
        headers=list(inspector_all_rows[0].keys()),
        rows=inspector_all_rows,
        sheet_name="AWS Inspector Findings",
    )

    print(f"[*] Generating {out_wiz_path}...")
    create_xlsx(
        filepath=out_wiz_path,
        headers=list(wiz_all_rows[0].keys()),
        rows=wiz_all_rows,
        sheet_name="Wiz Workload Vulnerabilities",
    )

    # Mirror to GRC-xTEST/scans if directory exists
    if os.path.isdir(TEST_SCANS_DIR):
        print(f"[*] Mirroring all 5 datasets to {TEST_SCANS_DIR}...")
        for src_f in [out_poam_path, out_tenable_path, out_qualys_path, out_inspector_path, out_wiz_path]:
            dest_f = os.path.join(TEST_SCANS_DIR, os.path.basename(src_f))
            shutil.copy2(src_f, dest_f)

    print("\n[SUCCESS] Generated all 5 synthetic Excel workbooks!")


if __name__ == "__main__":
    generate_all_datasets()
