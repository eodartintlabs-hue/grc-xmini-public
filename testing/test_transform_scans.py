#!/usr/bin/env python3
"""
Unit Test Suite for GRCx (v1.3.4 — Sasebo) Scan-to-POA&M Transformation Engine
(scripts/transform_scans.py).

Validates compliance-critical invariants:
  1. Host-verified auto-closure vs. unscanned host retention (including Tenable Plugin 19506
     Informational rows and IP <-> DNS Name alias reconciliation).
  2. OpenXML namespace preservation (no ns0/ns1 corruption on mc:Ignorable, x14, x14ac, etc.),
     fullCalcOnLoad="1", dynamic worksheet relationship target resolution, and template round-trip.
  3. XML 1.0 illegal control-character sanitization and Excel 32,767-character cell truncation.
  4. Monotonic POA&M ID sequence across BOTH previous OPEN and CLOSED workbooks (no ID reuse),
     and prevention of duplicate POA&M IDs when backup weakness-name matching runs.
  5. Duplicate scan row merge recalculating _sla_date_obj and scheduled_completion_date.
  6. CISA KEV / BOD 22-01 tracking (ignoring generic 'Exploit Available = Yes' when not in KEV,
     honoring CISA KEV dueDate/dateAdded) and excluding 'Plugin Publication Date' from detection date.
  7. NIST 800-53 control inference fixes ('cbc' lowercase match, 'unencrypted' -> SC-28/SC-8).
"""

import datetime
import os
import sys
import tempfile
import unittest
from unittest import mock
import xml.etree.ElementTree as ET
import zipfile

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(REPO_ROOT, "scripts"))

import transform_scans as ts  # noqa: E402


class TestTransformScansEngine(unittest.TestCase):
    """Comprehensive tests for scripts/transform_scans.py compliance & OpenXML invariants."""

    def setUp(self) -> None:
        self.today = datetime.date(2026, 10, 29)
        self.open_template = os.path.join(REPO_ROOT, "templates", "OPEN FedRAMP-POAM-Template.xlsx")
        self.closed_template = os.path.join(REPO_ROOT, "templates", "CLOSED LEGACY FedRAMP-POAM-Template.xlsx")

    # -----------------------------------------------------------------------
    # 1. XML Sanitization & Column Letter Offset Generation
    # -----------------------------------------------------------------------

    def test_column_letters_generated_cleanly(self) -> None:
        self.assertEqual(ts.OPEN_COL_LETTERS[0], "A")
        self.assertEqual(ts.OPEN_COL_LETTERS[-1], "AA")
        self.assertEqual(len(ts.OPEN_COL_LETTERS), 27)
        self.assertEqual(ts.CLOSED_COL_LETTERS[0], "A")
        self.assertEqual(ts.CLOSED_COL_LETTERS[4], "E")
        self.assertEqual(ts.CLOSED_COL_LETTERS[-1], "AA")
        self.assertEqual(len(ts.CLOSED_COL_LETTERS), 27)

    def test_sanitize_excel_string_strips_control_chars_and_truncates(self) -> None:
        dirty = "Banner:\x00\x07\x0b\x1f SSH-2.0-OpenSSH_8.9\nLine2\tTabbed"
        cleaned = ts.sanitize_excel_string(dirty)
        self.assertNotIn("\x00", cleaned)
        self.assertNotIn("\x07", cleaned)
        self.assertNotIn("\x0b", cleaned)
        self.assertNotIn("\x1f", cleaned)
        self.assertIn("SSH-2.0-OpenSSH_8.9\nLine2\tTabbed", cleaned)

        oversized = "A" * 40000
        truncated = ts.sanitize_excel_string(oversized)
        self.assertEqual(len(truncated), ts.EXCEL_MAX_CELL_CHARS)
        self.assertTrue(truncated.endswith("... [truncated]"))

    # -----------------------------------------------------------------------
    # 2. NIST Control Mapping & Root-Relative Sheet Path Resolution
    # -----------------------------------------------------------------------

    def test_infer_nist_controls_cbc_and_unencrypted(self) -> None:
        # "CBC" in mixed/lowercase text must match SC-8, SC-13
        controls_cbc = ts.infer_nist_controls("SSH Weak CBC Mode Ciphers Enabled", "3des-cbc supported", "")
        self.assertIn("SC-8", controls_cbc)
        self.assertIn("SC-13", controls_cbc)

        # "unencrypted" must map to SC-28, SC-8 rather than CM-6
        controls_unenc = ts.infer_nist_controls("Unencrypted Telnet Channel", "Cleartext transmission", "")
        self.assertIn("SC-28", controls_unenc)
        self.assertIn("SC-8", controls_unenc)

    def test_resolve_sheet_path_handles_leading_slash(self) -> None:
        with zipfile.ZipFile(self.open_template, "r") as zf:
            path = ts.resolve_sheet_path(zf, sheet_index=0)
            self.assertEqual(path, "xl/worksheets/sheet1.xml")

    # -----------------------------------------------------------------------
    # 3. Detection Date, Duplicate Scan Merge SLA Update & CISA KEV / BOD 22-01
    # -----------------------------------------------------------------------

    def test_plugin_publication_date_excluded_from_detection_date(self) -> None:
        records = [
            {
                "Plugin ID": "99999",
                "CVE": "CVE-2024-9999",
                "Risk": "High",
                "Host": "10.0.0.5",
                "Port": "443",
                "Protocol": "tcp",
                "Name": "Sample High Vulnerability",
                "Plugin Publication Date": "2018-01-01",
                "Last Observed": "2026-10-15",
            }
        ]
        entries = ts.normalize_scan_rows(
            records=records,
            scanner_type="tenable",
            scan_filename="scan.csv",
            today=self.today,
            default_poc="SecOps",
            kev_catalog={},
        )
        self.assertEqual(len(entries), 1)
        # Must use Last Observed (2026-10-15), NOT Plugin Publication Date (2018-01-01)
        self.assertEqual(entries[0]["original_detection_date"], "2026-10-15")

    def test_duplicate_scan_merge_recomputes_sla_date(self) -> None:
        records = [
            {
                "Plugin ID": "55555",
                "CVE": "CVE-2025-1111",
                "Risk": "Moderate",
                "Host": "10.0.0.10",
                "Port": "80",
                "Protocol": "tcp",
                "Name": "Multi-Port Service Vuln",
                "First Discovered": "2026-10-01",
            },
            {
                "Plugin ID": "55555",
                "CVE": "CVE-2025-1111",
                "Risk": "High",
                "Host": "10.0.0.10",
                "Port": "443",
                "Protocol": "tcp",
                "Name": "Multi-Port Service Vuln",
                "First Discovered": "2026-09-01",
            },
        ]
        entries = ts.normalize_scan_rows(
            records=records,
            scanner_type="tenable",
            scan_filename="scan.csv",
            today=self.today,
            default_poc="SecOps",
            kev_catalog={},
        )
        self.assertEqual(len(entries), 1)
        merged = entries[0]
        # Earlier detection date (2026-09-01) + Higher risk (High = 30 days) => 2026-10-01
        self.assertEqual(merged["original_detection_date"], "2026-09-01")
        self.assertEqual(merged["original_risk_rating"], "High")
        self.assertEqual(merged["scheduled_completion_date"], "2026-10-01")
        self.assertEqual(merged["_sla_date_obj"], datetime.date(2026, 10, 1))

    def test_bod_22_01_ignores_generic_exploit_available_and_uses_kev_catalog(self) -> None:
        kev_catalog = {
            "CVE-2024-6387": {
                "cveID": "CVE-2024-6387",
                "dateAdded": "2024-07-09",
                "dueDate": "2024-07-30",
            }
        }
        records = [
            {
                "Plugin ID": "10001",
                "CVE": "CVE-2024-0001",
                "Risk": "High",
                "Host": "10.0.0.1",
                "Name": "Non-KEV Exploit Available Vuln",
                "Exploit Available": "Yes",
                "First Discovered": "2026-10-01",
            },
            {
                "Plugin ID": "192814",
                "CVE": "CVE-2024-6387",
                "Risk": "High",
                "Host": "10.0.0.2",
                "Name": "OpenSSH RegreSSHion",
                "Exploit Available": "Yes",
                "First Discovered": "2026-10-01",
            },
        ]
        entries = ts.normalize_scan_rows(
            records=records,
            scanner_type="tenable",
            scan_filename="scan.csv",
            today=self.today,
            default_poc="SecOps",
            kev_catalog=kev_catalog,
        )
        by_cve = {e["cve"]: e for e in entries}
        # Generic Exploit Available = Yes without KEV membership must NOT trigger BOD 22-01
        self.assertEqual(by_cve["CVE-2024-0001"]["bod_22_01_tracking"], "")
        self.assertEqual(by_cve["CVE-2024-0001"]["bod_22_01_due_date"], "")

        # CISA KEV catalog match sets BOD 22-01 Tracking = Yes and uses official KEV dueDate
        self.assertEqual(by_cve["CVE-2024-6387"]["bod_22_01_tracking"], "Yes")
        self.assertEqual(by_cve["CVE-2024-6387"]["bod_22_01_due_date"], "2024-07-30")

    # -----------------------------------------------------------------------
    # 4. Reconciliation: Host-Verified Closure, IP/DNS Aliasing & POA&M ID Uniqueness
    # -----------------------------------------------------------------------

    def test_unscanned_host_stays_open_while_scanned_host_closes(self) -> None:
        # Previous OPEN has 2 items:
        #   - POAM-2026-0001 on 10.42.10.25 (which appears in new scan via Plugin 19506 Info row)
        #   - POAM-2026-0002 on 10.42.10.99 (which was offline / not scanned at all)
        prev_open = [
            {
                "poam_id": "POAM-2026-0001",
                "controls": "SC-8",
                "weakness_name": "Deprecated SSH KEX",
                "weakness_description": "Weak KEX",
                "weakness_detector_source": "Tenable Nessus",
                "source_identifier": "153953",
                "asset_identifier": "10.42.10.25 (22/TCP)",
                "original_risk_rating": "Moderate",
                "original_detection_date": "2026-08-01",
                "scheduled_completion_date": "2026-10-30",
                "overall_poam_status": "Ongoing",
                "status_date": "2026-09-01",
                "comments": "",
                "_det_date_obj": datetime.date(2026, 8, 1),
                "_sla_date_obj": datetime.date(2026, 10, 30),
                "_dedup_key": ("153953", "10.42.10.25"),
            },
            {
                "poam_id": "POAM-2026-0002",
                "controls": "SI-2",
                "weakness_name": "Offline Host Patch Missing",
                "weakness_description": "Missing patch on offline host",
                "weakness_detector_source": "Tenable Nessus",
                "source_identifier": "188888",
                "asset_identifier": "10.42.10.99 (443/TCP)",
                "original_risk_rating": "High",
                "original_detection_date": "2026-08-01",
                "scheduled_completion_date": "2026-08-31",
                "overall_poam_status": "Ongoing",
                "status_date": "2026-09-01",
                "comments": "",
                "_det_date_obj": datetime.date(2026, 8, 1),
                "_sla_date_obj": datetime.date(2026, 8, 31),
                "_dedup_key": ("188888", "10.42.10.99"),
            },
        ]

        # New scan has only Plugin 19506 (Info) for 10.42.10.25 and a new finding on 10.42.10.14
        raw_records = [
            {
                "Plugin ID": "19506",
                "Risk": "None",
                "Host": "10.42.10.25",
                "Port": "0",
                "Protocol": "tcp",
                "Name": "Nessus Scan Information",
            },
            {
                "Plugin ID": "176402",
                "CVE": "CVE-2023-38408",
                "Risk": "Critical",
                "Host": "10.42.10.14",
                "Port": "22",
                "Protocol": "tcp",
                "Name": "OpenSSH RCE",
                "First Discovered": "2026-10-01",
            },
        ]
        scanned_assets, alias_map = ts.collect_scanned_assets(raw_records)
        new_scan_entries = ts.normalize_scan_rows(
            records=raw_records,
            scanner_type="tenable",
            scan_filename="scan.csv",
            today=self.today,
            default_poc="SecOps",
            kev_catalog={},
        )

        # Also pass a previous CLOSED entry with POAM-2026-0010 to verify monotonic ID numbering
        prev_closed = [{"poam_id": "POAM-2026-0010"}]

        final_open, newly_closed, stats = ts.reconcile_poam_entries(
            prev_open_entries=prev_open,
            new_scan_entries=new_scan_entries,
            today=self.today,
            prev_closed_entries=prev_closed,
            scanned_assets=scanned_assets,
            asset_alias_map=alias_map,
            close_unscanned_hosts=False,
        )

        # 10.42.10.25 was scanned (Plugin 19506) and finding 153953 is gone -> moved to CLOSED
        self.assertEqual(len(newly_closed), 1)
        self.assertEqual(newly_closed[0]["poam_id"], "POAM-2026-0001")

        # 10.42.10.99 was NOT scanned -> retained in OPEN with _unverified_host flag
        open_by_id = {e["poam_id"]: e for e in final_open}
        self.assertIn("POAM-2026-0002", open_by_id)
        self.assertTrue(open_by_id["POAM-2026-0002"].get("_unverified_host"))
        self.assertIn("was not observed in the latest scan", open_by_id["POAM-2026-0002"]["comments"])
        self.assertEqual(stats["unverified_unscanned_open"], 1)

        # New finding on 10.42.10.14 must receive 2026-OCT-00011 (continuing past CLOSED POAM-2026-0010)
        self.assertIn("2026-OCT-00011", open_by_id)

    def test_ip_to_dns_alias_reconciles_and_backup_name_match_does_not_duplicate_ids(self) -> None:
        # Previous OPEN has POAM-2026-0001 tracked by IP 10.42.10.50 without source_identifier
        prev_open = [
            {
                "poam_id": "POAM-2026-0001",
                "controls": "SC-8",
                "weakness_name": "TLS Weak Cipher Suite",
                "weakness_description": "Weak cipher",
                "weakness_detector_source": "Tenable Nessus",
                "source_identifier": "OLD-ID-1",
                "asset_identifier": "10.42.10.50 (443/TCP)",
                "original_risk_rating": "Moderate",
                "original_detection_date": "2026-08-01",
                "scheduled_completion_date": "2026-10-30",
                "overall_poam_status": "Ongoing",
                "status_date": "2026-09-01",
                "comments": "",
                "_det_date_obj": datetime.date(2026, 8, 1),
                "_sla_date_obj": datetime.date(2026, 10, 30),
                "_dedup_key": ("old-id-1", "10.42.10.50"),
            }
        ]
        # New scan lists two distinct plugins with the same weakness name on DNS alias app01.internal (IP 10.42.10.50)
        raw_records = [
            {
                "Plugin ID": "20001",
                "Risk": "Moderate",
                "Host": "app01.internal",
                "IP Address": "10.42.10.50",
                "DNS Name": "app01.internal",
                "Port": "443",
                "Protocol": "tcp",
                "Name": "TLS Weak Cipher Suite",
                "First Discovered": "2026-10-01",
            },
            {
                "Plugin ID": "20002",
                "Risk": "Moderate",
                "Host": "app01.internal",
                "IP Address": "10.42.10.50",
                "DNS Name": "app01.internal",
                "Port": "8443",
                "Protocol": "tcp",
                "Name": "TLS Weak Cipher Suite",
                "First Discovered": "2026-10-01",
            },
        ]
        scanned_assets, alias_map = ts.collect_scanned_assets(raw_records)
        new_scan_entries = ts.normalize_scan_rows(
            records=raw_records,
            scanner_type="tenable",
            scan_filename="scan.csv",
            today=self.today,
            default_poc="SecOps",
            kev_catalog={},
        )
        final_open, newly_closed, _ = ts.reconcile_poam_entries(
            prev_open_entries=prev_open,
            new_scan_entries=new_scan_entries,
            today=self.today,
            scanned_assets=scanned_assets,
            asset_alias_map=alias_map,
        )
        self.assertEqual(len(newly_closed), 0)
        self.assertEqual(len(final_open), 2)
        poam_ids = [e["poam_id"] for e in final_open]
        # Must NOT assign duplicate IDs! One carries over POAM-2026-0001, second gets 2026-OCT-00002.
        self.assertEqual(sorted(poam_ids), ["2026-OCT-00002", "POAM-2026-0001"])

    def test_poam_id_dynamic_nomenclature_year_month_sequence(self) -> None:
        """Verify dynamic FedRAMP POA&M ID nomenclature YYYY-MMM-##### (e.g. 2026-SEP-00347)."""
        # Test direct format helper
        sept_date = datetime.date(2026, 9, 15)
        self.assertEqual(ts.format_poam_id(sept_date, 347), "2026-SEP-00347")
        self.assertEqual(ts.format_poam_id(sept_date, 1), "2026-SEP-00001")

        oct_date = datetime.date(2026, 10, 31)
        self.assertEqual(ts.format_poam_id(oct_date, 1), "2026-OCT-00001")
        self.assertEqual(ts.format_poam_id(oct_date, 99999), "2026-OCT-99999")

        # Test reconciliation baseline assigns YYYY-MMM-00001, 00002, etc.
        raw_records = [
            {
                "Plugin ID": "10001",
                "CVE": "CVE-2026-1111",
                "Risk": "High",
                "Host": "10.0.0.1",
                "Name": "Finding 1",
            },
            {
                "Plugin ID": "10002",
                "CVE": "CVE-2026-2222",
                "Risk": "Critical",
                "Host": "10.0.0.2",
                "Name": "Finding 2",
            },
        ]
        scanned_assets, alias_map = ts.collect_scanned_assets(raw_records)
        new_scan_entries = ts.normalize_scan_rows(
            records=raw_records,
            scanner_type="tenable",
            scan_filename="scan.csv",
            today=sept_date,
            default_poc="SecOps",
            kev_catalog={},
        )
        final_open, _, _ = ts.reconcile_poam_entries(
            prev_open_entries=[],
            new_scan_entries=new_scan_entries,
            today=sept_date,
            scanned_assets=scanned_assets,
            asset_alias_map=alias_map,
        )
        ids = [e["poam_id"] for e in final_open]
        self.assertEqual(ids, ["2026-SEP-00001", "2026-SEP-00002"])

        # Test continuing past existing YYYY-MMM-##### in previous closed workbook
        prev_closed = [{"poam_id": "2026-SEP-00346"}]
        final_open_cont, _, _ = ts.reconcile_poam_entries(
            prev_open_entries=[],
            new_scan_entries=new_scan_entries,
            today=sept_date,
            prev_closed_entries=prev_closed,
            scanned_assets=scanned_assets,
            asset_alias_map=alias_map,
        )
        ids_cont = [e["poam_id"] for e in final_open_cont]
        self.assertEqual(ids_cont, ["2026-SEP-00347", "2026-SEP-00348"])

    # -----------------------------------------------------------------------
    # 5. OpenXML Template Round-Trip, Namespace Preservation & fullCalcOnLoad
    # -----------------------------------------------------------------------

    def test_xlsx_round_trip_preserves_namespaces_and_sanitizes_control_chars(self) -> None:
        sample_entry = {
            "poam_id": "POAM-2026-0001",
            "controls": "IA-2, SC-8",
            "weakness_name": "OpenSSH RCE\x00\x07",
            "weakness_description": "Control chars \x1b\x02 stripped safely",
            "weakness_detector_source": "Tenable Nessus",
            "source_identifier": "176402 (CVE-2023-38408)",
            "asset_identifier": "10.42.10.14 (22/TCP)",
            "point_of_contact": "Cloud Security Team",
            "resources_required": "Standard Engineering Allocation",
            "remediation_plan": "1. Apply vendor patch.\n2. Re-scan.",
            "original_detection_date": "2026-08-05",
            "scheduled_completion_date": "2026-09-04",
            "planned_milestones": "2026-09-04: Patch and verify.",
            "milestone_changes": "None",
            "status_date": "2026-10-29",
            "vendor_dependency": "No",
            "last_vendor_checkin": "",
            "vendor_product_name": "OpenSSH",
            "original_risk_rating": "Critical",
            "adjusted_risk_rating": "",
            "risk_adjustment": "No",
            "false_positive": "No",
            "operational_requirement": "No",
            "deviation_rationale": "",
            "supporting_documents": "scan.csv",
            "comments": "Verified clean XML output.",
            "auto_approve": "No",
            "bod_22_01_tracking": "Yes",
            "bod_22_01_due_date": "2026-08-19",
        }

        with tempfile.TemporaryDirectory() as tmpdir:
            out_xlsx = os.path.join(tmpdir, "OPEN FedRAMP-POAM.xlsx")
            ts.write_poam_workbook(
                template_path=self.open_template,
                output_path=out_xlsx,
                entries=[sample_entry],
                is_closed_template=False,
            )

            with zipfile.ZipFile(out_xlsx, "r") as zf:
                sheet_xml = zf.read("xl/worksheets/sheet1.xml").decode("utf-8")
                wb_xml = zf.read("xl/workbook.xml").decode("utf-8")

                # Verify no ns0 / ns1 namespace renaming occurred
                self.assertNotIn("ns0:", sheet_xml)
                self.assertNotIn("ns1:", sheet_xml)
                self.assertNotIn("xmlns:ns0", sheet_xml)
                # Verify original Ignorable prefixes remain declared on root
                self.assertIn("xmlns:mc=", sheet_xml)
                self.assertIn("xmlns:x14ac=", sheet_xml)
                # Verify fullCalcOnLoad="1" is set on workbook.xml
                self.assertIn('fullCalcOnLoad="1"', wb_xml)
                # Verify sheet XML and sharedStrings XML parse cleanly
                ET.fromstring(sheet_xml)
                ET.fromstring(zf.read("xl/sharedStrings.xml"))

            # Round-trip read back using load_existing_poam_workbook
            loaded = ts.load_existing_poam_workbook(out_xlsx, is_closed_template=False)
            self.assertEqual(len(loaded), 1)
            self.assertEqual(loaded[0]["poam_id"], "POAM-2026-0001")
            self.assertEqual(loaded[0]["weakness_name"], "OpenSSH RCE")
            self.assertEqual(loaded[0]["original_detection_date"], "2026-08-05")
            self.assertEqual(loaded[0]["bod_22_01_due_date"], "2026-08-19")

    # -----------------------------------------------------------------------
    # 6. Sample Scan Fixtures Verification (75 Tenable, 50 Inspector, 100 POA&M)
    # -----------------------------------------------------------------------

    def test_sample_scans_reconcile_expected_counts_and_id_conventions(self) -> None:
        sample_dir = os.path.join(REPO_ROOT, "testing", "sample-scans")
        prev_poam_path = os.path.join(sample_dir, "previous_open_poam.xlsx")
        tenable_path = os.path.join(sample_dir, "tenable_monthly_scan.csv")
        inspector_path = os.path.join(sample_dir, "aws_inspector_scan.csv")

        prev_open = ts.load_existing_poam_workbook(prev_poam_path, is_closed_template=False)
        self.assertEqual(len(prev_open), 100)
        for item in prev_open:
            self.assertRegex(str(item["poam_id"]), r"^(VULN|COMP|PENT)-\d{5}$")

        # Tenable: 75 rows across Info/Low/Medium/High/Critical -> closes 30 items
        t_records = ts.load_scan_records(tenable_path)
        self.assertEqual(len(t_records), 75)
        t_scanned, t_aliases = ts.collect_scanned_assets(t_records)
        t_entries = ts.normalize_scan_rows(t_records, "tenable", "tenable_monthly_scan.csv", self.today, "SecOps")
        _, t_closed, _ = ts.reconcile_poam_entries(
            prev_open_entries=prev_open,
            new_scan_entries=t_entries,
            today=self.today,
            scanned_assets=t_scanned,
            asset_alias_map=t_aliases,
        )
        self.assertEqual(len(t_closed), 30)

        # AWS Inspector: 50 rows across LOW/MEDIUM/HIGH/CRITICAL -> closes 14 items
        i_records = ts.load_scan_records(inspector_path)
        self.assertEqual(len(i_records), 50)
        i_scanned, i_aliases = ts.collect_scanned_assets(i_records)
        i_entries = ts.normalize_scan_rows(i_records, "inspector", "aws_inspector_scan.csv", self.today, "SecOps")
        _, i_closed, _ = ts.reconcile_poam_entries(
            prev_open_entries=prev_open,
            new_scan_entries=i_entries,
            today=self.today,
            scanned_assets=i_scanned,
            asset_alias_map=i_aliases,
        )
        self.assertEqual(len(i_closed), 14)

    # -----------------------------------------------------------------------
    # 7. Multi-Scan Transformation & Deduplication (Up to 5 Scans)
    # -----------------------------------------------------------------------

    def test_merge_scan_entries_deduplicates_and_preserves_earliest_date_highest_risk(self) -> None:
        """Verify merging entries across multiple scans preserves earliest detection date and highest risk."""
        scan1_entry = {
            "_dedup_key": ("tenable:12345", "10.0.0.1"),
            "_asset_aliases": {"10.0.0.1"},
            "_scanner_type": "tenable",
            "_raw_solution": "Patch package v1",
            "_see_also": "",
            "_det_date_obj": datetime.date(2026, 9, 1),
            "_sla_date_obj": datetime.date(2026, 11, 30),
            "_stat_date_obj": datetime.date(2026, 9, 1),
            "poam_id": "",
            "weakness_name": "OpenSSH Vulnerability",
            "weakness_description": "Vulnerable SSH service",
            "detector_source": "Tenable Network Security",
            "source_identifier": "12345",
            "asset_identifier": "10.0.0.1 (eth0)",
            "point_of_contact": "SecOps",
            "remediation_plan": "Patch package v1",
            "original_detection_date": "2026-09-01",
            "scheduled_completion_date": "2026-11-30",
            "status_date": "2026-09-01",
            "original_risk_rating": "Moderate",
            "supporting_documents": "scan1.csv",
            "cve": "CVE-2026-1111",
            "bod_22_01_tracking": "No",
        }

        scan2_entry = {
            "_dedup_key": ("tenable:12345", "10.0.0.1"),
            "_asset_aliases": {"10.0.0.1", "host-a.internal"},
            "_scanner_type": "tenable",
            "_raw_solution": "Patch package v2",
            "_see_also": "https://example.com/advisory",
            "_det_date_obj": datetime.date(2026, 8, 15),  # Earlier detection date!
            "_sla_date_obj": datetime.date(2026, 9, 14),
            "_stat_date_obj": datetime.date(2026, 10, 1),
            "poam_id": "",
            "weakness_name": "OpenSSH Vulnerability",
            "weakness_description": "Vulnerable SSH service",
            "detector_source": "Tenable Network Security",
            "source_identifier": "12345",
            "asset_identifier": "10.0.0.1:22",
            "point_of_contact": "SecOps",
            "remediation_plan": "Patch package v2",
            "original_detection_date": "2026-08-15",
            "scheduled_completion_date": "2026-09-14",
            "status_date": "2026-10-01",
            "original_risk_rating": "High",  # Higher risk rating!
            "supporting_documents": "scan2.csv",
            "cve": "CVE-2026-1111, CVE-2026-2222",
            "bod_22_01_tracking": "Yes",
            "bod_22_01_due_date": "2026-09-15",
        }

        scan3_entry = {
            "_dedup_key": ("tenable:67890", "10.0.0.2"),  # Different finding and asset
            "_asset_aliases": {"10.0.0.2"},
            "_scanner_type": "tenable",
            "_raw_solution": "Update Apache",
            "_see_also": "",
            "_det_date_obj": datetime.date(2026, 10, 10),
            "_sla_date_obj": datetime.date(2026, 11, 9),
            "_stat_date_obj": datetime.date(2026, 10, 10),
            "poam_id": "",
            "weakness_name": "Apache HTTP Server Issue",
            "weakness_description": "Apache out of date",
            "detector_source": "Tenable Network Security",
            "source_identifier": "67890",
            "asset_identifier": "10.0.0.2",
            "point_of_contact": "SecOps",
            "remediation_plan": "Update Apache",
            "original_detection_date": "2026-10-10",
            "scheduled_completion_date": "2026-11-09",
            "status_date": "2026-10-10",
            "original_risk_rating": "High",
            "supporting_documents": "scan3.csv",
            "cve": "CVE-2026-3333",
            "bod_22_01_tracking": "No",
        }

        merged = ts.merge_scan_entries([[scan1_entry], [scan2_entry], [scan3_entry]])
        self.assertEqual(len(merged), 2)

        # Finding 1 should be consolidated
        f1 = [e for e in merged if e["_dedup_key"] == ("tenable:12345", "10.0.0.1")][0]
        self.assertEqual(f1["original_detection_date"], "2026-08-15")  # Earlier date
        self.assertEqual(f1["original_risk_rating"], "High")  # Higher risk
        self.assertIn("scan1.csv", f1["supporting_documents"])
        self.assertIn("scan2.csv", f1["supporting_documents"])
        self.assertIn("host-a.internal", f1["_asset_aliases"])
        self.assertEqual(f1["bod_22_01_tracking"], "Yes")

        # Finding 2 is separate
        f2 = [e for e in merged if e["_dedup_key"] == ("tenable:67890", "10.0.0.2")][0]
        self.assertEqual(f2["source_identifier"], "67890")

    def test_merge_scan_entries_supports_up_to_five_scans(self) -> None:
        """Verify merging works seamlessly across 5 distinct scan files."""
        scans = []
        for i in range(1, 6):
            entry = {
                "_dedup_key": (f"source:{i}", f"host-{i}"),
                "_asset_aliases": {f"host-{i}"},
                "_scanner_type": "tenable",
                "_raw_solution": f"Fix {i}",
                "_see_also": "",
                "_det_date_obj": datetime.date(2026, 10, i),
                "_sla_date_obj": datetime.date(2026, 11, i),
                "_stat_date_obj": datetime.date(2026, 10, i),
                "poam_id": "",
                "weakness_name": f"Vuln {i}",
                "weakness_description": f"Description {i}",
                "detector_source": "Tenable",
                "source_identifier": f"SRC-{i}",
                "asset_identifier": f"10.0.0.{i}",
                "point_of_contact": "SecOps",
                "remediation_plan": f"Fix {i}",
                "original_detection_date": f"2026-10-0{i}",
                "scheduled_completion_date": f"2026-11-0{i}",
                "status_date": f"2026-10-0{i}",
                "original_risk_rating": "Moderate",
                "supporting_documents": f"scan_{i}.csv",
                "cve": f"CVE-2026-{1000 + i}",
                "bod_22_01_tracking": "No",
            }
            scans.append([entry])

        merged = ts.merge_scan_entries(scans)
        self.assertEqual(len(merged), 5)
        for i in range(1, 6):
            self.assertTrue(any(e["source_identifier"] == f"SRC-{i}" for e in merged))

    def test_interactive_multi_scan_selection_prompting(self) -> None:
        """Simulate user selecting multiple scans interactively with y/N prompts."""
        sample_dir = os.path.join(REPO_ROOT, "testing", "sample-scans")
        t_path = os.path.join(sample_dir, "tenable_monthly_scan.csv")
        i_path = os.path.join(sample_dir, "aws_inspector_scan.csv")

        # Inputs:
        # 1. Select scan 1 (tenable_monthly_scan.csv)
        # 2. Add additional scan? 'y'
        # 3. Select scan 2 (aws_inspector_scan.csv)
        # 4. Add additional scan? 'n'
        # 5. Select previous OPEN FedRAMP POA&M: "" (none)
        # 6. Draft remediation plans? 'n'
        simulated_inputs = [
            t_path,
            "y",
            i_path,
            "n",
            "",
            "n",
        ]

        with mock.patch("sys.stdin.isatty", return_value=True):
            with mock.patch("builtins.input", side_effect=simulated_inputs):
                with mock.patch("sys.argv", ["grc transform", "--dry-run"]):
                    exit_code = ts.main()
                    self.assertEqual(exit_code, 0)

    def test_cli_multi_scan_flag_and_max_limit(self) -> None:
        """Verify passing multiple --scan flags and erroring when exceeding MAX_SCAN_FILES."""
        sample_dir = os.path.join(REPO_ROOT, "testing", "sample-scans")
        t_path = os.path.join(sample_dir, "tenable_monthly_scan.csv")
        i_path = os.path.join(sample_dir, "aws_inspector_scan.csv")

        # Passing two scans via CLI flags
        argv = [
            "grc transform",
            "--scan", t_path,
            "--scan", i_path,
            "--no-previous",
            "--draft-remediations", "n",
            "--dry-run",
        ]
        with mock.patch("sys.argv", argv):
            code = ts.main()
            self.assertEqual(code, 0)

        # Passing more than 5 scans should fail with exit code 1
        argv_excess = [
            "grc transform",
            "--scan", "s1.csv",
            "--scan", "s2.csv",
            "--scan", "s3.csv",
            "--scan", "s4.csv",
            "--scan", "s5.csv",
            "--scan", "s6.csv",
        ]
        with mock.patch("sys.argv", argv_excess):
            code = ts.main()
            self.assertEqual(code, 1)


if __name__ == "__main__":
    unittest.main()
