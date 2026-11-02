#!/usr/bin/env python3
"""
Unit Test Suite for GRC-xMINI (v1.4.4 — Yokota) Scan-to-POA&M Transformation Engine
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
        # 6. Select previous CLOSED FedRAMP POA&M: "" (none)
        # 7. Draft remediation plans? 'n'
        simulated_inputs = [
            t_path,
            "y",
            i_path,
            "n",
            "",
            "",
            "n",
        ]

        with mock.patch("sys.stdin.isatty", return_value=True):
            with mock.patch("builtins.input", side_effect=simulated_inputs):
                with mock.patch("sys.argv", ["grc transform", "--dry-run"]):
                    exit_code = ts.main()
                    self.assertEqual(exit_code, 0)

    def test_in_file_duplicate_merge_preserves_cves_and_kev_status(self) -> None:
        """Verifies P1 fix: in-file duplicate rows for the same plugin+host merge CVEs and KEV status."""
        kev_catalog = {
            "CVE-2024-6387": {
                "cveID": "CVE-2024-6387",
                "dateAdded": "2024-07-09",
                "dueDate": "2024-07-30",
            }
        }
        records = [
            {
                "Plugin ID": "192814",
                "CVE": "CVE-2024-0001",
                "Risk": "High",
                "Host": "10.0.0.10",
                "Port": "22",
                "Protocol": "tcp",
                "Name": "OpenSSH Multi-Port Finding",
                "First Discovered": "2026-10-01",
            },
            {
                "Plugin ID": "192814",
                "CVE": "CVE-2024-6387",
                "Risk": "Critical",
                "Host": "10.0.0.10",
                "Port": "2222",
                "Protocol": "tcp",
                "Name": "OpenSSH Multi-Port Finding",
                "First Discovered": "2026-09-15",
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
        self.assertEqual(len(entries), 1)
        merged = entries[0]
        self.assertIn("CVE-2024-0001", merged["cve"])
        self.assertIn("CVE-2024-6387", merged["cve"])
        self.assertEqual(merged["bod_22_01_tracking"], "Yes")
        self.assertEqual(merged["bod_22_01_due_date"], "2024-07-30")

    def test_calcchain_relationships_removed_from_xlsx_archive(self) -> None:
        """Verifies P1 fix: dropping xl/calcChain.xml also cleans workbook.xml.rels and [Content_Types].xml."""
        with tempfile.TemporaryDirectory() as tmpdir:
            out_xlsx = os.path.join(tmpdir, "OPEN FedRAMP-POAM.xlsx")
            ts.write_poam_workbook(
                template_path=self.open_template,
                output_path=out_xlsx,
                entries=[],
                is_closed_template=False,
            )
            with zipfile.ZipFile(out_xlsx, "r") as zf:
                self.assertNotIn("xl/calcChain.xml", zf.namelist())
                rels_xml = zf.read("xl/_rels/workbook.xml.rels").decode("utf-8")
                ct_xml = zf.read("[Content_Types].xml").decode("utf-8")
                self.assertNotIn("calcChain.xml", rels_xml)
                self.assertNotIn("/xl/calcChain.xml", ct_xml)

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

    def test_artifacts_dropoff_and_pickup_defaults(self) -> None:
        """Verifies Objective 3: Default intake is artifacts/drop-off and output base is artifacts/pick-up."""
        self.assertTrue(ts.DEFAULT_DROPOFF_DIR.endswith(os.path.join("artifacts", "drop-off")))
        self.assertTrue(ts.DEFAULT_PICKUP_DIR.endswith(os.path.join("artifacts", "pick-up")))
        self.assertEqual(ts.DEFAULT_SCANS_DIR, ts.DEFAULT_DROPOFF_DIR)

    def test_timestamped_output_directory_creation_and_fallback(self) -> None:
        """Verifies Objective 4: Auto-creation of timestamped folder with fallback to legacy format."""
        scans = ["/path/to/my_tenable_scan.csv"]
        # 1. Normal execution produces timestamped folder YYYY-MM-DD_HHMMSS
        ts_dir = ts.generate_output_dir_path(scans, base_pickup_dir="/artifacts/pick-up")
        folder_name = os.path.basename(ts_dir)
        self.assertRegex(folder_name, r"^\d{4}-\d{2}-\d{2}_\d{6}$")

        # 2. Legacy fallback produces poam-<stem>
        legacy_dir = ts.generate_output_dir_path(scans, base_pickup_dir="/artifacts/pick-up", force_legacy=True)
        self.assertEqual(os.path.basename(legacy_dir), "poam-my_tenable_scan")

        # 3. Multiple scans produce poam-<stem>-and-N-more in legacy fallback
        multi_scans = ["/path/to/scan1.csv", "/path/to/scan2.csv", "/path/to/scan3.csv"]
        multi_legacy = ts.generate_output_dir_path(multi_scans, base_pickup_dir="/artifacts/pick-up", force_legacy=True)
        self.assertEqual(os.path.basename(multi_legacy), "poam-scan1-and-2-more")

    def test_five_worksheet_fedramp_template_reads_only_first_worksheet_and_skips_guidance_rows(self) -> None:
        """
        Verify Bug #1 fix: When an analyst uploads a 5-worksheet FedRAMP v3.1 POA&M workbook
        (where Worksheet #1 has CSP metadata on Rows 1-4, POAM ID on Row 5, Guidance/Examples/Mandatory
        on Rows 6-8, and data on Row 9+, while Worksheets #2-#5 contain Closed, Configuration,
        PL-2, and Record of Changes tabs), xMINI reads strictly Worksheet #1 and ignores
        both template guidance/example rows (Rows 6-8) and Worksheets #2-#5.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            five_sheet_xlsx = os.path.join(tmpdir, "five_sheet_fedramp_poam.xlsx")
            ns_main = ts.MAIN_NS
            ns_r = ts.REL_NS

            # Build a 5-worksheet workbook modeled on the official FedRAMP v3.1 template:
            # Sheet 1: Open POA&M Items (Row 5 header, Rows 6-8 Guidance/Examples/Mandatory, Row 9 real item)
            # Sheets 2-5: Closed POA&M Items, Configuration Findings, PL-2 Findings, Record of Changes
            #             populated with decoy rows that MUST NOT be ingested.
            with zipfile.ZipFile(self.open_template, "r") as zin, zipfile.ZipFile(five_sheet_xlsx, "w", zipfile.ZIP_DEFLATED) as zout:
                ss_bytes = zin.read("xl/sharedStrings.xml")
                ts.register_xml_namespaces(ss_bytes)
                ss_root = ET.fromstring(ss_bytes)
                ss_list = ["".join(t.text or "" for t in si.findall(f".//{{{ns_main}}}t")) for si in ss_root.findall(f"{{{ns_main}}}si")]

                def add_ss(val: str) -> int:
                    if val in ss_list:
                        return ss_list.index(val)
                    idx = len(ss_list)
                    ss_list.append(val)
                    si = ET.SubElement(ss_root, f"{{{ns_main}}}si")
                    t = ET.SubElement(si, f"{{{ns_main}}}t")
                    t.text = val
                    return idx

                # Construct Sheet 1 with 8 header/instruction rows (POAM ID on Row 5) + 1 real finding on Row 9
                s1_bytes = zin.read("xl/worksheets/sheet1.xml")
                ts.register_xml_namespaces(s1_bytes)
                s1_root = ET.fromstring(s1_bytes)
                s1_data = s1_root.find(f"{{{ns_main}}}sheetData")
                orig_rows_1_to_4 = [r for r in list(s1_data) if int(r.attrib.get("r", "0")) <= 4]
                for r in list(s1_data):
                    s1_data.remove(r)

                # Rows 1-4: FedRAMP v3.1 CSP/CSO metadata block
                for r_idx, (a_txt, b_txt) in enumerate([
                    ("FedRAMP® Plan of Action and Milestones (POA&M)", ""),
                    ("", "Cloud Service Provider"),
                    ("Guidance", "Enter the name of the CSP as it appears in the SSP"),
                    ("", ""),
                ], start=1):
                    r_el = ET.SubElement(s1_data, f"{{{ns_main}}}row", {"r": str(r_idx)})
                    if a_txt:
                        c_a = ET.SubElement(r_el, f"{{{ns_main}}}c", {"r": f"A{r_idx}", "t": "s"})
                        ET.SubElement(c_a, f"{{{ns_main}}}v").text = str(add_ss(a_txt))
                    if b_txt:
                        c_b = ET.SubElement(r_el, f"{{{ns_main}}}c", {"r": f"B{r_idx}", "t": "s"})
                        ET.SubElement(c_b, f"{{{ns_main}}}v").text = str(add_ss(b_txt))

                # Shift original Rows 1-4 (Header, Guidance, Examples, Mandatory) down to Rows 5-8
                for old_r in orig_rows_1_to_4:
                    new_r_num = int(old_r.attrib["r"]) + 4
                    old_r.set("r", str(new_r_num))
                    for c_el in old_r.findall(f"{{{ns_main}}}c"):
                        col_let, _ = ts.split_cell_ref(c_el.attrib.get("r", "A1"))
                        c_el.set("r", f"{col_let}{new_r_num}")
                    s1_data.append(old_r)

                # Row 9: Real Open POA&M item on Worksheet #1
                r9 = ET.SubElement(s1_data, f"{{{ns_main}}}row", {"r": "9"})
                for col_let, val in [
                    ("B", "VULN-00001"),
                    ("C", "RA-5, SI-2"),
                    ("D", "Real Worksheet 1 Finding"),
                    ("E", "Valid finding from Worksheet 1 Row 9"),
                    ("F", "Tenable Nessus"),
                    ("G", "176402"),
                    ("H", "10.0.0.10"),
                    ("L", "2026-09-01"),
                    ("M", "2026-10-01"),
                    ("R", "High"),
                ]:
                    c_el = ET.SubElement(r9, f"{{{ns_main}}}c", {"r": f"{col_let}9", "t": "s"})
                    ET.SubElement(c_el, f"{{{ns_main}}}v").text = str(add_ss(val))

                # Construct decoy Sheet 2..5 containing decoy POAM IDs that must be ignored
                decoy_root = ET.fromstring(s1_bytes)
                decoy_data = decoy_root.find(f"{{{ns_main}}}sheetData")
                for r in list(decoy_data):
                    if int(r.attrib.get("r", "0")) >= 5:
                        decoy_data.remove(r)
                r5_decoy = ET.SubElement(decoy_data, f"{{{ns_main}}}row", {"r": "5"})
                for col_let, val in [
                    ("B", "DECOY-99999"),
                    ("D", "Should Never Be Read From Tabs 2-5"),
                    ("G", "999999"),
                    ("H", "10.99.99.99"),
                ]:
                    c_el = ET.SubElement(r5_decoy, f"{{{ns_main}}}c", {"r": f"{col_let}5", "t": "s"})
                    ET.SubElement(c_el, f"{{{ns_main}}}v").text = str(add_ss(val))
                decoy_xml_bytes = ts.serialize_xml_preserving_root_ns(decoy_root, s1_bytes)

                ss_root.set("count", str(len(ss_list)))
                ss_root.set("uniqueCount", str(len(ss_list)))

                wb_bytes = zin.read("xl/workbook.xml")
                wb_root = ET.fromstring(wb_bytes)
                sheets_el = wb_root.find(f"{{{ns_main}}}sheets")
                for s in list(sheets_el):
                    sheets_el.remove(s)

                rels_bytes = zin.read("xl/_rels/workbook.xml.rels")
                rels_root = ET.fromstring(rels_bytes)
                rel_ns_uri = rels_root.tag.split("}")[0].lstrip("{")
                for rel in list(rels_root):
                    if "worksheets/sheet" in rel.attrib.get("Target", ""):
                        rels_root.remove(rel)

                tab_names = [
                    "Open POA&M Items",
                    "Closed POA&M Items",
                    "Configuration Findings",
                    "PL-2 Findings",
                    "Record of Changes",
                ]
                for idx, tname in enumerate(tab_names, start=1):
                    rid = f"rId{10 + idx}"
                    ET.SubElement(
                        sheets_el,
                        f"{{{ns_main}}}sheet",
                        {"state": "visible", "name": tname, "sheetId": str(idx), f"{{{ns_r}}}id": rid},
                    )
                    ET.SubElement(
                        rels_root,
                        f"{{{rel_ns_uri}}}Relationship",
                        {
                            "Id": rid,
                            "Type": "http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet",
                            "Target": f"worksheets/sheet{idx}.xml",
                        },
                    )

                for item in zin.infolist():
                    if item.filename == "xl/worksheets/sheet1.xml":
                        zout.writestr(item, ts.serialize_xml_preserving_root_ns(s1_root, s1_bytes))
                    elif item.filename == "xl/sharedStrings.xml":
                        zout.writestr(item, ts.serialize_xml_preserving_root_ns(ss_root, ss_bytes))
                    elif item.filename == "xl/workbook.xml":
                        zout.writestr(item, ts.serialize_xml_preserving_root_ns(wb_root, wb_bytes))
                    elif item.filename == "xl/_rels/workbook.xml.rels":
                        zout.writestr(item, ts.serialize_xml_preserving_root_ns(rels_root, rels_bytes))
                    else:
                        zout.writestr(item, zin.read(item.filename))

                for idx in range(2, 6):
                    zout.writestr(f"xl/worksheets/sheet{idx}.xml", decoy_xml_bytes)

            # Verify 5 sheets exist in the uploaded workbook
            self.assertEqual(len(ts.get_workbook_sheet_names(five_sheet_xlsx)), 5)

            # Load via load_existing_poam_workbook: MUST return ONLY the 1 real finding from Tab 1 Row 9
            loaded = ts.load_existing_poam_workbook(five_sheet_xlsx, is_closed_template=False)
            self.assertEqual(len(loaded), 1)
            self.assertEqual(loaded[0]["poam_id"], "VULN-00001")
            self.assertEqual(loaded[0]["weakness_name"], "Real Worksheet 1 Finding")

    def test_combined_fedramp_poam_workbook_contains_open_and_closed_tabs_in_single_file(self) -> None:
        """
        Verify Bug #2 fix: Transforming scan data produces a single combined `FedRAMP-POAM.xlsx`
        workbook in the pick-up folder containing Tab 1 ('Open POA&M Items') and Tab 2
        ('Closed POA&M Items'), rather than two separate OPEN and CLOSED .xlsx files.
        """
        open_entry = {
            "poam_id": "2026-NOV-00002",
            "controls": "RA-5, SI-2",
            "weakness_name": "Active Open Vulnerability",
            "weakness_description": "Open finding on Tab 1",
            "detector_source": "Tenable Nessus",
            "source_identifier": "176402",
            "asset_identifier": "10.0.0.10",
            "point_of_contact": "SecOps",
            "resources_required": "Engineering",
            "remediation_plan": "Apply vendor patch",
            "original_detection_date": "2026-10-01",
            "scheduled_completion_date": "2026-10-31",
            "status_date": "2026-11-01",
            "vendor_dependency": "No",
            "last_vendor_checkin": "",
            "vendor_product_name": "OpenSSH",
            "original_risk_rating": "High",
            "adjusted_risk_rating": "",
            "risk_adjustment": "No",
            "false_positive": "No",
            "operational_requirement": "No",
            "deviation_rationale": "",
            "supporting_documents": "scan.csv",
            "comments": "Active on Tab 1",
            "bod_22_01_tracking": "No",
            "bod_22_01_due_date": "",
            "cve": "CVE-2023-38408",
        }
        closed_entry = {
            "poam_id": "2026-OCT-00001",
            "controls": "SC-8",
            "weakness_name": "Remediated Closed Vulnerability",
            "weakness_description": "Closed finding on Tab 2",
            "detector_source": "Tenable Nessus",
            "source_identifier": "153953",
            "asset_identifier": "10.0.0.25",
            "point_of_contact": "SecOps",
            "resources_required": "Engineering",
            "remediation_plan": "Patched and verified",
            "original_detection_date": "2026-09-01",
            "scheduled_completion_date": "2026-10-01",
            "status_date": "2026-11-01",
            "vendor_dependency": "No",
            "last_vendor_checkin": "",
            "vendor_product_name": "TLS",
            "original_risk_rating": "High",
            "adjusted_risk_rating": "",
            "risk_adjustment": "No",
            "false_positive": "No",
            "operational_requirement": "No",
            "deviation_rationale": "",
            "supporting_documents": "scan.csv",
            "comments": "[2026-11-01 Auto-Closed by GRCx]: Verified absent on scanned host.",
            "bod_22_01_tracking": "No",
            "bod_22_01_due_date": "",
            "cve": "CVE-2021-44228",
        }

        with tempfile.TemporaryDirectory() as tmpdir:
            combined_xlsx = os.path.join(tmpdir, "FedRAMP-POAM.xlsx")
            ts.write_combined_poam_workbook(
                open_template_path=self.open_template,
                closed_template_path=self.closed_template,
                output_path=combined_xlsx,
                open_entries=[open_entry],
                closed_entries=[closed_entry],
            )
            self.assertTrue(os.path.isfile(combined_xlsx))

            # Verify exactly 2 worksheets exist: Tab 1 = Open POA&M Items, Tab 2 = Closed POA&M Items
            sheet_names = ts.get_workbook_sheet_names(combined_xlsx)
            self.assertEqual(sheet_names, ["Open POA&M Items", "Closed POA&M Items"])

            # Verify reading Tab 1 (Open POA&M Items)
            loaded_open = ts.load_existing_poam_workbook(combined_xlsx, is_closed_template=False)
            self.assertEqual(len(loaded_open), 1)
            self.assertEqual(loaded_open[0]["poam_id"], "2026-NOV-00002")
            self.assertEqual(loaded_open[0]["weakness_name"], "Active Open Vulnerability")

            # Verify reading Tab 2 (Closed POA&M Items)
            loaded_closed = ts.load_existing_poam_workbook(combined_xlsx, is_closed_template=True)
            self.assertEqual(len(loaded_closed), 1)
            self.assertEqual(loaded_closed[0]["poam_id"], "2026-OCT-00001")
            self.assertEqual(loaded_closed[0]["weakness_name"], "Remediated Closed Vulnerability")

            # Also verify CLI end-to-end execution writes ONLY FedRAMP-POAM.xlsx + poam_transform_summary.md
            cli_out_dir = os.path.join(tmpdir, "pickup_run")
            sample_scan = os.path.join(REPO_ROOT, "testing", "sample-scans", "tenable_monthly_scan.csv")
            sample_prev = os.path.join(REPO_ROOT, "testing", "sample-scans", "previous_open_poam.xlsx")
            argv = [
                "grc transform",
                "--scan", sample_scan,
                "--previous-open", sample_prev,
                "--draft-remediations", "n",
                "--output-dir", cli_out_dir,
            ]
            with mock.patch("sys.argv", argv):
                rc = ts.main()
                self.assertEqual(rc, 0)

            out_files = sorted(os.listdir(cli_out_dir))
            self.assertEqual(out_files, ["FedRAMP-POAM.xlsx", "poam_transform_summary.md"])
            self.assertEqual(
                ts.get_workbook_sheet_names(os.path.join(cli_out_dir, "FedRAMP-POAM.xlsx")),
                ["Open POA&M Items", "Closed POA&M Items"],
            )

    # -----------------------------------------------------------------------
    # 13. Qualys VMDR and Wiz Cloud Security Adapters & Auto-Detection
    # -----------------------------------------------------------------------

    def test_qualys_adapter_and_auto_detection(self) -> None:
        row = {
            "QID": "38742",
            "Title": "OpenSSH RegreSSHion Remote Code Execution",
            "Severity": "5",
            "IP": "10.100.10.25",
            "Port": "22",
            "Protocol": "TCP",
            "Threat": "Signal handler race condition in OpenSSH sshd allows remote code execution.",
            "Impact": "Full administrative root takeover.",
            "Solution": "Upgrade OpenSSH package to 9.8p1 or newer.",
            "CVE": "CVE-2024-6387",
            "First Detected": "2026-07-01",
            "Last Detected": "2026-11-01",
        }
        # Auto-detection
        detected = ts.detect_scanner_type([row])
        self.assertEqual(detected, "qualys")

        # Parsing
        row_lc = {k.lower(): v for k, v in row.items()}
        parsed = ts.QualysAdapter.parse_row(row, row_lc, self.today, {}, strict_fedramp_risk=False)
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed["risk"], "Critical")
        self.assertEqual(parsed["source_id"], "38742")
        self.assertEqual(parsed["name"], "OpenSSH RegreSSHion Remote Code Execution")
        self.assertEqual(parsed["asset_base"], "10.100.10.25")
        self.assertEqual(parsed["detector_source"], "Qualys VMDR")
        self.assertEqual(parsed["cves"], "CVE-2024-6387")
        self.assertIn("Impact: Full administrative root takeover.", parsed["full_desc"])

        # Remediation plan URL generation
        dummy_entry = {
            "detector_source": "Qualys",
            "_scanner_type": "qualys",
            "source_identifier": "38742",
            "cve": "CVE-2024-6387",
            "weakness_name": parsed["name"],
            "solution": parsed["solution"],
            "see_also": "",
        }
        plan = ts.build_remediation_plan_with_urls(dummy_entry)
        self.assertIn("Official Qualys & Vendor Remediation References:", plan)
        self.assertIn("https://nvd.nist.gov/vuln/detail/CVE-2024-6387", plan)

    def test_wiz_adapter_and_auto_detection(self) -> None:
        row = {
            "Wiz ID": "WIZ-2024-0012",
            "Project Name": "Production FedRAMP Cluster",
            "Asset Name": "k8s-pod-auth-01",
            "Asset Type": "Container",
            "Vulnerability Name": "XZ Utils liblzma Upstream Malicious Backdoor",
            "Severity": "Critical",
            "Fixed Version": "5.6.1-r1",
            "CVE": "CVE-2024-3094",
            "Remediation": "Rebuild container image using patched base image.",
            "First Seen": "2026-03-30",
            "Last Seen": "2026-11-01",
        }
        # Auto-detection
        detected = ts.detect_scanner_type([row])
        self.assertEqual(detected, "wiz")

        # Parsing
        row_lc = {k.lower(): v for k, v in row.items()}
        parsed = ts.WizAdapter.parse_row(row, row_lc, self.today, {}, strict_fedramp_risk=False)
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed["risk"], "Critical")
        self.assertEqual(parsed["source_id"], "WIZ-2024-0012")
        self.assertEqual(parsed["name"], "XZ Utils liblzma Upstream Malicious Backdoor")
        self.assertEqual(parsed["asset_base"], "k8s-pod-auth-01")
        self.assertEqual(parsed["detector_source"], "Wiz")
        self.assertEqual(parsed["cves"], "CVE-2024-3094")
        self.assertEqual(parsed["asset_display"], "k8s-pod-auth-01 (Container)")
        self.assertEqual(parsed["solution"], "Rebuild container image using patched base image.")

        # Remediation plan URL generation
        dummy_entry = {
            "detector_source": "Wiz",
            "_scanner_type": "wiz",
            "source_identifier": "WIZ-2024-0012",
            "cve": "CVE-2024-3094",
            "weakness_name": parsed["name"],
            "solution": parsed["solution"],
            "see_also": "",
        }
        plan = ts.build_remediation_plan_with_urls(dummy_entry)
        self.assertIn("Official Wiz Cloud & Vendor Remediation References:", plan)
        self.assertIn("https://nvd.nist.gov/vuln/detail/CVE-2024-3094", plan)


if __name__ == "__main__":
    unittest.main()
