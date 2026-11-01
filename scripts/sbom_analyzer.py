#!/usr/bin/env python3
"""
sbom_analyzer.py - Software Bill of Materials (SBOM) to DISA STIG/SRG Mapping Engine
====================================================================================

Classification: Internal Compliance & Engineering Specification
Target Frameworks: DISA STIG, DoD SRG, NIST SP 800-53 Rev. 4/5, FedRAMP
Pipeline Role: Phase 3 (Analyze) & Phase 4 (Evidence) Deliverable Generator

Purpose:
  Parses Software Bill of Materials (SBOM) files in CycloneDX (JSON) or SPDX (JSON)
  formats, identifies software components, runtimes, dependencies, and OS packages,
  and maps them directly to applicable Defense Information Systems Agency (DISA)
  Security Technical Implementation Guides (STIGs) and Security Requirements Guides (SRGs).

Key Outputs:
  - STIG Applicability Matrix (Markdown / JSON / CSV)
  - Benchmark Scope & Risk Classification Summary
  - NIST SP 800-53 Traceability Matrix for POA&M / SCR-SCN Ingestion
"""

import argparse
import csv
import io
import json
import os
import re
import sys
from collections import defaultdict
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import parse_qs

try:
    from grc_common import utc_now_iso, utc_now_str
except ImportError:
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from grc_common import utc_now_iso, utc_now_str


# ==============================================================================
# DISA STIG & SRG KNOWLEDGE BASE CATALOG
# ==============================================================================

DISA_STIG_CATALOG: Dict[str, Dict[str, Any]] = {
    # General Application & Development
    "ASD_STIG": {
        "id": "U_ASD_V5R1_STIG",
        "title": "Application Security and Development (ASD) STIG",
        "benchmark_id": "Application_Security_and_Development_STIG",
        "version": "Version 5, Release 1",
        "type": "STIG",
        "target_domain": "Application Software, Custom Code, Libraries & Frameworks",
        "nist_controls": ["SI-2", "SI-4", "SI-7", "SI-10", "SI-16", "SC-8", "SC-12", "SC-13", "IA-2", "AC-3"],
        "max_severity": "CAT I",
        "description": "Applies to custom developed applications, software frameworks, and application-level open source libraries.",
    },
    "GENERIC_APP_SRG": {
        "id": "U_Application_SRG_V3R1",
        "title": "Application Security Requirements Guide (SRG)",
        "benchmark_id": "Application_SRG",
        "version": "Version 3, Release 1",
        "type": "SRG",
        "target_domain": "Generic Software Applications",
        "nist_controls": ["AC-2", "AC-3", "AC-6", "AU-2", "IA-5", "SC-8", "SI-2"],
        "max_severity": "CAT I",
        "description": "Baseline security requirements for software applications where a technology-specific STIG does not exist.",
    },

    # Runtimes, Languages & Execution Environments
    "JAVA_JRE_STIG": {
        "id": "U_Java_Runtime_Environment_STIG",
        "title": "Java Runtime Environment (JRE) STIG",
        "benchmark_id": "Java_Runtime_Environment_STIG",
        "version": "Version 1, Release 4",
        "type": "STIG",
        "target_domain": "Java Virtual Machine, OpenJDK, Oracle JRE",
        "nist_controls": ["SC-13", "SI-2", "SI-7", "AC-3"],
        "max_severity": "CAT I",
        "description": "Applies to systems hosting Java runtimes, JVM instances, and Java application servers.",
    },
    "NODEJS_SRG": {
        "id": "U_NodeJS_Application_SRG",
        "title": "Node.js Application Platform SRG",
        "benchmark_id": "NodeJS_Platform_SRG",
        "version": "Version 1, Release 1",
        "type": "SRG",
        "target_domain": "Node.js Runtimes & Server-Side JavaScript",
        "nist_controls": ["SI-2", "SI-4", "SC-8", "AC-6"],
        "max_severity": "CAT I",
        "description": "Security guidance for Node.js execution environments and asynchronous runtime modules.",
    },
    "PYTHON_SRG": {
        "id": "U_Python_Runtime_SRG",
        "title": "Python Runtime and Interpreter Security Requirements",
        "benchmark_id": "Python_Interpreter_SRG",
        "version": "Version 1, Release 2",
        "type": "SRG",
        "target_domain": "Python 3 Interpreter, PyPI Ecosystem",
        "nist_controls": ["SI-2", "SI-7", "SC-12", "AU-3"],
        "max_severity": "CAT I",
        "description": "Security baselines governing Python interpreter deployments, virtual environments, and package managers.",
    },
    "DOTNET_STIG": {
        "id": "U_Microsoft_NET_Framework_STIG",
        "title": "Microsoft .NET Framework STIG",
        "benchmark_id": "Microsoft_NET_Framework_STIG",
        "version": "Version 2, Release 2",
        "type": "STIG",
        "target_domain": ".NET Core / .NET Framework Runtimes",
        "nist_controls": ["SI-2", "SI-7", "SC-13"],
        "max_severity": "CAT II",
        "description": "Guidance for deployments utilizing .NET Core and CLR runtimes.",
    },

    # Web, Proxy & Application Servers
    "APACHE_HTTP_STIG": {
        "id": "U_Apache_Server_2.4_Unix_STIG",
        "title": "Apache Server 2.4 UNIX STIG",
        "benchmark_id": "Apache_Server_2_4_Unix_STIG",
        "version": "Version 2, Release 4",
        "type": "STIG",
        "target_domain": "Apache HTTP Server (httpd)",
        "nist_controls": ["AC-3", "AC-17", "SC-8", "SI-2", "SI-17"],
        "max_severity": "CAT I",
        "description": "Security configuration standards for Apache HTTPD web servers.",
    },
    "NGINX_STIG": {
        "id": "U_NGINX_Web_Server_STIG",
        "title": "NGINX Web Server / Reverse Proxy STIG",
        "benchmark_id": "NGINX_Web_Server_STIG",
        "version": "Version 1, Release 1",
        "type": "STIG",
        "target_domain": "NGINX Ingress, Reverse Proxy, Web Server",
        "nist_controls": ["AC-3", "AC-17", "SC-8", "SI-2", "SI-17"],
        "max_severity": "CAT I",
        "description": "Security requirements for NGINX HTTP servers, reverse proxies, and ingress controllers.",
    },
    "TOMCAT_STIG": {
        "id": "U_Apache_Tomcat_Application_Server_STIG",
        "title": "Apache Tomcat Application Server 9 STIG",
        "benchmark_id": "Apache_Tomcat_9_STIG",
        "version": "Version 2, Release 2",
        "type": "STIG",
        "target_domain": "Tomcat Servlet Container",
        "nist_controls": ["AC-3", "IA-2", "SC-8", "SI-2"],
        "max_severity": "CAT I",
        "description": "Applies to Tomcat servlet engines and Java EE web applications.",
    },
    "WEB_SERVER_SRG": {
        "id": "U_Web_Server_SRG_V3R1",
        "title": "Web Server Security Requirements Guide (SRG)",
        "benchmark_id": "Web_Server_SRG",
        "version": "Version 3, Release 1",
        "type": "SRG",
        "target_domain": "Generic Web Servers & Ingress Proxies",
        "nist_controls": ["SC-8", "SC-13", "SI-2", "AC-17"],
        "max_severity": "CAT I",
        "description": "Baseline requirements for web service engines (Caddy, Traefik, Envoy, Lighttpd).",
    },

    # Database & Storage Systems
    "POSTGRESQL_STIG": {
        "id": "U_PostgreSQL_9.x_STIG",
        "title": "PostgreSQL Database STIG",
        "benchmark_id": "PostgreSQL_Database_STIG",
        "version": "Version 2, Release 3",
        "type": "STIG",
        "target_domain": "PostgreSQL RDBMS Engine",
        "nist_controls": ["AC-3", "AU-2", "AU-12", "IA-2", "SC-8", "SC-13", "SI-2"],
        "max_severity": "CAT I",
        "description": "Covers PostgreSQL relational database instances and server packages.",
    },
    "MYSQL_STIG": {
        "id": "U_MySQL_Server_STIG",
        "title": "MySQL 8.0 Database Server STIG",
        "benchmark_id": "MySQL_Database_STIG",
        "version": "Version 2, Release 1",
        "type": "STIG",
        "target_domain": "MySQL / MariaDB RDBMS",
        "nist_controls": ["AC-3", "AU-2", "IA-2", "SC-8", "SI-2"],
        "max_severity": "CAT I",
        "description": "Applies to MySQL and MariaDB database deployments.",
    },
    "MONGODB_STIG": {
        "id": "U_MongoDB_Enterprise_Advanced_STIG",
        "title": "MongoDB Enterprise Advanced STIG",
        "benchmark_id": "MongoDB_STIG",
        "version": "Version 1, Release 2",
        "type": "STIG",
        "target_domain": "MongoDB Document Database",
        "nist_controls": ["AC-3", "AU-2", "SC-8", "SI-2"],
        "max_severity": "CAT I",
        "description": "Security guidance for NoSQL document stores utilizing MongoDB.",
    },
    "DATABASE_SRG": {
        "id": "U_Database_SRG_V3R1",
        "title": "Database Security Requirements Guide (SRG)",
        "benchmark_id": "Database_SRG",
        "version": "Version 3, Release 1",
        "type": "SRG",
        "target_domain": "Generic RDBMS, In-Memory Stores (Redis, Memcached), SQLite",
        "nist_controls": ["AC-3", "AU-2", "SC-8", "SC-13", "SI-2"],
        "max_severity": "CAT I",
        "description": "Baseline requirements for data stores lacking a dedicated technology STIG.",
    },

    # Operating Systems & Container Runtimes
    "RHEL_9_STIG": {
        "id": "U_RHEL_9_STIG",
        "title": "Red Hat Enterprise Linux 9 STIG",
        "benchmark_id": "RHEL_9_STIG",
        "version": "Version 1, Release 2",
        "type": "STIG",
        "target_domain": "RHEL 9, CentOS Stream 9, AlmaLinux 9, Rocky Linux 9",
        "nist_controls": ["AC-2", "AC-3", "AU-2", "CM-6", "IA-2", "SC-8", "SC-13", "SI-2", "SI-7"],
        "max_severity": "CAT I",
        "description": "Operating system security baseline for Red Hat Enterprise Linux 9 family.",
    },
    "RHEL_8_STIG": {
        "id": "U_RHEL_8_STIG",
        "title": "Red Hat Enterprise Linux 8 STIG",
        "benchmark_id": "RHEL_8_STIG",
        "version": "Version 1, Release 12",
        "type": "STIG",
        "target_domain": "RHEL 8, CentOS 8, AlmaLinux 8, Rocky Linux 8",
        "nist_controls": ["AC-2", "AC-3", "AU-2", "CM-6", "IA-2", "SC-8", "SC-13", "SI-2", "SI-7"],
        "max_severity": "CAT I",
        "description": "Operating system security baseline for Red Hat Enterprise Linux 8 family.",
    },
    "UBUNTU_22_STIG": {
        "id": "U_Canonical_Ubuntu_22.04_LTS_STIG",
        "title": "Canonical Ubuntu 22.04 LTS STIG",
        "benchmark_id": "Ubuntu_22_04_LTS_STIG",
        "version": "Version 1, Release 1",
        "type": "STIG",
        "target_domain": "Ubuntu 22.04 LTS Operating System Base",
        "nist_controls": ["AC-2", "AC-3", "AU-2", "CM-6", "IA-2", "SC-8", "SC-13", "SI-2"],
        "max_severity": "CAT I",
        "description": "Security baseline for Canonical Ubuntu 22.04 LTS distributions.",
    },
    "CONTAINER_PLATFORM_SRG": {
        "id": "U_Container_Platform_SRG_V1R1",
        "title": "Container Platform Security Requirements Guide (SRG)",
        "benchmark_id": "Container_Platform_SRG",
        "version": "Version 1, Release 1",
        "type": "SRG",
        "target_domain": "Docker, containerd, Podman, Container Images (Alpine, Distroless)",
        "nist_controls": ["AC-3", "AC-6", "CM-2", "CM-6", "SC-8", "SI-2", "SI-4", "SI-7"],
        "max_severity": "CAT I",
        "description": "Security standards for container images, runtime isolation, and microservices hosts.",
    },
    "KUBERNETES_STIG": {
        "id": "U_Kubernetes_STIG",
        "title": "Kubernetes STIG",
        "benchmark_id": "Kubernetes_STIG",
        "version": "Version 1, Release 3",
        "type": "STIG",
        "target_domain": "Kubernetes Clusters, CoreDNS, Kubelet, Helm",
        "nist_controls": ["AC-2", "AC-3", "AU-2", "CM-6", "SC-8", "SI-2"],
        "max_severity": "CAT I",
        "description": "Security standards for Kubernetes container orchestration environments.",
    },

    # Cryptographic & Network Security Infrastructure
    "OPENSSL_CRYPTO_SRG": {
        "id": "U_FIPS_Cryptographic_Module_SRG",
        "title": "Cryptographic Module and Protocol Security SRG",
        "benchmark_id": "Crypto_Module_SRG",
        "version": "Version 2, Release 1",
        "type": "SRG",
        "target_domain": "OpenSSL, LibreSSL, BoringSSL, Cryptographic Providers",
        "nist_controls": ["SC-12", "SC-13", "SI-7", "IA-7"],
        "max_severity": "CAT I",
        "description": "Requirements for cryptographic libraries, FIPS 140 compliance, and key management.",
    },
    "OPENSSH_STIG": {
        "id": "U_OpenSSH_Server_and_Client_STIG",
        "title": "OpenSSH Server and Client STIG",
        "benchmark_id": "OpenSSH_STIG",
        "version": "Version 1, Release 1",
        "type": "STIG",
        "target_domain": "OpenSSH Client, Server, SFTP",
        "nist_controls": ["AC-17", "IA-2", "SC-8", "SC-13", "SI-2"],
        "max_severity": "CAT I",
        "description": "Applies to SSH remote access utilities and secure transport implementations.",
    },
}

CATALOG_BY_ID: Dict[str, Dict[str, Any]] = {v["id"]: v for v in DISA_STIG_CATALOG.values()}

# Application dependency ecosystems (where client SDKs like `pkg:pypi/redis` or `pkg:npm/mysql` live)
APP_LIBRARY_ECOSYSTEMS = {"pypi", "npm", "maven", "golang", "nuget", "cargo", "gem"}


# ==============================================================================
# COMPONENT TO STIG RESOLUTION RULES
# ==============================================================================

# Regex patterns that apply even when a component is an application library
# (e.g., cryptographic modules and embedded servlet containers)
ALWAYS_MATCH_NAME_MAP: List[Tuple[re.Pattern, str, str]] = [
    (
        re.compile(r"^(openssl(?:-[0-9a-z\.\-]+)?|libcrypto[0-9a-z\.\-]*|libssl[0-9a-z\.\-]*|boringssl|libressl)$", re.I),
        "OPENSSL_CRYPTO_SRG",
        "Cryptographic communications provider",
    ),
    (
        re.compile(r"^(tomcat|apache-tomcat|tomcat-embed-[a-z0-9\-]+)$", re.I),
        "TOMCAT_STIG",
        "Tomcat servlet and JSP execution engine",
    ),
]

# Regex patterns for platform services, OS packages, runtimes, and servers
# (Skipped when PURL indicates an application-level client library in PyPI/npm/Maven/Go/NuGet/Cargo)
PLATFORM_SERVICE_NAME_MAP: List[Tuple[re.Pattern, str, str]] = [
    # Web & Application Servers
    (re.compile(r"^(nginx|nginx-core|nginx-full|openresty)$", re.I), "NGINX_STIG", "Reverse proxy and web server engine"),
    (re.compile(r"^(apache2|httpd|apache-http-server)$", re.I), "APACHE_HTTP_STIG", "Apache web server core service"),
    (re.compile(r"^(caddy|traefik|envoy|haproxy)$", re.I), "WEB_SERVER_SRG", "Web ingress and edge routing proxy"),

    # Runtimes & Interpreters (Tightened so 'java.*' never matches 'javascript' or 'java-jwt')
    (re.compile(r"^(python|python3|python3\.[0-9]+|cpython|pypy3?)$", re.I), "PYTHON_SRG", "Python runtime interpreter environment"),
    (re.compile(r"^(nodejs|node|node-js)$", re.I), "NODEJS_SRG", "Node.js JavaScript server runtime engine"),
    (
        re.compile(r"^(openjdk(?:-[0-9]+)?(?:-(?:jre|jdk)(?:-headless)?)?|java-(?:1\.)?[0-9]+-(?:openjdk|oracle)|jdk|jre|temurin-?[0-9]*|adoptium-?[0-9]*)$", re.I),
        "JAVA_JRE_STIG",
        "Java Virtual Machine (JVM) runtime",
    ),
    (re.compile(r"^(dotnet|dotnet-runtime.*|aspnetcore-runtime.*|microsoft\.netcore\.app)$", re.I), "DOTNET_STIG", ".NET runtime and core libraries"),

    # Databases & Caches (Server / Engine packages)
    (re.compile(r"^(postgresql(?:-[0-9]+)?|postgresql-server|postgres|libpq5?)$", re.I), "POSTGRESQL_STIG", "PostgreSQL database engine and connection stack"),
    (re.compile(r"^(mysql-server|mysql-community-server|mysqld|mariadb-server|mariadb)$", re.I), "MYSQL_STIG", "MySQL/MariaDB relational database service"),
    (re.compile(r"^(mongodb-org(?:-server)?|mongodb-enterprise(?:-server)?|mongod|mongodb)$", re.I), "MONGODB_STIG", "MongoDB document database engine"),
    (re.compile(r"^(redis-server|redis|memcached|sqlite3)$", re.I), "DATABASE_SRG", "In-memory cache or embedded database engine"),

    # SSH Infrastructure
    (re.compile(r"^(openssh|openssh-server|openssh-client|openssh-clients|ssh)$", re.I), "OPENSSH_STIG", "SSH cryptographic terminal and transport tool"),

    # Container & Orchestration Platforms
    (re.compile(r"^(docker-ce|docker-ee|docker-engine|containerd(?:\.io)?|podman|moby-engine)$", re.I), "CONTAINER_PLATFORM_SRG", "Container virtualization and runtime service"),
    (re.compile(r"^(kubernetes|kube-apiserver|kube-controller-manager|kube-scheduler|kubelet|kubectl|coredns|helm)$", re.I), "KUBERNETES_STIG", "Kubernetes cluster orchestration component"),

    # OS Distros & Base Images
    (re.compile(r"^(rhel|redhat-release|centos-release|rocky-release|almalinux-release)$", re.I), "RHEL_9_STIG", "RHEL-derivative enterprise operating system base"),
    (re.compile(r"^(ubuntu|ubuntu-minimal|debian|base-files)$", re.I), "UBUNTU_22_STIG", "Debian/Ubuntu Linux operating system baseline"),
    (re.compile(r"^(alpine-baselayout|alpine-base|distroless|busybox)$", re.I), "CONTAINER_PLATFORM_SRG", "Lightweight container operating system base image"),
]

# Backward-compatible combined alias
COMPONENT_NAME_MAP: List[Tuple[re.Pattern, str, str]] = ALWAYS_MATCH_NAME_MAP + PLATFORM_SERVICE_NAME_MAP

# PURL (Package URL) ecosystem mappings
PURL_ECOSYSTEM_MAP: Dict[str, Tuple[str, str]] = {
    "pypi": ("ASD_STIG", "Python application dependency (PyPI)"),
    "npm": ("ASD_STIG", "JavaScript/TypeScript application dependency (npm)"),
    "maven": ("ASD_STIG", "Java ecosystem application dependency (Maven)"),
    "golang": ("ASD_STIG", "Go language application dependency (Go Modules)"),
    "nuget": ("ASD_STIG", ".NET ecosystem application dependency (NuGet)"),
    "cargo": ("ASD_STIG", "Rust language application dependency (Crates)"),
    "gem": ("ASD_STIG", "Ruby ecosystem application dependency (RubyGems)"),
    "deb": ("UBUNTU_22_STIG", "Debian/Ubuntu system package (dpkg)"),
    "rpm": ("RHEL_9_STIG", "RHEL/CentOS system package (RPM)"),
    "alpine": ("CONTAINER_PLATFORM_SRG", "Alpine Linux container package (apk)"),
}


# ==============================================================================
# DATA MODELS
# ==============================================================================

class Component:
    """Normalized representation of an SBOM component/package."""

    def __init__(
        self,
        name: Any,
        version: Any = "Unknown",
        purl: Any = "",
        component_type: Any = "library",
        supplier: Any = "",
        license_str: Any = "",
        description: Any = "",
    ):
        self.name = str(name if name is not None else "").strip()
        ver_str = str(version if version is not None else "").strip()
        self.version = ver_str if ver_str else "Unknown"
        self.purl = str(purl if purl is not None else "").strip()
        ctype = str(component_type if component_type is not None else "library").strip().lower()
        self.component_type = ctype if ctype else "library"
        self.supplier = str(supplier if supplier is not None else "").strip()
        self.license_str = str(license_str if license_str is not None else "").strip()
        self.description = str(description if description is not None else "").strip()

    def get_ecosystem(self) -> Optional[str]:
        """Extracts the ecosystem/package manager from a PURL string."""
        if self.purl.startswith("pkg:"):
            body = self.purl[4:].split("?", 1)[0]
            parts = body.split("/")
            if parts and parts[0]:
                return parts[0].lower()
        return None

    def get_purl_distro(self) -> str:
        """Extracts distro qualifier or namespace hint from PURL or version string."""
        hints: List[str] = []
        if "?" in self.purl:
            qs = parse_qs(self.purl.split("?", 1)[1])
            for k in ("distro", "os", "arch"):
                if k in qs:
                    hints.extend(qs[k])
        if self.purl.startswith("pkg:"):
            body = self.purl[4:].split("?", 1)[0]
            parts = body.split("/")
            if len(parts) >= 2:
                hints.append(parts[1])
        hints.append(self.version)
        return " ".join(hints).lower()

    def __repr__(self) -> str:
        return f"<Component {self.name}@{self.version} ({self.purl or self.component_type})>"


class STIGMapping:
    """Association between an SBOM component and an applicable DISA STIG/SRG."""

    def __init__(
        self,
        component: Component,
        stig_key: str,
        match_reason: str,
        match_type: str,
    ):
        self.component = component
        self.stig_key = stig_key
        self.stig_info = DISA_STIG_CATALOG.get(stig_key, {})
        self.match_reason = match_reason
        self.match_type = match_type  # "REGEX_NAME", "PURL_ECOSYSTEM", "TYPE_INFERENCE", "FALLBACK"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "component_name": self.component.name,
            "component_version": self.component.version,
            "component_type": self.component.component_type,
            "purl": self.component.purl,
            "stig_id": self.stig_info.get("id", "UNKNOWN"),
            "stig_title": self.stig_info.get("title", "UNKNOWN"),
            "benchmark_id": self.stig_info.get("benchmark_id", "UNKNOWN"),
            "version": self.stig_info.get("version", "UNKNOWN"),
            "max_severity": self.stig_info.get("max_severity", "UNKNOWN"),
            "nist_controls": self.stig_info.get("nist_controls", []),
            "match_reason": self.match_reason,
            "match_type": self.match_type,
        }


# ==============================================================================
# SBOM PARSERS (CYCLONEDX & SPDX)
# ==============================================================================

class SBOMParser:
    """Parses CycloneDX and SPDX JSON SBOM documents into normalized Component objects."""

    @staticmethod
    def parse_file(file_path: str) -> List[Component]:
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"SBOM file not found: {file_path}")

        with open(file_path, "r", encoding="utf-8") as f:
            try:
                data = json.load(f)
            except json.JSONDecodeError as e:
                raise ValueError(f"Failed to parse SBOM JSON: {e}")

        if not isinstance(data, dict):
            raise ValueError("Invalid SBOM JSON root: expected a JSON object.")

        if data.get("bomFormat") == "CycloneDX" or ("components" in data and isinstance(data["components"], list)):
            return SBOMParser._parse_cyclonedx(data)
        if "spdxVersion" in data or ("packages" in data and isinstance(data["packages"], list)):
            return SBOMParser._parse_spdx(data)

        raise ValueError(
            "Unrecognized SBOM schema. File does not appear to be valid CycloneDX or SPDX JSON."
        )

    @staticmethod
    def _cdx_dict_to_component(comp: Dict[str, Any], default_type: str = "library") -> Optional[Component]:
        name = str(comp.get("name") or "").strip()
        if not name:
            return None

        licenses: List[str] = []
        for lic in comp.get("licenses", []) or []:
            if isinstance(lic, dict):
                if "license" in lic and isinstance(lic["license"], dict):
                    val = lic["license"].get("name") or lic["license"].get("id") or ""
                    if val:
                        licenses.append(str(val))
                elif "expression" in lic and lic["expression"]:
                    licenses.append(str(lic["expression"]))

        supplier_obj = comp.get("supplier")
        supplier = supplier_obj.get("name", "") if isinstance(supplier_obj, dict) else ""

        return Component(
            name=name,
            version=comp.get("version", "Unknown"),
            purl=comp.get("purl", ""),
            component_type=comp.get("type", default_type),
            supplier=supplier,
            license_str=", ".join(licenses),
            description=comp.get("description", ""),
        )

    @staticmethod
    def _parse_cyclonedx(data: Dict[str, Any]) -> List[Component]:
        components: List[Component] = []
        seen: Set[Tuple[str, str, str]] = set()

        def _add_comp(c_dict: Dict[str, Any], default_type: str = "library") -> None:
            if not isinstance(c_dict, dict):
                return
            comp_obj = SBOMParser._cdx_dict_to_component(c_dict, default_type=default_type)
            if comp_obj:
                key = (comp_obj.name.lower(), comp_obj.version.lower(), comp_obj.purl.lower())
                if key not in seen:
                    seen.add(key)
                    components.append(comp_obj)
            # Recursively walk nested components[].components
            for child in c_dict.get("components", []) or []:
                _add_comp(child, default_type="library")

        meta_component = data.get("metadata", {}).get("component") if isinstance(data.get("metadata"), dict) else None
        if isinstance(meta_component, dict):
            _add_comp(meta_component, default_type="application")

        for comp in data.get("components", []) or []:
            _add_comp(comp, default_type="library")

        return components

    @staticmethod
    def _parse_spdx(data: Dict[str, Any]) -> List[Component]:
        components: List[Component] = []
        seen: Set[Tuple[str, str, str]] = set()

        for pkg in data.get("packages", []) or []:
            if not isinstance(pkg, dict):
                continue
            name = str(pkg.get("name") or "").strip()
            if not name:
                continue

            purl = ""
            for ref in pkg.get("externalRefs", []) or []:
                if isinstance(ref, dict) and ref.get("referenceType") == "purl":
                    purl = str(ref.get("referenceLocator") or "")
                    break

            supplier = str(pkg.get("supplier") or "")
            if supplier.lower().startswith(("person:", "organization:")):
                supplier = supplier.split(":", 1)[1].strip()

            comp_obj = Component(
                name=name,
                version=pkg.get("versionInfo", "Unknown"),
                purl=purl,
                component_type="package",
                supplier=supplier,
                license_str=pkg.get("licenseConcluded") or pkg.get("licenseDeclared") or "",
                description=pkg.get("description") or pkg.get("summary") or "",
            )
            key = (comp_obj.name.lower(), comp_obj.version.lower(), comp_obj.purl.lower())
            if key not in seen:
                seen.add(key)
                components.append(comp_obj)

        return components


# ==============================================================================
# DISA STIG ANALYZER & RESOLUTION ENGINE
# ==============================================================================

class STIGAnalyzer:
    """Maps analyzed SBOM components to the authoritative DISA STIG and SRG catalog."""

    def __init__(self, components: List[Component]):
        self.components = components
        self.mappings: List[STIGMapping] = []

    def analyze(self) -> List[STIGMapping]:
        self.mappings = [self._resolve_component(comp) for comp in self.components]
        return self.mappings

    def _resolve_os_stig_key(self, comp: Component) -> Tuple[str, str]:
        """Resolves specific OS STIG key (RHEL 8 vs RHEL 9 vs Ubuntu 22.04) from distro/version hints."""
        distro_hint = f"{comp.name} {comp.get_purl_distro()}".lower()
        if any(tok in distro_hint for tok in ("el8", "rhel-8", "rhel8", "centos-8", "rocky-8", "almalinux-8")):
            return "RHEL_8_STIG", "RHEL 8 system package / OS baseline"
        if any(tok in distro_hint for tok in ("ubuntu", "debian", "deb")):
            return "UBUNTU_22_STIG", "Debian/Ubuntu system package / OS baseline"
        if any(tok in distro_hint for tok in ("alpine", "apk", "distroless")):
            return "CONTAINER_PLATFORM_SRG", "Container OS package baseline"
        if comp.name.lower() in ("rhel", "redhat-release", "centos", "rocky", "almalinux") and comp.version.startswith("8"):
            return "RHEL_8_STIG", "RHEL 8 operating system baseline"
        return "RHEL_9_STIG", "RHEL 9 system package / OS baseline"

    def _resolve_component(self, comp: Component) -> STIGMapping:
        name_clean = comp.name.strip().lower()
        ecosystem = comp.get_ecosystem()
        is_app_library = (ecosystem in APP_LIBRARY_ECOSYSTEMS and comp.component_type in ("library", "package"))

        # Step 1a: Always-applicable security/crypto/embedded engine patterns
        for pattern, stig_key, reason in ALWAYS_MATCH_NAME_MAP:
            if pattern.search(name_clean):
                return STIGMapping(
                    component=comp,
                    stig_key=stig_key,
                    match_reason=f"Direct component technology match: {reason}",
                    match_type="REGEX_NAME",
                )

        # Step 1b: Platform/server/runtime patterns (only when not an app-ecosystem client library)
        if not is_app_library:
            for pattern, stig_key, reason in PLATFORM_SERVICE_NAME_MAP:
                if pattern.search(name_clean):
                    if stig_key == "RHEL_9_STIG":
                        stig_key, _ = self._resolve_os_stig_key(comp)
                    return STIGMapping(
                        component=comp,
                        stig_key=stig_key,
                        match_reason=f"Direct component technology match: {reason}",
                        match_type="REGEX_NAME",
                    )

        # Step 2: Match against PURL ecosystem (with distro-aware RPM/DEB resolution)
        if ecosystem and ecosystem in PURL_ECOSYSTEM_MAP:
            if ecosystem == "rpm":
                stig_key, reason = self._resolve_os_stig_key(comp)
                return STIGMapping(
                    component=comp,
                    stig_key=stig_key,
                    match_reason=f"Resolved via PURL ecosystem (rpm): {reason}",
                    match_type="PURL_ECOSYSTEM",
                )
            stig_key, reason = PURL_ECOSYSTEM_MAP[ecosystem]
            return STIGMapping(
                component=comp,
                stig_key=stig_key,
                match_reason=f"Resolved via PURL ecosystem ({ecosystem}): {reason}",
                match_type="PURL_ECOSYSTEM",
            )

        # Step 3: Operating system indicators in component type
        if comp.component_type in ("operating-system", "os"):
            stig_key, reason = self._resolve_os_stig_key(comp)
            return STIGMapping(
                component=comp,
                stig_key=stig_key,
                match_reason=reason,
                match_type="TYPE_INFERENCE",
            )

        # Step 4: Container image indicators
        if comp.component_type in ("container", "container-image"):
            return STIGMapping(
                component=comp,
                stig_key="CONTAINER_PLATFORM_SRG",
                match_reason="Container image platform requirement",
                match_type="TYPE_INFERENCE",
            )

        # Step 5: Default Fallback to Application Security and Development STIG
        return STIGMapping(
            component=comp,
            stig_key="ASD_STIG",
            match_reason="Application dependency governed by General Application Security and Development (ASD) STIG",
            match_type="FALLBACK",
        )

    def generate_summary(self) -> Dict[str, Any]:
        stig_counts: Dict[str, int] = defaultdict(int)
        severity_counts: Dict[str, int] = defaultdict(int)
        nist_control_set: Set[str] = set()

        for m in self.mappings:
            stig_id = m.stig_info.get("id", "UNKNOWN")
            stig_counts[stig_id] += 1
            sev = m.stig_info.get("max_severity", "UNKNOWN")
            severity_counts[sev] += 1
            for c in m.stig_info.get("nist_controls", []):
                nist_control_set.add(c)

        return {
            "total_components": len(self.components),
            "unique_stigs_mapped": len(stig_counts),
            "stig_distribution": dict(sorted(stig_counts.items(), key=lambda x: x[1], reverse=True)),
            "severity_distribution": dict(severity_counts),
            "mapped_nist_controls": sorted(list(nist_control_set)),
        }


# ==============================================================================
# REPORT & DELIVERABLE GENERATORS
# ==============================================================================

class ReportGenerator:
    """Formats STIG applicability analyses into Markdown, JSON, or CSV deliverables."""

    @staticmethod
    def to_markdown(
        mappings: List[STIGMapping],
        summary: Dict[str, Any],
        sbom_filename: str = "SBOM",
    ) -> str:
        now = utc_now_str()

        md = [
            "# DISA STIG & SRG Applicability Matrix",
            f"> **Generated**: {now}  ",
            f"> **Source SBOM**: `{os.path.basename(sbom_filename)}`  ",
            "> **Classification / Use**: Internal Compliance & Security Audit Deliverable (SCR/SCN / FedRAMP / DoD)",
            "",
            "---",
            "",
            "## 1. Executive Summary",
            "",
            f"* **Total SBOM Components Evaluated**: `{summary['total_components']}`",
            f"* **Applicable DISA STIGs / SRGs Identified**: `{summary['unique_stigs_mapped']}`",
            f"* **Applicable CAT I Benchmark Scope**: `{summary['severity_distribution'].get('CAT I', 0)}` components (benchmark max severity — not active vulnerability findings)",
            f"* **Applicable CAT II Benchmark Scope**: `{summary['severity_distribution'].get('CAT II', 0)}` components (benchmark max severity — not active vulnerability findings)",
            "",
            "### 1.1 STIG Applicability Catalog",
            "",
            "| Benchmark ID | STIG / SRG Title | Version | Max Severity | Mapped Components |",
            "| :--- | :--- | :--- | :---: | :---: |",
        ]

        for stig_id, count in summary["stig_distribution"].items():
            info = CATALOG_BY_ID.get(stig_id, {})
            title = info.get("title", stig_id)
            ver = info.get("version", "N/A")
            sev = info.get("max_severity", "N/A")
            md.append(f"| `{stig_id}` | **{title}** | {ver} | `{sev}` | **{count}** |")

        md.extend([
            "",
            "---",
            "",
            "## 2. NIST SP 800-53 Control Coverage",
            "The mapped STIG baselines mandate compliance checks against the following NIST SP 800-53 controls:",
            "",
            f"> {', '.join(f'`{c}`' for c in summary['mapped_nist_controls'])}",
            "",
            "---",
            "",
            "## 3. Component-to-STIG Traceability Matrix",
            "",
            "| Component Name | Version | Type | Mapped DISA STIG / SRG | Severity | NIST Controls | Resolution Rationale |",
            "| :--- | :--- | :--- | :--- | :---: | :--- | :--- |",
        ])

        for m in sorted(mappings, key=lambda x: (x.stig_info.get("max_severity", ""), x.component.name)):
            c = m.component
            info = m.stig_info
            stig_title = info.get("title", m.stig_key)
            sev = info.get("max_severity", "N/A")
            controls_abbr = ", ".join(info.get("nist_controls", [])[:4])
            if len(info.get("nist_controls", [])) > 4:
                controls_abbr += ", ..."

            md.append(
                f"| **{c.name}** | `{c.version}` | `{c.component_type}` | {stig_title} | `{sev}` | {controls_abbr} | {m.match_reason} |"
            )

        md.append("")
        md.append("---")
        md.append("*Artifact produced by GRC-xMINI (`sbom_analyzer.py`)*")
        return "\n".join(md)

    @staticmethod
    def to_json(
        mappings: List[STIGMapping],
        summary: Dict[str, Any],
        sbom_filename: str = "SBOM",
    ) -> str:
        payload = {
            "metadata": {
                "generated_at": utc_now_iso(),
                "source_sbom": os.path.basename(sbom_filename),
                "analyzer": "sbom_analyzer.py (GRC-xMINI)",
            },
            "summary": summary,
            "mappings": [m.to_dict() for m in mappings],
        }
        return json.dumps(payload, indent=2)

    @staticmethod
    def to_csv(mappings: List[STIGMapping]) -> str:
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow([
            "Component Name",
            "Version",
            "Type",
            "PURL",
            "DISA STIG ID",
            "DISA STIG Title",
            "Benchmark ID",
            "STIG Version",
            "Max Severity",
            "NIST SP 800-53 Controls",
            "Match Rationale",
        ])
        for m in mappings:
            c = m.component
            info = m.stig_info
            writer.writerow([
                c.name,
                c.version,
                c.component_type,
                c.purl,
                info.get("id", ""),
                info.get("title", ""),
                info.get("benchmark_id", ""),
                info.get("version", ""),
                info.get("max_severity", ""),
                "; ".join(info.get("nist_controls", [])),
                m.match_reason,
            ])
        return output.getvalue()


# ==============================================================================
# CLI ENTRY POINT
# ==============================================================================

def build_cli() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="DISA STIG & SRG SBOM Applicability Analyzer (GRC-xMINI)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 sbom_analyzer.py --sbom /path/to/sbom.json --format markdown -o stig_matrix.md
  python3 sbom_analyzer.py --sbom cyclonedx.json --format json -o stig_applicability.json
  python3 sbom_analyzer.py --sbom spdx.json --format csv -o stig_export.csv
  python3 sbom_analyzer.py --catalog-dump
        """,
    )
    src_group = parser.add_mutually_exclusive_group(required=True)
    src_group.add_argument(
        "--sbom",
        "-s",
        help="Path to the input SBOM file (CycloneDX or SPDX JSON format).",
    )
    src_group.add_argument(
        "--catalog-dump",
        action="store_true",
        help="Print the internal DISA STIG / SRG reference catalog as JSON and exit.",
    )
    parser.add_argument(
        "--output",
        "-o",
        help="Output file path. If omitted, results are written to stdout.",
    )
    parser.add_argument(
        "--format",
        "-f",
        choices=["markdown", "json", "csv", "summary"],
        default="markdown",
        help="Output format (default: markdown).",
    )
    return parser


def main() -> None:
    parser = build_cli()
    args = parser.parse_args()

    if args.catalog_dump:
        print(json.dumps(DISA_STIG_CATALOG, indent=2))
        sys.exit(0)

    try:
        components = SBOMParser.parse_file(args.sbom)
    except Exception as e:
        print(f"[ERROR] Failed to load SBOM file: {e}", file=sys.stderr)
        sys.exit(1)

    analyzer = STIGAnalyzer(components)
    mappings = analyzer.analyze()
    summary = analyzer.generate_summary()

    formatters = {
        "markdown": lambda: ReportGenerator.to_markdown(mappings, summary, sbom_filename=args.sbom),
        "json": lambda: ReportGenerator.to_json(mappings, summary, sbom_filename=args.sbom),
        "csv": lambda: ReportGenerator.to_csv(mappings),
        "summary": lambda: json.dumps(summary, indent=2),
    }
    output_data = formatters[args.format]()

    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(output_data)
            print(f"[SUCCESS] STIG Applicability Matrix written to: {args.output}")
        except IOError as e:
            print(f"[ERROR] Failed to write output file: {e}", file=sys.stderr)
            sys.exit(1)
    else:
        print(output_data)


if __name__ == "__main__":
    main()
