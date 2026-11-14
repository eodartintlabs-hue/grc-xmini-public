# NIST SP 800-53 Rev. 5 Controls Traceability Matrix

> **Classification / Use**: Internal Compliance & Security Audit Deliverable (FedRAMP High / DoD RMF / SCR-SCN)  
> **Audit Target Identifier**: `dccc0b56a62dea31b1290d22898a9731089ca67b3e1721760544e1900298e94c`  
> **Evaluation Timestamp**: `2026-11-14 22:18:22 UTC`  

---

## 1. Compliance Status by Control Family

| Control ID | Control Name | Control Family | DISA STIG Impact | Audit Findings Count | Compliance Status |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **AC-3** | Access Enforcement | Access Control (AC) | `CAT I` | 0 | ✅ **COMPLIANT** |
| **AC-6** | Least Privilege | Access Control (AC) | `CAT I` | 0 | ✅ **COMPLIANT** |
| **CM-6** | Configuration Settings | Configuration Management (CM) | `CAT II` | 0 | ✅ **COMPLIANT** |
| **CM-8** | Information System Component Inventory | Configuration Management (CM) | `CAT II` | 0 | ⚪ **NOT ASSESSED** |
| **IA-2** | Identification and Authentication (Organizational Users) | Identification and Authentication (IA) | `CAT I` | 0 | ✅ **COMPLIANT** |
| **IA-7** | Cryptographic Module Authentication | Identification and Authentication (IA) | `CAT II` | 0 | ✅ **COMPLIANT** |
| **RA-5** | Vulnerability Monitoring and Scanning | Risk Assessment (RA) | `CAT I` | 0 | ⚪ **NOT ASSESSED** |
| **SC-12** | Cryptographic Key Establishment and Management | System and Communications Protection (SC) | `CAT I` | 0 | ✅ **COMPLIANT** |
| **SC-13** | Cryptographic Protection (FIPS 140 Validation) | System and Communications Protection (SC) | `CAT I` | 0 | ✅ **COMPLIANT** |
| **SC-28** | Protection of Information at Rest | System and Communications Protection (SC) | `CAT I` | 0 | ✅ **COMPLIANT** |
| **SC-8** | Transmission Confidentiality and Integrity | System and Communications Protection (SC) | `CAT I` | 0 | ✅ **COMPLIANT** |
| **SI-10** | Information Input Validation | System and Information Integrity (SI) | `CAT I` | 0 | ✅ **COMPLIANT** |
| **SI-16** | Memory Protection | System and Information Integrity (SI) | `CAT II` | 0 | ⚪ **NOT ASSESSED** |
| **SI-17** | Fail-Secure / Secure Communications Initiation | System and Information Integrity (SI) | `CAT I` | 0 | ✅ **COMPLIANT** |
| **SI-2** | Flaw Remediation | System and Information Integrity (SI) | `CAT I` | 0 | ✅ **COMPLIANT** |
| **SI-4** | Information System Monitoring | System and Information Integrity (SI) | `CAT I` | 0 | ✅ **COMPLIANT** |
| **SI-7** | Software, Firmware, and Information Integrity | System and Information Integrity (SI) | `CAT I` | 0 | ✅ **COMPLIANT** |

---

## 2. Detailed Control Breakdown & Evidence Mapping

### AC-3: Access Enforcement — ✅ COMPLIANT
* **Control Family**: Access Control (AC)
* **DISA STIG Baseline**: `CAT I`
* **Control Objective**: Enforce approved authorizations for logical access to information and system resources (e.g. security group ingress rules).
* **Evaluation Outcome**: No policy violations or vulnerabilities detected. Conforms to baseline.

### AC-6: Least Privilege — ✅ COMPLIANT
* **Control Family**: Access Control (AC)
* **DISA STIG Baseline**: `CAT I`
* **Control Objective**: Employ the principle of least privilege, allowing only authorized accesses necessary for accomplishing assigned tasks (e.g., prohibiting public cloud buckets).
* **Evaluation Outcome**: No policy violations or vulnerabilities detected. Conforms to baseline.

### CM-6: Configuration Settings — ✅ COMPLIANT
* **Control Family**: Configuration Management (CM)
* **DISA STIG Baseline**: `CAT II`
* **Control Objective**: Establish and document mandatory configuration settings for IT products using hardened baselines (DISA STIG / CIS).
* **Evaluation Outcome**: No policy violations or vulnerabilities detected. Conforms to baseline.

### CM-8: Information System Component Inventory — ⚪ NOT ASSESSED
* **Control Family**: Configuration Management (CM)
* **DISA STIG Baseline**: `CAT II`
* **Control Objective**: Develop and document an inventory of information system components (SBOM) detailing name, version, and license.
* **Evaluation Outcome**: No evidence file present from assessing scanner(s) (Grype, Trivy, SBOM).

### IA-2: Identification and Authentication (Organizational Users) — ✅ COMPLIANT
* **Control Family**: Identification and Authentication (IA)
* **DISA STIG Baseline**: `CAT I`
* **Control Objective**: Uniquely identify and authenticate organizational users (or processes acting on their behalf). Prohibits hardcoded static credentials, default passwords, and unmanaged API tokens.
* **Evaluation Outcome**: No policy violations or vulnerabilities detected. Conforms to baseline.

### IA-7: Cryptographic Module Authentication — ✅ COMPLIANT
* **Control Family**: Identification and Authentication (IA)
* **DISA STIG Baseline**: `CAT II`
* **Control Objective**: Authenticate to cryptographic modules using mechanisms meeting applicable federal laws, regulations, and standards.
* **Evaluation Outcome**: No policy violations or vulnerabilities detected. Conforms to baseline.

### RA-5: Vulnerability Monitoring and Scanning — ⚪ NOT ASSESSED
* **Control Family**: Risk Assessment (RA)
* **DISA STIG Baseline**: `CAT I`
* **Control Objective**: Monitor and scan for vulnerabilities in the system and hosted applications, prioritizing remediation of critical CVEs.
* **Evaluation Outcome**: No evidence file present from assessing scanner(s) (Grype, Trivy).

### SC-12: Cryptographic Key Establishment and Management — ✅ COMPLIANT
* **Control Family**: System and Communications Protection (SC)
* **DISA STIG Baseline**: `CAT I`
* **Control Objective**: Establish and manage cryptographic keys in accordance with NIST SP 800-56A/B and applicable FIPS guidelines.
* **Evaluation Outcome**: No policy violations or vulnerabilities detected. Conforms to baseline.

### SC-13: Cryptographic Protection (FIPS 140 Validation) — ✅ COMPLIANT
* **Control Family**: System and Communications Protection (SC)
* **DISA STIG Baseline**: `CAT I`
* **Control Objective**: Implement cryptographic modules validated under FIPS 140-2 / 140-3. Enforce OS kernel FIPS mode and validated security providers.
* **Evaluation Outcome**: No policy violations or vulnerabilities detected. Conforms to baseline.

### SC-28: Protection of Information at Rest — ✅ COMPLIANT
* **Control Family**: System and Communications Protection (SC)
* **DISA STIG Baseline**: `CAT I`
* **Control Objective**: Protect the confidentiality and integrity of information at rest (e.g., EBS volume encryption, S3 SSE-KMS).
* **Evaluation Outcome**: No policy violations or vulnerabilities detected. Conforms to baseline.

### SC-8: Transmission Confidentiality and Integrity — ✅ COMPLIANT
* **Control Family**: System and Communications Protection (SC)
* **DISA STIG Baseline**: `CAT I`
* **Control Objective**: Protect the confidentiality and integrity of transmitted information using strong cryptography (TLS 1.2+ / 1.3).
* **Evaluation Outcome**: No policy violations or vulnerabilities detected. Conforms to baseline.

### SI-10: Information Input Validation — ✅ COMPLIANT
* **Control Family**: System and Information Integrity (SI)
* **DISA STIG Baseline**: `CAT I`
* **Control Objective**: Validate information inputs to syntax rules, character sets, and payload limits before runtime interpretation.
* **Evaluation Outcome**: No policy violations or vulnerabilities detected. Conforms to baseline.

### SI-16: Memory Protection — ⚪ NOT ASSESSED
* **Control Family**: System and Information Integrity (SI)
* **DISA STIG Baseline**: `CAT II`
* **Control Objective**: Implement security safeguards to protect system memory from unauthorized code execution (e.g., DEP/NX, ASLR, memory-safe handling).
* **Evaluation Outcome**: No evidence file present from assessing scanner(s) (None configured).

### SI-17: Fail-Secure / Secure Communications Initiation — ✅ COMPLIANT
* **Control Family**: System and Information Integrity (SI)
* **DISA STIG Baseline**: `CAT I`
* **Control Objective**: Ensure the system fails to a secure state. Prohibits disabled TLS certificate validation and deprecated TLS 1.0/1.1 protocols.
* **Evaluation Outcome**: No policy violations or vulnerabilities detected. Conforms to baseline.

### SI-2: Flaw Remediation — ✅ COMPLIANT
* **Control Family**: System and Information Integrity (SI)
* **DISA STIG Baseline**: `CAT I`
* **Control Objective**: Identify, report, and correct system flaws (vulnerabilities and CVEs) within defined remediation timeframes.
* **Evaluation Outcome**: No policy violations or vulnerabilities detected. Conforms to baseline.

### SI-4: Information System Monitoring — ✅ COMPLIANT
* **Control Family**: System and Information Integrity (SI)
* **DISA STIG Baseline**: `CAT I`
* **Control Objective**: Monitor system execution to detect attacks and indicators of potential compromise. Prohibits unsanitized runtime shell execution (command injection).
* **Evaluation Outcome**: No policy violations or vulnerabilities detected. Conforms to baseline.

### SI-7: Software, Firmware, and Information Integrity — ✅ COMPLIANT
* **Control Family**: System and Information Integrity (SI)
* **DISA STIG Baseline**: `CAT I`
* **Control Objective**: Employ integrity verification tools to detect unauthorized changes and prohibit use of unsupported, unmaintained, or EOL libraries and providers.
* **Evaluation Outcome**: No policy violations or vulnerabilities detected. Conforms to baseline.

