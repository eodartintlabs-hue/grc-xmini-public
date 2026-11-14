# NIST SP 800-53 Rev. 5 Controls Traceability Matrix

> **Classification / Use**: Internal Compliance & Security Audit Deliverable (FedRAMP High / DoD RMF / SCR-SCN)  
> **Audit Target Identifier**: `aoc-07-iac-misconfig`  
> **Evaluation Timestamp**: `2026-11-14 22:18:22 UTC`  

---

## 1. Compliance Status by Control Family

| Control ID | Control Name | Control Family | DISA STIG Impact | Audit Findings Count | Compliance Status |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **AC-3** | Access Enforcement | Access Control (AC) | `CAT I` | 2 | ❌ **NON-COMPLIANT (2)** |
| **AC-6** | Least Privilege | Access Control (AC) | `CAT I` | 9 | ❌ **NON-COMPLIANT (9)** |
| **CM-6** | Configuration Settings | Configuration Management (CM) | `CAT II` | 21 | ❌ **NON-COMPLIANT (21)** |
| **CM-8** | Information System Component Inventory | Configuration Management (CM) | `CAT II` | 0 | ⚪ **NOT ASSESSED** |
| **IA-2** | Identification and Authentication (Organizational Users) | Identification and Authentication (IA) | `CAT I` | 1 | ❌ **NON-COMPLIANT (1)** |
| **IA-7** | Cryptographic Module Authentication | Identification and Authentication (IA) | `CAT II` | 0 | ✅ **COMPLIANT** |
| **RA-5** | Vulnerability Monitoring and Scanning | Risk Assessment (RA) | `CAT I` | 0 | ⚪ **NOT ASSESSED** |
| **SC-12** | Cryptographic Key Establishment and Management | System and Communications Protection (SC) | `CAT I` | 1 | ❌ **NON-COMPLIANT (1)** |
| **SC-13** | Cryptographic Protection (FIPS 140 Validation) | System and Communications Protection (SC) | `CAT I` | 2 | ❌ **NON-COMPLIANT (2)** |
| **SC-28** | Protection of Information at Rest | System and Communications Protection (SC) | `CAT I` | 11 | ❌ **NON-COMPLIANT (11)** |
| **SC-8** | Transmission Confidentiality and Integrity | System and Communications Protection (SC) | `CAT I` | 0 | ✅ **COMPLIANT** |
| **SI-10** | Information Input Validation | System and Information Integrity (SI) | `CAT I` | 0 | ✅ **COMPLIANT** |
| **SI-16** | Memory Protection | System and Information Integrity (SI) | `CAT II` | 0 | ⚪ **NOT ASSESSED** |
| **SI-17** | Fail-Secure / Secure Communications Initiation | System and Information Integrity (SI) | `CAT I` | 0 | ✅ **COMPLIANT** |
| **SI-2** | Flaw Remediation | System and Information Integrity (SI) | `CAT I` | 0 | ✅ **COMPLIANT** |
| **SI-4** | Information System Monitoring | System and Information Integrity (SI) | `CAT I` | 0 | ✅ **COMPLIANT** |
| **SI-7** | Software, Firmware, and Information Integrity | System and Information Integrity (SI) | `CAT I` | 0 | ✅ **COMPLIANT** |

---

## 2. Detailed Control Breakdown & Evidence Mapping

### AC-3: Access Enforcement — ❌ NON-COMPLIANT
* **Control Family**: Access Control (AC)
* **DISA STIG Baseline**: `CAT I`
* **Control Objective**: Enforce approved authorizations for logical access to information and system resources (e.g. security group ingress rules).
* **Evaluation Outcome**: Deficiencies detected out-of-band requiring remediation.

| Finding ID | Source Engine | Rule / CVE ID | Affected Location | Severity |
| :--- | :--- | :--- | :--- | :--- |
| **POAM-002-753715** | `Checkov` | `CKV_AWS_24` | `terraform/main.tf:26 (Resource: aws_security_group.open_management_sg)` | **CRITICAL** |
| **POAM-003-99FDCD** | `Checkov` | `CKV_AWS_25` | `terraform/main.tf:26 (Resource: aws_security_group.open_management_sg)` | **CRITICAL** |

### AC-6: Least Privilege — ❌ NON-COMPLIANT
* **Control Family**: Access Control (AC)
* **DISA STIG Baseline**: `CAT I`
* **Control Objective**: Employ the principle of least privilege, allowing only authorized accesses necessary for accomplishing assigned tasks (e.g., prohibiting public cloud buckets).
* **Evaluation Outcome**: Deficiencies detected out-of-band requiring remediation.

| Finding ID | Source Engine | Rule / CVE ID | Affected Location | Severity |
| :--- | :--- | :--- | :--- | :--- |
| **POAM-021-04820A** | `Checkov` | `CKV2_AWS_6` | `terraform/main.tf:16 (Resource: aws_s3_bucket.insecure_public_bucket)` | **CRITICAL** |
| **POAM-018-17DFED** | `Checkov` | `CKV2_AWS_61` | `terraform/main.tf:16 (Resource: aws_s3_bucket.insecure_public_bucket)` | **CRITICAL** |
| **POAM-015-B6D1F0** | `Checkov` | `CKV2_AWS_62` | `terraform/main.tf:16 (Resource: aws_s3_bucket.insecure_public_bucket)` | **CRITICAL** |
| **POAM-019-0B3628** | `Checkov` | `CKV_AWS_144` | `terraform/main.tf:16 (Resource: aws_s3_bucket.insecure_public_bucket)` | **CRITICAL** |
| **POAM-023-6BBF33** | `Checkov` | `CKV_AWS_145` | `terraform/main.tf:16 (Resource: aws_s3_bucket.insecure_public_bucket)` | **CRITICAL** |
| **POAM-020-8B1207** | `Checkov` | `CKV_AWS_18` | `terraform/main.tf:16 (Resource: aws_s3_bucket.insecure_public_bucket)` | **CRITICAL** |
| **POAM-017-19DF89** | `Checkov` | `CKV_AWS_20` | `terraform/main.tf:16 (Resource: aws_s3_bucket.insecure_public_bucket)` | **CRITICAL** |
| **POAM-022-367174** | `Checkov` | `CKV_AWS_21` | `terraform/main.tf:16 (Resource: aws_s3_bucket.insecure_public_bucket)` | **CRITICAL** |
| **POAM-014-91A2B3** | `Checkov` | `CKV_AWS_57` | `terraform/main.tf:16 (Resource: aws_s3_bucket.insecure_public_bucket)` | **CRITICAL** |

### CM-6: Configuration Settings — ❌ NON-COMPLIANT
* **Control Family**: Configuration Management (CM)
* **DISA STIG Baseline**: `CAT II`
* **Control Objective**: Establish and document mandatory configuration settings for IT products using hardened baselines (DISA STIG / CIS).
* **Evaluation Outcome**: Deficiencies detected out-of-band requiring remediation.

| Finding ID | Source Engine | Rule / CVE ID | Affected Location | Severity |
| :--- | :--- | :--- | :--- | :--- |
| **POAM-021-04820A** | `Checkov` | `CKV2_AWS_6` | `terraform/main.tf:16 (Resource: aws_s3_bucket.insecure_public_bucket)` | **CRITICAL** |
| **POAM-018-17DFED** | `Checkov` | `CKV2_AWS_61` | `terraform/main.tf:16 (Resource: aws_s3_bucket.insecure_public_bucket)` | **CRITICAL** |
| **POAM-015-B6D1F0** | `Checkov` | `CKV2_AWS_62` | `terraform/main.tf:16 (Resource: aws_s3_bucket.insecure_public_bucket)` | **CRITICAL** |
| **POAM-019-0B3628** | `Checkov` | `CKV_AWS_144` | `terraform/main.tf:16 (Resource: aws_s3_bucket.insecure_public_bucket)` | **CRITICAL** |
| **POAM-023-6BBF33** | `Checkov` | `CKV_AWS_145` | `terraform/main.tf:16 (Resource: aws_s3_bucket.insecure_public_bucket)` | **CRITICAL** |
| **POAM-020-8B1207** | `Checkov` | `CKV_AWS_18` | `terraform/main.tf:16 (Resource: aws_s3_bucket.insecure_public_bucket)` | **CRITICAL** |
| **POAM-017-19DF89** | `Checkov` | `CKV_AWS_20` | `terraform/main.tf:16 (Resource: aws_s3_bucket.insecure_public_bucket)` | **CRITICAL** |
| **POAM-022-367174** | `Checkov` | `CKV_AWS_21` | `terraform/main.tf:16 (Resource: aws_s3_bucket.insecure_public_bucket)` | **CRITICAL** |
| **POAM-002-753715** | `Checkov` | `CKV_AWS_24` | `terraform/main.tf:26 (Resource: aws_security_group.open_management_sg)` | **CRITICAL** |
| **POAM-003-99FDCD** | `Checkov` | `CKV_AWS_25` | `terraform/main.tf:26 (Resource: aws_security_group.open_management_sg)` | **CRITICAL** |
| **POAM-014-91A2B3** | `Checkov` | `CKV_AWS_57` | `terraform/main.tf:16 (Resource: aws_s3_bucket.insecure_public_bucket)` | **CRITICAL** |
| **POAM-024-844297** | `Checkov` | `CKV2_AWS_40` | `terraform/main.tf:59 (Resource: aws_iam_policy.wildcard_admin_policy)` | **HIGH** |
| **POAM-016-A5F0CD** | `Checkov` | `CKV2_AWS_5` | `terraform/main.tf:26 (Resource: aws_security_group.open_management_sg)` | **HIGH** |
| **POAM-010-ECDA6E** | `Checkov` | `CKV_AWS_286` | `terraform/main.tf:59 (Resource: aws_iam_policy.wildcard_admin_policy)` | **HIGH** |
| **POAM-013-CDEFF7** | `Checkov` | `CKV_AWS_288` | `terraform/main.tf:59 (Resource: aws_iam_policy.wildcard_admin_policy)` | **HIGH** |
| **POAM-006-08FF2B** | `Checkov` | `CKV_AWS_289` | `terraform/main.tf:59 (Resource: aws_iam_policy.wildcard_admin_policy)` | **HIGH** |
| **POAM-007-5035DB** | `Checkov` | `CKV_AWS_290` | `terraform/main.tf:59 (Resource: aws_iam_policy.wildcard_admin_policy)` | **HIGH** |
| **POAM-008-70B241** | `Checkov` | `CKV_AWS_355` | `terraform/main.tf:59 (Resource: aws_iam_policy.wildcard_admin_policy)` | **HIGH** |
| **POAM-012-6BB462** | `Checkov` | `CKV_AWS_62` | `terraform/main.tf:59 (Resource: aws_iam_policy.wildcard_admin_policy)` | **HIGH** |
| **POAM-009-C2A891** | `Checkov` | `CKV_AWS_63` | `terraform/main.tf:59 (Resource: aws_iam_policy.wildcard_admin_policy)` | **HIGH** |
| **POAM-001-62FB82** | `Checkov` | `CKV_SECRET_6` | `ansible/playbook.yml:11 (Resource: c5012a876a4f516b230d4b0f1cdf6216a1b0f54b)` | **HIGH** |

### CM-8: Information System Component Inventory — ⚪ NOT ASSESSED
* **Control Family**: Configuration Management (CM)
* **DISA STIG Baseline**: `CAT II`
* **Control Objective**: Develop and document an inventory of information system components (SBOM) detailing name, version, and license.
* **Evaluation Outcome**: No evidence file present from assessing scanner(s) (Grype, Trivy, SBOM).

### IA-2: Identification and Authentication (Organizational Users) — ❌ NON-COMPLIANT
* **Control Family**: Identification and Authentication (IA)
* **DISA STIG Baseline**: `CAT I`
* **Control Objective**: Uniquely identify and authenticate organizational users (or processes acting on their behalf). Prohibits hardcoded static credentials, default passwords, and unmanaged API tokens.
* **Evaluation Outcome**: Deficiencies detected out-of-band requiring remediation.

| Finding ID | Source Engine | Rule / CVE ID | Affected Location | Severity |
| :--- | :--- | :--- | :--- | :--- |
| **POAM-011-17C0CD** | `Checkov` | `CKV_AWS_287` | `terraform/main.tf:59 (Resource: aws_iam_policy.wildcard_admin_policy)` | **CRITICAL** |

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

### SC-12: Cryptographic Key Establishment and Management — ❌ NON-COMPLIANT
* **Control Family**: System and Communications Protection (SC)
* **DISA STIG Baseline**: `CAT I`
* **Control Objective**: Establish and manage cryptographic keys in accordance with NIST SP 800-56A/B and applicable FIPS guidelines.
* **Evaluation Outcome**: Deficiencies detected out-of-band requiring remediation.

| Finding ID | Source Engine | Rule / CVE ID | Affected Location | Severity |
| :--- | :--- | :--- | :--- | :--- |
| **POAM-011-17C0CD** | `Checkov` | `CKV_AWS_287` | `terraform/main.tf:59 (Resource: aws_iam_policy.wildcard_admin_policy)` | **CRITICAL** |

### SC-13: Cryptographic Protection (FIPS 140 Validation) — ❌ NON-COMPLIANT
* **Control Family**: System and Communications Protection (SC)
* **DISA STIG Baseline**: `CAT I`
* **Control Objective**: Implement cryptographic modules validated under FIPS 140-2 / 140-3. Enforce OS kernel FIPS mode and validated security providers.
* **Evaluation Outcome**: Deficiencies detected out-of-band requiring remediation.

| Finding ID | Source Engine | Rule / CVE ID | Affected Location | Severity |
| :--- | :--- | :--- | :--- | :--- |
| **POAM-004-008AFB** | `Checkov` | `CKV_AWS_189` | `terraform/main.tf:48 (Resource: aws_ebs_volume.unencrypted_volume)` | **HIGH** |
| **POAM-005-6114DD** | `Checkov` | `CKV_AWS_3` | `terraform/main.tf:48 (Resource: aws_ebs_volume.unencrypted_volume)` | **HIGH** |

### SC-28: Protection of Information at Rest — ❌ NON-COMPLIANT
* **Control Family**: System and Communications Protection (SC)
* **DISA STIG Baseline**: `CAT I`
* **Control Objective**: Protect the confidentiality and integrity of information at rest (e.g., EBS volume encryption, S3 SSE-KMS).
* **Evaluation Outcome**: Deficiencies detected out-of-band requiring remediation.

| Finding ID | Source Engine | Rule / CVE ID | Affected Location | Severity |
| :--- | :--- | :--- | :--- | :--- |
| **POAM-021-04820A** | `Checkov` | `CKV2_AWS_6` | `terraform/main.tf:16 (Resource: aws_s3_bucket.insecure_public_bucket)` | **CRITICAL** |
| **POAM-018-17DFED** | `Checkov` | `CKV2_AWS_61` | `terraform/main.tf:16 (Resource: aws_s3_bucket.insecure_public_bucket)` | **CRITICAL** |
| **POAM-015-B6D1F0** | `Checkov` | `CKV2_AWS_62` | `terraform/main.tf:16 (Resource: aws_s3_bucket.insecure_public_bucket)` | **CRITICAL** |
| **POAM-019-0B3628** | `Checkov` | `CKV_AWS_144` | `terraform/main.tf:16 (Resource: aws_s3_bucket.insecure_public_bucket)` | **CRITICAL** |
| **POAM-023-6BBF33** | `Checkov` | `CKV_AWS_145` | `terraform/main.tf:16 (Resource: aws_s3_bucket.insecure_public_bucket)` | **CRITICAL** |
| **POAM-020-8B1207** | `Checkov` | `CKV_AWS_18` | `terraform/main.tf:16 (Resource: aws_s3_bucket.insecure_public_bucket)` | **CRITICAL** |
| **POAM-017-19DF89** | `Checkov` | `CKV_AWS_20` | `terraform/main.tf:16 (Resource: aws_s3_bucket.insecure_public_bucket)` | **CRITICAL** |
| **POAM-022-367174** | `Checkov` | `CKV_AWS_21` | `terraform/main.tf:16 (Resource: aws_s3_bucket.insecure_public_bucket)` | **CRITICAL** |
| **POAM-014-91A2B3** | `Checkov` | `CKV_AWS_57` | `terraform/main.tf:16 (Resource: aws_s3_bucket.insecure_public_bucket)` | **CRITICAL** |
| **POAM-004-008AFB** | `Checkov` | `CKV_AWS_189` | `terraform/main.tf:48 (Resource: aws_ebs_volume.unencrypted_volume)` | **HIGH** |
| **POAM-005-6114DD** | `Checkov` | `CKV_AWS_3` | `terraform/main.tf:48 (Resource: aws_ebs_volume.unencrypted_volume)` | **HIGH** |

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

