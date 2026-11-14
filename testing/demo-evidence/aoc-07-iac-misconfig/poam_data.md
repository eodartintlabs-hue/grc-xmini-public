# Plan of Action and Milestones (POA&M) Datapoints

> **Classification / Use**: Internal Compliance & Security Audit Deliverable (FedRAMP High / DoD CC SRG / SCR-SCN)  
> **Audit Target Identifier**: `aoc-07-iac-misconfig`  
> **Source Subject**: `Local Audit Evidence`  
> **Cryptographic Hash (SHA-256)**: `N/A`  
> **Review Session ID**: `N/A`  
> **Evaluation Timestamp**: `2026-11-14 22:18:22 UTC`  
> **Overall Audit Posture**: **NON-COMPLIANT (Active Findings Identified)**  

---

## 1. Executive Vulnerability & Risk Summary

The following risk rollup aggregates all findings detected across static AST analysis (Semgrep), dependency scanning (Grype/Trivy), secret scanning (Gitleaks), Infrastructure-as-Code policy validation (Checkov), and cryptographic library audits:

| Severity Level | DISA STIG Impact Category | Active Findings Count | Mandatory Remediation SLA | Compliance Status |
| :--- | :--- | :--- | :--- | :--- |
| **CRITICAL** | **Category I (CAT I)** | **12** | **30 Calendar Days** | ❌ Non-Compliant |
| **HIGH** | **Category II (CAT II)** | **12** | **30 Calendar Days** | ❌ Non-Compliant |
| **MEDIUM** | **Category III (CAT III)** | **0** | **90 Calendar Days** | ✅ Clear |
| **LOW / INFO** | Informational | **0** | 180 Calendar Days | ✅ Monitored |
| **Needs Verification** | Assessor / Runtime Review | **0** | *Excluded from POA&M* | — |
| **TOTAL (POA&M Weaknesses)** | — | **24** | — | **NON-COMPLIANT (Active Findings Identified)** |

---

## 2. Standardized POA&M Itemization Table

All line items below are structured for automated ingestion into formal Enterprise POA&M tracking systems (eMASS, Archer, ServiceNow GRC, Jira Security):

| POAM ID | Primary NIST Control | Weakness / Finding Name | Severity / CAT | Source Engine | Affected Asset / File | Target Completion | Status |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **POAM-021-04820A** | `AC-6, CM-6, SC-28` | Ensure that S3 bucket has a Public Access block | **CRITICAL / CAT I** | `Checkov` | `terraform/main.tf:16 (Resource: aws_s3_bucket.insecure_public_bucket)` | `2026-12-14` | Open |
| **POAM-018-17DFED** | `AC-6, CM-6, SC-28` | Ensure that an S3 bucket has a lifecycle configuration | **CRITICAL / CAT I** | `Checkov` | `terraform/main.tf:16 (Resource: aws_s3_bucket.insecure_public_bucket)` | `2026-12-14` | Open |
| **POAM-015-B6D1F0** | `AC-6, CM-6, SC-28` | Ensure S3 buckets should have event notifications enabled | **CRITICAL / CAT I** | `Checkov` | `terraform/main.tf:16 (Resource: aws_s3_bucket.insecure_public_bucket)` | `2026-12-14` | Open |
| **POAM-019-0B3628** | `AC-6, CM-6, SC-28` | Ensure that S3 bucket has cross-region replication enabled | **CRITICAL / CAT I** | `Checkov` | `terraform/main.tf:16 (Resource: aws_s3_bucket.insecure_public_bucket)` | `2026-12-14` | Open |
| **POAM-023-6BBF33** | `AC-6, CM-6, SC-28` | Ensure that S3 buckets are encrypted with KMS by default | **CRITICAL / CAT I** | `Checkov` | `terraform/main.tf:16 (Resource: aws_s3_bucket.insecure_public_bucket)` | `2026-12-14` | Open |
| **POAM-020-8B1207** | `AC-6, CM-6, SC-28` | Ensure the S3 bucket has access logging enabled | **CRITICAL / CAT I** | `Checkov` | `terraform/main.tf:16 (Resource: aws_s3_bucket.insecure_public_bucket)` | `2026-12-14` | Open |
| **POAM-017-19DF89** | `AC-6, CM-6, SC-28` | S3 Bucket has an ACL defined which allows public READ access. | **CRITICAL / CAT I** | `Checkov` | `terraform/main.tf:16 (Resource: aws_s3_bucket.insecure_public_bucket)` | `2026-12-14` | Open |
| **POAM-022-367174** | `AC-6, CM-6, SC-28` | Ensure all data stored in the S3 bucket have versioning enabled | **CRITICAL / CAT I** | `Checkov` | `terraform/main.tf:16 (Resource: aws_s3_bucket.insecure_public_bucket)` | `2026-12-14` | Open |
| **POAM-002-753715** | `AC-3, CM-6` | Ensure no security groups allow ingress from 0.0.0.0:0 to port 22 | **CRITICAL / CAT I** | `Checkov` | `terraform/main.tf:26 (Resource: aws_security_group.open_management_sg)` | `2026-12-14` | Open |
| **POAM-003-99FDCD** | `AC-3, CM-6` | Ensure no security groups allow ingress from 0.0.0.0:0 to port 3389 | **CRITICAL / CAT I** | `Checkov` | `terraform/main.tf:26 (Resource: aws_security_group.open_management_sg)` | `2026-12-14` | Open |
| **POAM-011-17C0CD** | `IA-2, SC-12` | Ensure IAM policies does not allow credentials exposure | **CRITICAL / CAT I** | `Checkov` | `terraform/main.tf:59 (Resource: aws_iam_policy.wildcard_admin_policy)` | `2026-12-14` | Open |
| **POAM-014-91A2B3** | `AC-6, CM-6, SC-28` | S3 Bucket has an ACL defined which allows public WRITE access. | **CRITICAL / CAT I** | `Checkov` | `terraform/main.tf:16 (Resource: aws_s3_bucket.insecure_public_bucket)` | `2026-12-14` | Open |
| **POAM-024-844297** | `CM-6` | Ensure AWS IAM policy does not allow full IAM privileges | **HIGH / CAT II** | `Checkov` | `terraform/main.tf:59 (Resource: aws_iam_policy.wildcard_admin_policy)` | `2026-12-14` | Open |
| **POAM-016-A5F0CD** | `CM-6` | Ensure that Security Groups are attached to another resource | **HIGH / CAT II** | `Checkov` | `terraform/main.tf:26 (Resource: aws_security_group.open_management_sg)` | `2026-12-14` | Open |
| **POAM-004-008AFB** | `SC-13, SC-28` | Ensure EBS Volume is encrypted by KMS using a customer managed Key (CMK) | **HIGH / CAT II** | `Checkov` | `terraform/main.tf:48 (Resource: aws_ebs_volume.unencrypted_volume)` | `2026-12-14` | Open |
| **POAM-010-ECDA6E** | `CM-6` | Ensure IAM policies does not allow privilege escalation | **HIGH / CAT II** | `Checkov` | `terraform/main.tf:59 (Resource: aws_iam_policy.wildcard_admin_policy)` | `2026-12-14` | Open |
| **POAM-013-CDEFF7** | `CM-6` | Ensure IAM policies does not allow data exfiltration | **HIGH / CAT II** | `Checkov` | `terraform/main.tf:59 (Resource: aws_iam_policy.wildcard_admin_policy)` | `2026-12-14` | Open |
| **POAM-006-08FF2B** | `CM-6` | Ensure IAM policies does not allow permissions management / resource exposure without constraints | **HIGH / CAT II** | `Checkov` | `terraform/main.tf:59 (Resource: aws_iam_policy.wildcard_admin_policy)` | `2026-12-14` | Open |
| **POAM-007-5035DB** | `CM-6` | Ensure IAM policies does not allow write access without constraints | **HIGH / CAT II** | `Checkov` | `terraform/main.tf:59 (Resource: aws_iam_policy.wildcard_admin_policy)` | `2026-12-14` | Open |
| **POAM-005-6114DD** | `SC-13, SC-28` | Ensure all data stored in the EBS is securely encrypted | **HIGH / CAT II** | `Checkov` | `terraform/main.tf:48 (Resource: aws_ebs_volume.unencrypted_volume)` | `2026-12-14` | Open |
| **POAM-008-70B241** | `CM-6` | Ensure no IAM policies documents allow "*" as a statement's resource for restrictable actions | **HIGH / CAT II** | `Checkov` | `terraform/main.tf:59 (Resource: aws_iam_policy.wildcard_admin_policy)` | `2026-12-14` | Open |
| **POAM-012-6BB462** | `CM-6` | Ensure IAM policies that allow full "*-*" administrative privileges are not created | **HIGH / CAT II** | `Checkov` | `terraform/main.tf:59 (Resource: aws_iam_policy.wildcard_admin_policy)` | `2026-12-14` | Open |
| **POAM-009-C2A891** | `CM-6` | Ensure no IAM policies documents allow "*" as a statement's actions | **HIGH / CAT II** | `Checkov` | `terraform/main.tf:59 (Resource: aws_iam_policy.wildcard_admin_policy)` | `2026-12-14` | Open |
| **POAM-001-62FB82** | `CM-6` | Base64 High Entropy String | **HIGH / CAT II** | `Checkov` | `ansible/playbook.yml:11 (Resource: c5012a876a4f516b230d4b0f1cdf6216a1b0f54b)` | `2026-12-14` | Open |

---

## 3. Remediation & Corrective Action Plans

### 3.1 [POAM-021-04820A] Ensure that S3 bucket has a Public Access block
* **Affected Asset**: `terraform/main.tf:16 (Resource: aws_s3_bucket.insecure_public_bucket)`
* **Governing Controls**: `AC-6, CM-6, SC-28` | **Area of Concern**: `AOC-07: Infrastructure-as-Code Misconfiguration`
* **Detection Identifier**: `CKV2_AWS_6` (Checkov)
* **Detailed Finding**: IaC policy violation on resource 'aws_s3_bucket.insecure_public_bucket': Ensure that S3 bucket has a Public Access block
* **Prescribed Action / Fix**: Harden Infrastructure-as-Code template according to CIS / DISA STIG benchmarks.
* **Scheduled Completion SLA**: `2026-12-14` (30 days)

### 3.2 [POAM-018-17DFED] Ensure that an S3 bucket has a lifecycle configuration
* **Affected Asset**: `terraform/main.tf:16 (Resource: aws_s3_bucket.insecure_public_bucket)`
* **Governing Controls**: `AC-6, CM-6, SC-28` | **Area of Concern**: `AOC-07: Infrastructure-as-Code Misconfiguration`
* **Detection Identifier**: `CKV2_AWS_61` (Checkov)
* **Detailed Finding**: IaC policy violation on resource 'aws_s3_bucket.insecure_public_bucket': Ensure that an S3 bucket has a lifecycle configuration
* **Prescribed Action / Fix**: Harden Infrastructure-as-Code template according to CIS / DISA STIG benchmarks.
* **Scheduled Completion SLA**: `2026-12-14` (30 days)

### 3.3 [POAM-015-B6D1F0] Ensure S3 buckets should have event notifications enabled
* **Affected Asset**: `terraform/main.tf:16 (Resource: aws_s3_bucket.insecure_public_bucket)`
* **Governing Controls**: `AC-6, CM-6, SC-28` | **Area of Concern**: `AOC-07: Infrastructure-as-Code Misconfiguration`
* **Detection Identifier**: `CKV2_AWS_62` (Checkov)
* **Detailed Finding**: IaC policy violation on resource 'aws_s3_bucket.insecure_public_bucket': Ensure S3 buckets should have event notifications enabled
* **Prescribed Action / Fix**: Harden Infrastructure-as-Code template according to CIS / DISA STIG benchmarks.
* **Scheduled Completion SLA**: `2026-12-14` (30 days)

### 3.4 [POAM-019-0B3628] Ensure that S3 bucket has cross-region replication enabled
* **Affected Asset**: `terraform/main.tf:16 (Resource: aws_s3_bucket.insecure_public_bucket)`
* **Governing Controls**: `AC-6, CM-6, SC-28` | **Area of Concern**: `AOC-07: Infrastructure-as-Code Misconfiguration`
* **Detection Identifier**: `CKV_AWS_144` (Checkov)
* **Detailed Finding**: IaC policy violation on resource 'aws_s3_bucket.insecure_public_bucket': Ensure that S3 bucket has cross-region replication enabled
* **Prescribed Action / Fix**: Harden Infrastructure-as-Code template according to CIS / DISA STIG benchmarks.
* **Scheduled Completion SLA**: `2026-12-14` (30 days)

### 3.5 [POAM-023-6BBF33] Ensure that S3 buckets are encrypted with KMS by default
* **Affected Asset**: `terraform/main.tf:16 (Resource: aws_s3_bucket.insecure_public_bucket)`
* **Governing Controls**: `AC-6, CM-6, SC-28` | **Area of Concern**: `AOC-07: Infrastructure-as-Code Misconfiguration`
* **Detection Identifier**: `CKV_AWS_145` (Checkov)
* **Detailed Finding**: IaC policy violation on resource 'aws_s3_bucket.insecure_public_bucket': Ensure that S3 buckets are encrypted with KMS by default
* **Prescribed Action / Fix**: Harden Infrastructure-as-Code template according to CIS / DISA STIG benchmarks.
* **Scheduled Completion SLA**: `2026-12-14` (30 days)

### 3.6 [POAM-020-8B1207] Ensure the S3 bucket has access logging enabled
* **Affected Asset**: `terraform/main.tf:16 (Resource: aws_s3_bucket.insecure_public_bucket)`
* **Governing Controls**: `AC-6, CM-6, SC-28` | **Area of Concern**: `AOC-07: Infrastructure-as-Code Misconfiguration`
* **Detection Identifier**: `CKV_AWS_18` (Checkov)
* **Detailed Finding**: IaC policy violation on resource 'aws_s3_bucket.insecure_public_bucket': Ensure the S3 bucket has access logging enabled
* **Prescribed Action / Fix**: Harden Infrastructure-as-Code template according to CIS / DISA STIG benchmarks.
* **Scheduled Completion SLA**: `2026-12-14` (30 days)

### 3.7 [POAM-017-19DF89] S3 Bucket has an ACL defined which allows public READ access.
* **Affected Asset**: `terraform/main.tf:16 (Resource: aws_s3_bucket.insecure_public_bucket)`
* **Governing Controls**: `AC-6, CM-6, SC-28` | **Area of Concern**: `AOC-07: Infrastructure-as-Code Misconfiguration`
* **Detection Identifier**: `CKV_AWS_20` (Checkov)
* **Detailed Finding**: IaC policy violation on resource 'aws_s3_bucket.insecure_public_bucket': S3 Bucket has an ACL defined which allows public READ access.
* **Prescribed Action / Fix**: Harden Infrastructure-as-Code template according to CIS / DISA STIG benchmarks.
* **Scheduled Completion SLA**: `2026-12-14` (30 days)

### 3.8 [POAM-022-367174] Ensure all data stored in the S3 bucket have versioning enabled
* **Affected Asset**: `terraform/main.tf:16 (Resource: aws_s3_bucket.insecure_public_bucket)`
* **Governing Controls**: `AC-6, CM-6, SC-28` | **Area of Concern**: `AOC-07: Infrastructure-as-Code Misconfiguration`
* **Detection Identifier**: `CKV_AWS_21` (Checkov)
* **Detailed Finding**: IaC policy violation on resource 'aws_s3_bucket.insecure_public_bucket': Ensure all data stored in the S3 bucket have versioning enabled
* **Prescribed Action / Fix**: Harden Infrastructure-as-Code template according to CIS / DISA STIG benchmarks.
* **Scheduled Completion SLA**: `2026-12-14` (30 days)

### 3.9 [POAM-002-753715] Ensure no security groups allow ingress from 0.0.0.0:0 to port 22
* **Affected Asset**: `terraform/main.tf:26 (Resource: aws_security_group.open_management_sg)`
* **Governing Controls**: `AC-3, CM-6` | **Area of Concern**: `AOC-07: Infrastructure-as-Code Misconfiguration`
* **Detection Identifier**: `CKV_AWS_24` (Checkov)
* **Detailed Finding**: IaC policy violation on resource 'aws_security_group.open_management_sg': Ensure no security groups allow ingress from 0.0.0.0:0 to port 22
* **Prescribed Action / Fix**: Harden Infrastructure-as-Code template according to CIS / DISA STIG benchmarks.
* **Scheduled Completion SLA**: `2026-12-14` (30 days)

### 3.10 [POAM-003-99FDCD] Ensure no security groups allow ingress from 0.0.0.0:0 to port 3389
* **Affected Asset**: `terraform/main.tf:26 (Resource: aws_security_group.open_management_sg)`
* **Governing Controls**: `AC-3, CM-6` | **Area of Concern**: `AOC-07: Infrastructure-as-Code Misconfiguration`
* **Detection Identifier**: `CKV_AWS_25` (Checkov)
* **Detailed Finding**: IaC policy violation on resource 'aws_security_group.open_management_sg': Ensure no security groups allow ingress from 0.0.0.0:0 to port 3389
* **Prescribed Action / Fix**: Harden Infrastructure-as-Code template according to CIS / DISA STIG benchmarks.
* **Scheduled Completion SLA**: `2026-12-14` (30 days)

### 3.11 [POAM-011-17C0CD] Ensure IAM policies does not allow credentials exposure
* **Affected Asset**: `terraform/main.tf:59 (Resource: aws_iam_policy.wildcard_admin_policy)`
* **Governing Controls**: `IA-2, SC-12` | **Area of Concern**: `AOC-02: Password Hygiene`
* **Detection Identifier**: `CKV_AWS_287` (Checkov)
* **Detailed Finding**: IaC policy violation on resource 'aws_iam_policy.wildcard_admin_policy': Ensure IAM policies does not allow credentials exposure
* **Prescribed Action / Fix**: Harden Infrastructure-as-Code template according to CIS / DISA STIG benchmarks.
* **Scheduled Completion SLA**: `2026-12-14` (30 days)

### 3.12 [POAM-014-91A2B3] S3 Bucket has an ACL defined which allows public WRITE access.
* **Affected Asset**: `terraform/main.tf:16 (Resource: aws_s3_bucket.insecure_public_bucket)`
* **Governing Controls**: `AC-6, CM-6, SC-28` | **Area of Concern**: `AOC-07: Infrastructure-as-Code Misconfiguration`
* **Detection Identifier**: `CKV_AWS_57` (Checkov)
* **Detailed Finding**: IaC policy violation on resource 'aws_s3_bucket.insecure_public_bucket': S3 Bucket has an ACL defined which allows public WRITE access.
* **Prescribed Action / Fix**: Harden Infrastructure-as-Code template according to CIS / DISA STIG benchmarks.
* **Scheduled Completion SLA**: `2026-12-14` (30 days)

### 3.13 [POAM-024-844297] Ensure AWS IAM policy does not allow full IAM privileges
* **Affected Asset**: `terraform/main.tf:59 (Resource: aws_iam_policy.wildcard_admin_policy)`
* **Governing Controls**: `CM-6` | **Area of Concern**: `AOC-07: Infrastructure-as-Code Misconfiguration`
* **Detection Identifier**: `CKV2_AWS_40` (Checkov)
* **Detailed Finding**: IaC policy violation on resource 'aws_iam_policy.wildcard_admin_policy': Ensure AWS IAM policy does not allow full IAM privileges
* **Prescribed Action / Fix**: Harden Infrastructure-as-Code template according to CIS / DISA STIG benchmarks.
* **Scheduled Completion SLA**: `2026-12-14` (30 days)

### 3.14 [POAM-016-A5F0CD] Ensure that Security Groups are attached to another resource
* **Affected Asset**: `terraform/main.tf:26 (Resource: aws_security_group.open_management_sg)`
* **Governing Controls**: `CM-6` | **Area of Concern**: `AOC-07: Infrastructure-as-Code Misconfiguration`
* **Detection Identifier**: `CKV2_AWS_5` (Checkov)
* **Detailed Finding**: IaC policy violation on resource 'aws_security_group.open_management_sg': Ensure that Security Groups are attached to another resource
* **Prescribed Action / Fix**: Harden Infrastructure-as-Code template according to CIS / DISA STIG benchmarks.
* **Scheduled Completion SLA**: `2026-12-14` (30 days)

### 3.15 [POAM-004-008AFB] Ensure EBS Volume is encrypted by KMS using a customer managed Key (CMK)
* **Affected Asset**: `terraform/main.tf:48 (Resource: aws_ebs_volume.unencrypted_volume)`
* **Governing Controls**: `SC-13, SC-28` | **Area of Concern**: `AOC-07: Infrastructure-as-Code Misconfiguration`
* **Detection Identifier**: `CKV_AWS_189` (Checkov)
* **Detailed Finding**: IaC policy violation on resource 'aws_ebs_volume.unencrypted_volume': Ensure EBS Volume is encrypted by KMS using a customer managed Key (CMK)
* **Prescribed Action / Fix**: Harden Infrastructure-as-Code template according to CIS / DISA STIG benchmarks.
* **Scheduled Completion SLA**: `2026-12-14` (30 days)

### 3.16 [POAM-010-ECDA6E] Ensure IAM policies does not allow privilege escalation
* **Affected Asset**: `terraform/main.tf:59 (Resource: aws_iam_policy.wildcard_admin_policy)`
* **Governing Controls**: `CM-6` | **Area of Concern**: `AOC-07: Infrastructure-as-Code Misconfiguration`
* **Detection Identifier**: `CKV_AWS_286` (Checkov)
* **Detailed Finding**: IaC policy violation on resource 'aws_iam_policy.wildcard_admin_policy': Ensure IAM policies does not allow privilege escalation
* **Prescribed Action / Fix**: Harden Infrastructure-as-Code template according to CIS / DISA STIG benchmarks.
* **Scheduled Completion SLA**: `2026-12-14` (30 days)

### 3.17 [POAM-013-CDEFF7] Ensure IAM policies does not allow data exfiltration
* **Affected Asset**: `terraform/main.tf:59 (Resource: aws_iam_policy.wildcard_admin_policy)`
* **Governing Controls**: `CM-6` | **Area of Concern**: `AOC-07: Infrastructure-as-Code Misconfiguration`
* **Detection Identifier**: `CKV_AWS_288` (Checkov)
* **Detailed Finding**: IaC policy violation on resource 'aws_iam_policy.wildcard_admin_policy': Ensure IAM policies does not allow data exfiltration
* **Prescribed Action / Fix**: Harden Infrastructure-as-Code template according to CIS / DISA STIG benchmarks.
* **Scheduled Completion SLA**: `2026-12-14` (30 days)

### 3.18 [POAM-006-08FF2B] Ensure IAM policies does not allow permissions management / resource exposure without constraints
* **Affected Asset**: `terraform/main.tf:59 (Resource: aws_iam_policy.wildcard_admin_policy)`
* **Governing Controls**: `CM-6` | **Area of Concern**: `AOC-07: Infrastructure-as-Code Misconfiguration`
* **Detection Identifier**: `CKV_AWS_289` (Checkov)
* **Detailed Finding**: IaC policy violation on resource 'aws_iam_policy.wildcard_admin_policy': Ensure IAM policies does not allow permissions management / resource exposure without constraints
* **Prescribed Action / Fix**: Harden Infrastructure-as-Code template according to CIS / DISA STIG benchmarks.
* **Scheduled Completion SLA**: `2026-12-14` (30 days)

### 3.19 [POAM-007-5035DB] Ensure IAM policies does not allow write access without constraints
* **Affected Asset**: `terraform/main.tf:59 (Resource: aws_iam_policy.wildcard_admin_policy)`
* **Governing Controls**: `CM-6` | **Area of Concern**: `AOC-07: Infrastructure-as-Code Misconfiguration`
* **Detection Identifier**: `CKV_AWS_290` (Checkov)
* **Detailed Finding**: IaC policy violation on resource 'aws_iam_policy.wildcard_admin_policy': Ensure IAM policies does not allow write access without constraints
* **Prescribed Action / Fix**: Harden Infrastructure-as-Code template according to CIS / DISA STIG benchmarks.
* **Scheduled Completion SLA**: `2026-12-14` (30 days)

### 3.20 [POAM-005-6114DD] Ensure all data stored in the EBS is securely encrypted
* **Affected Asset**: `terraform/main.tf:48 (Resource: aws_ebs_volume.unencrypted_volume)`
* **Governing Controls**: `SC-13, SC-28` | **Area of Concern**: `AOC-07: Infrastructure-as-Code Misconfiguration`
* **Detection Identifier**: `CKV_AWS_3` (Checkov)
* **Detailed Finding**: IaC policy violation on resource 'aws_ebs_volume.unencrypted_volume': Ensure all data stored in the EBS is securely encrypted
* **Prescribed Action / Fix**: Harden Infrastructure-as-Code template according to CIS / DISA STIG benchmarks.
* **Scheduled Completion SLA**: `2026-12-14` (30 days)

### 3.21 [POAM-008-70B241] Ensure no IAM policies documents allow "*" as a statement's resource for restrictable actions
* **Affected Asset**: `terraform/main.tf:59 (Resource: aws_iam_policy.wildcard_admin_policy)`
* **Governing Controls**: `CM-6` | **Area of Concern**: `AOC-07: Infrastructure-as-Code Misconfiguration`
* **Detection Identifier**: `CKV_AWS_355` (Checkov)
* **Detailed Finding**: IaC policy violation on resource 'aws_iam_policy.wildcard_admin_policy': Ensure no IAM policies documents allow "*" as a statement's resource for restrictable actions
* **Prescribed Action / Fix**: Harden Infrastructure-as-Code template according to CIS / DISA STIG benchmarks.
* **Scheduled Completion SLA**: `2026-12-14` (30 days)

### 3.22 [POAM-012-6BB462] Ensure IAM policies that allow full "*-*" administrative privileges are not created
* **Affected Asset**: `terraform/main.tf:59 (Resource: aws_iam_policy.wildcard_admin_policy)`
* **Governing Controls**: `CM-6` | **Area of Concern**: `AOC-07: Infrastructure-as-Code Misconfiguration`
* **Detection Identifier**: `CKV_AWS_62` (Checkov)
* **Detailed Finding**: IaC policy violation on resource 'aws_iam_policy.wildcard_admin_policy': Ensure IAM policies that allow full "*-*" administrative privileges are not created
* **Prescribed Action / Fix**: Harden Infrastructure-as-Code template according to CIS / DISA STIG benchmarks.
* **Scheduled Completion SLA**: `2026-12-14` (30 days)

### 3.23 [POAM-009-C2A891] Ensure no IAM policies documents allow "*" as a statement's actions
* **Affected Asset**: `terraform/main.tf:59 (Resource: aws_iam_policy.wildcard_admin_policy)`
* **Governing Controls**: `CM-6` | **Area of Concern**: `AOC-07: Infrastructure-as-Code Misconfiguration`
* **Detection Identifier**: `CKV_AWS_63` (Checkov)
* **Detailed Finding**: IaC policy violation on resource 'aws_iam_policy.wildcard_admin_policy': Ensure no IAM policies documents allow "*" as a statement's actions
* **Prescribed Action / Fix**: Harden Infrastructure-as-Code template according to CIS / DISA STIG benchmarks.
* **Scheduled Completion SLA**: `2026-12-14` (30 days)

### 3.24 [POAM-001-62FB82] Base64 High Entropy String
* **Affected Asset**: `ansible/playbook.yml:11 (Resource: c5012a876a4f516b230d4b0f1cdf6216a1b0f54b)`
* **Governing Controls**: `CM-6` | **Area of Concern**: `AOC-07: Infrastructure-as-Code Misconfiguration`
* **Detection Identifier**: `CKV_SECRET_6` (Checkov)
* **Detailed Finding**: IaC policy violation on resource 'c5012a876a4f516b230d4b0f1cdf6216a1b0f54b': Base64 High Entropy String
* **Prescribed Action / Fix**: Harden Infrastructure-as-Code template according to CIS / DISA STIG benchmarks.
* **Scheduled Completion SLA**: `2026-12-14` (30 days)

