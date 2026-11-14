# Custom Baseline Ruleset Validation Audit Log

> **Classification / Use**: Internal Compliance & Security Audit Deliverable (Ruleset Verification Log)  
> **Audit Target Identifier**: `6dec88c8940840c0ee7bcea50a24226c50ddffd2be92ad8b107831996f9f67a2`  
> **Ruleset File**: `rules/custom-baseline-ruleset.yaml`  
> **Evaluation Timestamp**: `2026-11-14 22:18:22 UTC`  
> **Semgrep Evidence Status**: `ASSESSED (semgrep_findings.json loaded)`  

---

## 1. Execution Summary

The custom Semgrep baseline defines **37 high-assurance security rules** spanning password hygiene, cryptography, command injection, TLS validation, and infrastructure hardening across Go, Java, Python, and JavaScript.

| Metric | Value | Audit Significance |
| :--- | :--- | :--- |
| **Total Evaluated Rules** | **37 / 37** | Complete baseline coverage |
| **Triggered Rules (Violations Detected)** | **4** | Active findings requiring engineering triage |
| **Clean Rules (Passed Checks)** | **33** | Controls verified without violation |
| **Total Discovered Code Defects** | **9** | Raw AST match instances |

---

## 2. Itemized Rule Evaluation Audit Trail

| Rule Identifier | Target AOC | Governing NIST Control | Severity | Audit Status | Triggered Matches |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `grc-aoc02-python-hardcoded-credentials` | AOC-02: Password Hygiene | `IA-2` | `ERROR` | ✅ **PASSED (CLEAN)** | **0** |
| `grc-aoc02-go-hardcoded-credentials` | AOC-02: Password Hygiene | `IA-2` | `ERROR` | ✅ **PASSED (CLEAN)** | **0** |
| `grc-aoc02-java-hardcoded-credentials` | AOC-02: Password Hygiene | `IA-2` | `ERROR` | ✅ **PASSED (CLEAN)** | **0** |
| `grc-aoc02-javascript-hardcoded-credentials` | AOC-02: Password Hygiene | `IA-2` | `ERROR` | ✅ **PASSED (CLEAN)** | **0** |
| `grc-aoc03-python-weak-hashing` | AOC-03: Weak Encryption Check | `SC-13` | `WARNING` | ✅ **PASSED (CLEAN)** | **0** |
| `grc-aoc03-python-weak-ciphers` | AOC-03: Weak Encryption Check | `SC-13` | `ERROR` | ✅ **PASSED (CLEAN)** | **0** |
| `grc-aoc03-go-weak-hashing` | AOC-03: Weak Encryption Check | `SC-13` | `WARNING` | ✅ **PASSED (CLEAN)** | **0** |
| `grc-aoc03-go-weak-ciphers` | AOC-03: Weak Encryption Check | `SC-13` | `ERROR` | ✅ **PASSED (CLEAN)** | **0** |
| `grc-aoc03-java-weak-hashing` | AOC-03: Weak Encryption Check | `SC-13` | `WARNING` | ✅ **PASSED (CLEAN)** | **0** |
| `grc-aoc03-java-weak-ciphers` | AOC-03: Weak Encryption Check | `SC-13` | `ERROR` | ✅ **PASSED (CLEAN)** | **0** |
| `grc-aoc03-javascript-weak-hashing` | AOC-03: Weak Encryption Check | `SC-13` | `WARNING` | ✅ **PASSED (CLEAN)** | **0** |
| `grc-aoc03-javascript-weak-ciphers` | AOC-03: Weak Encryption Check | `SC-13` | `ERROR` | ✅ **PASSED (CLEAN)** | **0** |
| `grc-aoc04-python-command-injection` | AOC-04: Command Injection | `SI-4` | `ERROR` | ❌ **TRIGGERED** | **3** |
| `grc-aoc04-go-command-injection` | AOC-04: Command Injection | `SI-4` | `ERROR` | ❌ **TRIGGERED** | **2** |
| `grc-aoc04-java-command-injection` | AOC-04: Command Injection | `SI-4` | `ERROR` | ❌ **TRIGGERED** | **2** |
| `grc-aoc04-javascript-command-injection` | AOC-04: Command Injection | `SI-4` | `ERROR` | ❌ **TRIGGERED** | **2** |
| `grc-aoc05-python-disabled-tls-verification` | AOC-05: Improper TLS | `SI-17` | `ERROR` | ✅ **PASSED (CLEAN)** | **0** |
| `grc-aoc05-go-insecure-tls` | AOC-05: Improper TLS | `SI-17` | `ERROR` | ✅ **PASSED (CLEAN)** | **0** |
| `grc-aoc05-java-insecure-trust-manager` | AOC-05: Improper TLS | `SI-17` | `ERROR` | ✅ **PASSED (CLEAN)** | **0** |
| `grc-aoc05-javascript-disabled-tls-check` | AOC-05: Improper TLS | `SI-17` | `ERROR` | ✅ **PASSED (CLEAN)** | **0** |
| `grc-aoc06-generic-embedded-private-keys` | AOC-06: Secrets Management | `SC-12` | `ERROR` | ✅ **PASSED (CLEAN)** | **0** |
| `grc-aoc09-python-deprecated-crypto-module` | AOC-09: Crypto Dependencies on Unsupported Libraries | `SI-7` | `ERROR` | ✅ **PASSED (CLEAN)** | **0** |
| `grc-aoc09-go-deprecated-crypto-module` | AOC-09: Crypto Dependencies on Unsupported Libraries | `SI-7` | `WARNING` | ✅ **PASSED (CLEAN)** | **0** |
| `grc-aoc09-java-deprecated-crypto-provider` | AOC-09: Crypto Dependencies on Unsupported Libraries | `SI-7` | `WARNING` | ✅ **PASSED (CLEAN)** | **0** |
| `grc-aoc09-javascript-deprecated-crypto-package` | AOC-09: Crypto Dependencies on Unsupported Libraries | `SI-7` | `WARNING` | ✅ **PASSED (CLEAN)** | **0** |
| `grc-aoc10-python-unsafe-deserialization` | AOC-10: CRITICAL Severity Findings | `RA-5` | `ERROR` | ✅ **PASSED (CLEAN)** | **0** |
| `grc-aoc10-java-unsafe-deserialization` | AOC-10: CRITICAL Severity Findings | `RA-5` | `ERROR` | ✅ **PASSED (CLEAN)** | **0** |
| `grc-aoc10-javascript-dangerous-eval` | AOC-10: CRITICAL Severity Findings | `RA-5` | `ERROR` | ✅ **PASSED (CLEAN)** | **0** |
| `grc-aoc10-go-unsafe-pointer` | AOC-10: CRITICAL Severity Findings | `RA-5` | `ERROR` | ✅ **PASSED (CLEAN)** | **0** |
| `grc-aoc11-python-debug-exposed` | AOC-11: Violation of Category I STIGs | `SI-2` | `ERROR` | ✅ **PASSED (CLEAN)** | **0** |
| `grc-aoc11-go-plaintext-http-listener` | AOC-11: Violation of Category I STIGs | `SI-2` | `ERROR` | ✅ **PASSED (CLEAN)** | **0** |
| `grc-aoc11-java-xxe-processing` | AOC-11: Violation of Category I STIGs | `SI-2` | `ERROR` | ✅ **PASSED (CLEAN)** | **0** |
| `grc-aoc11-javascript-insecure-cookie-attributes` | AOC-11: Violation of Category I STIGs | `SI-2` | `ERROR` | ✅ **PASSED (CLEAN)** | **0** |
| `grc-aoc140-python-stdout-credential-leak` | AOC-140: Organization Specific Controls | `CM-6` | `WARNING` | ✅ **PASSED (CLEAN)** | **0** |
| `grc-aoc140-go-stdout-credential-leak` | AOC-140: Organization Specific Controls | `CM-6` | `WARNING` | ✅ **PASSED (CLEAN)** | **0** |
| `grc-aoc140-java-stdout-credential-leak` | AOC-140: Organization Specific Controls | `CM-6` | `WARNING` | ✅ **PASSED (CLEAN)** | **0** |
| `grc-aoc140-javascript-console-credential-leak` | AOC-140: Organization Specific Controls | `CM-6` | `WARNING` | ✅ **PASSED (CLEAN)** | **0** |

---

## 3. Discovered Violation Code Locations

* **Rule**: `rules.grc-aoc04-go-command-injection` (AOC-04: Command Injection)
  * **Location**: `src/executor.go:10`
  * **Message**: AOC-04 [NIST SP 800-53 SI-4]: Arbitrary shell execution invocation detected in Go. Execute binaries directly with separate arguments.
* **Rule**: `rules.grc-aoc04-go-command-injection` (AOC-04: Command Injection)
  * **Location**: `src/executor.go:15`
  * **Message**: AOC-04 [NIST SP 800-53 SI-4]: Arbitrary shell execution invocation detected in Go. Execute binaries directly with separate arguments.
* **Rule**: `rules.grc-aoc04-java-command-injection` (AOC-04: Command Injection)
  * **Location**: `src/CommandExecutor.java:11`
  * **Message**: AOC-04 [NIST SP 800-53 SI-4]: Dynamic command execution in Java via Runtime or ProcessBuilder. Sanitize input and pass arguments as discrete array elements.
* **Rule**: `rules.grc-aoc04-java-command-injection` (AOC-04: Command Injection)
  * **Location**: `src/CommandExecutor.java:15`
  * **Message**: AOC-04 [NIST SP 800-53 SI-4]: Dynamic command execution in Java via Runtime or ProcessBuilder. Sanitize input and pass arguments as discrete array elements.
* **Rule**: `rules.grc-aoc04-javascript-command-injection` (AOC-04: Command Injection)
  * **Location**: `src/system.js:15`
  * **Message**: AOC-04 [NIST SP 800-53 SI-4]: Potential command injection in Node.js child_process.exec. Prefer child_process.execFile with parameter arrays.
* **Rule**: `rules.grc-aoc04-javascript-command-injection` (AOC-04: Command Injection)
  * **Location**: `src/system.js:5`
  * **Message**: AOC-04 [NIST SP 800-53 SI-4]: Potential command injection in Node.js child_process.exec. Prefer child_process.execFile with parameter arrays.
* **Rule**: `rules.grc-aoc04-python-command-injection` (AOC-04: Command Injection)
  * **Location**: `src/runner.py:14`
  * **Message**: AOC-04 [NIST SP 800-53 SI-4]: Dynamic command execution via shell invocation in Python. Use subprocess.run with arguments list and shell=False.
* **Rule**: `rules.grc-aoc04-python-command-injection` (AOC-04: Command Injection)
  * **Location**: `src/runner.py:20`
  * **Message**: AOC-04 [NIST SP 800-53 SI-4]: Dynamic command execution via shell invocation in Python. Use subprocess.run with arguments list and shell=False.
* **Rule**: `rules.grc-aoc04-python-command-injection` (AOC-04: Command Injection)
  * **Location**: `src/runner.py:28`
  * **Message**: AOC-04 [NIST SP 800-53 SI-4]: Dynamic command execution via shell invocation in Python. Use subprocess.run with arguments list and shell=False.
