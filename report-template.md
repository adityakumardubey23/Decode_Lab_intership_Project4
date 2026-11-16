# System Vulnerability Report — Analyst Template

## 1. Assessment details
- Assessment date/time:
- Assessor:
- Device / asset identifier (avoid personal data where possible):
- Operating system and version:
- Scope and authorization:

## 2. Executive summary
Summarize the system's observed security posture. State limitations and any checks that could not be completed.

## 3. Findings
Document at least three evidence-backed findings from the authorized assessment.

### Finding 1 — [Short title]
- **Category:** Identity / Patching / Human perimeter / Network / Endpoint / Application
- **Evidence:** [Exact non-sensitive observation; include command and timestamp if useful]
- **Impact:** [What could happen if the weakness is left unresolved?]
- **Risk:** Critical / High / Medium / Low / Informational
- **Recommended remediation:** [Specific, approved action]
- **Owner and target date:**
- **Verification after remediation:** [Evidence that the control now works]

### Finding 2 — [Short title]
- **Category:**
- **Evidence:**
- **Impact:**
- **Risk:**
- **Recommended remediation:**
- **Owner and target date:**
- **Verification after remediation:**

### Finding 3 — [Short title]
- **Category:**
- **Evidence:**
- **Impact:**
- **Risk:**
- **Recommended remediation:**
- **Owner and target date:**
- **Verification after remediation:**

## 4. Checklist review
- [ ] Strong, unique passphrases / password manager
- [ ] Phishing-resistant MFA or documented exception
- [ ] Guest and stale accounts reviewed
- [ ] Administrator access follows least privilege
- [ ] OS, browser, and application updates reviewed
- [ ] Unapproved applications and extensions reviewed
- [ ] Host firewall active with justified exceptions
- [ ] Full-disk encryption verified
- [ ] Screen lock and physical security reviewed
- [ ] Endpoint protection and backups verified

## 5. Limitations
List unavailable commands, inaccessible settings, unverified controls, and assumptions. `UNKNOWN` is not equivalent to `PASS`.

## 6. Conclusion
State the overall risk posture, priority remediation actions, and the date for reassessment.

> Never include passwords, MFA codes, recovery keys, private keys, personal documents, or other secrets in this report.
