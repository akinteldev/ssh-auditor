"""Cryptography-related audit rules.

Checks for weak ciphers, key exchange algorithms, and host key
algorithms in sshd_config.
"""

from __future__ import annotations

from typing import Any

from ssh_auditor.rules.base import Finding, Rule, Severity


class ThreeDesCipherRule(Rule):
    """3DES-CBC must NOT be in the Ciphers list."""

    rule_id = "CRYPTO-001"
    severity = Severity.HIGH
    description = "3DES-CBC cipher is enabled (deprecated and vulnerable)"
    remediation = "Remove '3des-cbc' from the Ciphers list in sshd_config"
    cis_reference = "CIS 5.2.14"

    def check(self, directives: list[dict[str, Any]]) -> list[Finding]:
        for d in directives:
            if d["directive"].lower() == "ciphers":
                ciphers = [c.strip().lower() for c in d["value"].split(",")]
                if "3des-cbc" in ciphers:
                    return [
                        Finding(
                            rule_id=self.rule_id,
                            directive="Ciphers",
                            severity=self.severity,
                            description="3DES-CBC cipher is enabled (deprecated and vulnerable)",
                            remediation=self.remediation,
                            cis_reference=self.cis_reference,
                        )
                    ]
        return []


class CBCModeCipherRule(Rule):
    """Any CBC-mode cipher should be flagged as weak."""

    rule_id = "CRYPTO-002"
    severity = Severity.HIGH
    description = "CBC-mode cipher is enabled (vulnerable to padding oracle attacks)"
    remediation = "Remove all CBC-mode ciphers from the Ciphers list; prefer GCM or ChaCha20"
    cis_reference = "CIS 5.2.14"

    def check(self, directives: list[dict[str, Any]]) -> list[Finding]:
        for d in directives:
            if d["directive"].lower() == "ciphers":
                ciphers = [c.strip().lower() for c in d["value"].split(",")]
                cbc_ciphers = [c for c in ciphers if "-cbc" in c]
                if cbc_ciphers:
                    return [
                        Finding(
                            rule_id=self.rule_id,
                            directive="Ciphers",
                            severity=self.severity,
                            description=f"CBC-mode ciphers detected: {', '.join(cbc_ciphers)}",
                            remediation=self.remediation,
                            cis_reference=self.cis_reference,
                        )
                    ]
        return []


class WeakKexAlgorithmsRule(Rule):
    """Diffie-Hellman group1 or group14-sha1 should NOT be in KexAlgorithms."""

    rule_id = "CRYPTO-003"
    severity = Severity.MEDIUM
    description = "Weak key exchange algorithm is enabled"
    remediation = (
        "Remove 'diffie-hellman-group1-sha1' and "
        "'diffie-hellman-group14-sha1' from KexAlgorithms; "
        "use 'curve25519-sha256' instead"
    )
    cis_reference = "CIS 5.2.14"

    def check(self, directives: list[dict[str, Any]]) -> list[Finding]:
        weak_kex = {"diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1"}
        for d in directives:
            if d["directive"].lower() == "kexalgorithms":
                kex = [k.strip().lower() for k in d["value"].split(",")]
                found_weak = weak_kex & set(kex)
                if found_weak:
                    return [
                        Finding(
                            rule_id=self.rule_id,
                            directive="KexAlgorithms",
                            severity=self.severity,
                            description=f"Weak key exchange algorithms detected: {', '.join(sorted(found_weak))}",
                            remediation=self.remediation,
                            cis_reference=self.cis_reference,
                        )
                    ]
        return []


class DSAHostKeyRule(Rule):
    """ssh-dss should NOT be in HostKeyAlgorithms (deprecated DSA)."""

    rule_id = "CRYPTO-004"
    severity = Severity.MEDIUM
    description = "DSA host key algorithm (ssh-dss) is enabled"
    remediation = "Remove 'ssh-dss' from HostKeyAlgorithms; use ssh-ed25519 or rsa-sha2-512"
    cis_reference = "CIS 5.2.14"

    def check(self, directives: list[dict[str, Any]]) -> list[Finding]:
        for d in directives:
            if d["directive"].lower() == "hostkeyalgorithms":
                algorithms = [a.strip().lower() for a in d["value"].split(",")]
                if "ssh-dss" in algorithms:
                    return [
                        Finding(
                            rule_id=self.rule_id,
                            directive="HostKeyAlgorithms",
                            severity=self.severity,
                            description="DSA host key algorithm (ssh-dss) is enabled",
                            remediation=self.remediation,
                            cis_reference=self.cis_reference,
                        )
                    ]
        return []


class PreferEd25519Rule(Rule):
    """Should prefer Ed25519 or RSA keys over ECDSA."""

    rule_id = "CRYPTO-005"
    severity = Severity.LOW
    description = "Ed25519 or RSA host key algorithm not preferred in HostKeyAlgorithms"
    remediation = "Add 'ssh-ed25519' or 'rsa-sha2-512' to the beginning of HostKeyAlgorithms"
    cis_reference = "CIS 5.2.14"

    def check(self, directives: list[dict[str, Any]]) -> list[Finding]:
        for d in directives:
            if d["directive"].lower() == "hostkeyalgorithms":
                algorithms = [a.strip().lower() for a in d["value"].split(",")]
                preferred = {"ssh-ed25519", "rsa-sha2-512"}
                if not (preferred & set(algorithms)):
                    return [
                        Finding(
                            rule_id=self.rule_id,
                            directive="HostKeyAlgorithms",
                            severity=self.severity,
                            description="No Ed25519 or RSA (SHA-2) host key algorithm found",
                            remediation=self.remediation,
                            cis_reference=self.cis_reference,
                        )
                    ]
        return []


# Export all rule classes.
RULES = [
    ThreeDesCipherRule,
    CBCModeCipherRule,
    WeakKexAlgorithmsRule,
    DSAHostKeyRule,
    PreferEd25519Rule,
]
