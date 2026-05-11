"""Parser for sshd_config files.

Handles case-insensitive directives, comments, blank lines,
inline comments, Include directives, and Match blocks.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class Directive:
    """A single parsed sshd_config directive."""

    directive: str
    value: str
    file: str
    line_number: int


@dataclass
class MatchBlock:
    """A parsed Match block with its condition and contained directives."""

    condition: str
    line_number: int
    directives: list[Directive] = field(default_factory=list)


@dataclass
class ParsedConfig:
    """Complete parsed sshd_config result."""

    directives: list[Directive] = field(default_factory=list)
    match_blocks: list[MatchBlock] = field(default_factory=list)
    includes: list[Directive] = field(default_factory=list)


# Regex to strip inline comments (a # preceded by whitespace).
_INLINE_COMMENT_RE = re.compile(r"\s+#.*$")

# Regex to split a line into directive name and value.
_DIRECTIVE_RE = re.compile(r"^(\S+)\s+(.*)", re.DOTALL)

# Known SSH directives that contain multiple words (for title-casing).
_KNOWN_DIRECTIVES: dict[str, str] = {
    "permitrootlogin": "PermitRootLogin",
    "permitemptypasswords": "PermitEmptyPasswords",
    "passwordauthentication": "PasswordAuthentication",
    "challengeresponseauthentication": "ChallengeResponseAuthentication",
    "maxauthtries": "MaxAuthTries",
    "logingracetime": "LoginGraceTime",
    "usepam": "UsePAM",
    "x11forwarding": "X11Forwarding",
    "allowtcpforwarding": "AllowTcpForwarding",
    "permittunnel": "PermitTunnel",
    "gatewayports": "GatewayPorts",
    "clientaliveinterval": "ClientAliveInterval",
    "clientalivecountmax": "ClientAliveCountMax",
    "printmotd": "PrintMotd",
    "loglevel": "LogLevel",
    "strictmodes": "StrictModes",
    "hostkeyalgorithms": "HostKeyAlgorithms",
    "kexalgorithms": "KexAlgorithms",
}


def _normalise_directive(name: str) -> str:
    """Normalise an SSH directive name to its canonical title-case form.

    Args:
        name: Raw directive name from the config file.

    Returns:
        The canonical form (e.g. ``"PermitRootLogin"``).  Falls back to
        simple title-case for unknown directives.
    """
    lower = name.lower()
    return _KNOWN_DIRECTIVES.get(lower, lower.capitalize())


def _strip_inline_comment(value: str) -> str:
    """Remove inline comments from a configuration value.

    Args:
        value: Raw value string that may contain an inline comment.

    Returns:
        The value with any trailing inline comment removed and whitespace
        stripped.
    """
    return _INLINE_COMMENT_RE.sub("", value).strip()


def parse_sshd_config(file_path: str | Path) -> ParsedConfig:
    """Parse an sshd_config file into structured directives.

    Args:
        file_path: Path to the sshd_config file to parse.

    Returns:
        A ParsedConfig containing all directives, match blocks, and
        include directives found in the file.

    Raises:
        FileNotFoundError: If *file_path* does not exist.
        ValueError: If the file cannot be read.
    """
    path = Path(file_path)
    if not path.is_file():
        raise FileNotFoundError(f"Config file not found: {path}")

    result = ParsedConfig()
    current_match_block: MatchBlock | None = None

    with path.open("r", encoding="utf-8") as fh:
        for line_number, raw_line in enumerate(fh, start=1):
            line = raw_line.strip()

            # Skip blank lines and full-line comments.
            if not line or line.startswith("#"):
                continue

            # Strip inline comments.
            value = _strip_inline_comment(line)

            match_directive = _DIRECTIVE_RE.match(value)
            if not match_directive:
                continue

            directive_name = match_directive.group(1)
            directive_value = _strip_inline_comment(match_directive.group(2))

            # SSH config is case-insensitive; normalise directive names to
            # title-case (e.g. "permitrootlogin" → "PermitRootLogin").
            directive_name = _normalise_directive(directive_name)

            # Handle Match blocks.
            if directive_name == "Match":
                current_match_block = MatchBlock(
                    condition=directive_value,
                    line_number=line_number,
                )
                result.match_blocks.append(current_match_block)
                continue

            directive_record = Directive(
                directive=directive_name,
                value=directive_value,
                file=str(path),
                line_number=line_number,
            )

            if directive_name == "Include":
                result.includes.append(directive_record)
            elif current_match_block is not None:
                directive_record.directive = directive_name
                current_match_block.directives.append(directive_record)
            else:
                result.directives.append(directive_record)

    return result


def parse_sshd_config_to_dicts(
    file_path: str | Path,
) -> list[dict[str, str]]:
    """Parse an sshd_config file and return a flat list of directive dicts.

    This is a convenience wrapper around :func:`parse_sshd_config` that
    flattens directives from both the main scope and all Match blocks into
    a single list of dicts suitable for rule evaluation.

    Args:
        file_path: Path to the sshd_config file to parse.

    Returns:
        List of dicts with keys ``directive``, ``value``, ``file``, and
        ``line_number``.
    """
    parsed = parse_sshd_config(file_path)

    directives: list[dict[str, str]] = [
        {
            "directive": d.directive,
            "value": d.value,
            "file": d.file,
            "line_number": d.line_number,
        }
        for d in parsed.directives
    ]

    # Also include directives inside Match blocks (they are still part of
    # the effective configuration for audit purposes).
    for block in parsed.match_blocks:
        directives.extend(
            {
                "directive": d.directive,
                "value": d.value,
                "file": d.file,
                "line_number": d.line_number,
            }
            for d in block.directives
        )

    return directives
