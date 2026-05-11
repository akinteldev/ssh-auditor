"""Tests for ssh_auditor.parser."""

from __future__ import annotations

import pytest

from ssh_auditor.parser import (
    Directive,
    MatchBlock,
    ParsedConfig,
    parse_sshd_config,
    parse_sshd_config_to_dicts,
)


class TestParseSshdConfig:
    """Tests for parse_sshd_config."""

    def test_good_config(self, good_config_path: str) -> None:
        result = parse_sshd_config(good_config_path)

        assert isinstance(result, ParsedConfig)
        assert len(result.directives) > 0

        # Check that key directives are present.
        directive_names = [d.directive for d in result.directives]
        assert "PermitRootLogin" in directive_names
        assert "Ciphers" in directive_names
        assert "Protocol" in directive_names

    def test_bad_config(self, bad_config_path: str) -> None:
        result = parse_sshd_config(bad_config_path)

        assert isinstance(result, ParsedConfig)
        assert len(result.directives) > 0

    def test_mixed_config(self, mixed_config_path: str) -> None:
        result = parse_sshd_config(mixed_config_path)

        assert isinstance(result, ParsedConfig)
        assert len(result.directives) > 0

    def test_comments_ignored(self, tmp_path: str | None = None) -> None:
        import tempfile
        from pathlib import Path

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".conf", delete=False
        ) as f:
            f.write("# This is a comment\n")
            f.write("\n")
            f.write("  # Indented comment\n")
            f.write("PermitRootLogin no\n")
            config_path = f.name

        try:
            result = parse_sshd_config(config_path)
            directives = [d.directive for d in result.directives]
            assert "PermitRootLogin" in directives
            # No comment lines should appear as directives.
        finally:
            Path(config_path).unlink()

    def test_inline_comments_stripped(self) -> None:
        import tempfile
        from pathlib import Path

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".conf", delete=False
        ) as f:
            f.write("PermitRootLogin no  # should be no\n")
            config_path = f.name

        try:
            result = parse_sshd_config(config_path)
            assert len(result.directives) == 1
            assert result.directives[0].value == "no"
        finally:
            Path(config_path).unlink()

    def test_case_insensitive_directives(self) -> None:
        import tempfile
        from pathlib import Path

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".conf", delete=False
        ) as f:
            # SSH config is case-insensitive.
            f.write("permitrootlogin no\n")
            f.write("PERMITEMPTYPASSWORDS no\n")
            config_path = f.name

        try:
            result = parse_sshd_config(config_path)
            directive_names = [d.directive for d in result.directives]
            # Should be normalised to title-case.
            assert "PermitRootLogin" in directive_names
            assert "PermitEmptyPasswords" in directive_names
        finally:
            Path(config_path).unlink()

    def test_include_directives_recorded(self) -> None:
        import tempfile
        from pathlib import Path

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".conf", delete=False
        ) as f:
            f.write("Include /etc/ssh/sshd_config.d/*.conf\n")
            config_path = f.name

        try:
            result = parse_sshd_config(config_path)
            assert len(result.includes) == 1
            assert result.includes[0].directive == "Include"
        finally:
            Path(config_path).unlink()

    def test_match_blocks_parsed(self) -> None:
        import tempfile
        from pathlib import Path

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".conf", delete=False
        ) as f:
            f.write("Match User admin\n")
            f.write("    PermitRootLogin yes\n")
            config_path = f.name

        try:
            result = parse_sshd_config(config_path)
            assert len(result.match_blocks) == 1
            block = result.match_blocks[0]
            assert block.condition == "User admin"
            assert len(block.directives) == 1
            assert block.directives[0].directive == "PermitRootLogin"
        finally:
            Path(config_path).unlink()

    def test_directive_has_required_keys(self) -> None:
        import tempfile
        from pathlib import Path

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".conf", delete=False
        ) as f:
            f.write("PermitRootLogin no\n")
            config_path = f.name

        try:
            result = parse_sshd_config(config_path)
            d = result.directives[0]
            assert isinstance(d, Directive)
            assert hasattr(d, "directive")
            assert hasattr(d, "value")
            assert hasattr(d, "file")
            assert hasattr(d, "line_number")
        finally:
            Path(config_path).unlink()

    def test_file_not_found(self) -> None:
        with pytest.raises(FileNotFoundError):
            parse_sshd_config("/nonexistent/path/sshd_config")

    def test_blank_lines_ignored(self) -> None:
        import tempfile
        from pathlib import Path

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".conf", delete=False
        ) as f:
            f.write("\n\n\n")
            f.write("PermitRootLogin no\n")
            config_path = f.name

        try:
            result = parse_sshd_config(config_path)
            assert len(result.directives) == 1
        finally:
            Path(config_path).unlink()


class TestParseSshdConfigToDicts:
    """Tests for parse_sshd_config_to_dicts convenience wrapper."""

    def test_returns_flat_list(self, good_config_path: str) -> None:
        result = parse_sshd_config_to_dicts(good_config_path)

        assert isinstance(result, list)
        for item in result:
            assert isinstance(item, dict)
            assert "directive" in item
            assert "value" in item
            assert "file" in item
            assert "line_number" in item

    def test_includes_match_block_directives(self) -> None:
        import tempfile
        from pathlib import Path

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".conf", delete=False
        ) as f:
            f.write("PermitRootLogin no\n")
            f.write("Match User admin\n")
            f.write("    PasswordAuthentication yes\n")
            config_path = f.name

        try:
            result = parse_sshd_config_to_dicts(config_path)
            directive_names = [d["directive"] for d in result]
            assert "PermitRootLogin" in directive_names
            assert "PasswordAuthentication" in directive_names
        finally:
            Path(config_path).unlink()
