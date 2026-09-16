"""Comprehensive tests for cross-platform compatibility layer (compat.py)."""

import os
from pathlib import Path
from unittest.mock import patch

import pytest

from envguard_secrets_vault.compat import (
    atomic_write_json,
    atomic_write_text,
    from_posix_path,
    get_platform_info,
    get_terminal_size,
    is_linux,
    is_macos,
    is_termux,
    is_windows,
    normalize_line_endings,
    safe_read_json,
    safe_read_text,
    supports_color,
    to_posix_path,
)


class TestPlatformDiagnostics:
    def test_platform_check_types(self):
        assert isinstance(is_windows(), bool)
        assert isinstance(is_macos(), bool)
        assert isinstance(is_linux(), bool)
        assert isinstance(is_termux(), bool)

    def test_platform_info_structure(self):
        info = get_platform_info()
        assert isinstance(info, dict)
        required_keys = [
            "platform",
            "system",
            "release",
            "machine",
            "python_version",
            "is_windows",
            "is_macos",
            "is_linux",
            "is_termux",
            "default_encoding",
            "filesystem_encoding",
            "color_supported",
            "terminal_size",
        ]
        for key in required_keys:
            assert key in info, f"Missing key in platform info: {key}"

    def test_termux_detection(self):
        with patch.dict(os.environ, {"TERMUX_VERSION": "0.118"}):
            assert is_termux() is True
        with patch.dict(os.environ, {"ANDROID_ROOT": "/system"}, clear=True):
            assert is_termux() is True

    def test_supports_color_no_color(self):
        with patch.dict(os.environ, {"NO_COLOR": "1"}):
            assert supports_color() is False

    def test_supports_color_forced(self):
        with patch.dict(os.environ, {"CLICOLOR_FORCE": "1"}, clear=True):
            assert supports_color() is True

    def test_supports_color_dumb_term(self):
        with patch.dict(os.environ, {"TERM": "dumb", "CLICOLOR_FORCE": ""}, clear=True):
            assert supports_color() is False

    def test_terminal_size(self):
        cols, lines = get_terminal_size(fallback=(80, 24))
        assert cols > 0
        assert lines > 0


class TestPathAndStringConversions:
    def test_to_posix_path(self):
        assert to_posix_path("C:\\Users\\neo\\project\\.env") == "C:/Users/neo/project/.env"
        assert to_posix_path("foo/bar/baz") == "foo/bar/baz"
        assert to_posix_path("foo\\bar\\baz") == "foo/bar/baz"
        assert to_posix_path("") == "."
        assert to_posix_path(Path("nested/dir/file.txt")) == "nested/dir/file.txt"

    def test_from_posix_path(self):
        p = from_posix_path("nested/dir/file.txt")
        assert isinstance(p, Path)
        assert str(p) == str(Path("nested/dir/file.txt"))
        assert from_posix_path("") == Path(".")

    def test_normalize_line_endings(self):
        crlf = "LINE1\r\nLINE2\r\nLINE3\r\n"
        cr = "LINE1\rLINE2\rLINE3\r"
        lf = "LINE1\nLINE2\nLINE3\n"
        assert normalize_line_endings(crlf) == lf
        assert normalize_line_endings(cr) == lf
        assert normalize_line_endings(lf) == lf
        assert normalize_line_endings(crlf, line_ending="\r\n") == crlf


class TestAtomicFileOperations:
    def test_atomic_write_and_safe_read_text(self, tmp_path: Path):
        target = tmp_path / "subdir" / "test_file.txt"
        test_content = "SECRET_KEY=super_secret_value_🚀\nDATABASE_URL=postgres://localhost\n"
        
        atomic_write_text(target, test_content, make_parents=True)
        assert target.is_file()
        
        read_back = safe_read_text(target)
        assert read_back == test_content

    def test_atomic_write_and_safe_read_json(self, tmp_path: Path):
        target = tmp_path / "deep" / "nested" / "config.json"
        data = {
            "version": "1.0",
            "app_name": "EnvGuard 🛡️",
            "settings": {"debug": False, "port": 8080, "tags": ["prod", "secure"]},
        }
        
        atomic_write_json(target, data, make_parents=True, indent=2)
        assert target.is_file()
        
        loaded = safe_read_json(target)
        assert loaded == data

    def test_safe_read_nonexistent_file(self, tmp_path: Path):
        missing = tmp_path / "nonexistent.txt"
        with pytest.raises(FileNotFoundError):
            safe_read_text(missing)

    def test_safe_read_with_bom(self, tmp_path: Path):
        target = tmp_path / "bom_file.txt"
        content_with_bom = "\ufeffKEY=VALUE\n"
        target.write_text(content_with_bom, encoding="utf-8")
        
        read_back = safe_read_text(target)
        # BOM should be handled cleanly
        assert "KEY=VALUE" in read_back

    def test_safe_read_fallback_encoding(self, tmp_path: Path):
        target = tmp_path / "latin1_file.txt"
        # Write latin-1 specific bytes that fail standard UTF-8 decode
        with open(target, "wb") as f:
            f.write(b"KEY=caf\xe9_value\n")
        
        read_back = safe_read_text(target, encoding="utf-8", fallback_encodings=["latin-1"])
        assert "café_value" in read_back

    def test_to_posix_unc_path(self):
        unc = "\\\\server\\share\\path\\file.env"
        assert to_posix_path(unc) == "//server/share/path/file.env"

    def test_supports_color_windows_env(self):
        from unittest.mock import MagicMock
        mock_stdout = MagicMock()
        mock_stdout.isatty.return_value = True
        with patch("sys.stdout", mock_stdout):
            with patch("envguard_secrets_vault.compat.is_windows", return_value=True):
                with patch.dict(os.environ, {"WT_SESSION": "123"}, clear=True):
                    assert supports_color() is True
