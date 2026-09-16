"""Multi-OS compatibility layer for EnvGuard Secrets Vault.

Provides cross-platform support across Linux, macOS, Windows, and Termux Android.
Zero external runtime dependencies - pure Python stdlib.
"""

from __future__ import annotations

import json
import os
import platform
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Any, List, Optional, Tuple, Union


def is_windows() -> bool:
    """Return True if running on Microsoft Windows."""
    return sys.platform.startswith("win") or os.name == "nt"


def is_macos() -> bool:
    """Return True if running on Apple macOS / Darwin."""
    return sys.platform == "darwin"


def is_linux() -> bool:
    """Return True if running on GNU/Linux (including Android/Termux)."""
    return sys.platform.startswith("linux")


def is_termux() -> bool:
    """Return True if running inside Termux environment on Android."""
    if "TERMUX_VERSION" in os.environ or "ANDROID_ROOT" in os.environ:
        return True
    termux_prefix = os.environ.get("PREFIX", "")
    if "com.termux" in termux_prefix:
        return True
    return os.path.exists("/data/data/com.termux")


def supports_color() -> bool:
    """Check if current terminal environment supports ANSI color codes."""
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("CLICOLOR_FORCE") == "1":
        return True
    if os.environ.get("TERM") == "dumb":
        return False
    
    is_atty = hasattr(sys.stdout, "isatty") and sys.stdout.isatty()
    if not is_atty:
        return False
        
    if is_windows():
        # Check for Windows Terminal or ANSI console support
        return (
            "WT_SESSION" in os.environ
            or "ANSICON" in os.environ
            or "ConEmuANSI" in os.environ
            or os.environ.get("TERM_PROGRAM") == "vscode"
        )
    return True


def get_terminal_size(fallback: Tuple[int, int] = (80, 24)) -> Tuple[int, int]:
    """Return terminal size as (columns, lines)."""
    try:
        size = shutil.get_terminal_size(fallback=fallback)
        return size.columns, size.lines
    except Exception:
        return fallback


def get_platform_info() -> dict[str, Any]:
    """Collect comprehensive platform diagnostics."""
    return {
        "platform": sys.platform,
        "system": platform.system(),
        "release": platform.release(),
        "machine": platform.machine(),
        "python_version": sys.version.split()[0],
        "is_windows": is_windows(),
        "is_macos": is_macos(),
        "is_linux": is_linux(),
        "is_termux": is_termux(),
        "default_encoding": sys.getdefaultencoding(),
        "filesystem_encoding": sys.getfilesystemencoding(),
        "color_supported": supports_color(),
        "terminal_size": get_terminal_size(),
    }


def to_posix_path(path: Union[str, Path]) -> str:
    """Convert any filesystem path (Windows, UNC, relative) to a standard POSIX path string."""
    raw = str(path).replace("\\", "/")
    # Collapse duplicate slashes except leading double slash for network shares
    if raw.startswith("//"):
        return "//" + "/".join(segment for segment in raw[2:].split("/") if segment)
    parts = [segment for segment in raw.split("/") if segment]
    if raw.startswith("/"):
        return "/" + "/".join(parts)
    return "/".join(parts) if parts else "."


def from_posix_path(posix_str: str) -> Path:
    """Convert a POSIX path string to native OS Path object."""
    if not posix_str:
        return Path(".")
    # If on Windows and string starts with drive letter like C:/, handle appropriately
    return Path(posix_str)


def normalize_line_endings(content: str, line_ending: str = "\n") -> str:
    """Normalize CRLF and CR line endings to the specified line ending."""
    content = content.replace("\r\n", "\n").replace("\r", "\n")
    if line_ending != "\n":
        content = content.replace("\n", line_ending)
    return content


def atomic_write_text(
    file_path: Union[str, Path],
    content: str,
    encoding: str = "utf-8",
    make_parents: bool = True,
    mode: Optional[int] = 0o600,
) -> None:
    """Atomically write text content to file using a temporary file and atomic replace.

    Ensures that partial writes do not corrupt existing files if interrupted.
    """
    path = Path(file_path).resolve()
    if make_parents:
        path.parent.mkdir(parents=True, exist_ok=True)

    parent_dir = path.parent
    temp_file = None
    try:
        # Create temp file in same directory for atomic rename capability across filesystems
        with tempfile.NamedTemporaryFile(
            mode="w",
            dir=parent_dir,
            delete=False,
            encoding=encoding,
            newline="",
        ) as tf:
            temp_file = tf.name
            tf.write(content)
            tf.flush()
            try:
                os.fsync(tf.fileno())
            except (AttributeError, OSError):
                pass  # fsync may not be supported on all OS/filesystems

        # Set secure permissions if requested and not on Windows
        if mode is not None and not is_windows():
            try:
                os.chmod(temp_file, mode)
            except OSError:
                pass

        # Atomic replacement
        os.replace(temp_file, path)
        temp_file = None
    finally:
        if temp_file and os.path.exists(temp_file):
            try:
                os.remove(temp_file)
            except OSError:
                pass


def atomic_write_json(
    file_path: Union[str, Path],
    data: Any,
    indent: int = 2,
    encoding: str = "utf-8",
    make_parents: bool = True,
    sort_keys: bool = False,
    mode: Optional[int] = 0o600,
) -> None:
    """Atomically serialize and write JSON data to file."""
    json_text = json.dumps(data, indent=indent, sort_keys=sort_keys, ensure_ascii=False) + "\n"
    atomic_write_text(
        file_path=file_path,
        content=json_text,
        encoding=encoding,
        make_parents=make_parents,
        mode=mode,
    )


def safe_read_text(
    file_path: Union[str, Path],
    encoding: str = "utf-8",
    fallback_encodings: Optional[List[str]] = None,
) -> str:
    """Read text from file with UTF-8 BOM stripping and encoding fallbacks."""
    path = Path(file_path)
    if not path.is_file():
        raise FileNotFoundError(f"File not found: {file_path}")

    encodings_to_try = [encoding, "utf-8-sig"]
    if fallback_encodings:
        encodings_to_try.extend(fallback_encodings)
    else:
        encodings_to_try.extend(["latin-1", "cp1252"])

    last_error: Optional[Exception] = None
    for enc in encodings_to_try:
        try:
            with open(path, "r", encoding=enc) as f:
                return f.read()
        except UnicodeDecodeError as exc:
            last_error = exc
            continue

    if last_error:
        raise last_error
    return ""


def safe_read_json(
    file_path: Union[str, Path],
    encoding: str = "utf-8",
) -> Any:
    """Safely read and parse JSON file."""
    text = safe_read_text(file_path, encoding=encoding)
    return json.loads(text)
