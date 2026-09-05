"""
config_loader.py — Unified Hermes Path and Configuration Loader
"""

import logging
import os
import stat
import warnings
from pathlib import Path
from typing import Optional, Dict

logger = logging.getLogger("hermes.config_loader")

HERMES_HOME = Path(os.environ.get("HERMES_HOME", Path.home() / ".hermes"))
DATA_DIR = HERMES_HOME / "data"
LOGS_DIR = HERMES_HOME / "logs"
BACKUPS_DIR = HERMES_HOME / "backups"
SCRIPTS_DIR = HERMES_HOME / "scripts"

DB_MAP: Dict[str, Path] = {
    "state": DATA_DIR / "state.db",
    "verification_evidence": DATA_DIR / "verification_evidence.db",
    "kanban": DATA_DIR / "kanban.db",
    "response_store": DATA_DIR / "response_store.db",
    "semantic_cache": DATA_DIR / "semantic_cache.db",
}
DB_MAPPING = DB_MAP


def get_hermes_path(subpath: Optional[str] = None) -> Path:
    """Get standardized path under HERMES_HOME."""
    if subpath:
        return HERMES_HOME / subpath
    return HERMES_HOME


import re

SENSITIVE_KEY_SUBSTRINGS = ("KEY", "SECRET", "TOKEN", "PASSWORD", "PASS", "AUTH", "CREDENTIAL")


def is_sensitive_key(key: str) -> bool:
    """Check if the configuration key contains sensitive credential keywords."""
    if not isinstance(key, str):
        return False
    k = key.upper()
    return any(sub in k for sub in SENSITIVE_KEY_SUBSTRINGS)


def get_db_path(db_name: str) -> Path:
    """
    Get standardized path for a given database with strict path traversal & symlink defenses.
    :raises ValueError: When db_name contains path escape attempts or illegal characters.
    """
    if not isinstance(db_name, str) or not db_name.strip():
        raise ValueError("非法的資料庫名稱 (Illegal db_name): 名稱不可為空")

    # 1. 預定義之核心白名單資料庫直接回傳
    if db_name in DB_MAP:
        return DB_MAP[db_name]

    # 2. 禁止相對路徑、路徑分隔符、空字節與特殊字元
    if any(char in db_name for char in ("/", "\\", "\x00")) or ".." in db_name:
        raise ValueError(f"路徑穿越阻斷 (Path traversal detected): {db_name}")

    if not re.match(r"^[a-zA-Z0-9_\-]+$", db_name):
        raise ValueError(f"非法的資料庫名稱格式 (Illegal db_name format): {db_name}")

    data_candidate = DATA_DIR / f"{db_name}.db"
    home_candidate = HERMES_HOME / f"{db_name}.db"
    target_candidate = data_candidate if data_candidate.exists() else home_candidate

    # 3. 符號連結 (Symlink) 逃逸主動檢查
    if target_candidate.is_symlink():
        dest = target_candidate.resolve()
        try:
            dest.relative_to(HERMES_HOME.resolve())
        except ValueError:
            raise ValueError(f"安全阻斷：資料庫符號連結指向工作區外部 (Symlink escape): {target_candidate} -> {dest}")

    # 4. 解析實體路徑確保局限在 HERMES_HOME 內部
    resolved = target_candidate.resolve()
    try:
        resolved.relative_to(HERMES_HOME.resolve())
    except ValueError:
        raise ValueError(f"路徑逃逸阻斷 (Path escape): {db_name}")

    return target_candidate


def get_env_var(key: str, default: Optional[str] = None, mask_if_sensitive: bool = False, strict_permissions: bool = True) -> Optional[str]:
    """
    Read configuration from environment variable or ~/.hermes/.env.
    :param key: Environment variable name.
    :param default: Fallback value if key is not found.
    :param mask_if_sensitive: If True and the key is recognized as sensitive, returns masked string.
    :param strict_permissions: If True, raises PermissionError if .env has overly permissive permissions.
    """
    val = None
    if key in os.environ:
        val = os.environ[key]
    else:
        env_file = HERMES_HOME / ".env"
        if env_file.exists():
            check_file_permissions(env_file, strict=strict_permissions)
            try:
                with open(env_file, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith("#") and "=" in line:
                            k, v = line.split("=", 1)
                            if k.strip() == key:
                                val = v.strip().strip('"').strip("'")
                                break
            except Exception as e:
                logger.debug(f"讀取 .env 略過: {e}")

    if val is None:
        return default

    if mask_if_sensitive and is_sensitive_key(key):
        from hermes_core.security_filter import mask_secret_string
        return mask_secret_string(val)

    return val


def get_secret(key: str, default: Optional[str] = None) -> Optional[str]:
    """
    Dedicated safe accessor for sensitive credentials (API keys, tokens, passwords).
    Explicitly separated from general configuration logging.
    """
    return get_env_var(key, default=default, mask_if_sensitive=False)


def check_file_permissions(file_path: Path, strict: bool = False) -> bool:
    """
    Check if a sensitive config or env file has safe POSIX permissions (no world-readable/writable bits).
    :param file_path: Path to the target file.
    :param strict: If True, raises PermissionError when permissions are too open.
    :return: True if permissions are safe, False otherwise.
    """
    if not file_path.exists():
        return True
    try:
        mode = file_path.stat().st_mode
        # Check if others have any read/write/execute permissions (0o007)
        if mode & stat.S_IRWXO:
            msg = (
                f"安全警告：敏感檔案 '{file_path}' 權限過度開放 ({oct(mode)[-4:]})！"
                f"建議執行 'chmod 600 {file_path}' 限制僅限擁有者讀寫。"
            )
            if strict:
                raise PermissionError(msg)
            warnings.warn(msg, UserWarning, stacklevel=2)
            return False
        return True
    except PermissionError:
        raise
    except (OSError, AttributeError):
        return True


def load_config(strict_permissions: bool = False) -> dict:
    """
    Load config.yaml if available, verifying file permission safety.
    :param strict_permissions: If True, raises PermissionError if config.yaml is world-readable/writable.
    """
    config_file = HERMES_HOME / "config.yaml"
    if not config_file.exists():
        return {}

    # 檢查設定檔權限 (非擁有者不可讀寫)
    check_file_permissions(config_file, strict=strict_permissions)

    try:
        import yaml
        with open(config_file, "r", encoding="utf-8") as f:
            content = f.read()
            if "!!" in content:
                raise ValueError("安全阻斷：禁止在 config.yaml 中使用自訂 YAML 標籤 (Custom YAML tags '!!' are forbidden)")
            return yaml.load(content, Loader=yaml.SafeLoader) or {}
    except (PermissionError, ValueError):
        raise
    except Exception as e:
        logger.warning(f"讀取設定檔失敗: {e}")
        return {}
