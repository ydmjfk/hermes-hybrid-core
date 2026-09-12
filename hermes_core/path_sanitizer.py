"""
path_sanitizer.py — 企業級沙盒路徑淨化與目錄穿越防禦引擎 (HAOS CAP-006 & ToolManager)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
核心職責：
1. 嚴格邊界檢查 (Boundary Enforcement)：所有檔案操作必須鎖定於指定工作區 (Workspace Root) 內。
2. 目錄穿越防禦 (Anti-Path-Traversal)：攔截 '../'、'..\\'、Null Byte ('\x00') 與 URL 雙重編碼繞過。
3. 符號連結攻擊防禦 (Anti-Symlink-Attack)：透過 os.path.realpath 解析實體節點，嚴防指向外部機敏檔案。
4. 高危敏感檔案黑名單 (Sensitive Path Blacklist)：全面禁止 Agent 存取金鑰、設定檔與系統重要目錄。
"""

import os
import sys
import unicodedata
from contextlib import contextmanager
from urllib.parse import unquote
from pathlib import Path
from typing import List, Optional, Set, Union, Iterator, IO, Any


class PathSanitizerError(Exception):
    """路徑淨化與沙盒驗證基礎異常"""
    pass


class PathTraversalError(PathSanitizerError):
    """偵測到目錄穿越或越界存取異常"""
    pass


class SensitivePathBlockedError(PathSanitizerError):
    """存取受保護的高敏感檔案或系統目錄異常"""
    pass


# 預設禁止存取的敏感檔案與目錄名稱 (全域黑名單)
DEFAULT_BLOCKED_NAMES: Set[str] = {
    ".ssh",
    ".gnupg",
    ".aws",
    ".azure",
    ".gcp",
    ".kube",
    ".docker",
    ".npmrc",
    ".nuget",
    ".nugetrc",
    ".env",
    ".env.local",
    ".env.production",
    "config.yaml",
    ".git",
    ".bashrc",
    ".bash_profile",
    ".profile",
    ".zshrc",
    ".local",
    "id_rsa",
    "id_ed25519",
    "authorized_keys",
    "known_hosts",
    "passwd",
    "shadow",
    "sudoers",
    "credentials",
    "credentials.json",
    "service_account.json",
    "master.key",
    ".vscode",
    ".idea",
    ".terraform",
    "Dockerfile",
    "docker-compose.yml",
    "docker-compose.yaml",
}

# 敏感憑證、加密金鑰與私鑰副檔名黑名單 (全面阻斷憑證/金鑰檔案直接讀取)
DEFAULT_BLOCKED_EXTENSIONS: Set[str] = {
    ".pem",
    ".key",
    ".p12",
    ".pfx",
    ".jks",
    ".crt",
    ".cer",
    ".der",
    ".enc",
    ".gpg",
    ".asc",
    ".kdbx",
    ".tfvars",
}

# 系統層級禁止存取的絕對路徑前綴
DEFAULT_BLOCKED_SYSTEM_PREFIXES: List[str] = [
    "/etc",
    "/proc",
    "/sys",
    "/dev",
    "/root",
    "/var/run",
    "/boot",
]


class PathSanitizer:
    """
    沙盒路徑驗證器 (HAOS Path Sanitizer Engine)
    """

    def __init__(
        self,
        workspace_root: Optional[Union[str, Path]] = None,
        blocked_names: Optional[Set[str]] = None,
        blocked_extensions: Optional[Set[str]] = None,
        allow_system_temp: bool = False
    ):
        if workspace_root:
            self.workspace_root = Path(workspace_root).expanduser().resolve()
        else:
            # 預設以環境變數 HERMES_WORKSPACE_ROOT 或當前工作目錄為邊界
            env_root = os.environ.get("HERMES_WORKSPACE_ROOT")
            self.workspace_root = Path(env_root).expanduser().resolve() if env_root else Path.cwd().resolve()

        self.blocked_names = set(blocked_names) if blocked_names is not None else set(DEFAULT_BLOCKED_NAMES)
        self.blocked_extensions = set(blocked_extensions) if blocked_extensions is not None else set(DEFAULT_BLOCKED_EXTENSIONS)
        self.allow_system_temp = allow_system_temp

    def sanitize_path(
        self,
        target_path: Union[str, Path],
        must_exist: bool = False,
        allow_subdirectories: bool = True
    ) -> Path:
        """
        淨化並檢驗傳入路徑。
        
        :param target_path: 待驗證的相對或絕對路徑字串/Path 物件
        :param must_exist: 是否要求目標路徑必須已經存在
        :param allow_subdirectories: 是否允許存取工作區底下的子目錄
        :return: 解析後的安全絕對 Path 物件
        :raises PathTraversalError: 當路徑超出沙盒工作區邊界時拋出
        :raises SensitivePathBlockedError: 當路徑命中敏感檔黑名單時拋出
        """
        if not target_path:
            raise PathTraversalError("路徑不可為空 (Path cannot be empty)")

        # 1. URL 解碼與 Unicode 規範化防禦繞過 (e.g. %2e%2e 或 全形點)
        path_str = str(target_path)
        decoded_path = unquote(path_str)
        normalized_path = unicodedata.normalize('NFKC', decoded_path)

        # 2. 防禦空位元組注入 (Null Byte Injection)
        if "\x00" in normalized_path or "%00" in normalized_path:
            raise PathTraversalError("偵測到空字節注入攻擊 (Null byte injection detected)")

        try:
            raw_path = Path(normalized_path).expanduser()
            if raw_path.is_absolute():
                candidate = raw_path
            else:
                candidate = self.workspace_root / raw_path

            # 3. 符號連結 (Symlink) 逃逸與循環參照防護 (使用 os.readlink 防範循環遞迴卡死)
            curr = candidate
            seen_links = set()
            max_hops = 32
            hops = 0
            while curr.is_symlink():
                hops += 1
                curr_str = str(curr)
                if hops > max_hops or curr_str in seen_links:
                    raise PathTraversalError(f"偵測到符號連結迴圈 (Symlink loop detected): '{candidate}'")
                seen_links.add(curr_str)
                try:
                    raw_target = os.readlink(curr)
                except OSError as e:
                    raise PathTraversalError(f"無法讀取符號連結: {e}")
                dest = Path(raw_target)
                if not dest.is_absolute():
                    dest = curr.parent / dest
                curr = dest

            # 4. 解析實體路徑 (消除 symlink 與 ..)
            resolved = curr.resolve()

        except PathSanitizerError:
            raise
        except Exception as e:
            raise PathTraversalError(f"路徑格式解析失敗: {e}")

        # 5. 檢查系統層級絕對路徑阻斷
        resolved_str = str(resolved)
        for prefix in DEFAULT_BLOCKED_SYSTEM_PREFIXES:
            if resolved_str == prefix or resolved_str.startswith(f"{prefix}/"):
                raise SensitivePathBlockedError(f"安全阻斷：禁止存取系統底層路徑 '{resolved}'")

        # 6. 驗證工作區邊界 (Workspace Boundary Enforcement)
        try:
            rel = resolved.relative_to(self.workspace_root)
        except ValueError:
            # 若未包含在 workspace_root 內，檢查是否屬於臨時目錄特許
            if self.allow_system_temp:
                import tempfile
                temp_dir = Path(tempfile.gettempdir()).resolve()
                try:
                    resolved.relative_to(temp_dir)
                    rel = None
                except ValueError:
                    raise PathTraversalError(
                        f"安全阻斷：目標路徑 '{resolved}' 越界！超出工作區邊界 '{self.workspace_root}'"
                    )
            else:
                raise PathTraversalError(
                    f"安全阻斷：目標路徑 '{resolved}' 越界！超出工作區邊界 '{self.workspace_root}'"
                )

        if not allow_subdirectories and rel is not None and len(rel.parts) > 1:
            raise PathTraversalError(f"安全阻斷：不允許存取子目錄 '{resolved}'")

        # 5. 敏感檔案與資料夾黑名單過濾
        parts_set = set(resolved.parts)
        matched_blocked = parts_set & self.blocked_names
        if matched_blocked:
            raise SensitivePathBlockedError(
                f"安全阻斷：禁止存取高敏感保護檔案/目錄 {matched_blocked} (路徑: {resolved})"
            )

        if resolved.suffix.lower() in self.blocked_extensions:
            raise SensitivePathBlockedError(
                f"安全阻斷：禁止存取敏感憑證/私鑰檔案副檔名 '{resolved.suffix}' (路徑: {resolved})"
            )

        # 6. 存在性校驗
        if must_exist and not resolved.exists():
            raise FileNotFoundError(f"目標檔案不存在: {resolved}")

        return resolved

    def is_safe_path(self, target_path: Union[str, Path], must_exist: bool = False) -> bool:
        """快速檢測路徑是否安全合規，不拋出例外"""
        try:
            self.sanitize_path(target_path, must_exist=must_exist)
            return True
        except (PathSanitizerError, FileNotFoundError):
            return False

    @contextmanager
    def safe_open(
        self,
        target_path: Union[str, Path],
        mode: str = "r",
        encoding: Optional[str] = "utf-8",
        errors: Optional[str] = "strict",
        **kwargs
    ) -> Iterator[IO[Any]]:
        """
        TOCTOU 防護之安全檔案開啟器 (P1-05 & P2-07)。
        1. 執行標準沙盒邊界、黑名單與機敏副檔名安全校驗。
        2. 自工作區根目錄起，以 O_DIRECTORY | O_NOFOLLOW 進行逐層目錄 FD (File Descriptor) 解析，
           嚴防路徑中間目錄在比對後被競爭抽換為指向外部機敏目錄的符號連結 (Directory-level Symlink Race)。
        3. 最後以父目錄 FD 開啟葉節點檔案，使用 O_NOFOLLOW 並二度比對 stat(before) 與 fstat(after) 之 inode/dev，
           徹底杜絕 TOCTOU 競爭抽換。
        """
        import stat as stat_mod
        clean_path = self.sanitize_path(target_path, must_exist=("r" in mode))

        # 決定開啟旗標
        flags = 0
        if "b" in mode:
            if "+" in mode or "w" in mode:
                flags |= os.O_RDWR | (os.O_CREAT if "w" in mode else 0)
            elif "a" in mode:
                flags |= os.O_WRONLY | os.O_APPEND | os.O_CREAT
            else:
                flags |= os.O_RDONLY
        else:
            if "+" in mode or "w" in mode:
                flags |= os.O_RDWR | (os.O_CREAT if "w" in mode else 0)
            elif "a" in mode:
                flags |= os.O_WRONLY | os.O_APPEND | os.O_CREAT
            else:
                flags |= os.O_RDONLY

        o_nofollow = getattr(os, "O_NOFOLLOW", 0)

        # 計算相對路徑層級
        try:
            rel_parts = clean_path.relative_to(self.workspace_root).parts
            base_root = self.workspace_root
        except ValueError:
            if self.allow_system_temp:
                import tempfile
                temp_dir = Path(tempfile.gettempdir()).resolve()
                rel_parts = clean_path.relative_to(temp_dir).parts
                base_root = temp_dir
            else:
                raise PathTraversalError(
                    f"安全阻斷：目標路徑 '{clean_path}' 超出工作區邊界 '{self.workspace_root}'"
                )

        stat_before = None
        if clean_path.exists():
            stat_before = clean_path.stat()

        # 逐層開啟並驗證中間目錄 FD，防止中間目錄被抽換為 symlink
        curr_fd = None
        try:
            curr_fd = os.open(str(base_root), os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            for comp in rel_parts[:-1]:
                try:
                    next_fd = os.open(comp, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | o_nofollow, dir_fd=curr_fd)
                except OSError as e:
                    raise SensitivePathBlockedError(
                        f"TOCTOU / 符號連結攻擊攔截：中間目錄 '{comp}' 無法安全開啟或為符號連結 ({e})"
                    )
                st = os.fstat(next_fd)
                if not stat_mod.S_ISDIR(st.st_mode):
                    os.close(next_fd)
                    raise SensitivePathBlockedError(f"安全阻斷：中間路徑節點 '{comp}' 非目錄")
                os.close(curr_fd)
                curr_fd = next_fd

            # 最終以父目錄 FD 安全開啟葉節點檔案 (強制 O_NOFOLLOW)
            leaf_name = rel_parts[-1] if rel_parts else "."
            try:
                fd = os.open(leaf_name, flags | o_nofollow, dir_fd=curr_fd)
            except OSError as e:
                raise SensitivePathBlockedError(
                    f"TOCTOU / 符號連結攻擊攔截：目標檔案 '{leaf_name}' 為符號連結或被抽換 ({e})"
                )
        finally:
            if curr_fd is not None:
                try:
                    os.close(curr_fd)
                except OSError:
                    pass

        # 驗證打開後的檔案描述符
        try:
            stat_after = os.fstat(fd)
            if stat_before is not None:
                if (stat_before.st_dev, stat_before.st_ino) != (stat_after.st_dev, stat_after.st_ino):
                    raise SensitivePathBlockedError(
                        f"TOCTOU 攻擊攔截：開啟檔案期間節點 (inode/dev) 發生抽換變更 '{clean_path}'"
                    )

            if "b" in mode:
                fp = open(fd, mode=mode, closefd=True)
            else:
                fp = open(fd, mode=mode, encoding=encoding, errors=errors, closefd=True)
            try:
                yield fp
            finally:
                fp.close()
        except:
            try:
                os.close(fd)
            except OSError:
                pass
            raise


# 模組級共用單例
_default_sanitizer = PathSanitizer()


def sanitize_path(
    target_path: Union[str, Path],
    workspace_root: Optional[Union[str, Path]] = None,
    must_exist: bool = False
) -> Path:
    """
    全域捷徑：對傳入路徑進行安全淨化與沙盒校驗
    """
    if workspace_root:
        return PathSanitizer(workspace_root).sanitize_path(target_path, must_exist=must_exist)
    return _default_sanitizer.sanitize_path(target_path, must_exist=must_exist)


def is_safe_path(
    target_path: Union[str, Path],
    workspace_root: Optional[Union[str, Path]] = None,
    must_exist: bool = False
) -> bool:
    """
    全域捷徑：布林值判斷路徑是否安全
    """
    if workspace_root:
        return PathSanitizer(workspace_root).is_safe_path(target_path, must_exist=must_exist)
    return _default_sanitizer.is_safe_path(target_path, must_exist=must_exist)


def safe_open(
    target_path: Union[str, Path],
    mode: str = "r",
    workspace_root: Optional[Union[str, Path]] = None,
    **kwargs
) -> Iterator[IO[Any]]:
    """
    全域捷徑：TOCTOU 防護之安全檔案開啟器
    """
    sanitizer = PathSanitizer(workspace_root) if workspace_root else _default_sanitizer
    return sanitizer.safe_open(target_path, mode=mode, **kwargs)
