"""
async_attachment_worker.py — Synology Chat 異步附件佇列與背景推播器
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
功能：
1. 將大型檔案與單據 PDF 推播移至背景佇列 (Background Thread Queue)
2. 主對話迴圈秒級回傳文字訊息，附件在背景秒級無縫送達
3. 具備自動重試 (3 次) 與失敗降級日誌
"""

import queue
import threading
import time
from pathlib import Path
from typing import Optional, Union
from .chat_client import send_chat_file
from .evidence_logger import log_event

_attachment_queue = queue.Queue()
_worker_thread = None
_worker_lock = threading.Lock()


def _worker_loop():
    while True:
        item = _attachment_queue.get()
        if item is None:
            break
        file_path, message, channel_id, retries = item
        success = False
        for attempt in range(retries):
            try:
                success = send_chat_file(file_path, message=message, channel_id=channel_id)
                if success:
                    log_event("async_chat", f"Async file pushed successfully: {Path(file_path).name}")
                    break
            except Exception as e:
                log_event("async_chat", f"Async file push attempt {attempt+1} failed: {e}", level="WARNING")
            time.sleep(1.0)

        if not success:
            log_event("async_chat", f"Failed to push async file after {retries} retries: {Path(file_path).name}", level="ERROR")
        _attachment_queue.task_done()


def ensure_worker_running():
    global _worker_thread
    with _worker_lock:
        if _worker_thread is None or not _worker_thread.is_alive():
            _worker_thread = threading.Thread(target=_worker_loop, daemon=True, name="AsyncAttachmentWorker")
            _worker_thread.start()


def enqueue_chat_file(file_path: Union[str, Path], message: str = "", channel_id: Optional[str] = None, retries: int = 3):
    """將檔案附件推播加入背景佇列"""
    ensure_worker_running()
    _attachment_queue.put((str(file_path), message, channel_id, retries))
    log_event("async_chat", f"Enqueued async attachment: {Path(file_path).name}")


if __name__ == "__main__":
    ensure_worker_running()
    print("✅ async_attachment_worker module operational.")
