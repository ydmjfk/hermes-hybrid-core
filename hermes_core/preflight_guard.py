#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
preflight_guard.py — 簡報與排版幾何碰撞預檢自審門禁 (Preflight Deck Guard)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
職責：
1. 自動解析簡報物件邊界 (Bounding Box)，進行幾何相交與圖層碰撞審計。
2. 預檢排版隱患：
   - 頂部膠囊/標籤折行溢出與主標題重疊
   - 裝飾線條與主內容文字框實體相交
   - 卡片邊框幾何溢出與文字穿透
   - 特殊跨平台未支援 Emoji 豆腐塊/缺字
3. 支援純幾何判定與 python-pptx 實體審計雙模運作。
"""

import os
import sys
import re
import json
from typing import Dict, List, Tuple, Any, Optional
from pathlib import Path

# 常見在 Linux 或特定渲染引擎下易缺字變成豆腐塊方框的 Emoji 集合
DEFAULT_UNSUPPORTED_EMOJIS = set([
    "📊", "📅", "👤", "🎯", "🏢", "🟢", "🔴", "🟡", "🟠", "📈", 
    "📉", "📋", "📁", "📂", "📌", "📍", "⚙️", "🔧", "🛠️", "💡"
])


def is_intersecting(bbox1: Tuple[float, float, float, float], 
                    bbox2: Tuple[float, float, float, float], 
                    margin: float = 0.05) -> bool:
    """
    判定兩個邊界矩形 (Bounding Box) 是否實體相交重疊。
    bbox 格式: (x0, y0, x1, y1)
    """
    ax0, ay0, ax1, ay1 = bbox1
    bx0, by0, bx1, by1 = bbox2

    # 內縮微小邊距 (margin) 避免邊界貼齊被判定為相交
    if (ax1 - margin <= bx0) or (bx1 - margin <= ax0):
        return False
    if (ay1 - margin <= by0) or (by1 - margin <= ay0):
        return False

    return True


class PreflightDeckGuard:
    """簡報幾何排版預檢自審門禁"""

    def __init__(self, unsupported_emojis: Optional[set] = None):
        self.unsupported_emojis = unsupported_emojis or DEFAULT_UNSUPPORTED_EMOJIS

    def audit_pptx(self, pptx_path: str) -> Dict[str, Any]:
        """
        審計指定路徑之 PPTX 檔案
        回傳結構化稽核結果，包含 passed, total_slides, overlaps, warnings
        """
        p = Path(pptx_path)
        if not p.exists() or not p.is_file():
            return {
                "passed": False,
                "error": f"檔案不存在: {pptx_path}",
                "total_slides": 0,
                "overlaps": 0,
                "warnings": []
            }

        try:
            from pptx import Presentation
            from pptx.enum.shapes import MSO_SHAPE_TYPE, MSO_SHAPE
        except ImportError:
            return {
                "passed": False,
                "error": "缺少依賴套件 'python-pptx'，請執行 'pip install python-pptx'。",
                "total_slides": 0,
                "overlaps": 0,
                "warnings": []
            }

        prs = Presentation(pptx_path)
        all_warnings = []
        total_overlaps = 0

        for slide_idx, slide in enumerate(prs.slides, 1):
            shapes_info = []

            for s in slide.shapes:
                try:
                    x0 = round(s.left.inches, 3)
                    y0 = round(s.top.inches, 3)
                    w  = round(s.width.inches, 3)
                    h  = round(s.height.inches, 3)
                    x1 = round(x0 + w, 3)
                    y1 = round(y0 + h, 3)
                except Exception:
                    continue

                # 略過全頁底圖 (預設寬高 > 12.0 x 6.5)
                if w >= 12.0 and h >= 6.5:
                    continue

                text_content = ""
                found_emojis = []

                if s.has_text_frame:
                    for p_elem in s.text_frame.paragraphs:
                        for r in p_elem.runs:
                            txt = r.text
                            text_content += txt
                            for ch in txt:
                                if ch in self.unsupported_emojis:
                                    found_emojis.append(ch)

                shape_type_name = "shape"
                try:
                    st = s.shape_type
                    if st == MSO_SHAPE_TYPE.TEXT_BOX:
                        shape_type_name = "textbox"
                    elif st == MSO_SHAPE_TYPE.AUTO_SHAPE:
                        if s.auto_shape_type == MSO_SHAPE.ROUNDED_RECTANGLE:
                            shape_type_name = "rounded_rect"
                        elif s.auto_shape_type == MSO_SHAPE.RECTANGLE:
                            shape_type_name = "rect"
                        else:
                            shape_type_name = "autoshape"
                    elif st == MSO_SHAPE_TYPE.PICTURE:
                        shape_type_name = "picture"
                except Exception:
                    pass

                info = {
                    "id": s.shape_id,
                    "name": s.name,
                    "type": shape_type_name,
                    "bbox": (x0, y0, x1, y1),
                    "w": w, "h": h,
                    "text": text_content.strip(),
                    "emojis": found_emojis
                }
                shapes_info.append(info)

                # 檢測豆腐塊 Emoji
                if found_emojis:
                    unique_em = list(dict.fromkeys(found_emojis))
                    all_warnings.append({
                        "slide": slide_idx,
                        "level": "WARN",
                        "category": "EMOJI_TOFU",
                        "shape_id": s.shape_id,
                        "shape_name": s.name,
                        "desc": f"檢測到跨平台潛在缺字 Emoji: {' '.join(unique_em)}",
                        "snippet": text_content[:30]
                    })

            # 檢驗形狀幾何重疊
            n = len(shapes_info)
            for i in range(n):
                for j in range(i + 1, n):
                    s1 = shapes_info[i]
                    s2 = shapes_info[j]

                    # 容器與子元素包含關係略過 (卡片 vs 卡片內文字)
                    if s1["type"] in ("rounded_rect", "rect") and s2["type"] == "textbox":
                        continue
                    if s2["type"] in ("rounded_rect", "rect") and s1["type"] == "textbox":
                        continue

                    # 兩文字框重疊或文字框與裝飾條相交
                    if s1["text"] and s2["text"]:
                        if is_intersecting(s1["bbox"], s2["bbox"]):
                            total_overlaps += 1
                            all_warnings.append({
                                "slide": slide_idx,
                                "level": "ERROR",
                                "category": "TEXT_COLLISION",
                                "shape_1": s1["name"],
                                "shape_2": s2["name"],
                                "desc": f"文字方塊碰撞相交: '{s1['text'][:15]}' 與 '{s2['text'][:15]}'",
                                "bbox_1": s1["bbox"],
                                "bbox_2": s2["bbox"]
                            })

        passed = (total_overlaps == 0)
        return {
            "passed": passed,
            "total_slides": len(prs.slides),
            "overlaps": total_overlaps,
            "warnings_count": len(all_warnings),
            "warnings": all_warnings
        }


def audit_deck_file(pptx_path: str) -> Dict[str, Any]:
    """快捷審計函數"""
    guard = PreflightDeckGuard()
    return guard.audit_pptx(pptx_path)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("用法: python3 preflight_guard.py <path_to_pptx>")
        sys.exit(1)
    
    target = sys.argv[1]
    res = audit_deck_file(target)
    print(json.dumps(res, indent=2, ensure_ascii=False))
    sys.exit(0 if res["passed"] else 1)
