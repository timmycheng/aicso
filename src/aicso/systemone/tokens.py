"""Token估算单一实现（issue #57：engine //3 与 client /4 两套实现漂移收敛）

保守上界口径：CJK≈1 token/字符、其他≈3字符/token、空串0。
宁可高估——供微批预算切分（超限走422二分兜底）与请求规模估算；
实际用量一律以响应usage为准。
"""
from __future__ import annotations


def estimate_tokens(text: str) -> int:
    """粗估文本token数（保守上界）"""
    if not text:
        return 0
    cjk = sum(1 for ch in text if "\u4e00" <= ch <= "\u9fff")
    return cjk + (len(text) - cjk) // 3
