"""本地兜底分流 — System One不可用时的降级路径

设计依据: docs/REFACTOR_DESIGN.md §5.5
规则: src_ip+dst_ip 精确匹配（沿用原即时规则语义，10分钟窗口，命中滑动续期）。
无外部依赖，确定性时延。
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta

from aicso.models.alert import Alert

PAIR_WINDOW_MINUTES = 10


@dataclass
class FallbackMatch:
    case_id: str
    key: str


class LocalFallback:
    """src_ip+dst_ip 即时兜底规则"""

    def __init__(self, window_minutes: int = PAIR_WINDOW_MINUTES):
        self.window_minutes = window_minutes
        # pair_key -> (case_id, last_seen)
        self._pair_cache: dict[str, tuple[str, datetime]] = {}

    def try_route(self, alert: Alert) -> FallbackMatch | None:
        """尝试兜底匹配，未命中返回None（由调用方建新Case后register）"""
        if not (alert.src_ip and alert.dst_ip):
            return None
        pair_key = f"{alert.src_ip}>{alert.dst_ip}"
        cached = self._pair_cache.get(pair_key)
        if cached is None:
            return None
        case_id, last_seen = cached
        if datetime.utcnow() - last_seen <= timedelta(minutes=self.window_minutes):
            self._pair_cache[pair_key] = (case_id, datetime.utcnow())
            return FallbackMatch(case_id=case_id, key=pair_key)
        # 窗口过期，惰性删除
        del self._pair_cache[pair_key]
        return None

    def register(self, alert: Alert, case_id: str) -> None:
        """新建Case时注册兜底槽位"""
        if not (alert.src_ip and alert.dst_ip):
            return
        pair_key = f"{alert.src_ip}>{alert.dst_ip}"
        self._pair_cache[pair_key] = (case_id, datetime.utcnow())

    def deactivate(self, case_id: str) -> None:
        """Case关闭/合并后清除其兜底槽位"""
        expired = [k for k, (cid, _) in self._pair_cache.items() if cid == case_id]
        for k in expired:
            del self._pair_cache[k]

    def rebuild(self, rows: list[dict]) -> int:
        """从DB行重建pair缓存（重启恢复）

        rows: [{case_id, src_ip, dst_ip, last_seen}]
        窗口过期的pair自然失效（try_route按last_seen判过期），无需特殊处理。
        """
        self._pair_cache.clear()
        for row in rows:
            if row.get("src_ip") and row.get("dst_ip"):
                pair_key = f"{row['src_ip']}>{row['dst_ip']}"
                last_seen = row.get("last_seen")
                if not isinstance(last_seen, datetime):
                    try:
                        last_seen = datetime.fromisoformat(str(last_seen))
                    except (ValueError, TypeError):
                        last_seen = datetime.utcnow()
                self._pair_cache[pair_key] = (row["case_id"], last_seen)
        return len(self._pair_cache)

    def stats(self) -> dict:
        return {"pair_cache_size": len(self._pair_cache)}
