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
    """src_ip+dst_ip 即时兜底规则

    weak_auto_merge（issue #44）：弱实体自动合并开关，默认关——弱实体
    （host/user/hash/domain…）仅产生候选交模型裁决；开启后共享弱实体的
    告警在窗口内直接汇入（误并风险自担：共享服务账号/同主机多事件）。
    """

    def __init__(self, window_minutes: int = PAIR_WINDOW_MINUTES,
                 weak_auto_merge: bool = False):
        self.window_minutes = window_minutes
        self.weak_auto_merge = weak_auto_merge
        # pair_key/weak_key -> (case_id, last_seen)
        self._pair_cache: dict[str, tuple[str, datetime]] = {}
        self._weak_cache: dict[str, tuple[str, datetime]] = {}

    def _weak_keys(self, alert: Alert) -> list[str]:
        return [f"{etype}:{value}"
                for etype, value in (alert.entities or {}).items() if value]

    def try_route(self, alert: Alert) -> FallbackMatch | None:
        """尝试兜底匹配，未命中返回None（由调用方建新Case后register）"""
        if alert.src_ip and alert.dst_ip:
            pair_key = f"{alert.src_ip}>{alert.dst_ip}"
            cached = self._pair_cache.get(pair_key)
            if cached is not None:
                case_id, last_seen = cached
                if datetime.utcnow() - last_seen <= timedelta(minutes=self.window_minutes):
                    self._pair_cache[pair_key] = (case_id, datetime.utcnow())
                    return FallbackMatch(case_id=case_id, key=pair_key)
                # 窗口过期，惰性删除
                del self._pair_cache[pair_key]
        if self.weak_auto_merge:
            for weak_key in self._weak_keys(alert):
                cached = self._weak_cache.get(weak_key)
                if cached is None:
                    continue
                case_id, last_seen = cached
                if datetime.utcnow() - last_seen <= timedelta(minutes=self.window_minutes):
                    self._weak_cache[weak_key] = (case_id, datetime.utcnow())
                    return FallbackMatch(case_id=case_id, key=weak_key)
                del self._weak_cache[weak_key]
        return None

    def register(self, alert: Alert, case_id: str) -> None:
        """新建Case时注册兜底槽位"""
        if alert.src_ip and alert.dst_ip:
            pair_key = f"{alert.src_ip}>{alert.dst_ip}"
            self._pair_cache[pair_key] = (case_id, datetime.utcnow())
        if self.weak_auto_merge:
            for weak_key in self._weak_keys(alert):
                self._weak_cache[weak_key] = (case_id, datetime.utcnow())

    def deactivate(self, case_id: str) -> None:
        """Case关闭/合并后清除其兜底槽位"""
        for cache in (self._pair_cache, self._weak_cache):
            expired = [k for k, (cid, _) in cache.items() if cid == case_id]
            for k in expired:
                del cache[k]

    def rebuild(self, rows: list[dict]) -> int:
        """从DB行重建pair缓存（重启恢复）

        rows: [{case_id, src_ip, dst_ip, last_seen}]
        窗口过期的pair自然失效（try_route按last_seen判过期），无需特殊处理。
        弱实体槽位不重建（DB行无实体列）——重启后由新告警汇入时
        record_hit/register 重新吸收（issue #44 v1接受）。
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
        return {"pair_cache_size": len(self._pair_cache),
                "weak_cache_size": len(self._weak_cache)}
