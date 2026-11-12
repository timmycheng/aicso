"""Case路由候选索引 — 实体倒排索引

设计依据: docs/REFACTOR_DESIGN.md §5.1
本地粗筛候选Case（0成本、微秒级），System One 只做 ≤top_k+1 选项的判定。
纯内存态，可从DB活跃Case重建（§5.6）。
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime

from aicso.models.alert import Alert


def _parse_ts(value) -> datetime | None:
    """SQLite 返回的 TIMESTAMP 可能是 ISO 字符串"""
    if value is None:
        return None
    if isinstance(value, datetime):
        return value
    try:
        return datetime.fromisoformat(str(value))
    except ValueError:
        return None


def entity_keys_of(alert: Alert) -> list[str]:
    """从告警提取实体键（倒排索引的key）

    IP/对端为位置型强信号；alert.entities 为类型化弱实体（issue #44，
    host/user/file_hash/dst_domain…）——弱实体仅产生候选交模型裁决。
    rule_id 不参与候选生成：同一检测规则全网多目标触发是SIEM常态，
    仅同规则意味着"同类攻击"而非"同一事件"（issue #31）；
    rule_id 仍保留在 entity_signature 中供决策缓存使用。
    """
    keys: list[str] = []
    if alert.src_ip:
        keys.append(f"ip:{alert.src_ip}")
    if alert.dst_ip:
        keys.append(f"ip:{alert.dst_ip}")
    if alert.src_ip and alert.dst_ip:
        keys.append(f"pair:{alert.src_ip}>{alert.dst_ip}")
    for etype, value in (alert.entities or {}).items():
        if value:
            keys.append(f"{etype}:{value}")
    return keys


def entity_signature(alert: Alert) -> str:
    """告警实体签名（决策缓存的key）"""
    entities = "|".join(f"{k}={v}" for k, v in sorted((alert.entities or {}).items()))
    return f"{alert.src_ip or '-'}|{alert.dst_ip or '-'}|{alert.rule_id or '-'}|{entities}"


def _weak_entity_keys(raw_entities) -> list[str]:
    """alerts.entities JSON 列 → 弱实体键（重启重建用；类型门控由调用方 _admit 承担）"""
    if not raw_entities:
        return []
    if isinstance(raw_entities, str):
        try:
            raw_entities = json.loads(raw_entities)
        except (TypeError, ValueError):
            return []
    if not isinstance(raw_entities, dict):
        return []
    return [
        f"{etype}:{value}"
        for etype, value in raw_entities.items()
        if value
    ]


@dataclass
class CaseSlot:
    """索引中的活跃Case槽位"""
    case_id: str
    summary: str                  # 一句话摘要（供System One Choice选项展示）
    last_seen: datetime = field(default_factory=datetime.utcnow)
    hits: int = 0                 # 累计汇入告警数
    entity_keys: set[str] = field(default_factory=set)

    def to_summary(self) -> str:
        return self.summary or self.case_id


class CaseRoutingIndex:
    """实体倒排索引: entity_key -> 活跃Case集合

    候选打分 = 与告警实体的交集大小，并列时最近活跃优先。
    entity_types（issue #44）：进索引的弱实体类型门控——ip/pair 恒可入，
    其余类型仅白名单内的入索引产生候选；类型可在 RoutingConfig.entity_types
    配置（回放审计/人工处置/LLM建议后续动态调整的落点）。
    """

    def __init__(self, top_k: int = 10, entity_types: set[str] | None = None):
        self.top_k = top_k
        self.entity_types: set[str] = set(entity_types or ())
        self._slots: dict[str, CaseSlot] = {}
        self._entity_map: dict[str, set[str]] = {}

    def _admit(self, key: str) -> bool:
        """实体键准入：ip/pair 强类型恒入，弱类型按配置白名单（issue #44）"""
        prefix = key.split(":", 1)[0]
        if prefix in ("ip", "pair"):
            return True
        return prefix in self.entity_types

    def add_case(self, case_id: str, summary: str, entity_keys: list[str]) -> None:
        slot = CaseSlot(
            case_id=case_id,
            summary=summary,
            entity_keys={k for k in entity_keys if self._admit(k)},
        )
        self._slots[case_id] = slot
        for key in slot.entity_keys:
            self._entity_map.setdefault(key, set()).add(case_id)

    def record_hit(self, case_id: str, entity_keys: list[str]) -> None:
        """告警汇入后更新槽位活跃度并吸收新实体（Case生长）"""
        slot = self._slots.get(case_id)
        if slot is None:
            return
        slot.last_seen = datetime.utcnow()
        slot.hits += 1
        for key in entity_keys:
            if self._admit(key) and key not in slot.entity_keys:
                slot.entity_keys.add(key)
                self._entity_map.setdefault(key, set()).add(case_id)

    def contains(self, case_id: str) -> bool:
        """Case是否在索引中活跃（路由防御检查用，避免每路由一次SELECT）"""
        return case_id in self._slots

    def case_entities(self, case_id: str) -> set[str]:
        """目标Case当前的实体集（汇入依据审计用）"""
        slot = self._slots.get(case_id)
        return set(slot.entity_keys) if slot else set()

    def entity_map(self) -> dict[str, set[str]]:
        """实体倒排视图（合并候选发现用），返回副本"""
        return {key: set(cids) for key, cids in self._entity_map.items()}

    def deactivate(self, case_id: str) -> None:
        """Case关闭/合并后移出候选（P2由CASE_STATUS_CHANGED事件驱动）"""
        slot = self._slots.pop(case_id, None)
        if slot is None:
            return
        for key in slot.entity_keys:
            case_ids = self._entity_map.get(key)
            if case_ids:
                case_ids.discard(case_id)
                if not case_ids:
                    del self._entity_map[key]

    def candidates(self, entity_keys: list[str]) -> list[CaseSlot]:
        """按实体交集打分取top-K候选"""
        scores: dict[str, int] = {}
        for key in entity_keys:
            if not self._admit(key):
                continue
            for case_id in self._entity_map.get(key, ()):  # 空集合安全
                scores[case_id] = scores.get(case_id, 0) + 1
        if not scores:
            return []
        slots = [(cid, score) for cid, score in scores.items() if cid in self._slots]
        slots.sort(key=lambda x: (-x[1], -self._slots[x[0]].last_seen.timestamp()))
        return [self._slots[cid] for cid, _ in slots[: self.top_k]]

    def rebuild(self, rows: list[dict]) -> int:
        """从DB行重建索引（重启恢复，§5.6）

        rows: [{case_id, summary, src_ip, dst_ip, rule_id, entities, last_seen, hits}]
        同一Case可能多行（多条告警/多pair），实体取并集、时间取最新、hits累加。
        实体列（#44弱实体）参与重建——与热路径 entity_keys_of 一致，
        保证重启前后路由行为一致（review #56发现8）。
        """
        self._slots.clear()
        self._entity_map.clear()
        for row in rows:
            case_id = row["case_id"]
            # 与 entity_keys_of 一致：ip/pair + 白名单弱实体（rule_id不参与，issue #31）
            entities = []
            if row.get("src_ip"):
                entities.append(f"ip:{row['src_ip']}")
            if row.get("dst_ip"):
                entities.append(f"ip:{row['dst_ip']}")
            if row.get("src_ip") and row.get("dst_ip"):
                entities.append(f"pair:{row['src_ip']}>{row['dst_ip']}")
            for key in _weak_entity_keys(row.get("entities")):
                entities.append(key)

            existing = self._slots.get(case_id)
            if existing is not None:
                existing.entity_keys.update(entities)
                parsed = _parse_ts(row.get("last_seen"))
                if parsed and parsed > existing.last_seen:
                    existing.last_seen = parsed
                existing.hits += row.get("hits", 0)
                continue

            slot = CaseSlot(
                case_id=case_id,
                summary=row.get("summary", case_id),
                last_seen=_parse_ts(row.get("last_seen")) or datetime.utcnow(),
                hits=row.get("hits", 0),
                entity_keys=set(entities),
            )
            self._slots[case_id] = slot
            for key in slot.entity_keys:
                self._entity_map.setdefault(key, set()).add(case_id)
        return len(self._slots)

    def stats(self) -> dict:
        return {
            "active_cases": len(self._slots),
            "entity_keys": len(self._entity_map),
            "top_k": self.top_k,
        }

    def slot_rows(self) -> list[dict]:
        """槽位明细（供UI/API展示）"""
        now = datetime.utcnow()
        rows = []
        for slot in sorted(self._slots.values(),
                           key=lambda s: -s.last_seen.timestamp()):
            rows.append({
                "case_id": slot.case_id,
                "summary": slot.summary,
                "hits": slot.hits,
                "entity_count": len(slot.entity_keys),
                "last_seen": slot.last_seen,
                "idle_seconds": (now - slot.last_seen).total_seconds(),
            })
        return rows
