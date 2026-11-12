"""Case 合并/拆分引擎（P2，设计§8）

合并：共享实体候选对 → System One 判定（合并入谁/不合并）→ 主Case吸收，
     被并Case打 merged_into 重定向（tombstone），双方时间线留审计，幂等。
拆分：从Case拆出告警子集新建Case，split_from 回链，双方时间线记录。

幂等：merge/split 操作以状态为幂等键——已 merged_into 的Case重复合并直接跳过。
"""
from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime

import structlog
from ulid import ULID

from aicso.config import SystemOneConfig
from aicso.models.alert import Alert
from aicso.models.case import Case, CaseSeverity, CaseStatus
from aicso.router.fallback import LocalFallback
from aicso.router.index import CaseRoutingIndex, entity_keys_of
from aicso.store.alert_store import AlertStore
from aicso.store.case_store import CaseStore
from aicso.systemone.client import Choice, SystemOneClient, SystemOneError

logger = structlog.get_logger()


@dataclass
class CandidatePair:
    case_a: str
    case_b: str
    shared_entities: list[str]
    source: str = "hot"    # hot=索引发现 | cold=DB历史发现（#48）


@dataclass
class MergeEvaluation:
    case_a: str
    case_b: str
    choice: str            # merge_into_a | merge_into_b | no_merge
    confidence: float
    executed: bool = False
    detail: dict = field(default_factory=dict)
    evidence: dict = field(default_factory=dict)   # 关联证据链（#48）


# 实体键前缀 → 人读分类（证据链展示用）
ENTITY_LABELS = {
    "ip": "IP",
    "pair": "IP对",
    "host": "主机",
    "user": "用户",
    "file_hash": "文件哈希",
    "dst_domain": "域名",
}


def classify_entities(keys: list[str]) -> dict[str, list[str]]:
    """实体键按类型分类（证据链结构化展示）"""
    out: dict[str, list[str]] = {}
    for key in keys:
        etype, _, value = key.partition(":")
        label = ENTITY_LABELS.get(etype, etype)
        out.setdefault(label, []).append(value)
    return out


class MergeSplitEngine:
    """合并/拆分引擎：System One 判定 + 幂等执行"""

    def __init__(
        self,
        case_store: CaseStore,
        alert_store: AlertStore,
        client: SystemOneClient | None,
        scfg: SystemOneConfig,
        index: CaseRoutingIndex,
        fallback: LocalFallback,
    ):
        self.case_store = case_store
        self.alert_store = alert_store
        self._client = client
        self.scfg = scfg
        self.index = index
        self.fallback = fallback

    # ---- 候选发现 ----

    def find_candidate_pairs(self, min_shared: int = 1, limit: int = 20) -> list[CandidatePair]:
        """从实体倒排索引发现共享实体的Case候选对（热发现）"""
        entity_map = self.index.entity_map()
        pair_scores: dict[tuple[str, str], list[str]] = {}
        for key, case_ids in entity_map.items():
            ids = sorted(case_ids)
            for i in range(len(ids)):
                for j in range(i + 1, len(ids)):
                    pair_scores.setdefault((ids[i], ids[j]), []).append(key)

        pairs = [
            CandidatePair(case_a=a, case_b=b, shared_entities=keys)
            for (a, b), keys in pair_scores.items()
            if len(keys) >= min_shared
        ]
        pairs.sort(key=lambda p: -len(p.shared_entities))
        return pairs[:limit]

    async def find_cold_candidate_pairs(
        self, min_shared: int = 1, limit: int = 20,
    ) -> list[CandidatePair]:
        """DB历史发现冷Case候选对（issue #48）

        pair窗过期≠事件结束——索引之外的存量Case（未合并/未关闭）若共享
        IP实体同样应进入合并裁决。min_shared 只是降噪预筛，最终裁决在模型。
        弱实体冷发现需JSON展开扫描，v1 仅IP维度（热路径覆盖近期弱实体）。
        """
        rows = await self.alert_store.db.fetch_all(
            """
            SELECT a1.case_id AS case_a, a2.case_id AS case_b,
                   a1.src_ip AS s1, a1.dst_ip AS d1
            FROM alerts a1
            JOIN alerts a2
              ON a1.case_id < a2.case_id
             AND (a1.src_ip IN (a2.src_ip, a2.dst_ip)
                  OR a1.dst_ip IN (a2.src_ip, a2.dst_ip))
            JOIN cases c1 ON c1.case_id = a1.case_id
             AND c1.merged_into IS NULL
             AND c1.status NOT IN ('closed', 'resolved')
            JOIN cases c2 ON c2.case_id = a2.case_id
             AND c2.merged_into IS NULL
             AND c2.status NOT IN ('closed', 'resolved')
            WHERE a1.src_ip IS NOT NULL OR a1.dst_ip IS NOT NULL
            LIMIT 5000
            """,
        )
        pair_keys: dict[tuple[str, str], set[str]] = {}
        for row in rows:
            pair = (row["case_a"], row["case_b"])
            keys = pair_keys.setdefault(pair, set())
            for ip in (row["s1"], row["d1"]):
                if ip:
                    keys.add(f"ip:{ip}")
        pairs = [
            CandidatePair(case_a=a, case_b=b, shared_entities=sorted(keys),
                          source="cold")
            for (a, b), keys in pair_keys.items()
            if len(keys) >= min_shared
        ]
        pairs.sort(key=lambda p: -len(p.shared_entities))
        return pairs[:limit]

    # ---- System One 判定 ----

    async def _case_stats(self, case_id: str) -> dict:
        """Case整体画像：告警数/时间跨度/主要规则（#48整体化裁决上下文）"""
        row = await self.alert_store.db.fetch_one(
            """SELECT COUNT(*) AS cnt,
                      MIN(timestamp) AS first_seen, MAX(timestamp) AS last_seen
               FROM alerts WHERE case_id = ?""",
            (case_id,),
        )
        rules = await self.alert_store.db.fetch_all(
            """SELECT rule_name, COUNT(*) AS n FROM alerts
               WHERE case_id = ? GROUP BY rule_name ORDER BY n DESC LIMIT 3""",
            (case_id,),
        )
        return {
            "alerts": row["cnt"] if row else 0,
            "first_seen": str(row["first_seen"]) if row else "-",
            "last_seen": str(row["last_seen"]) if row else "-",
            "top_rules": [f"{r['rule_name'] or '-'}×{r['n']}" for r in rules],
        }

    async def evaluate_pair(
        self, case_a_id: str, case_b_id: str,
        shared_entities: list[str] | None = None,
    ) -> MergeEvaluation | None:
        """判定两个Case是否应合并；System One不可用返回None

        shared_entities: 候选发现的共享实体键——缺失时从索引补算（#48证据链）
        """
        if not self._client or case_a_id == case_b_id:
            return None
        row_a = await self.case_store.get(case_a_id)
        row_b = await self.case_store.get(case_b_id)
        if not row_a or not row_b:
            return None
        # 已合并的Case不再参与评估
        if row_a.get("merged_into") or row_b.get("merged_into"):
            return None

        stats_a = await self._case_stats(case_a_id)
        stats_b = await self._case_stats(case_b_id)
        if shared_entities is None:
            shared_entities = sorted(
                self.index.case_entities(case_a_id)
                & self.index.case_entities(case_b_id))
        classified = classify_entities(shared_entities)
        entity_desc = "；".join(
            f"{label}[{', '.join(values)}]" for label, values in classified.items()
        ) or "无共享实体记录"

        def _case_line(title: str, row: dict, stats: dict) -> str:
            return (
                f"安全事件{title}：{row['title']}（严重度 {row['severity']}，"
                f"{stats['alerts']}条告警，"
                f"时间跨度 {stats['first_seen']} ~ {stats['last_seen']}，"
                f"主要规则 {', '.join(stats['top_rules']) or '-'}）"
            )

        state = (
            f"{_case_line('A', row_a, stats_a)}\n"
            f"{_case_line('B', row_b, stats_b)}\n"
            f"两事件共享实体：{entity_desc}\n"
            "两者由告警分流产生，请判断是否为同一真实事件。"
        )
        try:
            response = await self._client.system_one(
                state=state,
                questions={
                    "merge_decision": Choice(
                        instructions=(
                            "事件A与事件B是否应合并为同一个事件处置？"
                            "若合并，应保留哪一个为主体？"
                            "判定依据：共享实体（IP/主机/用户/哈希/域名）与行为连贯性。"
                            "注意：时间跨度长的攻击链（潜伏/慢速渗透）很常见，"
                            "时间间隔本身不是否决理由，应以实体关联与行为连贯性为准。"
                        ),
                        criteria={
                            "merge_into_a": "是同一事件，以A为主体合并B",
                            "merge_into_b": "是同一事件，以B为主体合并A",
                            "no_merge": "不是同一事件，不应合并",
                        },
                    ),
                },
            )
        except SystemOneError as e:
            logger.warning("merge.evaluate_failed", case_a=case_a_id,
                           case_b=case_b_id, error=str(e))
            return None

        answer = response.answers.get("merge_decision")
        if answer is None:
            return None
        confidence = answer.confidence or 0.0
        choice = answer.choice
        if choice not in ("merge_into_a", "merge_into_b", "no_merge"):
            choice = "no_merge"
        return MergeEvaluation(
            case_a=case_a_id, case_b=case_b_id,
            choice=choice, confidence=confidence,
            evidence={
                "shared_entities": classified,
                "shared_entity_keys": shared_entities,
                "case_a": stats_a,
                "case_b": stats_b,
            },
        )

    # ---- 合并执行（幂等） ----

    async def merge(self, primary_id: str, absorbed_id: str, reason: str = "",
                    evidence: dict | None = None) -> dict:
        """主Case吸收被并Case。幂等：absorbed已有merged_into时跳过。

        evidence: 关联证据链（#48）——共享实体分类/时间跨度/告警画像，
        写入双方时间线事件，审计可回溯"为什么关联"。
        """
        if primary_id == absorbed_id:
            return {"ok": False, "reason": "same_case"}
        absorbed = await self.case_store.get(absorbed_id)
        if not absorbed:
            return {"ok": False, "reason": "absorbed_not_found"}
        if absorbed.get("merged_into"):  # 幂等键
            return {"ok": True, "skipped": "already_merged",
                    "merged_into": absorbed["merged_into"]}
        primary = await self.case_store.get(primary_id)
        if not primary:
            return {"ok": False, "reason": "primary_not_found"}
        if primary.get("merged_into"):
            return {"ok": False, "reason": "primary_already_merged"}

        moved = await self.alert_store.move_alerts(absorbed_id, primary_id)

        evidence = evidence or {}
        await self._add_event(primary_id, "case_merged", {
            "absorbed": absorbed_id,
            "alerts_moved": moved,
            "reason": reason,
            "evidence": evidence,
        })
        await self._add_event(absorbed_id, "merged_into", {
            "into": primary_id,
            "alerts_moved": moved,
            "reason": reason,
            "evidence": evidence,
        })
        await self.case_store.update_relation(absorbed_id, merged_into=primary_id)
        # 交互频次操作：flush保证重定向立即可读（幂等键依赖该字段）
        await self.case_store.db.flush()

        # 路由状态清理：被并Case退出候选（重启重建由merged_into过滤兜底）
        self.index.deactivate(absorbed_id)
        self.fallback.deactivate(absorbed_id)

        logger.info("merge.executed", primary=primary_id, absorbed=absorbed_id,
                    alerts_moved=moved)
        return {"ok": True, "alerts_moved": moved}

    # ---- 拆分执行 ----

    async def split(
        self, case_id: str, alert_ids: list[str], reason: str = "",
        new_title: str = "",
    ) -> dict:
        """从Case拆出告警子集新建Case（split_from回链）"""
        origin = await self.case_store.get(case_id)
        if not origin:
            return {"ok": False, "reason": "case_not_found"}
        if not alert_ids:
            return {"ok": False, "reason": "empty_alert_ids"}

        # 校验告警归属
        rows = await self.alert_store.db.fetch_all(
            f"SELECT * FROM alerts WHERE case_id = ? AND alert_id IN "
            f"({','.join('?' * len(alert_ids))})",
            (case_id, *alert_ids),
        )
        if not rows:
            return {"ok": False, "reason": "no_matching_alerts"}


        def _alert_from_row(r: dict) -> Alert:
            """行→Alert（含类型化实体恢复，#48：弱实体随拆分迁移）"""
            try:
                entities = json.loads(r.get("entities") or "{}")
            except (json.JSONDecodeError, TypeError):
                entities = {}
            return Alert(
                alert_id=r["alert_id"], source=r["source"],
                rule_id=r.get("rule_id"), rule_name=r.get("rule_name"),
                severity=r.get("severity"), src_ip=r.get("src_ip"),
                dst_ip=r.get("dst_ip"), entities=entities,
            )

        first = _alert_from_row(rows[0])
        new_case = Case(
            case_id=f"CSO-{datetime.utcnow().strftime('%Y%m%d')}-{uuid.uuid4().hex[:12].upper()}",
            title=new_title or f"{origin['title']} (拆分)",
            severity=CaseSeverity(origin["severity"]),
            status=CaseStatus.NEW,
            metadata={"routing": {"split_from": case_id, "reason": reason}},
        )
        new_case.split_from = case_id
        new_case.record_case_created(source=f"split_from_{case_id}")
        await self.case_store.create(new_case)
        await self.case_store.update_relation(new_case.case_id, split_from=case_id)
        # flush：新Case行必须先于 move_alerts 的FK直写可见
        # （仿真抓到：写缓冲未落库时直写UPDATE触发FOREIGN KEY违约）
        await self.case_store.db.flush()

        moved = await self.alert_store.move_alerts(case_id, new_case.case_id, alert_ids)
        moved_ids = [r["alert_id"] for r in rows]

        await self._add_event(new_case.case_id, "case_split_created", {
            "from": case_id, "alerts_moved": moved, "reason": reason,
            "alert_ids": moved_ids,
        })
        await self._add_event(case_id, "case_split", {
            "to": new_case.case_id, "alerts_moved": moved,
            "reason": reason, "alert_ids": moved_ids,
        })

        # 新Case注册路由状态（实体来自被迁移告警）
        entities: list[str] = []
        for r in rows:
            entities.extend(entity_keys_of(_alert_from_row(r)))
        self.index.add_case(new_case.case_id, new_case.title, entities)
        self.fallback.register(first, new_case.case_id)

        logger.info("split.executed", origin=case_id, new=new_case.case_id,
                    alerts_moved=moved)
        return {"ok": True, "new_case_id": new_case.case_id, "alerts_moved": moved}

    # ---- 周期扫描 ----

    async def sweep(self, max_pairs: int = 5, min_shared: int = 1,
                    include_cold: bool = True) -> list[MergeEvaluation]:
        """扫描候选对并评估执行（System One判定+高置信度自动合并）

        min_shared 只是降低噪声的预筛，最终裁决在 System One。
        include_cold（#48）：热索引之外，DB存量Case按共享IP发现候选——
        长时攻击的早期Case不因pair窗过期而失去被关联机会。
        """
        pairs = self.find_candidate_pairs(min_shared=min_shared,
                                          limit=max_pairs)
        if include_cold:
            hot_set = {(p.case_a, p.case_b) for p in pairs}
            cold = await self.find_cold_candidate_pairs(min_shared=min_shared,
                                                        limit=max_pairs)
            pairs.extend(p for p in cold
                         if (p.case_a, p.case_b) not in hot_set)
        evaluations: list[MergeEvaluation] = []
        for pair in pairs:
            evaluation = await self.evaluate_pair(
                pair.case_a, pair.case_b, shared_entities=pair.shared_entities)
            if evaluation is None:
                continue
            evaluation.detail["pair_source"] = pair.source
            evaluations.append(evaluation)
            if (
                evaluation.choice in ("merge_into_a", "merge_into_b")
                and evaluation.confidence >= self.scfg.confidence_threshold
            ):
                primary = (
                    evaluation.case_a if evaluation.choice == "merge_into_a"
                    else evaluation.case_b
                )
                absorbed = (
                    evaluation.case_b if evaluation.choice == "merge_into_a"
                    else evaluation.case_a
                )
                result = await self.merge(
                    primary, absorbed,
                    reason=f"System One判定(置信度{evaluation.confidence:.2f})",
                    evidence=evaluation.evidence,
                )
                evaluation.executed = bool(result.get("ok")) and not result.get("skipped")
        return evaluations

    # ---- 内部 ----

    async def _add_event(self, case_id: str, event_type: str, detail: dict) -> None:
        from aicso.models.case import CaseEvent

        event = CaseEvent(
            event_id=f"{case_id}-evt-{str(ULID())}",
            event_type=event_type,
            actor="merge_split_engine",
            detail=detail,
        )
        await self.case_store.add_event(case_id, event)
