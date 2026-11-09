"""Case 合并/拆分引擎（P2，设计§8）

合并：共享实体候选对 → System One 判定（合并入谁/不合并）→ 主Case吸收，
     被并Case打 merged_into 重定向（tombstone），双方时间线留审计，幂等。
拆分：从Case拆出告警子集新建Case，split_from 回链，双方时间线记录。

幂等：merge/split 操作以状态为幂等键——已 merged_into 的Case重复合并直接跳过。
"""
from __future__ import annotations

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


@dataclass
class MergeEvaluation:
    case_a: str
    case_b: str
    choice: str            # merge_into_a | merge_into_b | no_merge
    confidence: float
    executed: bool = False
    detail: dict = field(default_factory=dict)


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
        """从实体倒排索引发现共享实体的Case候选对"""
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

    # ---- System One 判定 ----

    async def evaluate_pair(
        self, case_a_id: str, case_b_id: str,
    ) -> MergeEvaluation | None:
        """判定两个Case是否应合并；System One不可用返回None"""
        if not self._client or case_a_id == case_b_id:
            return None
        row_a = await self.case_store.get(case_a_id)
        row_b = await self.case_store.get(case_b_id)
        if not row_a or not row_b:
            return None
        # 已合并的Case不再参与评估
        if row_a.get("merged_into") or row_b.get("merged_into"):
            return None

        state = (
            f"安全事件A：{row_a['title']}（当前严重度 {row_a['severity']}）\n"
            f"安全事件B：{row_b['title']}（当前严重度 {row_b['severity']}）\n"
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
        )

    # ---- 合并执行（幂等） ----

    async def merge(self, primary_id: str, absorbed_id: str, reason: str = "") -> dict:
        """主Case吸收被并Case。幂等：absorbed已有merged_into时跳过。"""
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

        await self._add_event(primary_id, "case_merged", {
            "absorbed": absorbed_id,
            "alerts_moved": moved,
            "reason": reason,
        })
        await self._add_event(absorbed_id, "merged_into", {
            "into": primary_id,
            "alerts_moved": moved,
            "reason": reason,
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


        first = Alert(
            alert_id=rows[0]["alert_id"], source=rows[0]["source"],
            rule_id=rows[0].get("rule_id"), rule_name=rows[0].get("rule_name"),
            severity=rows[0].get("severity"), src_ip=rows[0].get("src_ip"),
            dst_ip=rows[0].get("dst_ip"),
        )
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
            entities.extend(entity_keys_of(Alert(
                alert_id=r["alert_id"], source=r["source"],
                rule_id=r.get("rule_id"), rule_name=r.get("rule_name"),
                severity=r.get("severity"), src_ip=r.get("src_ip"),
                dst_ip=r.get("dst_ip"),
            )))
        self.index.add_case(new_case.case_id, new_case.title, entities)
        self.fallback.register(first, new_case.case_id)

        logger.info("split.executed", origin=case_id, new=new_case.case_id,
                    alerts_moved=moved)
        return {"ok": True, "new_case_id": new_case.case_id, "alerts_moved": moved}

    # ---- 周期扫描 ----

    async def sweep(self, max_pairs: int = 5, min_shared: int = 1) -> list[MergeEvaluation]:
        """扫描候选对并评估执行（System One判定+高置信度自动合并）

        min_shared 只是降低噪声的预筛，最终裁决在 System One。
        """
        pairs = self.find_candidate_pairs(min_shared=min_shared, limit=max_pairs)
        evaluations: list[MergeEvaluation] = []
        for pair in pairs:
            evaluation = await self.evaluate_pair(pair.case_a, pair.case_b)
            if evaluation is None:
                continue
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
