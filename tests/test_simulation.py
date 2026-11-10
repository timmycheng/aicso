"""仿真套件 CI 包装（issue #33）——快速规模跑核心矩阵，纳入回归门禁"""
from __future__ import annotations

import pytest

from scripts.simulation_test import (
    run_all,
)


@pytest.mark.timeout(300)
async def test_simulation_core_matrix():
    """local+scripted 核心矩阵（分流13项/合并拆分11项/恢复/效率）"""
    result = await run_all(scale=0.3, with_systemone=False)
    assert result["ok"] is True, (
        "仿真矩阵存在失败: "
        + "; ".join(
            f"[{suite}] {s['name']} — {s['detail']}"
            for suite, sims in result["results"].items()
            for s in sims if not s["ok"]
        )
    )


@pytest.mark.timeout(120)
async def test_simulation_dataset_mode():
    """dataset回放有效性断言（issue #40）：Sysmon原始形状合成流 + field_mapping 真实映射路径

    两个攻击场景(同pair暴破/C2信标) + 一个良性噪声流(蜜罐扫描,逐条独立IP)，
    离线确定性：暴破收敛1个case、C2收敛1个case、噪声逐条独立、三断言全过。
    """
    from scripts.simulation_test import ScenarioStream, suite_dataset

    def sysmon_record(src, dst, ts, event_id=3, severity="high"):
        record = {"@timestamp": ts, "SourceName": "Microsoft-Windows-Sysmon",
                  "Channel": "Microsoft-Windows-Sysmon/Operational",
                  "EventID": event_id, "Severity": severity,
                  "Hostname": "HOST1.lab.local", "Message": "Network connection"}
        if src:
            record["SourceIp"] = src
        if dst:
            record["DestinationIp"] = dst
        return record

    brute = [sysmon_record("185.199.108.153", "10.0.0.66", f"2020-08-07T14:3{i}:00Z")
             for i in range(6)]
    brute.append(sysmon_record(None, None, "2020-08-07T14:39:00Z", event_id=10))  # 无IP进程事件
    c2 = [sysmon_record("198.51.100.23", "10.0.0.77", f"2020-08-07T15:0{i}:00Z")
          for i in range(5)]
    honeybucket = [sysmon_record(f"177.131.167.{145 + i}", f"10.0.1.{i}",
                                 f"2022-02-18T17:3{i}:00Z", severity="info")
                   for i in range(6)]
    streams = [ScenarioStream("mimikatz", brute),
               ScenarioStream("c2_beacon", c2),
               ScenarioStream("honeybucket", honeybucket, kind="benign")]
    mapping = {"src_ip": "SourceIp", "dst_ip": "DestinationIp",
               "rule_name": "Channel", "severity_text": "Severity",
               "timestamp": "@timestamp", "source": "SourceName"}

    results, metrics = await suite_dataset(streams, field_mapping=mapping)

    assert all(r.ok for r in results), (
        "dataset有效性断言失败: " + "; ".join(
            f"{r['name']} — {r['detail']}" for r in results if not r["ok"]))
    scenarios = metrics["scenarios"]
    assert scenarios["mimikatz"]["ip_cases"] == 1, "同pair暴破应收敛为1个case"
    assert scenarios["c2_beacon"]["ip_cases"] == 1, "C2信标应收敛为1个case"
    assert scenarios["honeybucket"]["ip_cases"] == 6, "逐条独立IP噪声应各自建case"
    assert metrics["mapping_warnings"] >= 1, "无IP进程事件应产生映射警告"

