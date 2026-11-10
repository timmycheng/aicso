"""真实告警数据集回放验证（issue #40）

用公开真实告警数据源验证 case 产出有效性（合并收敛/跨场景隔离/噪声鲁棒）:
  - OTRF/Security-Datasets（MIT）: https://github.com/OTRF/Security-Datasets
    场景化 JSONL（Sysmon/Windows 原始字段，--preset security-datasets），
    一个数据集文件 = 一个攻击场景 = 天然的 expected-case 标签
  - splunk/botsv3: Splunk search 导出 JSON 后同样可回放（--field-mapping 自配）
  - sbousseaden/EVTX-ATTACK-SAMPLES + Winlogbeat 输出: ECS 格式，--schema ecs

模式:
  direct  本地引擎直灌（离线，同仿真管道），输出有效性记分卡
  kafka   aiokafka 逐条 produce 到 topic，走真实 Kafka→映射→分流链路
          （需 uv sync --extra kafka；消费由正常运行的 AiCSO 完成，
          消费组遵循规范 aicso-<环境>-<数据源>，如 aicso-dev-dataset-replay）

时间戳语义：回放保留事件原始时间戳，但路由 pair 窗与索引 last_seen 按
摄入时钟计（PAIR_WINDOW_MINUTES=10）——--rate 低速回放会真实影响汇入结果。

文件格式: .jsonl（每行一事件）/ .json（数组或单对象）/ .csv（DictReader，列名即字段路径）
目录输入会递归收集全部支持文件；文件名 stem 即场景名（即 expected-case 标签）。

用法:
  uv run python scripts/replay_dataset.py <路径>... --mode direct
  uv run python scripts/replay_dataset.py <路径>... --mode kafka --bootstrap localhost:9092
  uv run python scripts/replay_dataset.py data/sd/ --preset security-datasets --rate 100
"""
from __future__ import annotations

import argparse
import asyncio
import csv
import io
import json
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from scripts.simulation_test import ScenarioStream, suite_dataset  # noqa: E402

SUPPORTED_SUFFIXES = (".jsonl", ".json", ".csv")

# Security-Datasets（Sysmon/nxlog 原始字段）→ 内部Alert 路径映射
# alert_id 缺省不映射：由套件按 "<场景名>-<序号>" 兜底生成（跨主机 RecordNumber 会重复）
PRESETS: dict[str, dict | None] = {
    "security-datasets": {
        "src_ip": "SourceIp",
        "dst_ip": "DestinationIp",
        "src_port": "SourcePort",
        "dst_port": "DestinationPort",
        "rule_id": "EventID",
        "rule_name": "Channel",
        "severity_text": "Severity",
        "severity_int": "SeverityValue",
        "timestamp": "@timestamp",
        "protocol": "Protocol",
        "source": "SourceName",
    },
    "none": None,
}


def load_file_records(path: Path) -> list[dict]:
    """单文件 → 事件记录列表（jsonl/json/csv）

    .json 兼容 JSONL 内容：Security-Datasets 实际以 .json 扩展名存 JSONL。
    """
    text = path.read_text(encoding="utf-8", errors="replace")
    if path.suffix == ".csv":
        return list(csv.DictReader(io.StringIO(text)))
    if path.suffix == ".jsonl":
        return _parse_jsonl(text)
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        return _parse_jsonl(text)   # .json 扩展名的 JSONL 内容
    if isinstance(parsed, list):
        return [r for r in parsed if isinstance(r, dict)]
    return [parsed] if isinstance(parsed, dict) else []


def _parse_jsonl(text: str) -> list[dict]:
    records = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return records


def collect_files(paths: list[str]) -> list[Path]:
    """文件或目录（递归）→ 支持格式的文件清单"""
    files: list[Path] = []
    for p in paths:
        path = Path(p)
        if path.is_dir():
            files.extend(f for f in sorted(path.rglob("*"))
                         if f.is_file() and f.suffix.lower() in SUPPORTED_SUFFIXES)
        elif path.is_file() and path.suffix.lower() in SUPPORTED_SUFFIXES:
            files.append(path)
        else:
            print(f"  ⚠ 跳过（不存在或格式不支持）: {p}")
    return files


def load_streams(paths: list[str], max_records: int = 0,
                 mapping_by_name: dict[str, dict] | None = None,
                 mapping_default: dict | None = None) -> list[ScenarioStream]:
    """路径集合 → 场景流列表（文件stem=场景名=expected-case标签）

    mapping_by_name: 按场景名(stem)覆盖字段路径；其余用 mapping_default。
    """
    streams: list[ScenarioStream] = []
    budget = max_records if max_records else None   # None=不限
    for f in collect_files(paths):
        try:
            records = load_file_records(f)
        except (OSError, json.JSONDecodeError, csv.Error) as e:
            print(f"  ⚠ 读取失败 {f}: {e}")
            continue
        if not records:
            print(f"  ⚠ 空数据集: {f}")
            continue
        if budget is not None:
            records = records[:budget]
            budget -= len(records)
        per_stream = (mapping_by_name or {}).get(f.stem)
        print(f"  场景 {f.stem}[{f.suffix}] {len(records)}条 ← {f}"
              + ("（自定义映射）" if per_stream else ""))
        streams.append(ScenarioStream(name=f.stem, records=records,
                                      field_mapping=per_stream))
        if budget is not None and budget <= 0:
            break
    return streams


def resolve_field_mapping(args) -> tuple[dict | None, dict[str, dict]]:
    """字段映射解析 → (默认映射, 按场景名映射)

    --field-mapping JSON 两种形态:
      {"src_ip": "...", ...}                     平铺=全部场景的默认映射
      {"default": {...}, "<场景名>": {...}, ...}  按场景覆盖（混合格式数据集）
    preset 作为默认映射的底座。
    """
    default = dict(PRESETS.get(args.preset) or {})
    by_name: dict[str, dict] = {}
    if args.field_mapping:
        with open(args.field_mapping, encoding="utf-8") as f:
            custom = json.load(f)
        if isinstance(custom, dict) and "default" in custom:
            default.update(custom.get("default") or {})
            for name, m in custom.items():
                if name != "default" and isinstance(m, dict):
                    by_name[name] = dict(default, **m)
        elif isinstance(custom, dict):
            default.update(custom)
    return (default or None), by_name


async def produce_kafka(streams: list[ScenarioStream], args) -> int:
    """逐条 produce 原始记录（保留源字段）到 Kafka topic

    缺 alert_id 的记录补 "<场景名>-<序号>"（确定性ID，重启重放幂等吸收）；
    AiCSO 侧 datasource field_mapping 需映射 alert_id 才能享受主键去重。
    """
    try:
        from aiokafka import AIOKafkaProducer
    except ImportError:
        print("需要 kafka 依赖: uv sync --extra kafka")
        return 2

    producer = AIOKafkaProducer(
        bootstrap_servers=args.bootstrap,
        value_serializer=lambda v: v,
        linger_ms=args.linger_ms,
    )
    await producer.start()
    total = 0
    try:
        for stream in streams:
            sent = 0
            for i, record in enumerate(stream.records):
                if "alert_id" not in record:
                    record["alert_id"] = f"{stream.name}-{i}"
                payload = json.dumps(record, ensure_ascii=False).encode("utf-8")
                await producer.send_and_wait(args.topic, payload)
                sent += 1
                total += 1
                if args.max_records and total >= args.max_records:
                    break
                if args.rate > 0:
                    await asyncio.sleep(1.0 / args.rate)
            print(f"  ✓ {stream.name}: produce {sent}条 → {args.topic}")
            if args.max_records and total >= args.max_records:
                break
    finally:
        await producer.flush()
        await producer.stop()
    print(f"共 produce {total}条 → {args.bootstrap}/{args.topic}")
    print(f"消费提示: AiCSO datasource group_id 用 aicso-dev-{streams[0].name}"
          f"（独立消费组，勿与他人共用）")
    return 0


async def main() -> int:
    parser = argparse.ArgumentParser(description="真实告警数据集回放验证")
    parser.add_argument("paths", nargs="+", help="数据集文件或目录（递归）")
    parser.add_argument("--mode", choices=("direct", "kafka"), default="direct",
                        help="direct=本地引擎直灌出记分卡 | kafka=produce到topic")
    parser.add_argument("--preset", choices=tuple(PRESETS), default="security-datasets",
                        help="内置字段映射preset")
    parser.add_argument("--field-mapping",
                        help="JSON文件：字段路径覆盖preset（平铺=全局默认，"
                             "含default键=按场景名覆盖，见 scripts/dataset_mappings/ 示例）")
    parser.add_argument("--schema", choices=("auto", "ecs", "generic"), default="generic",
                        help="ECS格式数据用 --schema ecs 零映射")
    parser.add_argument("--rate", type=float, default=0.0,
                        help="每秒回放条数（0=尽快；低速会真实影响pair窗汇入）")
    parser.add_argument("--benign", nargs="*", default=[],
                        help="场景名包含这些子串的按良性噪声流处理（不计收敛断言，只查误并）")
    parser.add_argument("--max-records", type=int, default=0, help="总条数上限（0=不限）")
    parser.add_argument("--bootstrap", default="localhost:9092", help="Kafka bootstrap")
    parser.add_argument("--topic", default="siem-alerts", help="目标topic")
    parser.add_argument("--linger-ms", type=int, default=50, help="producer批量等待")
    args = parser.parse_args()

    default, by_name = resolve_field_mapping(args)
    streams = load_streams(args.paths, max_records=args.max_records,
                           mapping_by_name=by_name, mapping_default=default)
    if not streams:
        print("无可用数据集")
        return 1
    for s in streams:
        if any(sub in s.name for sub in args.benign):
            s.kind = "benign"
    kinds = " ".join(f"{s.name}[{s.kind}]" for s in streams)
    print(f"共 {len(streams)}场景 / {sum(len(s.records) for s in streams)}条记录: {kinds}\n")

    if args.mode == "kafka":
        return await produce_kafka(streams, args)

    results, metrics = await suite_dataset(
        streams, field_mapping=default, schema=args.schema,
        rate=args.rate, max_records=args.max_records)
    return 0 if all(r.ok for r in results) else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
