"""统一Schema映射（issue #35）"""
from aicso.mapping.engine import SchemaMapper, generated_alert_id, get_nested
from aicso.mapping.profiles import BUILTIN_PROFILES, ECS_PROFILE, GENERIC_PROFILE

__all__ = [
    "BUILTIN_PROFILES",
    "ECS_PROFILE",
    "GENERIC_PROFILE",
    "SchemaMapper",
    "generated_alert_id",
    "get_nested",
]
