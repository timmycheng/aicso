"""TriageAgent 测试"""
import json
import pytest

from aicso.agents.triage import (
    _extract_json, _validate_dimensions, VALID_DIMENSIONS,
)


class TestExtractJson:
    def test_plain_json(self):
        data = {"key": "value"}
        result = _extract_json(json.dumps(data))
        assert result == data

    def test_json_in_code_block(self):
        text = '```json\n{"key": "value"}\n```'
        result = _extract_json(text)
        assert result == {"key": "value"}

    def test_json_in_code_block_no_lang(self):
        text = '```\n{"key": "value"}\n```'
        result = _extract_json(text)
        assert result == {"key": "value"}

    def test_json_with_prefix_text(self):
        text = 'Here is the result:\n{"key": "value"}'
        result = _extract_json(text)
        assert result == {"key": "value"}

    def test_json_with_surrounding_text(self):
        text = 'Based on analysis:\n{"key": "value"}\nDone.'
        result = _extract_json(text)
        assert result == {"key": "value"}

    def test_no_json_raises(self):
        with pytest.raises(json.JSONDecodeError):
            _extract_json("no json here")

    def test_nested_json(self):
        data = {
            "is_true_positive": True,
            "confidence": 0.85,
            "aggregation_rule": {
                "dimensions": ["src_ip+dst_ip"],
                "window_minutes": 30,
            },
        }
        text = f"分析结果：\n```json\n{json.dumps(data, ensure_ascii=False)}\n```"
        result = _extract_json(text)
        assert result["aggregation_rule"]["dimensions"] == ["src_ip+dst_ip"]


class TestValidateDimensions:
    def test_valid_dimensions(self):
        result = _validate_dimensions(["src_ip+dst_ip", "src_ip"])
        assert result == ["src_ip+dst_ip", "src_ip"]

    def test_mixed_valid_invalid(self):
        result = _validate_dimensions(["src_ip+dst_ip", "invalid_dim"])
        assert result == ["src_ip+dst_ip"]

    def test_all_invalid_with_category_hint(self):
        result = _validate_dimensions(["bad"], "暴力破解")
        assert result == ["src_ip+dst_ip"]

    def test_all_invalid_no_hint(self):
        result = _validate_dimensions(["bad"])
        assert result == ["src_ip+dst_ip"]

    def test_empty_with_category(self):
        result = _validate_dimensions([], "端口扫描")
        assert result == ["src_ip"]

    def test_empty_no_category(self):
        result = _validate_dimensions([], "")
        assert result == ["src_ip+dst_ip"]

    def test_all_dimensions_valid(self):
        for dim in VALID_DIMENSIONS:
            result = _validate_dimensions([dim])
            assert result == [dim]
