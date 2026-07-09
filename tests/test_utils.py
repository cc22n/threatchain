import json
import pytest
from app.utils import parse_llm_json


def test_plain_json():
    assert parse_llm_json('{"a": 1}') == {"a": 1}


def test_fenced_json():
    assert parse_llm_json('```json\n{"a": 1}\n```') == {"a": 1}


def test_fence_without_language_tag():
    assert parse_llm_json('```\n{"a": 1}\n```') == {"a": 1}


def test_prose_before_fence():
    content = 'Here is the JSON you asked for:\n```json\n{"a": 1}\n```'
    assert parse_llm_json(content) == {"a": 1}


def test_prose_around_bare_json():
    content = 'Sure! The result is {"a": 1} as requested.'
    assert parse_llm_json(content) == {"a": 1}


def test_unclosed_fence():
    content = '```json\n{"a": 1}'
    assert parse_llm_json(content) == {"a": 1}


def test_json_array():
    assert parse_llm_json('[1, 2, 3]') == [1, 2, 3]


def test_no_json_raises():
    with pytest.raises(json.JSONDecodeError):
        parse_llm_json('there is no json here')
