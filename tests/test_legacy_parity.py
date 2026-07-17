from __future__ import annotations

import ast
import importlib.util
import io
from pathlib import Path
import subprocess
import sys
from typing import Any

import mycli_lite

ROOT = Path(__file__).parents[1]


def _load_legacy_module() -> Any:
    spec = importlib.util.spec_from_file_location('mycli_lite_legacy', ROOT / 'mycli_lite_legacy.py')
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


mycli_lite_legacy = _load_legacy_module()


def test_legacy_public_api_and_version_match_modern_artifact() -> None:
    assert mycli_lite_legacy.__version__ == mycli_lite.__version__
    assert mycli_lite_legacy.__all__ == mycli_lite.__all__


def test_legacy_protocol_and_auth_vectors_match_modern_artifact() -> None:
    integer_vectors = (0, 250, 251, 65535, 65536, 16777215, 16777216, 2**64 - 1)
    for value in integer_vectors:
        encoded = mycli_lite._encode_lenenc_int(value)
        assert mycli_lite_legacy._encode_lenenc_int(value) == encoded
        assert mycli_lite_legacy._read_lenenc_int(encoded) == mycli_lite._read_lenenc_int(encoded)

    nonce = b'12345678abcdefgh1234'
    password = b'secret'
    assert mycli_lite_legacy._scramble_native_password(password, nonce) == mycli_lite._scramble_native_password(password, nonce)
    assert mycli_lite_legacy._scramble_caching_sha2(password, nonce) == mycli_lite._scramble_caching_sha2(password, nonce)


def test_legacy_models_and_output_match_modern_artifact() -> None:
    modern_columns = (
        mycli_lite.Column('na\nme', '', '', '', '', 45, 0xFD, 0),
        mycli_lite.Column('blob', '', '', '', '', 63, 0xFC, 0),
        mycli_lite.Column('empty', '', '', '', '', 45, 0xFD, 0),
    )
    legacy_columns = tuple(
        mycli_lite_legacy.Column(
            column.name,
            column.schema,
            column.table,
            column.original_table,
            column.original_name,
            column.charset_id,
            column.type_code,
            column.flags,
        )
        for column in modern_columns
    )
    modern_result = mycli_lite.Result(columns=modern_columns, rows=[('snowman ☃\n', b'\0\xff', None)])
    legacy_result = mycli_lite_legacy.Result(columns=legacy_columns, rows=[('snowman ☃\n', b'\0\xff', None)])

    for output_format in ('table', 'tsv', 'csv', 'vertical'):
        modern_output = io.StringIO()
        legacy_output = io.StringIO()
        mycli_lite.write_results([modern_result], output_format=output_format, output=modern_output, null_value='NULL')
        mycli_lite_legacy.write_results([legacy_result], output_format=output_format, output=legacy_output, null_value='NULL')
        assert legacy_output.getvalue() == modern_output.getvalue()


def test_legacy_raw_artifact_runs_isolated() -> None:
    result = subprocess.run(
        [sys.executable, '-I', '-S', str(ROOT / 'mycli_lite_legacy.py'), '--version'],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0
    assert result.stdout == f'mycli-lite {mycli_lite.__version__}\n'
    assert result.stderr == ''


def test_legacy_runtime_imports_are_standard_library_only() -> None:
    tree = ast.parse((ROOT / 'mycli_lite_legacy.py').read_text(encoding='utf-8'))
    imports: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(alias.name.partition('.')[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imports.add(node.module.partition('.')[0])
    imports.discard('__future__')
    assert imports <= sys.stdlib_module_names
