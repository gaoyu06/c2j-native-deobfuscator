"""CLI-output contract tests for the top-level j2c-dumper orchestrator.

These pin the honest user-facing reporting the pipeline must print:

  * ``inspect-binary`` prints the selected ``analysis.profile`` (and does NOT
    invent ``bindingGaps`` on ``binary.json``), and
  * ``merge-manifest`` prints the manifest's ``bindingGaps`` (count + kinds),
    which is where binding gaps actually live.

The fixture is the committed PE ``j2cc`` DLL shared with the binary_introspect
suite, so no cross toolchain is needed to run these.
"""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from j2c_dumper_cli.main import app

# py/j2c_dumper_cli/tests/ -> py/ -> binary_introspect fixtures.
FIXTURE_DLL = (
    Path(__file__).resolve().parents[2]
    / "binary_introspect"
    / "tests"
    / "fixtures"
    / "jni_dispatch_j2cc.dll"
)

runner = CliRunner()


def _ambiguous_classes() -> dict:
    """Two 2-method classes and two 3-method classes: both shared-dispatch
    branch counts (2 and 3) match multiple classes, forcing bindingGaps."""

    def methods(count: int) -> list[dict]:
        return [
            {
                "name": f"m{index}",
                "desc": "()V",
                "access": 0x0100,
                "isObfuscatedNative": True,
            }
            for index in range(count)
        ]

    return {
        "input": {"jarPath": "input.jar"},
        "classes": [
            {"name": "com/example/First", "methods": methods(2)},
            {"name": "com/example/Second", "methods": methods(2)},
            {"name": "com/example/Third", "methods": methods(3)},
            {"name": "com/example/Fourth", "methods": methods(3)},
        ],
    }


def test_inspect_binary_prints_profile_and_writes_it_to_binary_json(tmp_path: Path) -> None:
    binary_json = tmp_path / "binary.json"

    result = runner.invoke(
        app, ["inspect-binary", str(FIXTURE_DLL), "-o", str(binary_json)]
    )
    assert result.exit_code == 0, result.output

    # binary.json records the auto-detected named profile...
    doc = json.loads(binary_json.read_text(encoding="utf-8"))
    assert doc["analysis"]["profile"] == "j2cc"

    # ...and the human console output surfaces it.
    assert "profile=j2cc" in result.output

    # binary.json must NOT invent a bindingGaps field: gaps are a manifest fact.
    assert "bindingGaps" not in doc


def test_merge_manifest_prints_binding_gaps_and_writes_them(tmp_path: Path) -> None:
    binary_json = tmp_path / "binary.json"
    classes_json = tmp_path / "classes.json"
    manifest_json = tmp_path / "manifest.json"

    inspect = runner.invoke(
        app, ["inspect-binary", str(FIXTURE_DLL), "-o", str(binary_json)]
    )
    assert inspect.exit_code == 0, inspect.output

    classes_json.write_text(json.dumps(_ambiguous_classes()), encoding="utf-8")

    result = runner.invoke(
        app,
        [
            "merge-manifest",
            str(classes_json),
            str(binary_json),
            "-o",
            str(manifest_json),
        ],
    )
    assert result.exit_code == 0, result.output

    # The console reports the gap count (and the gap kind).
    assert "bindingGaps=2" in result.output
    assert "ambiguous-count-only-table" in result.output

    # The written manifest carries those two gaps.
    manifest = json.loads(manifest_json.read_text(encoding="utf-8"))
    gaps = manifest["bindingGaps"]
    assert [g["kind"] for g in gaps] == [
        "ambiguous-count-only-table",
        "ambiguous-count-only-table",
    ]
    assert {g["nMethods"] for g in gaps} == {2, 3}


def test_inspect_binary_alone_reports_zero_free_gaps_only_after_merge(tmp_path: Path) -> None:
    """inspect-binary alone is honest: it prints the profile but no bindingGaps,
    because gaps only exist once tables are bound against a classes.json. Merging
    against a classes.json whose counts are unique yields bindingGaps=0."""
    binary_json = tmp_path / "binary.json"
    classes_json = tmp_path / "classes.json"
    manifest_json = tmp_path / "manifest.json"

    runner.invoke(app, ["inspect-binary", str(FIXTURE_DLL), "-o", str(binary_json)])

    unique_classes = {
        "input": {"jarPath": "input.jar"},
        "classes": [
            {
                "name": "com/example/ClassA",
                "methods": [
                    {"name": "a0", "desc": "()V", "access": 0x0100, "isObfuscatedNative": True},
                    {"name": "a1", "desc": "()V", "access": 0x0100, "isObfuscatedNative": True},
                ],
            },
            {
                "name": "com/example/ClassB",
                "methods": [
                    {"name": "b0", "desc": "()V", "access": 0x0100, "isObfuscatedNative": True},
                    {"name": "b1", "desc": "()V", "access": 0x0100, "isObfuscatedNative": True},
                    {"name": "b2", "desc": "()V", "access": 0x0100, "isObfuscatedNative": True},
                ],
            },
        ],
    }
    classes_json.write_text(json.dumps(unique_classes), encoding="utf-8")

    result = runner.invoke(
        app,
        ["merge-manifest", str(classes_json), str(binary_json), "-o", str(manifest_json)],
    )
    assert result.exit_code == 0, result.output
    assert "bindingGaps=0" in result.output

    manifest = json.loads(manifest_json.read_text(encoding="utf-8"))
    assert manifest["bindingGaps"] == []
