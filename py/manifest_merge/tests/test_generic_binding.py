import json
from pathlib import Path

import pytest

from manifest_merge.core import _jni_export_names, merge

# py/manifest_merge/tests/ -> py/manifest_merge/ -> py/ -> repo root.
SCHEMAS = Path(__file__).resolve().parents[3] / "schemas"


def _manifest_schema() -> dict:
    return json.loads(
        (SCHEMAS / "manifest.schema.json").read_text(encoding="utf-8")
    )


def _classes(methods):
    return {
        "input": {"jarPath": "input.jar"},
        "classes": [
            {
                "name": "sample/Native_Class",
                "methods": [
                    {
                        "name": name,
                        "desc": desc,
                        "access": 0x0100,
                        "isObfuscatedNative": True,
                    }
                    for name, desc in methods
                ],
            }
        ],
    }


def test_jni_export_is_bound_by_specification_name() -> None:
    classes = _classes([("run_fast", "(I)V")])
    short, long = _jni_export_names(
        "sample/Native_Class", "run_fast", "(I)V"
    )
    assert short == "Java_sample_Native_1Class_run_1fast"

    manifest = merge(
        classes,
        {
            "input": {"libPath": "native.so"},
            "nativeRegistry": [
                {
                    "source": "jni-export",
                    "fnSymbol": long,
                    "fnAddr": "0x401000",
                }
            ],
        },
    )

    method = manifest["classes"][0]["methods"][0]
    assert method["fnAddr"] == "0x401000"
    assert method["fnSymbol"] == long


def test_named_register_natives_table_binds_without_count_guessing() -> None:
    classes = _classes([("alpha", "()V"), ("beta", "(I)I")])
    manifest = merge(
        classes,
        {
            "nativeRegistry": [
                {
                    "source": "register-natives-static",
                    "fnAddrs": ["0x401000", "0x401020"],
                    "methods": [
                        {"name": "alpha", "desc": "()V", "fnAddr": "0x401000"},
                        {"name": "beta", "desc": "(I)I", "fnAddr": "0x401020"},
                    ],
                }
            ]
        },
    )

    methods = manifest["classes"][0]["methods"]
    assert [method["fnAddr"] for method in methods] == [
        "0x401000",
        "0x401020",
    ]


def test_merge_preserves_binary_analysis_profile() -> None:
    manifest = merge(
        _classes([("alpha", "()V")]),
        {"analysis": {"profile": "native_obfuscator", "methodDiscovery": "jni-spec"}},
    )

    assert manifest["analysis"] == {
        "profile": "native_obfuscator",
        "methodDiscovery": "jni-spec",
    }


def test_ambiguous_named_table_is_not_rebound_by_position() -> None:
    classes = {
        "input": {"jarPath": "input.jar"},
        "classes": [
            {
                "name": owner,
                "methods": [
                    {
                        "name": "same",
                        "desc": "()V",
                        "access": 0x0100,
                        "isObfuscatedNative": True,
                    }
                ],
            }
            for owner in ("sample/First", "sample/Second")
        ],
    }
    site = {
        "source": "register-natives-static",
        "fnAddrs": ["0x401000"],
        "methods": [{"name": "same", "desc": "()V", "fnAddr": "0x401000"}],
    }

    manifest = merge(classes, {"nativeRegistry": [site]})

    assert "boundTo" not in site
    assert all(
        "fnAddr" not in method
        for cls in manifest["classes"]
        for method in cls["methods"]
    )


def test_ambiguous_unnamed_count_only_table_is_left_unbound_with_gap() -> None:
    classes = {
        "input": {"jarPath": "input.jar"},
        "classes": [
            {
                "name": owner,
                "methods": [
                    {
                        "name": method_name,
                        "desc": "()V",
                        "access": 0x0100,
                        "isObfuscatedNative": True,
                    }
                ],
            }
            for owner, method_name in (
                ("sample/First", "first"),
                ("sample/Second", "second"),
            )
        ],
    }
    site = {
        "source": "register-natives-stack",
        "registerNativesCallSite": "0x5000",
        "fnAddrs": ["0x401000"],
    }

    manifest = merge(classes, {"nativeRegistry": [site]})

    assert "boundTo" not in site
    assert all(
        "fnAddr" not in method
        for cls in manifest["classes"]
        for method in cls["methods"]
    )
    assert manifest["bindingGaps"] == [
        {
            "kind": "ambiguous-count-only-table",
            "nMethods": 1,
            "candidateClasses": ["sample/First", "sample/Second"],
            "message": (
                "Native table at 0x5000 has 1 method address and matches "
                "multiple classes by count (sample/First, sample/Second); "
                "left unbound"
            ),
            "source": "register-natives-stack",
            "registerNativesCallSite": "0x5000",
        }
    ]


def test_unreadable_register_natives_entry_is_recorded_as_binding_gap() -> None:
    """A binary.json nativeRegistry entry marked ``register-natives-unreadable``
    (a visible RegisterNatives site whose ``JNINativeMethod[]`` did not decode)
    must surface as an ``unreadable-table`` binding gap and must NEVER bind a
    class — the garbage table is never turned into a bind."""
    classes = _classes([("alpha", "()V"), ("beta", "(I)I")])
    manifest = merge(
        classes,
        {
            "nativeRegistry": [
                {
                    "source": "register-natives-unreadable",
                    "registerNativesCallSite": "0x1016",
                    "nMethods": 2,
                    "tableAddress": "0x3ef0",
                    "reason": "invalid-method-descriptors",
                }
            ]
        },
    )

    assert all(
        "fnAddr" not in method
        for cls in manifest["classes"]
        for method in cls["methods"]
    )
    assert manifest["bindingGaps"] == [
        {
            "kind": "unreadable-table",
            "nMethods": 2,
            "reason": "invalid-method-descriptors",
            "message": (
                "RegisterNatives table at 0x1016 was seen but its method "
                "name/descriptor bytes did not decode "
                "(invalid-method-descriptors); 2 methods left unbound"
            ),
            "source": "register-natives-unreadable",
            "registerNativesCallSite": "0x1016",
            "tableAddress": "0x3ef0",
        }
    ]


def test_ambiguous_count_only_gap_manifest_validates_against_schema() -> None:
    """An ``ambiguous-count-only-table`` gap manifest (the shared-dispatch
    ambiguous case) must still validate against ``manifest.schema.json`` after
    the ``bindingGaps`` items became a ``oneOf`` — the ambiguous variant keeps
    its ``candidateClasses`` (minItems 2) requirement."""
    jsonschema = pytest.importorskip("jsonschema")

    classes = {
        "input": {"jarPath": "input.jar"},
        "classes": [
            {
                "name": owner,
                "methods": [
                    {
                        "name": method_name,
                        "desc": "()V",
                        "access": 0x0100,
                        "isObfuscatedNative": True,
                    }
                ],
            }
            for owner, method_name in (
                ("sample/First", "first"),
                ("sample/Second", "second"),
            )
        ],
    }
    site = {
        "source": "register-natives-stack",
        "registerNativesCallSite": "0x5000",
        "fnAddrs": ["0x401000"],
    }
    manifest = merge(classes, {"nativeRegistry": [site]})

    gap = manifest["bindingGaps"][0]
    assert gap["kind"] == "ambiguous-count-only-table"
    assert len(gap["candidateClasses"]) >= 2

    schema = _manifest_schema()
    jsonschema.Draft7Validator.check_schema(schema)
    jsonschema.Draft7Validator(schema).validate(manifest)


def test_unreadable_gap_manifest_validates_against_schema() -> None:
    """The ``unreadable-table`` gap manifest must validate against the new
    ``oneOf`` variant — required ``kind``/``nMethods``/``message`` and NO
    required ``candidateClasses`` (unreadable tables are not attributed by
    count)."""
    jsonschema = pytest.importorskip("jsonschema")

    classes = _classes([("alpha", "()V"), ("beta", "(I)I")])
    manifest = merge(
        classes,
        {
            "nativeRegistry": [
                {
                    "source": "register-natives-unreadable",
                    "registerNativesCallSite": "0x1016",
                    "nMethods": 2,
                    "tableAddress": "0x3ef0",
                    "reason": "invalid-method-descriptors",
                }
            ]
        },
    )

    gap = manifest["bindingGaps"][0]
    assert gap["kind"] == "unreadable-table"
    assert "candidateClasses" not in gap

    schema = _manifest_schema()
    jsonschema.Draft7Validator(schema).validate(manifest)


def test_schema_still_requires_ambiguous_gap_candidate_classes() -> None:
    """Lock-in: the old ``ambiguous-count-only-table`` required fields are not
    weakened. An ambiguous gap missing ``candidateClasses`` must be REJECTED
    (it matches neither ``oneOf`` variant), proving the ``oneOf`` did not turn
    into an accept-anything shape."""
    jsonschema = pytest.importorskip("jsonschema")

    bad = {
        "schemaVersion": 1,
        "classes": [],
        "bindingGaps": [
            {
                "kind": "ambiguous-count-only-table",
                "nMethods": 2,
                "message": "missing candidateClasses",
            }
        ],
    }
    schema = _manifest_schema()
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.Draft7Validator(schema).validate(bad)
