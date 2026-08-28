"""Sanity tests for the lifter using hand-crafted pseudo-C snippets that mirror
what Ghidra would emit for j2c-transpiled functions."""

import json

import pytest

from ast_matcher.core import lift_function
from ast_matcher.lifter import driver


def test_iadd_pattern():
    code = """
    void __ngen_foo(JNIEnv* env) {
        cstack0.i = 3;
        cstack1.i = 5;
        cstack0.i = cstack0.i + cstack1.i;
        return;
    }
    """
    result = lift_function(code)
    ops = [i["op"] for i in result["instructions"]]
    assert "ICONST_3" in ops
    assert "ICONST_5" in ops
    assert "IADD" in ops


def test_iload_istore():
    code = """
    void __ngen_foo(JNIEnv* env) {
        cstack0.i = clocal2.i;
        clocal3.i = cstack0.i;
        return;
    }
    """
    result = lift_function(code)
    ops = [i["op"] for i in result["instructions"]]
    assert "ILOAD" in ops
    assert "ISTORE" in ops


def test_getfield_pattern():
    code = """
    void __ngen_foo(JNIEnv* env) {
        cstack0.i = env->GetIntField(cstack0.l, cfields[7]);
        return;
    }
    """
    lookups = {"cfields": [{"owner": "X", "name": "y", "desc": "I"}] * 8}
    lookups["cfields"][7] = {"owner": "com/Foo", "name": "bar", "desc": "I"}
    result = lift_function(code, lookups=lookups)
    insns = result["instructions"]
    getfield = next(i for i in insns if i["op"] == "GETFIELD")
    assert getfield["owner"] == "com/Foo"
    assert getfield["name"] == "bar"
    assert getfield["desc"] == "I"


def test_invokevirtual_pattern():
    code = """
    void __ngen_foo(JNIEnv* env) {
        env->CallVoidMethod(cstack0.l, cmethods[3]);
        return;
    }
    """
    lookups = {"cmethods": [
        {"owner": "X", "name": "m", "desc": "()V"},
        {"owner": "X", "name": "m", "desc": "()V"},
        {"owner": "X", "name": "m", "desc": "()V"},
        {"owner": "java/io/PrintStream", "name": "println", "desc": "(Ljava/lang/String;)V"},
    ]}
    result = lift_function(code, lookups=lookups)
    insns = result["instructions"]
    invk = next(i for i in insns if i["op"] == "INVOKEVIRTUAL")
    assert invk["owner"] == "java/io/PrintStream"
    assert invk["name"] == "println"


@pytest.mark.parametrize(
    ("artifact_name", "analysis", "explicit_profile", "expected_profile"),
    [
        ("manifest.json", {"profile": "native_obfuscator"}, None, "native_obfuscator"),
        ("binary.json", {"profile": "j2cc"}, None, "j2cc"),
        ("manifest.json", {"profile": "native_obfuscator"}, "generic", "generic"),
        ("manifest.json", {}, None, "generic"),
    ],
)
def test_ghidra_lifter_selects_profile_from_artifact_analysis(
    tmp_path,
    monkeypatch,
    artifact_name,
    analysis,
    explicit_profile,
    expected_profile,
):
    dump_path = tmp_path / "ghidra-dump.json"
    dump_path.write_text(
        json.dumps(
            {
                "functions": [
                    {
                        "owner": "sample/Native",
                        "methodName": "run",
                        "methodDesc": "()V",
                        "code": "void run(void) {}",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    artifact_path = tmp_path / artifact_name
    artifact_path.write_text(json.dumps({"analysis": analysis}), encoding="utf-8")

    selected_profiles = []

    def fake_lift(*args, **kwargs):
        selected_profiles.append(kwargs["profile"].name)
        return {"instructions": [{"op": "RETURN"}], "warnings": []}

    monkeypatch.setattr(driver, "lift_ghidra_function", fake_lift)

    driver.lift_ghidra_dump(
        dump_path,
        artifact_path,
        profile_name=explicit_profile,
    )

    assert selected_profiles == [expected_profile]


if __name__ == "__main__":
    test_iadd_pattern()
    test_iload_istore()
    test_getfield_pattern()
    test_invokevirtual_pattern()
    print("all 4 tests passed")
