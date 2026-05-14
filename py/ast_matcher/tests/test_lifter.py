"""Sanity tests for the lifter using hand-crafted pseudo-C snippets that mirror
what Ghidra would emit for j2c-transpiled functions."""

from ast_matcher.core import lift_function


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


if __name__ == "__main__":
    test_iadd_pattern()
    test_iload_istore()
    test_getfield_pattern()
    test_invokevirtual_pattern()
    print("all 4 tests passed")
