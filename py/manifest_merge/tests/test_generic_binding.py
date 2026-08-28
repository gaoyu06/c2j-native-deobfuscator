from manifest_merge.core import _jni_export_names, merge


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
