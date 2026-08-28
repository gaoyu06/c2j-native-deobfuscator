# 适配新的 native obfuscator 变体

j2c-dumper 的通用方法发现默认使用 `generic`：它只依赖 JNI 规范、ABI 和
标准方法表结构，不要求 Ghidra。**profile** 只描述特定 JNI-native 转译变体
额外提供的启发式。内置项包括：

- `generic` — 自动处理静态表、栈构造表、共享调用点与 `Java_*` 导出
- `native_obfuscator` — 启用一种异常文案格式与每类注册策略
- `j2cc` — 启用共享 `initClass` 派发策略

如果标准 JNI 注册足以列出方法，不需要新增 profile。只有需要非标准采集或
方法体提示时才创建 profile。

## 一、profile 包含什么

`py/binary_introspect/binary_introspect/profile.py` 里的
`Profile` 数据类定义了所有可调旋钮：

| 字段 | 干嘛 |
|---|---|
| `name` | CLI 名字 (`--profile <name>`) |
| `arch_filter` / `os_filter` | 只在指定架构/系统启用 (e.g. `("x86_64",) / ("windows",)`) |
| `register_natives_index` | JNI vtable 里 RegisterNatives 的索引，默认 215 |
| `harvest_strategy` | `"auto"`（通用静态/栈表）、`"per_class"` 或 `"shared_dispatch"` |
| `invoke_error_re` / `field_error_re` | 可选错误字符串正则；`generic` 为 `None` |
| `skip_if_patterns` | 一组 `(cond_re, body_re)` — 匹配到的 if 语句被 lifter 丢弃（视为 native-side bookkeeping） |
| `enable_exception_guard_heuristics` | 是否启用跨语句异常/缓存 guard 清理 |
| `rewrite_ghidra_vtable_calls` | 是否启用 Ghidra 特定 pseudo-C 重写 |
| `extract_cache_table` | 是否提取供可选 pseudo-C lifter 使用的变体缓存表 |
| `detector` | 可选 callable，给出 0..1 的分数表示当前 binary 是否匹配这个 profile |
| `helper_fingerprints` | 把 Ghidra 输出里的 `FUN_xxxx` 助手按 (参数形状 → 语义) 绑回去 |

## 二、最小变体：仅改错误字符串格式

假设某变体的错误信息格式从 `"Cannot invoke X.Y.Z(args)"`
改成了 `"Failed to call X.Y.Z(args)"`。这种情况只需复用 native_obfuscator
profile 改一个字段：

```python
# my_profiles/variant_x.py
import re
from binary_introspect.profile import Profile, register_profile

register_profile(Profile(
    name="variant_x",
    description="Custom throw-format variant",
    arch_filter=("x86_64",),
    invoke_error_re=re.compile(
        r"^Failed\s+to\s+call\s+"
        r"(?P<owner>[\w.$]+)\.(?P<name>[\w$<>]+)"
        r"\((?P<args>[^)]*)\)$"
    ),
    skip_if_patterns=[],   # 不跳过任何 if guards
))
```

放在 `PYTHONPATH` 上即可，启动时 `import` 一下：

```bash
PYTHONPATH=./my_profiles python -c "import variant_x" \
    binary-introspect introspect ./mybin.dll -o binary.json --profile variant_x
```

## 三、深度变体：新 harvest 策略

`generic` 的 `"auto"` 已覆盖：

- `.rdata` / `.data` 中的标准 `JNINativeMethod[]`；
- 栈上逐项构造、在调用前传入的表；
- 多分支复用同一个 `RegisterNatives` 调用点；
- `Java_*` 导出（由 manifest 阶段按 JNI 编码精确绑定）；
- 可选模拟捕获到的运行时表。

因此上述情形不需要新策略。如果某变体使用非标准编码、间接解密或自定义
dispatch，先判断它能否通过 `--emulate-registration` 捕获；仍不能捕获时，
再增加新的 `harvest_strategy` 插件。

步骤：

1. 在 `profile.py` 的 `harvest_strategy` 字段文档里加上新策略名
2. 在 `jni_tables.py` 的 `find_jni_method_tables` 里加上新分支：
   ```python
   if profile.harvest_strategy == "custom_table":
       branches = _harvest_custom_table(cs, site, exec_rngs, profile)
       # ...
   ```
3. 实现 `_harvest_custom_table` 函数，并用小型合成 fixture 验证
4. 保证 `generic` 路径不导入该插件也能继续工作

## 四、自定义检测

`detector` 是个 `Callable[[lief.Binary], float]`：

```python
def my_detect(b):
    # 检查该变体标志性的导出名 / 字符串
    if b.format != lief.Binary.FORMATS.PE: return 0.0
    if any("__obfx_init" in s.name for s in b.exported_symbols): return 0.9
    return 0.0

register_profile(Profile(..., detector=my_detect))
```

自动检测时所有 profile 的 score 取最大值。要让自己的 profile 在歧义场景胜出，
返回 ≥0.9 的高 score。

## 五、运行时强制选择

任何场景下都可以用 `--profile <name>` 跳过自动检测：

```bash
python -m j2c_dumper_cli.main inspect-binary mybin.dll \
    -o binary.json --profile variant_x
python -m j2c_dumper_cli.main inspect-binary mybin.dll \
    -o binary.json --profile generic
```

## 六、通用层与插件边界

当前通用层已经参数化：

1. **架构 / ABI**：`Abi` 分别声明第三参数（方法表）和第四参数
   (`nMethods`) 的寄存器。内置 `amd64-windows` 与 `amd64-sysv`。
2. **vtable 调用**：从 Capstone memory operand 读取 displacement，
   不依赖 `call qword ptr [...]` 的文本渲染；`RegisterNatives` 固定取索引 215。
3. **表形态**：自动处理静态标准结构、栈构造和多分支共享调用点。
4. **方法清单**：`inspect-binary` / `static-lite` 不依赖 Ghidra。

以下能力属于可选插件：

- Ghidra 未类型化 pseudo-C 的 vtable rewrite；
- 异常文案 invoke/field hint；
- 异常与缓存 guard 跳过；
- 变体缓存表和 helper fingerprint；
- 非标准方法表 harvest。

`generic` 对上述插件保持关闭或保守。新增 profile 应只开启有二进制证据支持的
功能，并允许 lifter feature flag 再逐项关闭。

新增 CPU 架构仍需实现一个 `Abi`（包括反汇编器、PC 相对地址解码、参数寄存器
和栈写入识别）。非标准注册若无法被模拟捕获，则需 harvest 插件。Ghidra
变量命名或输出格式只影响可选的方法体 lifter，不应阻断方法清单生成。
