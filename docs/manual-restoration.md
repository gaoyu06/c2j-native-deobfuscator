# 手动还原流程

自动恢复（无论动态还是静态）产出的 jar 已经能用反编译器打开，但跟原始
源码相比仍有差距 —— SSA 槽位、被烧成常量的 trace 值、被吃掉的分支等。
这个文档记录如何把自动产物**作为起点**，用人工推理补全到接近原始源码。

完整对比图见
[`screenshots/showcase/manual-restoration-dynamic.png`](../screenshots/showcase/manual-restoration-dynamic.png)
和
[`screenshots/showcase/manual-restoration-static.png`](../screenshots/showcase/manual-restoration-static.png)。

---

## 动态路径的手动清理

### 输入

- `out.jar`（rebuilder 产物，含 `j2c.RuntimeTrace` 注解）
- `trace.jsonl`（agent 的 JNI 调用流水账）
- `recovered/*.json`（lifter 中间产物）

反编译 `out.jar`，得到带各种合成痕迹的 Java 代码。看一个具体方法：

```java
// === 自动产物 ===
@RuntimeTrace({"[1] int_arg", "[2] int_arg"})
public Cell step(boolean var1) {
    Object var2 = null;
    Object var3 = null;
    Object var4 = null;
    Object var5 = null;
    Object var6 = null;
    Object var7 = null;
    Object var8 = null;
    var2 = ((char[])this).head();
    var3 = new Cell(6, 4);
    ((LinkedList)var7).addFirst(var3);
    return (Cell)((LinkedList)var8).removeLast();
}
```

### 5 类典型的手动改动

| # | 现象 | 怎么处理 | 来源 |
|---|---|---|---|
| 1 | `Object varN = null;` 一堆声明 | **删掉** | 这是 lifter 的 SSA 合成槽位（`DUP+ASTORE` 模式），保留 jobject 跨语句的引用同一性用；不是真的 Java 变量 |
| 2 | `var2 = ((LinkedList)var7).addFirst(...)` 中间变量链 | **inline** —— 单用即丢的临时变量直接展开 | 看用了一次还是多次；JVMTI agent 倾向于每个 jobject 都给一个槽位 |
| 3 | `((char[])this).head()` 这种荒诞 cast | **去掉** | agent 在不能确定 jobject 实际类型时退化到 `[C`（char 数组）作为占位；receiver 的真实类型从方法所属类推出 |
| 4 | `new Cell(6, 4)` 这种具体数字 | **替换成符号表达式** | 看 `@RuntimeTrace({"[1] int_arg", "[2] int_arg"})` 注解 —— `int_arg` 表示这两个值是 trace 在运行时烧进去的；原代码大概率是 `h.x + dir.dx, h.y + dir.dy` |
| 5 | 缺失的 if/else 分支 | **补回去** | trace 只走了脚本触发的路径；从方法名 + 类语义判断完整控制流（例如 `turn()` 的 180° 守卫一定存在，否则方法就废了） |

### 清理后

```java
// === 手动还原后 ===
public Cell step(boolean grow) {
    Cell h = head();
    Cell nh = new Cell(h.x + dir.dx, h.y + dir.dy);
    body.addFirst(nh);
    if (!grow) {
        body.removeLast();
    }
    return nh;
}
```

### 还原成本

- 一个有 6-7 个方法的小类（如 `Snake`），熟手 **10-15 分钟**
- 字段名、方法名、字段类型都准确（lifter 都标好了）
- 控制流补全靠领域知识，**和"读懂别人的代码"难度相当**

---

## 静态路径的手动补全

### 输入

- `out.jar`（rebuilder 产物，可能部分类是 unverified）
- `recovered/*.json`（lifter 中间产物 —— **比反编译输出信息量大**）
- `manifest.json` 里的 `cacheTable`（每个 cclasses/cfields/cmethods slot 的 owner/name/desc 三元组）
- 原始 `ghidra-dump.json`（最底层，用于校验 lifter 的边界情况）

静态路径的**自动产物可能"看起来很空"**，但中间产物里有很多线索 —— 只是反编译器没拿来用。手动补全的核心在**读中间产物**。

### 单方法补全实例

`Snake.head()` 的反编译输出：

```java
public Cell head() {
    Trace.UNVERIFIED_head();
    return this.body;       // ← 但 head() 返回类型是 Cell，不是 LinkedList
}
```

光看这个会觉得没救。但打开
`recovered-v9/Snake__head____LCell_.json`：

```json
{
  "owner": "Snake",
  "name": "head",
  "desc": "()LCell;",
  "instructions": [
    {"op": "ATHROW"},
    {"op": "ACONST_NULL"},
    {"op": "GETFIELD", "owner": "Snake", "name": "body",
                       "desc": "Ljava/util/LinkedList;"},
    {"op": "DUP"}, {"op": "ASTORE", "var": 64},
    ...
    {"op": "ARETURN"}
  ]
}
```

`GETFIELD Snake.body` 已经识别出来了，但 lifter 没把后续的
`INVOKEVIRTUAL LinkedList.getFirst()` 接到 GETFIELD 的结果上 ——
这是静态路径的已知短板（操作数栈 SSA 不完整，见 ROADMAP）。

手动补全：

```java
// === 手动还原 ===
public Cell head() {
    return (Cell) body.getFirst();
}
```

依据：
- `body : Ljava/util/LinkedList;` 来自 GETFIELD 节点
- `getFirst : ()Ljava/lang/Object;` 来自 `cacheTable.methods` 里
  `DAT_1800880c0 = java/util/LinkedList.getFirst:()Ljava/lang/Object;`
  这条记录（自动恢复时没用上的资源）
- 返回类型 `LCell;` 来自方法描述符 → 需要 cast

### 静态路径手动补全的固定动作

1. **打开 `cacheTable`** —— 这是所有"`?.?`"的真实答案。如果某个 JNI ID
   slot 在 cacheTable 里有 `(owner, name, desc)`，对应的 invoke / 字段
   访问就能直接还原。
2. **看 `recovered/<class>__<method>__<desc>.json`** —— 即使 lifter
   产出的 opcode 序列不能验证、反编译器跳过了，opcode 本身仍然按发现
   顺序记录在这里。把它当 pseudocode 读。
3. **看 `ghidra-dump.json`** —— pseudo-C 里的 `env->Xxx(...)` 序列才
   是最原始的"这个 native 函数在做什么"。lifter 没能把它们都翻译成
   opcode，但人能读懂。
4. **比对 `manifest.json`** —— 类的字段表 / 方法表都在那里。如果
   `(owner, name, desc)` 命中了 manifest，类型签名就是确定的。

### 还原成本（静态）

- 比动态路径慢，平均 **1.5-3 倍** 时间
- 对**逻辑结构**（控制流、循环、try-catch）依赖人脑推理更多
- 但对加壳 / 反调试 / 没法运行的目标，这是**唯一可行路径**

---

## 通用建议

- **优先选动态路径**，能跑就跑。手动清理量小、自动产物准确度高
- **静态路径作为"读懂二进制"工具**，自动产物是阅读起点，不是终点
- 不管哪条路径，**永远把中间产物（`recovered/*.json`、`trace.jsonl`、
  `manifest.json.cacheTable`）当作主资料**，反编译后的 Java 只是
  "好读的呈现"
- 对每个被还原的方法，**写一行注释说推断来源**（"这里的 if guard
  是补的，原 trace 没走到"），方便后续验证 / 跟 git history 对账
