# include 篩選修正版

原因：原始 agent.cpp 沒有解析 include 選項，傳入後會被忽略。

## Windows x64 直接使用

使用本 ZIP 附帶的 `prebuilt/windows/x64/j2c_agent-windows-x64.dll` 取代舊 DLL。
假設專案解壓到 `C:\c2j`，在 PowerShell 執行：

```powershell
java "-agentpath:C:\c2j\prebuilt\windows\x64\j2c_agent-windows-x64.dll=trace=C:\c2j\trace.jsonl,include=obf.*;native.*" -jar app.jar
```

把 `app.jar` 換成你的 JAR。Minecraft 啟動器請將完整、含引號的 `-agentpath` 參數
放在 JVM 參數欄，並將 DLL 路徑改成實際位置。PowerShell 的整個參數必須加引號，
否則 `;` 會被當作命令分隔符。

新 trace 第一條 agent-loaded 記錄應包含：

```json
{"include":"obf.*;native.*","includeActive":true}
```

實際記錄也會有 ev、ts 等欄位。請使用新的 trace，不要與舊紀錄混看。

## 篩選範圍

- 支援分號分隔的多個規則，`*` 包含子套件；點號與斜線均可使用。
- native bind、enter、exit 及各種 JNI 寫入路徑均受篩選。
- 未選取 native 方法的巢狀呼叫暫停寫入；其內再呼叫已選取方法時恢復。
- 保留已選取方法操作 JDK 或其他相依類別的 JNI 資料，以及其 Java 呼叫的例外資訊，供還原使用。
- 生命週期與 capability 記錄仍會存在；JNI 的 memberOwner 不一定是 obf 或 native，因為它代表被操作的相依類別。
- `log-all=true` 不會繞過已啟用的 include。省略或空 include 保留原行為。

## 驗證與附檔

已在 Linux 的 Java 17 與 Java 21 執行真實 JVMTI/JNI 整合測試，八種設定均通過：
無篩選、點號規則、斜線規則、規則空白、log-all、完全不匹配、重複 include、空 include。
測試包括多執行緒、巢狀選取與排除、reference JNI 寫入、例外、進出配對；另有類名及萬用字元單元測試。

附帶 Windows x64 DLL 與 Linux x64 SO。Windows DLL 已交叉編譯並檢查 Agent_OnLoad、
Agent_OnAttach、Agent_OnUnload 匯出；本環境沒有 Windows JVM，未實際執行 Windows 測試。
其他平台可用原 GitHub Actions 建置，Linux x64 工作也會執行這次新增的回歸測試。
