# 本次修改與限制

依要求，未執行測試、編譯或目標程式驗證。ZIP 內容為修改後的原始碼，不含新編譯的 agent。

## 已修改

- native MethodExit 依 descriptor 記錄真正的 return_value；例外退出不讀取未定義的回傳值。
- MethodEntry 明確標記 argsCaptured=false 與缺口原因，不偽造參數。
- 補 Float/Double 方法與欄位 hooks、Static 欄位寫入、Static/Nonvirtual 呼叫缺少的型別與 A/V 形式、NewObjectA。
- 補 ExceptionCheck/Occurred/Clear、MonitorEnter/Exit、一般 String 存取、primitive ArrayElements/Release hooks。
- ArrayRegion 保存完整元素陣列；浮點數使用足夠精度，非有限值使用字串標記。
- translator 支援新增的欄位與方法型別；bulk Region、ArrayElements 等尚無完整語義的操作明確拒絕，不靜默轉成單一元素操作。
- 每次 native invocation 的 JNI 證據保存在 recovered 目錄旁的 .invocations 目錄，避免只有最長一次 trace 可供分析。主要輸出仍為最長路徑的分析視圖，不代表多分支合成。
- 破損 JSON、截斷 trace 會拒絕翻譯；報告列出未觀察到的 native methods。
- 回傳修補插入的數值預設值標記為 unrecovered_return_default。
- 保留承載原始初始化的 special_clinit_* 呼叫。
- unverified class 輸出預設關閉，僅明確 analysis-only 模式可啟用。
- JNI 動態分析結果必須使用 class-rebuilder --analysis-only；不再將未重建 native 控制流程的分析結果視為執行版。
- frame 計算失敗時嚴格路徑拒絕以 stub 代換，失敗的輸出檔刪除。
- 更新 enter/exit trace schema。

## 尚未完成，不能宣稱已脫離 DLL

- native ABI 入口 trampoline：完整擷取 this/class、reference 及 primitive 參數。
- native 指令級控制流程、運算資料流、分支合併、迴圈及 helper 還原。
- String/Array Critical 區域追蹤與原生記憶體寫入來源分析。
- 完整物件身分及 reference lifetime 模型。
- 原始 class initializer 邏輯還原、例外處理表及 invokedynamic 重建。
- JVM 驗證、目標應用執行及原版／還原版行為對照。

## 使用注意

請沿用專案建置流程重新建置 agent 和 JVM 工具；不要直接沿用舊二進位。
ArrayRegion 的 args[3] 現為完整 JSON array；外部 trace 消費端也須同步處理。
如需動態分析輸出，重建時加上 --analysis-only。只有需要查看未通過 frame 計算的 class 時，另外加 --allow-unverified-classes true。
.invocations 是原始證據，請勿當作 recovered bodies 傳給 class-rebuilder。
使用新的輸出目錄，避免混入舊 trace 或 recovered JSON。
