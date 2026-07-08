# Windows Software Residual Scanner (Windows軟體殘留診斷工具)


當 Windows 軟體透過常規管道卸載後，往往會在系統深層（如 Windows Installer 快取、離線登錄檔、使用者隱藏資料夾）留下特徵殘留。這會導致企業內部的資產盤點軟體小概率持續觸發漏洞告警，判定該軟體依然存活。

本工具是一個**完全唯讀、無害且全面**的盤點腳本，旨在幫助 IT 管理員與使用者深度掃描指定軟體的殘留，並產出結構化報告以利評估自行手動清除。

---

## ⚠️ 【核心盲區】關鍵字匹配機制的技術現實（使用必讀）

本工具的預設比對模式為 `Contains`（底層調用 .NET `IndexOf` 並忽略大小寫）。系統只會識別**完全連續的子字串**。若輸入不當的縮寫，將導致因字串比對不到而缺失資料。

> ### 📌 致命錯誤範例：以 VS Code 為例
> 微軟官方於 Windows 註冊的標準名稱為 **`Visual Studio Code`**。
> * **❌ 錯誤輸入：** `Vs Code`
> * **底層盲區解析：** 在字串 `"Visual Studio Code"` 之中，不存在連續的 `"vs code"`，因此**所有核心登錄檔將全數判定不匹配（抓不到東西）**。
> * **唯一命中的假象：** 掃描結果可能僅出現一筆 `C:\Program Files\Microsoft VS Code`，那僅僅是因為微軟在實體資料夾命名中剛好使用了該連續字串，並不代表系統已盤點完整。

### 💡 關鍵字輸入策略與最佳實踐
當目標軟體名稱包含多個單字、或存在常見縮寫時，**強烈建議在啟動腳本時將比對模式切換為 `Regex`（正規表達式）**。

| 目標軟體 | ❌ 錯誤/流產輸入 (Contains) | 建議標準輸入 (Contains) | 建議正則輸入 (切換為 Regex 模式) |
| :--- | :--- | :--- | :--- |
| **Visual Studio Code** | `VS Code`, `VsCode` | `Visual Studio Code` | `VSCode\|VS Code\|Visual Studio Code` |


---

## 🌟 核心優勢與設計盲點防護

* **零 `Win32_Product` 調用**：避免傳統 WMI 查詢會強制觸發 Windows Installer 自動修復（大量產生 Event 1035 日誌）與 CPU/IO 效能問題。
* **跨使用者 (All Users) 深挖**：自動列舉系統所有使用者安全識別碼（SID），並透過原生 `reg.exe` 機制掛載離線使用者的 `NTUSER.DAT` 與 `UsrClass.dat`。全面找出多使用者環境、共用電腦底下的偵測死角。
* **極高相容性**：理論支援從 Windows 7、Windows 10、11 到 Windows Server 2025 的所有主流 Windows 平台。
* **廣度優先檔案檢索 (BFS)：** 針對 `ProgramFiles` 與使用者 `AppData\Local` 等現代 User-level 安裝重災區進行分流檢索，預設動態限制安全深度，兼顧效能與深層殘留偵測。

---


## 💻 系統需求與環境測試

* **已驗證環境**：Windows 11 (64-bit) 實機環境測試通過。
* **相容性說明**：本工具之核心邏輯（如離線登錄檔掛載、Installer 核心快取枚舉）理論上相容於 Windows 7 / 10 / Server 2016~2025。**但由於目前缺乏相應測試環境，舊版作業系統與伺服器生產環境尚未經過實際驗證。** 歡迎提交 Issue 或 Pull Request 協助完善相容性清單！

---

## ⚠️ 專業免責聲明 (Disclaimer)

1. **本工具僅提供「唯讀盤點」功能**，絕不會主動刪除系統上的任何檔案或登錄檔。
2. 掃描報告中列出的項目，可能包含與該關鍵字同名之系統核心依賴庫（例如特定版本的 Visual C++ Redistributable 某組件）。
3. **警告：** 嚴禁在未經詳細技術評估前盲目刪除報告中的路徑。誤刪 Windows Installer 底層快取或註冊表可能導致其他正常軟體損毀或系統不穩定，使用者須自行承擔手動清除之風險。

---

## 🚀 使用方法

### 專案結構
```text
Windows-Software-Residual-Scanner/
│
├── run-scanner.bat       # 進入點
├── Scan-Residuals.ps1    # 核心盤點邏輯
└── README.md             # 本說明文件
```

### 步驟 1：下載專案
將本專案克隆（Clone）或下載 ZIP 解壓縮至本機任一資料夾。

### 步驟 2：以管理員身分執行
1. 滑鼠右鍵點擊 `run-scanner.bat`。
2. 選擇 **「以系統管理員身分執行 (Run as Administrator)」**。

### 步驟 3：輸入關鍵字
在命令提示字元視窗中輸入你要尋找的軟體關鍵字（例如：`ReiBoot` 、 `AnyDesk` 或 使用正則表示式），指定關鍵字是包含模式(Contains)還是正則表示式(Regex)，然後開始掃描。

### 步驟 4：查看輸出的CSV檔內容

---

## 📊 產出報告

執行完成後，工具會在 **腳本所在的同一個資料夾** 下自動生成一份 CSV 報告：
* 檔名格式：`Check-Software_[電腦名稱]_[時間戳記].csv`
* 檔名格式：`AssetDiag_[關鍵字]_[電腦名稱]_[時間戳記].csv`
* 範例：`Scan-Residuals_ReiBoot_DESKTOP-ABC123_20260705_2130.csv`


### 欄位說明：
| 欄位名稱 | 說明 |
| :--- | :--- |
| **Timestamp** | 跡證偵測時間 |
| **Hostname** | 執行掃描的本機電腦名稱 |
| **Confidence** | 可信度(僅參考) |
| **Category** | 殘留類別（例如：HKLM_Registry, Windows_Installer_COM_Cache, User_Registry） |
| **Path** | 實體檔案路徑、機碼路徑或 MSI GUID |
| **Details** | 該跡證的詳細中繼資料（如產品顯示名稱、服務路徑等） |
| **Status** | Detected/Uncertain |

### 截圖

<img width="961" height="561" alt="執行結果" src="https://github.com/user-attachments/assets/e394211e-9111-432f-9fbd-e0f2908d32a5" />
<img width="972" height="171" alt="執行結果2" src="https://github.com/user-attachments/assets/c5951cbe-e235-4d6b-a27c-7d207183fce9" />

---

## 🛡️ 開源授權
本專案基於 **MIT License** 授權開源，歡迎自由分發、修改並用於商業或個人環境。
