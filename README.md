# Windows Software Residual Scanner (Windows軟體殘留找尋工具)


當 Windows 軟體透過常規管道卸載後，往往會在系統深層（如 Windows Installer 快取、離線登錄檔、使用者隱藏資料夾）留下特徵殘留。這會導致企業內部的資產盤點軟體小概率持續觸發漏洞告警，判定該軟體依然存活。

本工具是一個**完全唯讀、無害且全面**的盤點腳本，旨在幫助 IT 管理員與使用者深度掃描指定軟體的殘留，並產出結構化報告以利評估自行手動清除。

---

## 🌟 核心優勢與設計盲點防護

* **零 `Win32_Product` 調用**：避免傳統 WMI 查詢會強制觸發 Windows Installer 自動修復（大量產生 Event 1035 日誌）與 CPU/IO 效能問題。
* **跨使用者 (All Users) 深挖**：自動掛載非當前登入使用者的離線登錄檔（`NTUSER.DAT` 與 `UsrClass.dat`），全面防堵多使用者環境下的偵測死角。
* **極高相容性**：理論支援從 Windows 7、Windows 10、11 到 Windows Server 2025 的所有主流 Windows 平台。
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
在命令提示字元視窗中輸入你要尋找的軟體關鍵字（例如：`ReiBoot` 或 `AnyDesk`），程式即開始執行六大階段的深層掃描。

---

## 📊 產出報告

執行完成後，工具會在 **腳本所在的同一個資料夾** 下自動生成一份 CSV 報告：
* 檔名格式：`Check-Software_[電腦名稱]_[時間戳記].csv`
* 檔名格式：`Scan-Residuals_[關鍵字]_[電腦名稱]_[時間戳記].csv`
* 範例：`Scan-Residuals_ReiBoot_DESKTOP-ABC123_20260705_2130.csv`


### 欄位說明：
| 欄位名稱 | 說明 |
| :--- | :--- |
| **Timestamp** | 跡證偵測時間 |
| **Hostname** | 執行掃描的本機電腦名稱 |
| **Category** | 殘留類別（例如：HKLM_Registry, Windows_Installer_COM_Cache, User_Registry） |
| **RiskLevel** | 評估風險等級（高/中/低），供手動清除時參考 |
| **Path** | 實體檔案路徑、機碼路徑或 MSI GUID |
| **Details** | 該跡證的詳細中繼資料（如產品顯示名稱、服務路徑等） |

---

## 🛡️ 開源授權
本專案基於 **MIT License** 授權開源，歡迎自由分發、修改並用於商業或個人環境。
