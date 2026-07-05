<#
.SYNOPSIS
    Windows 跨使用者與深層軟體殘留唯讀盤點腳本
    產出格式：CSV
#>

# 1. 強制提權檢查 (鑑識標準：必須為 Administrator)
$IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $IsAdmin) {
    Write-Error "[拒絕執行] 權限不足：必須以「系統管理員身分」執行此腳本，否則無法掛載離線登錄檔或讀取 Installer 目錄。"
    Read-Host "按任意鍵結束..."
    exit
}


# 設定輸出編碼為 UTF-8，解決 CMD 視窗顯示亂碼問題
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

# 輸出專業聲明
Write-Host "======================================================================" -ForegroundColor Magenta
Write-Host "【警示聲明】" -ForegroundColor Yellow
Write-Host "本工具僅針對指定關鍵字進行系統掃描，產出報告可能包含該關鍵字所屬之"
Write-Host "關聯元件、相依庫或無關之誤判項目。"
Write-Host "警告：本工具僅提供唯讀盤點，嚴禁在未經評估下直接依掃描結果進行刪除，"
Write-Host "      使用者應自行承擔執行後之所有風險。"
Write-Host "======================================================================" -ForegroundColor Magenta
Write-Host ""

# 2. 初始設定與正則防護
$Keyword = Read-Host "請輸入要盤點的軟體關鍵字 (例如 7-Zip)"
if ([string]::IsNullOrWhiteSpace($Keyword) -or $Keyword.Length -lt 3) {
    Write-Warning "[拒絕執行] 關鍵字過短或無效，為避免產出過多雜訊與 I/O 浪費，中斷作業。"
    Read-Host "按任意鍵結束..."
    exit
}

# 進行正則跳脫，防禦 C++ 或特殊字元引發腳本崩潰或全域誤判
$SafeKeyword = [regex]::Escape($Keyword)
$Timestamp = Get-Date -Format "yyyyMMdd_HHmm"
# 一行流消毒：直接過濾 Windows 非法字元、控制字元與空白，全數替換為底線
$CleanKeywordForFilename = $Keyword -replace '[\\/:*?"<>|[:cntrl:]\s]+', '_'
$ReportPath = "$PSScriptRoot\Scan-Residuals_${CleanKeywordForFilename}_$($env:COMPUTERNAME)_${Timestamp}.csv"
$InventoryData = @()

Write-Host "開始進行 [$Keyword] 盤點，這可能需要幾分鐘的時間..." -ForegroundColor Cyan

# --- 輔助函數：加入結果 ---
function Add-Finding {
    param([string]$Category, [string]$Path, [string]$Details)
    $script:InventoryData += [PSCustomObject]@{
        Timestamp = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
        Hostname  = $env:COMPUTERNAME
        Category  = $Category
        Path      = $Path
        Details   = $Details
    }
    Write-Host "[發現] $Category - $Path" -ForegroundColor Yellow
}

# ---
# 階段一：全域登錄檔 (HKLM) 傳統移除清單與自動執行
# ---
Write-Host "[1/6] 掃描 HKLM 移除清單與自動執行點..."
$HKLMPaths = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
    "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\*",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce\*",
    "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run\*"
)
Get-ItemProperty -Path $HKLMPaths -ErrorAction SilentlyContinue | 
    Where-Object {
        $_.PSChildName -match $SafeKeyword -or
        ([string]$_.PSObject.Properties.Value -match $SafeKeyword)
    } |
    ForEach-Object { 
        if ($_.PSPath -match "\\(Run|RunOnce)\\") {
            $MatchedProp = $_.PSObject.Properties | Where-Object { [string]$_.Value -match $SafeKeyword } | Select-Object -First 1
            $DetailsStr = "AutoRun [ $($MatchedProp.Name): $($MatchedProp.Value) ]"
        } else {
            $DetailsStr = if ($_.DisplayName) { $_.DisplayName } else { $_.PSChildName }
        }
        Add-Finding -Category "HKLM_Registry" -Path $_.PSPath -Details $DetailsStr 
    }

Write-Host "[2/6] 掃描 Windows Installer 登錄檔特徵..."
$DeepPaths = @(
    "HKLM:\SOFTWARE\Classes\Installer\Products\*",
    "HKLM:\SOFTWARE\Classes\Installer\Features\*",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\*"
)
Get-ItemProperty -Path $DeepPaths -ErrorAction SilentlyContinue | 
    Where-Object { $_.ProductName -match $SafeKeyword -or $_.PSChildName -match $SafeKeyword } |
    ForEach-Object { 
        Add-Finding -Category "Windows_Installer_Registry" -Path $_.PSPath -Details ($_.ProductName -replace "`0","")
    }

# ---
# 階段二：系統服務與 100% 覆蓋率的實體 MSI 快取特徵掃描
# ---
Write-Host "[3/6] 掃描 系統服務與 Installer 核心快取..."

# 服務掃描 (相容 PSv2/Win7)
try { $Services = Get-CimInstance -ClassName Win32_Service -ErrorAction Stop }
catch { $Services = Get-WmiObject -Class Win32_Service -ErrorAction SilentlyContinue }

$Services | Where-Object { $_.Name -match $SafeKeyword -or $_.DisplayName -match $SafeKeyword -or $_.PathName -match $SafeKeyword } |
    ForEach-Object { 
        $DetailsStr = "DisplayName: [$($_.DisplayName)] | Path: $($_.PathName)"
        Add-Finding -Category "Service" -Path $_.Name -Details $DetailsStr
    }

# Installer COM 快取與二進位特徵掃描
$InstallerFolder = "$env:SystemRoot\Installer"
if (Test-Path $InstallerFolder) {
    try {
        $Installer = New-Object -ComObject WindowsInstaller.Installer
        $RegProducts = $Installer.GetType().InvokeMember("Products", [System.Reflection.BindingFlags]::GetProperty, $null, $Installer, $null)
        
        foreach ($ProductCode in $RegProducts) {
            $ProdName = $Installer.GetType().InvokeMember("ProductInfo", [System.Reflection.BindingFlags]::GetProperty, $null, $Installer, @($ProductCode, "InstalledProductName"))
            $LocalPackage = $Installer.GetType().InvokeMember("ProductInfo", [System.Reflection.BindingFlags]::GetProperty, $null, $Installer, @($ProductCode, "LocalPackage"))
            
            if ($ProdName -match $SafeKeyword -or $ProductCode -match $SafeKeyword) {
                Add-Finding -Category "Windows_Installer_COM_Cache" -Path "GUID: $ProductCode" -Details "Name: $ProdName | CachePath: $LocalPackage"
            }
        }
    } catch {
        Write-Host "  [!] COM 物件枚舉失敗，自動切換至二進位 MSI 檔案暴力特徵掃描..." -ForegroundColor DarkGray
        Get-ChildItem -Path $InstallerFolder -Filter "*.msi" -ErrorAction SilentlyContinue | ForEach-Object {
            try {
                $MsiDb = $Installer.GetType().InvokeMember("OpenDatabase", [System.Reflection.BindingFlags]::InvokeMethod, $null, $Installer, @($_.FullName, 0))
                $View = $MsiDb.GetType().InvokeMember("OpenView", [System.Reflection.BindingFlags]::InvokeMethod, $null, $MsiDb, @("SELECT `Value` FROM `Property` WHERE `Property`='ProductName'"))
                $View.GetType().InvokeMember("Execute", [System.Reflection.BindingFlags]::InvokeMethod, $null, $View, $null)
                $Record = $View.GetType().InvokeMember("Fetch", [System.Reflection.BindingFlags]::InvokeMethod, $null, $View, $null)
                $MsiProdName = $Record.GetType().InvokeMember("StringData", [System.Reflection.BindingFlags]::GetProperty, $null, $Record, 1)
                
                if ($MsiProdName -match $SafeKeyword) {
                    Add-Finding -Category "Raw_MSI_File_Residual" -Path $_.FullName -Details "Product: $MsiProdName"
                }
            } catch {}
        }
    }
}

# ---
# 階段三：排程任務與 Appx 封裝
# ---
Write-Host "[4/6] 掃描 排程任務與 Appx 封裝..."
try {
    Get-ScheduledTask -ErrorAction Stop | 
        Where-Object { $_.TaskName -match $SafeKeyword -or $_.TaskPath -match $SafeKeyword } |
        ForEach-Object { Add-Finding -Category "ScheduledTask" -Path $_.TaskPath -Details $_.TaskName }
} catch {
    Write-Host "  此系統版本不支援 Get-ScheduledTask (預期內行為，已略過)。" -ForegroundColor DarkGray
}

try {
    Get-AppxPackage -AllUsers -ErrorAction Stop | 
        Where-Object { $_.Name -match $SafeKeyword -or $_.PackageFullName -match $SafeKeyword } |
        ForEach-Object { Add-Finding -Category "AppxPackage" -Path $_.InstallLocation -Details $_.PackageFullName }
} catch {
    Write-Host "  此系統版本不支援 Get-AppxPackage (預期內行為，已略過)。" -ForegroundColor DarkGray
}

# ---
# 階段四：跨使用者配置與登錄檔 (包含 NTUSER.DAT 與 UsrClass.dat)
# ---
Write-Host "[5/6] 掃描 使用者目錄與離線登錄檔 (NTUSER.DAT / UsrClass.dat)..."

# 取得 User Profile，嚴格使用 SID 正規表示式過濾，避免路徑硬編碼問題與系統帳戶雜訊
$Profiles = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\*" | 
            Where-Object { $_.PSChildName -match "^S-1-5-21-\d+-\d+-\d+-\d+$" }

foreach ($Profile in $Profiles) {
    $SID = $Profile.PSChildName
    $ProfilePath = $Profile.ProfileImagePath
    if (-not (Test-Path $ProfilePath)) { continue }

    $UserName = ($ProfilePath -split '\\')[-1]
	Write-Host "  - $UserName ( $SID ) ..."
    
    # 封裝掛載並掃描登錄檔函數
    function Invoke-UserHiveScan ($HivePath, $TempHiveName, $TargetSubKeys, $CategoryPrefix) {
        $HiveLoaded = $false
        $BaseHive = ""
        
        if (Test-Path "Registry::HKEY_USERS\$SID") {
            $BaseHive = "Registry::HKEY_USERS\$SID"
        } elseif (Test-Path $HivePath) {
            $regLoadOutput = & reg.exe load "HKU\$TempHiveName" "$HivePath" 2>&1
            if ($LASTEXITCODE -eq 0) {
                $BaseHive = "Registry::HKEY_USERS\$TempHiveName"
                $HiveLoaded = $true
            } else {
                Write-Host "  [錯誤] 無法掛載 $HivePath : $regLoadOutput" -ForegroundColor Red
            }
        }

        if ($BaseHive) {
            $SearchPaths = $TargetSubKeys | ForEach-Object { "$BaseHive$_" }
            Get-ItemProperty -Path $SearchPaths -ErrorAction SilentlyContinue |
                Where-Object {
                    $_.PSChildName -match $SafeKeyword -or ($_.PSObject.Properties.Value -match $SafeKeyword)
                } |
                ForEach-Object { 
                    Add-Finding -Category "$CategoryPrefix" -Path $_.PSPath -Details "User: $UserName" 
                }
        }

        if ($HiveLoaded) {
            [GC]::Collect()
            [GC]::WaitForPendingFinalizers()
            Start-Sleep -Seconds 1
            & reg.exe unload "HKU\$TempHiveName" | Out-Null
        }
    }

    # 1. 掃描 NTUSER.DAT
    $NtuserKeys = @(
        "\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\*",
        "\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce\*"
    )
    Invoke-UserHiveScan -HivePath "$ProfilePath\NTUSER.DAT" -TempHiveName "TempHive_$SID" -TargetSubKeys $NtuserKeys -CategoryPrefix "User_Registry"

    # 2. 掃描 UsrClass.dat (處理被隱藏的檔案關聯與 COM 物件駐留點)
    $UsrClassKeys = @(
        "\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\*"
    )
    Invoke-UserHiveScan -HivePath "$ProfilePath\AppData\Local\Microsoft\Windows\UsrClass.dat" -TempHiveName "TempClass_$SID" -TargetSubKeys $UsrClassKeys -CategoryPrefix "User_UsrClass"
}

# ---
# 階段五：全域與使用者資料夾特徵碼盲掃 (高 I/O 消耗警告)
# ---
Write-Host "[6/6] 掃描 全域與使用者深層資料夾..."
$GlobalDirs = @(
    $env:ProgramData, 
    ${env:ProgramFiles}, 
    ${env:ProgramFiles(x86)}
)

foreach ($Profile in $Profiles) {
    $GlobalDirs += "$($Profile.ProfileImagePath)\AppData\Local"
    $GlobalDirs += "$($Profile.ProfileImagePath)\AppData\Roaming"
}

foreach ($Dir in $GlobalDirs | Select-Object -Unique) {
    if (Test-Path $Dir) {
        Get-ChildItem -Path $Dir -Filter "*$Keyword*" -Directory -Recurse -ErrorAction SilentlyContinue |
            ForEach-Object { Add-Finding -Category "Orphaned_Directory" -Path $_.FullName -Details "Directory Match" }
    }
}

# ---
# 產出報告
# ---
Write-Host "`n[處理完成] 產出報告..."
if ($InventoryData.Count -gt 0) {
    $InventoryData | Export-Csv -Path $ReportPath -NoTypeInformation -Encoding UTF8
    Write-Host "盤點完成！共發現 $($InventoryData.Count) 筆紀錄。" -ForegroundColor Green
    Write-Host "報告已匯出至: $ReportPath" -ForegroundColor Green
} else {
    Write-Host "盤點完成！未發現包含 [$Keyword] 的明顯紀錄。" -ForegroundColor Green
    "Timestamp,Hostname,Category,Path,Details" | Out-File $ReportPath -Encoding UTF8
}
