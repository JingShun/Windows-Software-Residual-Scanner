<#
.SYNOPSIS
	本機端軟體盤點殘留診斷工具
    Windows 軟體殘留多維度盤點與資產幽靈機碼（Ghost Registry）交叉診斷工具。
    透過排查多用戶配置單元（Hive）、Windows Installer 註冊快取及現代 AppX 機制，精準定位引發資產告警之殘留特徵。
    支援版本：PowerShell 4.0 +
#>

function Assert-ExecutionEnvironment {
    if ([Environment]::Is64BitOperatingSystem -and -not [Environment]::Is64BitProcess) {
        Write-Error "[執行中止] WOW64 環境將引發登錄檔重新導向盲區！"
        exit 1
    }
    $WindowsPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $WindowsPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Error "[拒絕執行] 必須以系統管理員身分執行。"
        exit 1
    }
    [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
}

function Initialize-ScannerContext {
    param([string]$Keyword, [string]$SearchMode, [int]$MaxDepth)
    if ([string]::IsNullOrWhiteSpace($Keyword) -or $Keyword.Trim().Length -lt 2) {
        Write-Warning "[拒絕執行] 關鍵字過短或為空白。"
        exit 1
    }
    $script:MaxScanDepth = $MaxDepth
    $script:InventoryData = New-Object System.Collections.ArrayList
    $script:MountedHives = New-Object 'System.Collections.Generic.HashSet[string]'
    $script:SearchMode = $SearchMode
    $script:MatchedAppXFamilies = New-Object 'System.Collections.Generic.HashSet[string]'
	
	$script:CurrentScanUserName = $null

    if ($SearchMode -eq "Regex") {
        try { $script:Pattern = $Keyword; [regex]::new($script:Pattern) | Out-Null } 
        catch { Write-Error "[拒絕執行] 無效正則表達式"; exit 1 }
    } else {
        $script:SearchKeyword = $Keyword
    }
}

function Test-KeywordMatch([string]$InputText) {
    if ([string]::IsNullOrEmpty($InputText)) { return $false }
    if ($script:SearchMode -eq "Regex") { return $InputText -match $script:Pattern } 
    else { return $InputText.IndexOf($script:SearchKeyword, [StringComparison]::OrdinalIgnoreCase) -ge 0 }
}

function Register-Finding {
    param([string]$Category, [string]$Path, [string]$Details, [string]$Confidence = "Medium", [string]$Status = "Detected")

	if ($null -ne $script:CurrentScanUserName -and $script:CurrentScanUserName -ne "") {
        $Details = "User: $script:CurrentScanUserName | $Details"
    }

    $null = $script:InventoryData.Add([PSCustomObject]@{
        Timestamp  = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
        Hostname   = $env:COMPUTERNAME
        Confidence = $Confidence
        Category   = $Category
        Path       = $Path
        Details    = $Details
        Status     = $Status
    })

    $Color = switch ($Confidence) {
        "High"   { "Green" }
        "Medium" { "Yellow" }
        "Low"    { "DarkGray" }
        default  { "White" }
    }
    if ($Status -eq "Uncertain") { $Color = "DarkYellow" }

    Write-Host "[$Confidence] $Category - $Path" -ForegroundColor $Color
}

function Scan-RegistrySubKeys {
    param([string]$BasePath, [string]$Category, [switch]$IsCLSID, [string]$BaseConfidence = "Medium")
    if (-not (Test-Path $BasePath)) { return }
    try {
        $SubKeys = Get-ChildItem -Path $BasePath -ErrorAction SilentlyContinue
		$TargetProps = "InprocServer32", "LocalServer32", "ProgID"
        foreach ($SubKey in $SubKeys) {
            try {
                if (Test-KeywordMatch $SubKey.PSChildName) {
                    Register-Finding -Category $Category -Path $SubKey.PSPath -Details "KeyName Direct Match" -Confidence $BaseConfidence
                    continue 
                }
                
                if ($IsCLSID) {
                    foreach ($Target in $TargetProps) {
                        $TargetKeyPath = "$($SubKey.PSPath)\$Target"
                        if (Test-Path $TargetKeyPath) {
                            $TargetKey = Get-Item -Path $TargetKeyPath -ErrorAction SilentlyContinue
                            if ($TargetKey) {
                                $DefValue = [string]$TargetKey.GetValue("")
                                if (Test-KeywordMatch $DefValue) { Register-Finding -Category "${Category}_$Target" -Path $TargetKeyPath -Details "Data: $DefValue" -Confidence "Medium" }
                            }
                        }
                    }
                    continue
                }

                foreach ($ValueName in $SubKey.GetValueNames()) {
                    $ValueData = [string]$SubKey.GetValue($ValueName)
                    if (Test-KeywordMatch $ValueName -or Test-KeywordMatch $ValueData) {
                        $DisplayValueName = if ([string]::IsNullOrEmpty($ValueName)) { "(Default)" } else { $ValueName }
                        Register-Finding -Category $Category -Path $SubKey.PSPath -Details "[$DisplayValueName]: $ValueData" -Confidence "Low"
                        break 
                    }
                }
            } catch { continue }
        }
    } catch { Register-Finding -Category "${Category}_Error" -Path $BasePath -Details $_.Exception.Message -Status "Uncertain" -Confidence "Low" }
}

function Scan-RegistryKeyProperties {
    param([string]$TargetKeyPath, [string]$Category, [string]$Confidence = "Low")
    if (-not (Test-Path $TargetKeyPath)) { return }
    try {
        $KeyObj = Get-Item -Path $TargetKeyPath -ErrorAction SilentlyContinue
        if ($null -eq $KeyObj) { return }
        foreach ($ValueName in $KeyObj.GetValueNames()) {
            try {
                $ValueData = [string]$KeyObj.GetValue($ValueName)
                if (Test-KeywordMatch $ValueName -or Test-KeywordMatch $ValueData) {
                    $DisplayValueName = if ([string]::IsNullOrEmpty($ValueName)) { "(Default)" } else { $ValueName }
                    Register-Finding -Category $Category -Path "$TargetKeyPath -> $DisplayValueName" -Details "Data: $ValueData" -Confidence $Confidence
                }
            } catch { continue }
        }
    } catch { Register-Finding -Category "${Category}_Error" -Path $TargetKeyPath -Details $_.Exception.Message -Status "Uncertain" -Confidence "Low" }
}

function Scan-ServicesRegistry {
    $ServicesPath = "HKLM:\SYSTEM\CurrentControlSet\Services"
    if (-not (Test-Path $ServicesPath)) { return }
    Write-Host "[$(Get-Date -Format 'HH:mm:ss')] 執行 系統服務登錄實體檢索..." -ForegroundColor Cyan
	
	$TargetProps = "ImagePath","DisplayName","Description"
	
    try {
        $SubKeys = Get-ChildItem -Path $ServicesPath -ErrorAction SilentlyContinue
        foreach ($SubKey in $SubKeys) {
            if (Test-KeywordMatch $SubKey.PSChildName) {
                Register-Finding -Category "Service_Registry" -Path $SubKey.PSPath -Details "ServiceName Direct Match" -Confidence "High"
                continue
            }
            foreach ($TargetProp in $TargetProps) {
				try {
					$Val = [string]$SubKey.GetValue($TargetProp)
					if (Test-KeywordMatch $Val) {
						Register-Finding -Category "Service_Registry_Property" -Path "$($SubKey.PSPath)\$TargetProp" -Details "Data: $Val" -Confidence "Medium"
					}
				} catch { continue }
            }
        }
    } catch { return }
}

function Scan-ModernApplications {
    Write-Host "[$(Get-Date -Format 'HH:mm:ss')] 執行 AppX / MSIX 現代應用程式動態與靜態交叉盤點..." -ForegroundColor Cyan
    try {
        $AppxPackages = Get-AppxPackage -AllUsers -ErrorAction SilentlyContinue
        foreach ($Appx in $AppxPackages) {
            if (Test-KeywordMatch $Appx.Name -or Test-KeywordMatch $Appx.PackageFullName) {
                # 提取 PackageFamilyName 供後續 User Profile 離線實體比對使用
                $null = $script:MatchedAppXFamilies.Add($Appx.PackageFamilyName)
                Register-Finding -Category "ModernApp_AppX" -Path "AppX:\$($Appx.PackageFullName)" -Details "Family: $($Appx.PackageFamilyName)" -Confidence "High"
            }
        }
    } catch {
        Register-Finding -Category "ModernApp_AppX_Error" -Path "Get-AppxPackage" -Details $_.Exception.Message -Status "Uncertain" -Confidence "Low"
    }
    
    $AppModelRepo = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\Repository\Packages"
    if (Test-Path $AppModelRepo) {
        Scan-RegistrySubKeys -BasePath $AppModelRepo -Category "ModernApp_Registry" -BaseConfidence "High"
    }
}

function Scan-WindowsInstallerDatabase {
    Write-Host "[$(Get-Date -Format 'HH:mm:ss')] 執行 Windows Installer 資產殘留掃描..." -ForegroundColor Cyan

    # 定義要追蹤的關鍵字 PackedGUID 集合，用來比對無名孤兒
    $TargetPackedGuids = New-Object 'System.Collections.Generic.HashSet[string]'

    # 階段一：掃描 Classes\Installer\Products (資產工具最常見的誤判源)
    $ClassesPath = "SOFTWARE\Classes\Installer\Products"
    $ClassesKey = $null
    try {
        $ClassesKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($ClassesPath, $false)
        if ($null -ne $ClassesKey) {
            foreach ($PackedGuid in $ClassesKey.GetSubKeyNames()) {
                $SubKey = $null
                try {
                    $SubKey = $ClassesKey.OpenSubKey($PackedGuid, $false)
                    if ($null -eq $SubKey) { continue }

                    $Fields = @{
                        "ProductName"  = [string]$SubKey.GetValue("ProductName")
                        "PackageCode"  = [string]$SubKey.GetValue("PackageCode")
                        "Transforms"   = [string]$SubKey.GetValue("Transforms")
                        "LocalPackage" = [string]$SubKey.GetValue("LocalPackage")
                    }

                    foreach ($Key in $Fields.Keys) {
                        if (Test-KeywordMatch $Fields[$Key]) {
                            Register-Finding `
                                -Category "Asset_Classes_Product" `
                                -Path "HKLM:\$ClassesPath\$PackedGuid" `
                                -Details "Matched [$Key]: $($Fields[$Key])" `
                                -Confidence "High"
                            
                            # 記住這個引發嫌疑的 PackedGUID，供階段二交叉比對
                            $null = $TargetPackedGuids.Add($PackedGuid)
                            break
                        }
                    }
                } catch { continue }
                finally { if ($null -ne $SubKey) { $SubKey.Dispose() } }
            }
        }
    } finally { if ($null -ne $ClassesKey) { $ClassesKey.Dispose() } }


    # 階段二：掃描 UserData
    $BaseKeyPath = "SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData"
    $BaseKey = $null
    try {
        $BaseKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($BaseKeyPath, $false)
        if ($null -eq $BaseKey) { return }

        foreach ($SID in $BaseKey.GetSubKeyNames()) {
            $ProductsPath = "$BaseKeyPath\$SID\Products"
            $ProductsKey = $null
            try {
                $ProductsKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($ProductsPath, $false)
                if ($null -eq $ProductsKey) { continue }

                foreach ($Guid in $ProductsKey.GetSubKeyNames()) {
                    $InstallPropPath = "$ProductsPath\$Guid\InstallProperties"
                    $PropKey = $null
                    try {
                        $PropKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($InstallPropPath, $false)
                        
                        # 當 InstallProperties
                        if ($null -eq $PropKey) {
                            # 只有當這個 GUID 在階段一已經被確認與關鍵字有關時，才判定為目標孤兒
                            if ($TargetPackedGuids.Contains($Guid)) {
                                Register-Finding `
                                    -Category "Installer_Orphan_Targeted" `
                                    -Path "HKLM:\$ProductsPath\$Guid" `
                                    -Details "InstallProperties Missing but high relation to target software" `
                                    -Confidence "Medium"
                            }
                            continue
                        }

                        # 正常有機碼狀態下的 7 大核心欄位比對
                        $Fields = @{
                            "DisplayName"           = [string]$PropKey.GetValue("DisplayName")
                            "Publisher"             = [string]$PropKey.GetValue("Publisher")
                            "InstallLocation"       = [string]$PropKey.GetValue("InstallLocation")
                            "UninstallString"       = [string]$PropKey.GetValue("UninstallString")
                            "QuietUninstallString"  = [string]$PropKey.GetValue("QuietUninstallString")
                            "InstallSource"         = [string]$PropKey.GetValue("InstallSource")
                            "DisplayVersion"        = [string]$PropKey.GetValue("DisplayVersion")
                        }

                        foreach ($Key in $Fields.Keys) {
                            if (Test-KeywordMatch $Fields[$Key]) {
                                Register-Finding `
                                    -Category "Asset_Ghost_Property" `
                                    -Path "HKLM:\$InstallPropPath" `
                                    -Details "Matched Field [$Key]: $($Fields[$Key])" `
                                    -Confidence "High"
                                break
                            }
                        }
                    }
                    catch { continue }
                    finally { if ($null -ne $PropKey) { $PropKey.Dispose() } }
                }
            } catch { continue }
            finally { if ($null -ne $ProductsKey) { $ProductsKey.Dispose() } }
        }
    } finally { if ($null -ne $BaseKey) { $BaseKey.Dispose() } }
}

function Scan-LiveServicesAndDrivers {
    Write-Host "[$(Get-Date -Format 'HH:mm:ss')] 執行 在線服務與系統驅動狀態交叉檢視..." -ForegroundColor Cyan
    try {
        $LiveServices = Get-CimInstance -ClassName Win32_Service -ErrorAction Stop
        $Drivers = Get-CimInstance -ClassName Win32_SystemDriver -ErrorAction Stop
    } catch {
        $LiveServices = Get-WmiObject -Class Win32_Service -ErrorAction SilentlyContinue
        $Drivers = Get-WmiObject -Class Win32_SystemDriver -ErrorAction SilentlyContinue
    }
    foreach ($Svc in $LiveServices) {
        if (Test-KeywordMatch $Svc.Name -or Test-KeywordMatch $Svc.DisplayName -or Test-KeywordMatch $Svc.PathName) {
            Register-Finding -Category "Live_Service" -Path "Service:\$($Svc.Name)" -Details "State: $($Svc.State)" -Confidence "High"
        }
    }
    foreach ($Drv in $Drivers) {
        if (Test-KeywordMatch $Drv.Name -or Test-KeywordMatch $Drv.DisplayName -or Test-KeywordMatch $Drv.PathName) {
            Register-Finding -Category "Live_Kernel_Driver" -Path "Driver:\$($Drv.Name)" -Details "State: $($Drv.State)" -Confidence "High"
        }
    }
}

function Scan-FileSystemResiduals {
    param([System.Collections.ArrayList]$TargetDirs)
    Write-Host "[$(Get-Date -Format 'HH:mm:ss')] 執行 實體檔案系統廣度優先搜尋, 深度限制: $script:MaxScanDepth)..." -ForegroundColor Cyan
    foreach ($RootPath in ($TargetDirs | Select-Object -Unique)) {
        if (-not (Test-Path $RootPath)) { continue }
        $Queue = New-Object System.Collections.Queue
        $Queue.Enqueue(@{ DirInfo = [System.IO.DirectoryInfo]::new($RootPath); Depth = 0 })
        
        while ($Queue.Count -gt 0) {
            $Current = $Queue.Dequeue()
            if ($Current.Depth -gt $script:MaxScanDepth) { continue }
            try {
                foreach ($File in $Current.DirInfo.EnumerateFiles()) {
                    if (Test-KeywordMatch $File.Name) { Register-Finding -Category "Residual_File" -Path $File.FullName -Details "Size: $($File.Length) bytes" -Confidence "Low" }
                }
                foreach ($SubDir in $Current.DirInfo.EnumerateDirectories()) {
                    # 阻斷符號連結與接點，避免存取異常與無窮迴圈
                    if (($SubDir.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -eq [System.IO.FileAttributes]::ReparsePoint) { continue }
                    
                    if (Test-KeywordMatch $SubDir.Name) { Register-Finding -Category "Residual_Directory" -Path $SubDir.FullName -Details "BFS Matched" -Confidence "Medium" }
                    if ($Current.Depth -lt $script:MaxScanDepth) { $Queue.Enqueue(@{ DirInfo = $SubDir; Depth = ($Current.Depth + 1) }) }
                }
            } catch { continue }
        }
    }
}

function Scan-CLSID_DotNetNative {
	# 執行 .NET Native CLSID 掃描，繞過 PS Cmdlet 物件封裝瓶頸
    Write-Host "[$(Get-Date -Format 'HH:mm:ss')] 執行 .NET Native CLSID 掃描..." -ForegroundColor Cyan

    $Targets = @("InprocServer32", "LocalServer32", "ProgID")
    $BaseKey = $null

    try {
		# 直接以 .NET 原生 API 開啟唯讀連線
        $BaseKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey("SOFTWARE\Classes\CLSID", $false)
        if ($null -eq $BaseKey) { return }

        $SubKeyNames = $BaseKey.GetSubKeyNames()

        foreach ($Guid in $SubKeyNames) {
            $GuidPath = "HKLM:\SOFTWARE\Classes\CLSID\$Guid"

            # 記憶體層級的高速字串比對，命中直接中斷當次檢查
            if (Test-KeywordMatch $Guid) {
                Register-Finding -Category "Global_CLSID" -Path $GuidPath -Details "KeyName Direct Match" -Confidence "Medium"
                continue
            }

            $GuidKey = $null
            try {
                # 僅針對權限拒絕等真實例外進行攔截
                $GuidKey = $BaseKey.OpenSubKey($Guid, $false)
                if ($null -eq $GuidKey) { continue }

				# [新增修補] 讀取 GUID 機碼本身的 (Default) 值 (COM 元件描述)
                $GuidDefault = [string]$GuidKey.GetValue("")
                if (Test-KeywordMatch $GuidDefault) {
                    Register-Finding -Category "Global_CLSID_Description" -Path $GuidPath -Details "Name: $GuidDefault" -Confidence "Medium"
                }
				
                foreach ($Target in $Targets) {
                    $TargetKey = $null
                    try {
                        $TargetKey = $GuidKey.OpenSubKey($Target, $false)
                        if ($null -eq $TargetKey) { continue }

                        # 聚焦打擊：只讀取真正有意義的 (Default) 值，排除 ThreadingModel 等無效 I/O 浪費
                        $DefaultValue = [string]$TargetKey.GetValue("")
                        if (Test-KeywordMatch $DefaultValue) {
                            Register-Finding -Category "Global_CLSID_$Target" -Path "$GuidPath\$Target" -Details "Default: $DefaultValue" -Confidence "Medium"
                        }
                    }
                    catch {
                        # 吞噬特定 COM 節點的存取拒絕異常，確保掃描持續進行
                        continue
                    }
                    finally {
                        if ($null -ne $TargetKey) { $TargetKey.Dispose() }
                    }
                }
            }
            catch { continue }
            finally {
                if ($null -ne $GuidKey) { $GuidKey.Dispose() }
            }
        }
    }
    finally {
        if ($null -ne $BaseKey) { $BaseKey.Dispose() }
    }
}


# === 主程序啟動 ===
Assert-ExecutionEnvironment

# 設定輸出編碼為 UTF-8，解決 CMD 視窗顯示亂碼問題
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

# 輸出聲明

Write-Host "====================================================================="
Write-Host "=====                                                           ====="
Write-Host "=====                 本機端軟體盤點殘留診斷工具                ====="
Write-Host "=====                                                           ====="
Write-Host "====================================================================="
Write-Host "【警示聲明】" -ForegroundColor Yellow
Write-Host "本工具僅用關鍵字進行系統掃描，產出報告可能包含該關鍵字的元件、相依庫或無關之誤判項目。"
Write-Host "警告：本工具僅提供唯讀盤點，嚴禁在未經評估下直接依掃描結果進行刪除，"
Write-Host "      使用者應自行承擔執行後之所有風險。"
Write-Host "====================================================================="
Write-Host ""


$InputKeyword = Read-Host "請輸入要盤點的軟體關鍵字"
$InputMode    = Read-Host "請選擇比對模式 [Contains / Regex] (預設 Contains)"
$InputDepth   = Read-Host "請輸入檔案系統最大掃描深度 (預設 5)"

Write-Host ""
Write-Host "[$(Get-Date -Format 'HH:mm:ss')] 啟動 當前時間:$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Cyan

if ([string]::IsNullOrWhiteSpace($InputMode)) { $InputMode = "Contains" }
$DepthInt = 5; [int]::TryParse($InputDepth, [ref]$DepthInt) | Out-Null
if (-not [int]::TryParse($InputDepth, [ref]$DepthInt)) {
    $DepthInt = 5
}

Initialize-ScannerContext -Keyword $InputKeyword -SearchMode $InputMode -MaxDepth $DepthInt

$Timestamp = Get-Date -Format "yyyyMMdd_HHmm"
$CleanFilename = $InputKeyword -replace '[\\/:*?"<>|[:cntrl:]\s]+', '_'
$ReportPath = "$PSScriptRoot\AssetDiag_${CleanFilename}_$($env:COMPUTERNAME)_${Timestamp}.csv"

try {
    Scan-LiveServicesAndDrivers
    Scan-ModernApplications
    Scan-ServicesRegistry

    # Write-Host "[$(Get-Date -Format 'HH:mm:ss')] INFO Scan-RegistryKeyProperties..."

    $PropertyScanList = @(
        @("HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\SharedDLLs", "Low"),
        @("HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "Medium"),
        @("HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "Medium"),
        @("HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment", "Low")
    )
    foreach ($Item in $PropertyScanList) { Scan-RegistryKeyProperties -TargetKeyPath $Item[0] -Category "Global_Properties" -Confidence $Item[1] }

    # Write-Host "[$(Get-Date -Format 'HH:mm:ss')] INFO Scan-RegistrySubKeys..."
    $SubKeyScanList = @(
        @("HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", "High"),
        @("HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall", "High"),
        @("HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths", "Medium"),
        @("HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\App Paths", "Medium")
    )
    foreach ($Item in $SubKeyScanList) { Scan-RegistrySubKeys -BasePath $Item[0] -Category "Global_Registry" -BaseConfidence $Item[1] }	

	Scan-CLSID_DotNetNative

    Scan-WindowsInstallerDatabase

    Write-Host "[$(Get-Date -Format 'HH:mm:ss')] 啟動 多用戶配置單元 隔離檢索 (含離線 AppX 比對)..." -ForegroundColor Cyan
    $Profiles = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\*" | Where-Object { $_.PSChildName -match "^S-1-(5-21|12-1)-\d+" }
    $FileSystemTargets = New-Object System.Collections.ArrayList
    $null = $FileSystemTargets.Add($env:ProgramData); $null = $FileSystemTargets.Add("$env:ProgramData\Package Cache")
    $null = $FileSystemTargets.Add(${env:ProgramFiles})
    if (Test-Path ${env:ProgramFiles(x86)}) { $null = $FileSystemTargets.Add(${env:ProgramFiles(x86)}) }

    foreach ($Profile in $Profiles) {
        $SID = $Profile.PSChildName; $ProfilePath = $Profile.ProfileImagePath
        if (-not (Test-Path $ProfilePath)) { continue }
		
		# 利用 .NET 高速將 SID 反查為明文 Username，用完就設回null
		$script:CurrentScanUserName = $null
		try {
			$SidObj = New-Object System.Security.Principal.SecurityIdentifier($SID)
			$UserObj = $SidObj.Translate([System.Security.Principal.NTAccount])
			$script:CurrentScanUserName = $UserObj.Value  # 格式會是 "DOMAIN\Username" 或 "COMPUTER\Username"
		} catch {
			# 如果是已刪除的孤兒帳號，則退而求其次從路徑提取
			$script:CurrentScanUserName = Split-Path $ProfilePath -Leaf
		}
		
        $null = $FileSystemTargets.Add("$ProfilePath\AppData\Local")

        # 捨棄緩慢的 AppX User API，改採 O(1) 實體目錄性能較好
        $UserAppXPackageDir = "$ProfilePath\AppData\Local\Packages"
        if (Test-Path $UserAppXPackageDir) {
            foreach ($Family in $script:MatchedAppXFamilies) {
                if (Test-Path "$UserAppXPackageDir\$Family") {
                    Register-Finding -Category "ModernApp_User_Offline" -Path "$UserAppXPackageDir\$Family" -Details "AppX Offline Profile Match" -Confidence "High"
                }
            }
        }

        # NTUSER.DAT 處理
        $BaseHive = ""; $HiveLoaded = $false
        if (Test-Path "Registry::HKEY_USERS\$SID") { $BaseHive = "Registry::HKEY_USERS\$SID" }
        elseif (Test-Path "$ProfilePath\NTUSER.DAT") {
            & reg.exe load "HKU\Temp_$SID" "$ProfilePath\NTUSER.DAT" 2>&1 | Out-Null
            if ($LASTEXITCODE -eq 0) { $BaseHive = "Registry::HKEY_USERS\Temp_$SID"; $HiveLoaded = $true; $null = $script:MountedHives.Add("HKU\Temp_$SID") }
        }
        if ($BaseHive) {
            Scan-RegistryKeyProperties -TargetKeyPath "$BaseHive\Environment" -Category "User_Environment" -Confidence "Low"
            Scan-RegistryKeyProperties -TargetKeyPath "$BaseHive\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Category "User_Run" -Confidence "Medium"

            Scan-RegistryKeyProperties -TargetKeyPath "$BaseHive\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" -Category "User_RunOnce" -Confidence "Medium"
            Scan-RegistrySubKeys -BasePath "$BaseHive\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" -Category "User_Uninstall" -BaseConfidence "High"
            Scan-RegistrySubKeys -BasePath "$BaseHive\SOFTWARE\Classes\CLSID" -Category "User_CLSID" -IsCLSID -BaseConfidence "Medium"
        }

        # UsrClass.dat 處理
        $ClassHive = ""; $ClassLoaded = $false
        if (Test-Path "Registry::HKEY_USERS\${SID}_Classes") { $ClassHive = "Registry::HKEY_USERS\${SID}_Classes" }
        elseif (Test-Path "$ProfilePath\AppData\Local\Microsoft\Windows\UsrClass.dat") {
            & reg.exe load "HKU\Temp_${SID}_Classes" "$ProfilePath\AppData\Local\Microsoft\Windows\UsrClass.dat" 2>&1 | Out-Null
            if ($LASTEXITCODE -eq 0) { $ClassHive = "Registry::HKEY_USERS\Temp_${SID}_Classes"; $ClassLoaded = $true; $null = $script:MountedHives.Add("HKU\Temp_${SID}_Classes") }
        }
        if ($ClassHive) {
            Scan-RegistrySubKeys -BasePath "$ClassHive\CLSID" -Category "UserClass_CLSID" -IsCLSID -BaseConfidence "Medium"
            Scan-RegistrySubKeys -BasePath "$ClassHive\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel" -Category "UserClass_AppModel" -BaseConfidence "Medium"
        }

        [GC]::Collect(); [GC]::WaitForPendingFinalizers()
        if ($HiveLoaded) { 
            & reg.exe unload "HKU\Temp_$SID" 2>&1 | Out-Null
            if ($LASTEXITCODE -eq 0) { $null = $script:MountedHives.Remove("HKU\Temp_$SID") }
        }
        if ($ClassLoaded) { 
            & reg.exe unload "HKU\Temp_${SID}_Classes" 2>&1 | Out-Null
            if ($LASTEXITCODE -eq 0) { $null = $script:MountedHives.Remove("HKU\Temp_${SID}_Classes") }
        }
		
		# 用完就設回null
		$script:CurrentScanUserName = $null
    }

    Scan-FileSystemResiduals -TargetDirs $FileSystemTargets

} finally {
    if ($script:MountedHives.Count -gt 0) {
        Write-Host "`n[強制清理] 執行解掛安全機制..." -ForegroundColor Red
        [GC]::Collect(); [GC]::WaitForPendingFinalizers()
        foreach ($Hive in @($script:MountedHives)) {
            & reg.exe unload "$Hive" 2>&1 | Out-Null
            if ($LASTEXITCODE -ne 0) { Register-Finding -Category "HIVE_LOCK" -Path $Hive -Details "Require Reboot" -Status "Uncertain" -Confidence "Low" }
        }
    }
    
    if ($script:InventoryData.Count -gt 0) {
        $script:InventoryData | Export-Csv -Path $ReportPath -NoTypeInformation -Encoding UTF8
        Write-Host "`n盤點完成！共發現 $($script:InventoryData.Count) 筆紀錄。報告已匯出: $ReportPath" -ForegroundColor Green
    } else {
        "Timestamp,Hostname,Confidence,Category,Path,Details,Status" | Out-File $ReportPath -Encoding UTF8
        Write-Host "`n盤點完成！未發現項目。" -ForegroundColor Green
    }
	Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Finish !!" -ForegroundColor Cyan
}