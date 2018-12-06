$global:os = (Get-WmiObject Win32_OperatingSystem | Select-Object Caption).Caption
$global:bits = (Get-WmiObject Win32_OperatingSystem | Select-Object OSArchitecture).OSArchitecture
[bool]$global:domainJoin = $false
[bool]$global:renamePC = $false
[bool]$global:GVCNeeded = $false

filter Get-FileSize {
    "{0:2} {1}" -f $(
        If ($_ -lt 1kb) {($_/1kb), 'Bytes'}
        ElseIf ($_ -lt 1mb) {($_/1mb), 'KB'}
        ElseIf ($_ -lt 1gb) {($_/1gb), 'MB'}
        Else {($_/1gb), 'GB'}
    )
}

Function DownloadFile {
    Param (
        [Parameter(Mandatory=$true)]$from,
        $to = "$env:WINDIR\Temp"
    )

    $dest = Join-Path $to ($from | Split-Path -Leaf)
    $start = Get-Date
    Invoke-WebRequest $url -OutFile $dest

    $time = ((Get-Date) - $start).ToString('hh\:mm\:ss')
    $size = (Get-Item $dest).Length | Get-FileSize

    Get-Item $dest | Unblock-File
}

Function ExtractZip($file,$destination) {
    $shell = New-Object -ComObject shell.Application
    $zip = $shell.Namespace($file)
    ForEach ($item in $zip.Items()) {
        $shell.Namespace($destnation).copyhere($item)
    }
}

Function IsInstalled($program) {
    $split = $program.Split(" ")
    [bool]$installed = $false

    For ($i = 1; $i -lt $split.Count; $i++) {
        If (!($REG)) {
            $REG = (Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object {$_.DisplayName -like "*$($split[$i])*"}) -ne $null
        }
    }
    For ($i = 1; $i -lt $split.Count; $i++) {
        If (!($WMI)) {
            $WMI = (Get-WmiObject Win32_Product | Where-Object {$_.Caption -like "*$($split[$i])*"}) -ne $null
        }
    }
    If ($REG -or $WMI) {
        [bool]$installed = $true
    }
    return $installed
}

Function CreateShortcut {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true,Position=0,ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNull()]
        [string]$exe,
        [Parameter(Mandatory=$true,Position=1,ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNull()]
        [string]$folder,
        [Parameter(Mandatory=$false,Position=2,ValueFromPipelineByPropertyName=$true)]
        [string]$args,
        [Parameter(Mandatory=$false,Position=3,ValueFromPipelineByPropertyName=$true)]
        [string]$icoLoc,
        [Parameter(Mandatory=$false,Position=4,ValueFromPipelineByPropertyName=$true)]
        [string]$icoPos
    )

    $shell = New-Object -ComObject ("Wscript.Shell")
    $sc = $shell.CreateShortcut("folder")
    $sc.TargetPath = $exe
    $sc.Arguments = $args
    $sc.IconLocation = "$icoLoc, $icoPos"
    $sc.Save()
}

Function NewUser {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true,Position=0,ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNull()]
        [string]$NewUser = "atadmin",
        [Parameter(Mandatory=$true,Position=1,ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNull()]
        [string]$NewPassword = "auxeP@$$"
    )

    New-LocalUser $NewUser -Password ($NewPassword | ConvertTo-SecureString -AsPlainText -Force)
    Add-LocalGroupMember -Group "Administrators" -Member $NewUser
}

Function LogonAsUser {
    Param (
        [Parameter(Mandatory=$true,Position=0,ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNull()]
        [string]$un = "atadmin",
        [Parameter(Mandatory=$true,Position=1,ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNull()]
        [string]$pw = "auxeP@$$",
        [Parameter(Mandatory=$false,Position=3,ValueFromPipelineByPropertyName=$true)]
        [string]$domain
    )
    If ($domain) {
        $dom = $domain.split('.')[0]
        $user = $dom + '\' + $un
    }
    Else {
        $user = $un
    }
    
    $isAdmin = (Get-LocalGroupMember -Group "Administrators" | Where-Object {$_.Name -like "*$($user)"}) -ne $null
    If (!($isAdmin)) {
        Add-LocalGroupMember -Group "Administrators" -Member $user
    }
    
    If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\WinLogon")) {
        New-Item -Path "HKLM:\SOFTWARE\Micorosft\Windows NT\CurrentVersion\WinLogon" -Force | Out-Null
    }
    
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\WinLogon" -Name "AutoAdminLogon" -Type DWORD -Value "1"
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\WinLogon" -Name "DefaultUserName" -Type String -Value $un
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\WinLogon" -Name "DefaultPassword" -Type String -Value $pw

    If ($dom) {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\WinLogon" -Name "DefaultDomainName" -Type String -Value $dom
    }
}

Function DisableLogonAsUser {
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\WinLogon" -Name "AutoAdminLogon" -Type DWORD -Value "0"
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\WinLogon" -Name "DefaultUserName" -Type String -Value ""
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\WinLogon" -Name "DefaultPassword" -Type String -Value ""
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\WinLogon" -Name "DefaultDomainName" -Type String -Value ""
}

Function RenamePC {
    Param (
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNull()]
        [string]$NewPCName
    )

    $PCName = $env:COMPUTERNAME
    Rename-Computer -ComputerName $PCName -NewName $NewPCName -Force -Confirm:$false -Restart
}

Function AdjustPowerSettings {
    $powerPlan = Get-WmiObject -Namespace root\cimv2\power -Class Win32_PowerPlan -Filter "ElementName = 'High Performance'"
    $powerPlan.Activate()

    powercfg -change -monitor-timeout-ac 0
    powercfg -change -disk-timeout-ac 0
    powercfg -change -hibernate-timeout-ac 0
    powercfg -change -standby-timeout-ac 0
}

Function DisableUAC {
    $UACReg = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"

    If ($global:os -like "*Windowws 10*") {
        New-ItemProperty -Path $UACReg -Name "EnableLUA" -Value "1" -PropertyType DWORD -Force | Out-Null
        New-ItemProprety -Path $UACReg -Name "ConsentPromptBehavior" -Value "0" -PropertyType DWORD -Force | Out-Null
        New-ItemProperty -Path $UACReg -Name "PromptOnSecureDesktop" -Value "0" -PropertyType DWORD -Force | Out-Null
    }
    ElseIf ($global:os -like "*Windows 7*") {
        New-ItemProperty -Path $UACReg -Name "EnableLUA" -Value "1" -PropertyType DWORD -Force | Out-Null
    }
}

Function DomainJoin {
    Param (
        [Parameter(Mandatory=$true,Position=0,ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNull()]
        [string]$domain,
        [Parameter(Mandatory=$true,Position=1,ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNull()]
        [string]$domAdminUN = $domain.Split('.')[0] + "\atadmin",
        [Parameter(Mandatory=$true,Position=2,ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNull()]
        [string]$domAdminPW = "@uXeT3k!"
    )
    $dun = $domAdminUN
    $dpw = $domAdminPW | ConvertTo-SecureString -AsPlainText -Force
    $domCreds = New-Object System.Management.Automation.PSCredential($dun,$dpw)

    Add-Computer -DomainName $domain -Credential $domCreds
}

Function DisableTelemetry {
    Write-Output "Disabling Telemetry..."
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Type DWORD -Value "0"
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Type DWORD -Value "0"
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" -Name "AllowBuildPreview" -Type DWORD -Value "0"
    Disable-ScheduledTask -TaskName "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" | Out-Null
    Disable-ScheduledTask -TaskName "Microsoft\Windows\Application Experience\ProgramDataUpdater" | Out-Null
    Disable-ScheduledTask -TaskName "Microsoft\Windows\Autochk\Proxy" | Out-Null
    Disable-ScheduledTask -TaskName "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" | Out-Null
    Disable-ScheduledTask -TaskName "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" | Out-Null
    Disable-ScheduledTask -TaskName "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollectore" | Out-Null
}

Function DisableWifiSense {
    Write-Output "Disabling WiFi Sense..."
    If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting")) {
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" -Name "Value" -Type DWORD -Value "1"
    If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots")) {
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" -Name "Value" -Type DWORD -Value "1"
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" -Name "AutoConnectAllowedOEM" -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" -Name "WiFiSenseAllowed" -ErrorAction SilentlyContinue
}

Function DisableSmartScreen {
    Write-Output "Disabling SmartScreen Filter..."
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableSmartScreen" -Type DWORD -Value "0"
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter" -Name "EnabledV9" -Type DWORD -Value "0"
}

Function DisableWebSearch {
    Write-Output "Disabling Bing Search in Start Menu..."
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "BingSearchEnabled" -Type DWORD -Value "0"
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "CortanaConsent" -Type DWORD -Value "0"
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "DisableWebSearch" -Type DWORD -Value "1"
}

Function DisableAppSuggestions {
    Write-Output "Disabling Application Suggestions..."
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "ContentDeliveryAllowed" -Type DWORD -Value "0"
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "OemPreInstalledAppsEnabled" -Type DWORD -Value "0"
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "PreInstalledAppsEnabled" -Type DWORD -Value "0"
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "PreInstalledAppsEverEnabled" -Type DWORD -Value "0"
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SilentInstalledAppsEnabled" -Type DWORD -Value "0"
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-310093Enabled" -Type DWORD -Value "0"
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338387Enabled" -Type DWORD -Value "0"
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338388Enabled" -Type DWORD -Value "0"
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338389Enabled" -Type DWORD -Value "0"
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338393Enabled" -Type DWORD -Value "0"
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353696Enabled" -Type DWORD -Value "0"
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353698Enabled" -Type DWORD -Value "0"
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SystemPaneSuggestionsEnabled" -Type DWORD -Value "0"
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsConsumerFeatures" -Type DWORD Value "1"
    If ([System.Environment]::OSVersion.Version.Build -ge 17134) {
        $key = Get-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CloudStore\Store\Cache\DefaultAccount\*windows.data.placeholdertilecollection\Current"
        Set-ItemProperty -Path $key.PSPath -Name "Data" -Type Binary -Value $key.Data[0..15]
        Stop-Process -Name "ShellExperienceHost" -Force -ErrorAction SilentlyContinue
    }
}

Function DisableFeedback {
    Write-Output "Disabling Feedback..."
    If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Siuf\Rules")) {
        New-Item -Path "HKCU:\SOFTWARE\Microsoft\Siuf\Rules" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Siuf\Rules" -Name "NumberOfSIUFInPeriod" -Type DWORD -Value "0"
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "DoNotShowFeedbackNotifications" -Type DWORD -Value "0"
    Disable-ScheduledTask -Path "Microsoft\Windows\Feedback\Siuf\DmClient" -ErrorAction SilentlyContinue
    Disable-ScheduledTask -Path "Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload" -ErrorAction SilentlyContinue
}

Function DisableTailoredExperiences {
    Write-Output "Disabling Tailored Experiences..."
    If (!(Test-Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent")) {
        New-Item -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableTailoredExperiencesWithDiagnosticData" -ErrorAction SilentlyContinue
}

Function DisableAdvertisingID {
    Write-Output "Disable Advertising ID..."
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" -Name "DisabledByGroupPolicy" -Type DWORD -Value "1"
}

Function DisableCortana {
    Write-Output "Disabling Cortana..."
    If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Personalization\Settings")) {
        New-Item -Path "HKCU:\SOFTWARE\Microsoft\Personalization\Settings" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Personalization\Settings" -Name "AcceptedPrivacyPolicy" -Type DWORD -Value "0"
    If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization")) {
        New-Item -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization" -Name "RestrictImplicitTextCollection" -Type DWORD -Value "1"
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization" -Name "RestrictImplicitInkCollection" -Type DWORD -Value "1"
    If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore")) {
        New-Item -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" -Name "HarvestContacts" -Type DWORD -Value "0"
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortana" -Type DWORD -Value "0"
}

Function AdjustFirewall {
    cmd.exe /c "netsh advfirewall set currentprofile firewallpolicy allowinbound,allowoutbound"
}

Function SetNetworkDiscovery {
    $ndServices = @("SSDPServer","dnscache","upnphost","FDResPub","winrm")

    ForEach ($svc in $ndServices) {
        $state = (Get-Service $svc | Select Status).Status
        Set-Service -Name $svc -StartupType "Automatic"
        If (!($state)) {
            Start-Service $svc
        }
    }
}

Function SetRemotePS {
    Enable-PSRemoting -Force -Confirm:$false
}

Function EnableScriptHost {
    Write-Output "Enabling Windows Script Host..."
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings" -Name "Enabled" -Type DWORD -Value "1"
}

Function DisableScriptHost {
    Write-Output "Enabling Windows Script Host..."
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings" -Name "Enabled" -Type DWORD -Value "0"
}

Function EnableF8BootMenu {
    Write-Output "Enabling F8 Boot Menu Options..."
    bcdedit /set `{current`} BootMenuPolicy Legacy | Out-Null
}

Function DisableUpdateRestart {
    Write-Output "Disabling Windows Update Automatic Restart..."
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoRebootWithLoggedOnUsers" -Type DWORD -Value "1"
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AUPowerManagement" -Type DWORD -Value "0"
}

Function EnableRemoteDesktop {
    Write-Output "Enabling Remote Desktop w/o Network Level Authentication..."
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Type DWORD -Value "0"
    Enable-NetFirewallRule -Name "RemoteDesktop*"
}

Function SetControlPanelSmallIcons {
    Write-Output "Setting Control Panel view to small Icons..."
    If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel")) {
        New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel" | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel" -Name "StartupPage" -Type DWORD -Value "1"
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel" -Name "AllItemsIconView" -Type DWORD -Value "1"
}

Function DisableShortcutInName {
    Write-Output "Disable adding '- shortcut' ot shortcut name..."
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "link" -Type Binary -Value ([byte[]](0,0,0,0))
}

Function EnableNumLock {
    Write-Output "Enabling NumLock after Startup..."
    If (!(Test-Path "HKU:")) {
        New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS | Out-Null
    }
    Set-ItemProperty -Path "HKU:\.DEFAULT\Control Panel\Keyboard" -Name "InitialKeyboardIndicators" -Type DWORD -Value 2147483650
    Add-Type -AssemblyName System.Windows.Forms
    If (!([System.Windows.Forms.Control]::IsKeyLocked('NumLock'))) {
        $wsh = New-Object -ComObject WScript.Shell
        $wsh.SendKeys('{NUMLOCK}')
    }
}

Function ShowKnownExtensions {
    Write-Output "Showing Known File Extensions in Explorer..."
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Type DWORD -Value "0"
}

Function UninstallMsftBloat {
    Write-Output "Uninstalling Default Microsoft Bloatware..."
    $apps = @(
        "Microsoft.BingFinance",
        "Microsoft.BingNews",
        "Microsoft.BingSports",
        "Microsoft.BingTranslator",
        "Microsoft.BingWeather",
        "Microsoft.MinecraftUWP")
    ForEach ($app in $apps) {
        Get-AppXPackage $app | Remove-AppXPackage
    }
}

Function Uninstall3rdPartyBloat {
    Write-Otuput "Uninstalling Default 3rd Party Bloatware..."
    $apps = @(
        "4DF9E0F8.Netflix",
        "828B5831.HiddenCityMysteryofShadows",
        "9E2F88E3.Twitter",
        "A278AB0D.DisneyMagicKingdoms",
        "A278AB0D.MarchofEmpires",
        "D52A8D61.FarmVille2CountryEscape",
        "D5EA27B7.Duolingo-LearnLanguagesForFree",
        "Facebook.Facebook",
        "flaregamesGmbH.RoyalRevolt2",
        "GAMELOFTSA.Asphalt8Airborne",
        "king.com.BubbleWitch3Saga",
        "king.com.CandyCrushSaga",
        "PandoraMediaInc.29680B314EFC2",
        "SpotifyAB.SpotifyMusic",
        "XINGAG.XING",
        "king.com.CandyCrushSodaSaga",
        "Nordcurrent.CookingFever",
        "A278AB0D.DragonMediaLegends"
    )

    ForEach ($app in $apps) {
        Get-AppXPackage $app | Remove-AppXPackage
    }
}

Function ImportTaskbar {
    $hotFixes = @("KB4093112","KB4099989")
    ForEach ($hotFix in $hotFixes) {
        $exists = (Get-Hotfix | Where {$_.HotfixID -eq $hotfix} -ErrorAction SilentlyContinue) -ne $null
        If ($exists) {
            $hf = $hotfix.Replace("KB","")
            & wusa.exe /uninstall /KB:$hf /quiet /norestart
        }
    }
    
    Import-StartLayout -LayoutPath \\$server\vt\taskbarlayout.xml -MountPath C:\
}

Function UnpinTaskbarIcons {
    Write-Output "Unpinning all Taskbar Icons..."
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Taskband" -Name "Favorites" -Type Binary -Value ([byte[]](255))
    Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Taskband" -Name "FavoritesResolve" -ErrorAction SilentlyContinue
}

Function PinTaskbarIcons {
    Function Pin2TB {
        Param (
            [Parameter(Mandatory=$true, HelpMessage="TargetItemToPin")]
            [ValidateNotNull()]
            [string]$Target
        )
        $keyPath1 = "HKCU:\SOFTWARE\Classes"
        $keyPath2 = "*"
        $keyPath3 = "shell"
        $keyPath4 = "{:}"
        $valueName = "ExplorerCommandHandler"
        $valueData = (Get-ItemProperty ("HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\" + "CommandStore\shell\Windows.taskbarpin")).ExplorerCommandHandler
        $key2 = (Get-Item $keyPath1).OpenSubKey($keyPath2, $true)
        $key3 = $key2.CreateSubKey($keyPath3, $true)
        $key4 = $key3.CreateSubKey($keyPath4, $true)
        $key4.SetValue($valueName,$valueData)

        $shell = New-Object -ComObject "Shell.Application"
        $folder = $shell.Namespace((Get-Item $Target).DirectoryName)
        $item = $folder.ParseName((Get-Item $Target).Name)
        $item.InvokeVerb("{:}")

        $key3.DeleteSubKey($keyPath4)
        If ($key3.SubKeyCount -eq 0 -and $key3.ValueCount -eq 0) {
            $key2.DeleteSubKey($keyPath3)
        }
    }

    Pin2TB explorer.exe ""
    Pin2TB explorer.exe "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\System Tools\File Explorer.lnk"
    Pin2TB "C:\Program Files (x86)\Google\Chrome\Application\chrome.exe"
    Pin2TB "C:\Program Files\Microsoft Office\root\Office16\EXCEL.EXE"
    Pin2TB "C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE"
    Pin2TB "C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE"
}

Workflow New-PCSetup {
    Param (
        [Parameter(Mandatory=$true,Position=0,ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNull()]
        [string]$domain,
        [Parameter(Mandatory=$true,Position=1,ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNull()]
        [string]$LocAdminUN = "atadmin",
        [Parameter(Mandatory=$true,Position=2,ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNull()]
        [string]$LocAdminPW = "auxeP@$$",
        [Parameter(Mandatory=$true,Position=3)]
        [ValidateNotNull()]
        [string]$server
    )
    DisableUAC
    AdjustPowerSettings
    NewUser
    SetNetworkDiscovery
    RenamePC
    Restart-Computer -Wait
    DisableTelemetry
    DisableWiFiSense
    DisableSmartScreen
    DisableWebSearch
    DisableAppSuggestions
    DisableFeedback
    DisableTailoredExperiences
    DisableAdvertisingID
    DisableCortana
    UninstallMsftBloat
    Uninstall3rdPartyBloat
    DomainJoin
    Restart-Computer -Wait
    LogonAsUser
    Restart-Computer -Wait
    ImportTaskBar
    AdjustFirewall
    SetNetworkDiscovery
    SetRemotePS
    EnableScriptHost
    EnableF8BootMenu
    DisableUpdateRestart
    EnableRemoteDesktop
    SetControlPanelSmallIcons
    DisableShortcutInName
    EnableNumLock
    ShowKnownExtensions
    DisableLogonAsUser
    Unregister-ScheduledJob -Name NewPCSetupResume
}

$adm = "atadmin"
$pwd = ConverTo-SecureString -String "auxeP@$$" -AsPlainText -Force
$wfCred = New-Object System.Management.Automation.PSCredntial($adm, $pwd)
$AtStartup = New-JobTrigger -AtStartup
Register-ScheduledJob -Name NewPCSetupResume -Credential $wfCred -Trigger $AtStartup -ScriptBlock {
    Import-Module PSWorkflow;
    Get-Job -Name NewPCSetup -State Suspended | Resume-Job
}
New-PCSetup -JobName NewPCSetup
