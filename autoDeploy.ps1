$global:os = (Get-WmiObject Win32_OperatingSystem | Select-Object Caption).Caption
$global:bitVer = (Get-WmiObject Win32_OperatingSystem | Select-Object OSArchitecture).OSArchitecture
$global:delete = @()
$global:pins = @()
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

Function Download-File {
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

Function Extract-Zip($file, $destination) {
	$shell = New-Object -ComObject shell.Application
	$zip = $shell.Namespace($file)
	ForEach ($item in $zip.items()) {
		$shell.Namespace($destination).copyhere($item)
	}
}

Function IsInstalled($program) {
	$split = $program.split(" ")
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

Function Create-Shortcut {
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
	
	$shell = New-Object -ComObject ("WScript.Shell")
	$sc = $shell.CreateShortcut($folder)
	$sc.TargetPath = $exe
	$sc.Arguments = $args
	$sc.IconLocation = "$icoLoc, $icoPos"
	$sc.Save()
}
	
Function Desktop-Shortcuts {
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory=$true,Position=0,ValueFromPipelineByPropertyName=$true)]
		[ValidateNotNull()]
		[string]$ConnectionName,
		[Parameter(Mandatory=$true,Position=0,ValueFromPipelineByPropertyName=$true)]
		[ValidateNotNull()]
		[string]$user,
		[Parameter(Mandatory=$true,Position=0,ValueFromPipelineByPropertyName=$true)]
		[ValidateNotNull()]
		[Alias("pass")]
		[string]$password,
		[Parameter(Mandatory=$true,Position=0,ValueFromPipelineByPropertyName=$true)]
		[ValidateNotNull()]
		[string]$downloadPath
	)
	
	Get-ChildItem -Path "C:\Users\$user\Desktop" | Where-Object {$_.Name -like "*.lnk"} | Remove-Item -Force -Confirm:$false
	
	$dlPath1 = $downloadPath + "/icon_calc.ico"
	$dlPath2 = $downloadPath + "/icon_note.ico"
	
	Download-File -from $dlPath1 -to "C:\Windows\System32"
	Download-File -from $dlPath2 -to "C:\Windows\System32"
	
	Create-Shortcut -exe "C:\Windows\explorer.exe" -folder "C:\Users\$user\Desktop\Calculator.lnk" -args "shell:AppsFolder\Microsoft.WindowsCalculator_8wekyb3d8bbwe!App" -icoLoc "C:\Windows\System32\icon_calc.ico"
    Create-Shortcut -exe "C:\Windows\explorer.exe" -folder "C:\Users\$user\Desktop\Microsoft Edge.lnk" -args "shell:AppsFolder\Microsoft.MicrosoftEdge_8wekyb3d8bbwe!MicrosoftEdge" -icoLoc "C:\Windows\SystemApps\Microsoft.MicrosoftEdge_8wekyb3d8bbwe\MicrosoftEdge.exe"
    Create-Shortcut -exe "C:\Windows\explorer.exe" -folder "C:\Users\$user\Desktop\Sticky Notes.lnk" -args "shell:AppsFolder\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe!App" -icoLoc "C:\Windows\System32\icon_note.ico"
    Create-Shortcut -exe "C:\Windows\explorer.exe" -folder "C:\Users\$user\Desktop\Network.lnk" -args "::{7007ACC7-3202-11D1-AAD2-00805FC1270E}" -icoLoc "C:\Windows\System32\SHELL32.dll" -icoIndex "17"
    Create-Shortcut -exe "C:\Windows\explorer.exe" -folder "C:\Users\$user\Desktop\This PC.lnk" -args "shell:::{20D04FE0-3AEA-1069-A2D8-08002B30309D}" -icoLoc "C:\Windows\System32\SHELL32.dll" -icoIndex "15"
    Create-Shortcut -exe "C:\Users\$user\AppData\Local\HawkSoft\CMS\Program\HawkSoftCMS.exe" -folder "C:\Users\$user\Desktop\Client Management System.lnk"
    Create-Shortcut -exe "S:\" -folder "C:\Users\$user\Desktop\data (SERVER) (S).lnk"
    Create-Shortcut -exe "C:\Program Files (x86)\Microsoft Office\root\Office16\EXCEL.EXE" -folder "C:\Users\$user\Desktop\Excel.lnk"
    Create-Shortcut -exe "C:\Program Files (x86)\Microsoft Office\root\Office16\OUTLOOK.EXE" -folder "C:\Users\$user\Desktop\Outlook.lnk"
    Create-Shortcut -exe "C:\Program Files (x86)\Microsoft Office\root\Office16\POWERPNT.EXE" -folder "C:\Users\$user\Desktop\PowerPoint.lnk"
    Create-Shortcut -exe "C:\Windows\system32\SnippingTool.exe" -folder "C:\Users\$user\Desktop\Snipping Tool.lnk"
    Create-Shortcut -exe "C:\Program Files\SonicWall\Global VPN Client\SWGVC.exe" -folder "C:\Users\$user\Desktop\SonicWALL Global VPN Client.lnk" -args "/E `"$ConnectionName`" /U $user /P $pass"
    Create-Shortcut -exe "C:\Program Files (x86)\Microsoft Office\root\Office16\WINWORD.EXE" -folder "C:\Users\$user\Desktop\Word.lnk"
    Create-Shortcut -exe "C:\Program Files (x86)\Google\Chrome\Application\chrome.exe" -folder "C:\Users\$user\Desktop\Google Chrome.lnk"
    Create-Shortcut -exe "C:\Program Files (x86)\WinDirStat\windirstat.exe" -folder "C:\Users\$user\Desktop\WinDirStat.lnk"
    Create-Shortcut -exe "C:\Program Files (x86)\Adobe\Acrobat Reader DC\Reader\AcroRd32.exe" -folder "C:\Users\$user\Desktop\Acrobat Reader DC.lnk"
}

Function New-User {
	Param (
		[Parameter(Mandatory=$true,Position=0,ValueFromPipelineByPropertyName=$true)]
		[ValidateNotNull()]
		[string]$NewUser,
		[Parameter(Mandatory=$true,Position=1,ValueFromPipelineByPropertyName=$true)]
		[ValidateNotNull()]
		[string]$NewPassword
	)
	
	New-LocalUser $NewUser -Password ($NewPassword | ConvertTo-SecureString -AsPlainText -Force)
	Add-LocalGroupMember -Group "Administrators" -Member $NewUser
}

Function Rename-PC {
	Param (
		[Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)]
		[ValidateNotNull()]
		[string]$NewPCName
	)
	
	$PCName = $env:COMPUTERNAME
	
	Rename-Computer -ComputerName $PCName -NewName $NewPCName -Force -Confirm:$false -Restart
}

If ($global:renamePC) {
	Rename-PC
}

Function Adjust-PowerSettings {
	$powerPlan = Get-WmiObject -Namespace root\cimv2\power -Class Win32_PowerPlan -Filter "ElementName = 'High Performance'"
	$powerPlan.Activate()
	
	powercfg -change -monitor-timeout-ac 0
	powercfg -change -disk-timeout-ac 0
	powercfg -change -hibernate-timeout-ac 0
	powercfg -change -standby-timeout-ac 0
}

Function Disable-UAC {
	$UACReg = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
	
	If ($global:os -like "*Windows 10*") {
		New-ItemProperty -Path $UACReg -Name "EnableLUA" -Value "1" -PropertyType DWORD -Force | Out-Null
		New-ItemProperty -Path $UACReg -Name "ConsentPromptBehaviorAdmin" -Value "0" -PropertyType DWORD -Force | Out-Null
		New-ItemProperty -Path $UACReg -Name "PromptOnSecureDesktop" -Value "0" -PropertyType DWORD -Force | Out-Null
	}
	ElseIf ($global:os -like "*Windows 7*") {
		New-ItemProperty -Path $UACReg -Name "EnableLUA" -Value "0" -PropertyType DWORD -Force | Out-Null
	}
}

New-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\CloudContent -Name "DisableWindowsConsumerFeatures" -Value "1" -PropertyType DWORD -Force | Out-Null

Function Unpin-TaskbarApps {
	Param (
		[string]$app
	)
	
	try {
		((New-Object -Com Shell.Application).Namespace('shell:::{4234d49b-0245-4df3-b780-3893943456e1}').Items() | Where-Object {$_.Name -eq $app}).Verbs() | Where-Object {$_.Name.Replace('&','') -match 'From "Taskbar" UnPin | Unpin from Taskbar'} | % {$_.DoIt()}
		return "App $app unpinned from Taskbar"
}
