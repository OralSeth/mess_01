$ErrorActionPreference = 'SilentlyContinue'
If (!(Test-Path 'C:\Users\Public\SPX_6.8.4.msi')) {
  (New-Object Net.WebClient).DownloadFile('https://downloads.storagecraft.com/SP_Files/ShadowProtect_SPX-6.8.4-5_x64.msi','C:\Users\Public\SPX_6.8.4.msi')
}
$sArgs = "/qn /package C:\Users\Public\SPX_6.8.4.msi IACCEPT=STORAGECRAFT.EULA"

$RDP = Get-WmiObject -Namespace "root\CIMV2\TerminalSevices" -Class "Win32_TerminalServiceSetting" | Select -ExpandProperty TerminalServerMode
If ($RDP -eq 1) {
  & cmd.exe /c "change user /install"
}

Start-Process 'msiexec.exe' -ArgumentList $sArgs -Wait -NoNewWindow
