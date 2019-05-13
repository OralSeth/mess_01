(New-Object Net.WebClient).DownloadFile('https://rmm.msinetworks.com/labtech/Transfer/Utilities/FileZilla/client_3.42.1.exe','C:\Users\Public\fz.exe')

& cmd.exe /c "C:\Users\Public\fz.exe /S /user=All"

Remove-Item "C:\Users\Public\fz.exe" -Force -Confirm:$false | Out-Null

$obj = New-Object -ComObject WScript.Shell
$link = $obj.CreateShortcut("C:\ProgramData\Microsoft\Windows\Start Menu\Programs\FileZilla FTP Client\FileZilla.lnk")
$link.TargetPath = "C:\Program Files\FileZilla FTP Client\filezilla.exe" 
$link.Arguments = "ftp://OSANT@kjscribe:oralsurg@ftp.transcriptiongear.com"
$link.Save()

<#
If (!(Test-Path "HKU:\")) {
    New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS | Out-Null
}

$users = @{
	'10.0.1.'      = "Angela.Davis"
	'10.0.2.'      = "Marco.Solis"
	'10.0.4.'      = "Glynda.Layton"
	'10.0.15.'     = "Deyanira.Fajardo"
	'192.168.207.' = "Ashley.Perry"
}

$ip = (Get-NetIPConfiguration | Where-Object {$_.IPv4DefaultGateway -ne $null -And $_.NetAdapter.Status -ne "disconnected"}).IPv4Address.IPAddress
$ip = (([ipaddress] $ip).GetAddressBytes()[0..2] -join ".") + "."

$user = $users[$ip]

$sid = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\*' | Where-Object {$_.ProfileImagePath -like "*$user*"} | Select-Object -ExpandProperty PSChildName
$sid = $sid.Replace(' ','')

$desktop = (Get-ItemProperty -Path "HKU:\$sid\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" -Name "Desktop").Desktop
#>

$obj = New-Object -ComObject WScript.Shell
$link = $obj.CreateShortcut("C:\Users\Public\Desktop\FileZilla.lnk")
$link.TargetPath = "C:\Program Files\FileZilla FTP Client\filezilla.exe" 
$link.Arguments = "ftp://OSANT@kjscribe:oralsurg@ftp.transcriptiongear.com"
$link.Save()
