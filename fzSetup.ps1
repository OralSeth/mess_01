(New-Object Net.WebClient).DownloadFile('https://rmm.msinetworks.com/labtech/Transfer/Utilities/FileZilla/client_3.42.1.exe','C:\Users\Public\fz.exe')

& cmd.exe /c "C:\Users\Public\fz.exe /S /user=All"

Remove-Item "C:\Users\Public\fz.exe" -Force -Confirm:$false | Out-Null

$obj = New-Object -ComObject WScript.Shell
$link = $obj.CreateShortcut("C:\ProgramData\Microsoft\Windows\Start Menu\Programs\FileZilla FTP Client\FileZilla.lnk")
$link.TargetPath = "C:\Program Files\FileZilla FTP Client\filezilla.exe" 
$link.Arguments = "ftp://OSANT@kjscribe:oralsurg@ftp.transcriptiongear.com"
$link.Save()

$obj = New-Object -ComObject WScript.Shell
$link = $obj.CreateShortcut("C:\Users\Public\Desktop\FileZilla.lnk")
$link.TargetPath = "C:\Program Files\FileZilla FTP Client\filezilla.exe" 
$link.Arguments = "ftp://OSANT@kjscribe:oralsurg@ftp.transcriptiongear.com"
$link.Save()
