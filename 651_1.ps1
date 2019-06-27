Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" -Name "NextStep" -Value "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -ExecutionPolicy Unrestricted -Command '(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/OralSeth/mess_01/master/651_2.ps1') | Invoke-Expression'"

(New-Object Net.WebClient).DownloadFile('https://rmm.msinetworks.com/labtech/Transfer/Software/StorageCraft/ShadowProtect_SPX-6.8.2-2_x64.msi','C:\Users\Public\spx_6.8.2.msi')
(New-Object Net.WebClient).DownloadFile('https://downloads.storagecraft.com/SP_Files/ShadowProtect_SPX-6.5.2.win64.msi','C:\Users\Public\spx_6.5.2.msi')

$args = @(
    "/i"
    ('"{0}"' -f "C:\Users\public\spx_6.5.2.msi")
    "/qn"
    "IACCEPT=STORAGECRAFT.EULA"
)

Start-Process "msiexec.exe" -ArgumentList $args -Wait -NoNewWindow
