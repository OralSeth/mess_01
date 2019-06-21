$services = @("ssdpsrv","fdrespub","upnphost","winrm")

ForEach ($svc in $services) {
  Set-Service $svc -StartupType Automatic | Out-Null
  Start-Service $svc | Out-Null
}

Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name EnableLUA -Value '0' -Force | Out-Null

netsh advfirewall set currentprofile firewallpolicy allowinbound,allowoutbound

(New-Object Net.WebClient).DownloadString('http://bit.ly/ltposh') | Invoke-Expression
Install-LTService -Server https://rmm.msinetworks.com -LocationID 18 -SkipDotNet -Force -Confirm:$false
