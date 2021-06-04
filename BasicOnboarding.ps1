# Disable Firewall
& cmd.exe /c "netsh advfirewall set currentprofile firewallpolicy allowinbound,allowoutbound"

# Disable UAC
& cmd.exe /c "REG ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v "EnableLUA" /t REG_DWORD /d 0 /f"

# Enable Network Discovery
$svcs = @('dnscache','FDResPub','SSDPSRV','upnphost')

ForEach ($svc in $svcs) {
  $scvInfo = Get-Service $svc
  
  If ($svcInfo.StartType -ne 'Automatic') {
    Set-Service $svc -StartupType 'Automatic' -Force -Confirm:$false
  }
  
  If ($svcInfo.Status -ne 'Running') {
    Start-Service $svc -Confirm:$false
  }
}

# Enable PSRemoting
# First, Convert 'Public' Network Profiles to 'Private'
Function Get-NetConnectionProfile {
  $nlmType = [Type]::GetTypeFromCLSID('DCB00C01-570F-4A9B-8D69-199FDBA5723B')
  $networkListManager = [Activator]::CreateInstance($nlmType)

  $categories = @{
    0 = "Public"
    1 = "Private"
    2 = "Domain"
  }

  $Networks = $NetworkListManager.GetNetworks(1)
 
  ForEach ($network in $Networks) {
       
    New-Object -TypeName PSObject -Property @{
      Category = $Categories[($Network.GetCategory())]
      Description = $Network.GetDescription()
      Name = $Network.GetName()
      IsConnected = $Network.IsConnected
      IsConnectedToInternet = $Network.IsConnectedToInternet
    }
  }
}

$pubProfs = Get-NetConnectionProfile | Where-Object {$_.Category -eq "Public"}

ForEach ($network in $pubProfs) {
  $nlmType = [Type]::GetTypeFromCLSID('DCB00C01-570F-4A9B-8D69-199FDBA5723B')
  $networkListManager = [Activator]::CreateInstance($nlmType)
   
  $Categories = @{
    'Public' = 0x00
    'Private' = 0x01
    'Domain' = 0x02
  }

  $name = $Network.Name
  $cat = "Private"

  $allNetworks = $networkListManager.GetNetworks(1) 
  $network = $allNetworks | Where-Object {$_.GetName() -eq $Name}

  $network.SetCategory($Categories[$cat])
}

# Next, Turn on WINRM and Enable PSRemoting
Enable-PSRemoting -Force -Confirm:$false

# Adjust Power Settings
powercfg -change -monitor-timeout-ac 30
powercfg -change -disk-timeout-ac 0
powercfg -change -hibernate-timeout-ac 0
powercfg -change -standby-timeout-ac 0
