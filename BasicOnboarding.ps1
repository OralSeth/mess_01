# Disable Firewall
& cmd.exe /c "netsh advfirewall set currentprofile firewallpolicy allowinbound,allowoutbound"

# Disable UAC
& cmd.exe /c "REG ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v 'EnableLUA' /t REG_DWORD /d 0 /f"

# Enable Network Discovery
$svcs = @('dnscache','FDResPub','SSDPSRV','upnphost')

ForEach ($svc in $svcs) {
  $scvInfo = Get-Service $svc
  
  If ($svcInfo.StartType -ne 'Automatic') {
    Set-Service $svc -StartupType 'Automatic' -Confirm:$false
  }
  
  If ($svcInfo.Status -ne 'Running') {
    Start-Service $svc -Confirm:$false
  }
}

# Enable PSRemoting
<#
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

If ($pubProfs) {
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
}
#>

# Next, Turn on WINRM and Enable PSRemoting
$testWSMan = Test-WSMan -ErrorAction SilentlyContinue

If (-Not $testWSMan) {
  Enable-PSRemoting -Force -Confirm:$false
}

<#
# Adjust Power Settings
# This will check Current Settings, and Adjust as Needed

$os = (Get-WmiObject Win32_OperatingSystem).Caption
If ($os -like "*Server*") {
  [int]$add = 6
}
Else {
  [int]$add = 5
}

# Get GUID of Current Active Power Scheme
$pwrGUIDRaw = (((Get-WmiObject Win32_PowerPlan -Namespace 'root\cimv2\power' | Where {$_.IsActive -eq "true"}).InstanceID).Split("\\"))[1]
$pwrGUIDLength = $pwrGUIDRaw.Length - 2
$pwrGUID = $pwrGUIDRaw.Substring(1, $pwrGUIDLength)

# Get All Settings
$pwrSettings = powercfg -query $pwrGUID

# HDD Turn Off
For ($hdd = 0; $hdd -lt $pwrSettings.Length; $hdd++) {
  $hddLine = $pwrSettings[$hdd]
  
  If ($hddLine -like "*Turn off hard disk after*") {
    $hddIndex = $hdd
    break
  }
}

$hddRaw = $pwrSettings[$hddIndex + $add]
$hdd = $hddRaw.Substring($hddRaw.IndexOf(":")+2)

If ($hdd -ne "0x00000000") {
  powercfg -change -disk-timeout-dc 0
}

# Sleep
For ($s = 0; $s -lt $pwrSettings.Length; $s++) {
  $sLine = $pwrSettings[$s]
  If ($sLine.ToLower() -like "*sleep after*") {
    $sIndex = $s
    break
  }
}

$sleepRaw = $pwrSettings[$sIndex + $add]
$sleep = $sleepRaw.Substring($sleepRaw.IndexOf(":")+2)

If ($sleep -ne "0x00000000") {
  powercfg -change -standby-timeout-ac 0
}

# Hibernate
For ($h = 0; $h -lt $pwrSettings.Length; $h++) {
  $hLine = $pwrSettings[$h]
  If ($hLine.ToLower() -like "*hibernate after*") {
    $hIndex = $h
    break
  }
}

$hibernateRaw = $pwrSettings[$hIndex + $add]
$hibernate = $hibernateRaw.Substring($hibernateRaw.IndexOf(":")+2)

If ($hibernate -ne "0x00000000") {
  powercfg -change -hibernate-timeout-ac 0
}

# Screen Time-Out
For ($m = 0; $m -lt $pwrSettings.Length; $m++) {
  $mLine = $pwrSettings[$m]
  If ($mLine.ToLower() -like "*turn off display after*") {
    $mIndex = $m
    break
  }
}

$monitorRaw = $pwrSettings[$mIndex + $add]
$monitor = $monitorRaw.Substring($monitorRaw.IndexOf(":")+2)

If ($monitor -ne "0x00000708") {
  powercfg -change -monitor-timeout-ac 30
}
#>
