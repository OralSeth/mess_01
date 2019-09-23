Function Test-RegistryValue {
  Param(
    [Alias("PSPath")]
    [Parameter(Position=0,Mandatory=$true,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)]
    [string]$Path,
    [Parameter(Position=1,Mandatory=$true)]
    [string]$Name,
    [switch]$PassThru
  )
            
  Process {
    If (Test-Path $Path) {
      $Key = Get-Item -LiteralPath $Path
      If ($null -ne $Key.GetValue($Name, $null)) {
        If ($PassThru) {
          Get-ItemProperty $Path $Name
        }
        Else {
          $true
        }
      }
      Else {
        $false
      }
    }
    Else {
      $false
    }
  }
}
If (!(Test-RegistryValue -Path "HKLM:\SOFTWARE\Wow6432Node\PracticeWorks\WinOMS CS\IMAGES" -Name "PATH")) {
  New-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\PracticeWorks\WinOMS CS\IMAGES" -Name 'PATH' -PropertyType String -Value '\\10.75.1.14\mdcs\IMAGES' -Force -Confirm:$false | Out-Null
}
Else {
  Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\PracticeWorks\WinOMS CS\IMAGES" -Name 'PATH' -Value '\\10.75.1.14\mdcs\IMAGES'
}
If (!(Test-RegistryValue -Path "HKLM:\SOFTWARE\Wow6432Node\PracticeWorks\image\Database" -Name "ServerName")) {
  New-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\PracticeWorks\image\Database" -Name 'ServerName' -PropertyType String -Value '10.75.1.14\ORSQLEXP' -Force -Confirm:$false | Out-Null
}
Else {
  Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\PracticeWorks\image\Database" -Name 'ServerName' -Value '10.75.1.14\ORSQLEXP'
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\PracticeWorks\image" -Name 'Path' -Value '\\10.75.1.14\oms\image\pwimage'
Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\PracticeWorks\image" -Name 'ServerPath' -Value '\\10.75.1.14\oms\image\pwimage'
Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\ODBC\ODBC.INI\mdcs" -Name 'CommLinks' -Value 'TCPIP{host=10.75.1.14}'
Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\PWInc\WINOMSCS" -Name 'ServerExeDir' -Value '\\10.75.1.14\mdcs\MDCSRegistered'
Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\PWInc\PWSvr" -Name 'PWSvrDir' -Value '\\10.75.1.14\mdcs\PWSvr'
Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\PWInc\CS OMS Imaging" -Name 'ServerExeDir' -Value '\\10.75.1.14\oms\image\pwimage'

If (!(Test-Path HKU:)) {
  New-PSDrive -PSProvider Registry -Name HKU -Root HKEY_USERS | Out-Null
}

$SIDs = (Get-ChildItem -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList" | Where-Object {$_.Name -like '*S-1-5-21-*'} | Select-Object Name).Name

ForEach ($sid in $SIDS) { 
  $id = $sid.Split('\')[6]
  $path = "HKU:\$id\Software\PracticeWorks\Image"

  If (Test-Path $path) {
    Set-ItemProperty -Path $path -Name 'Path' -Value '\\10.75.1.14\oms\image\pwimage'
  }
}

$erx = Get-WmiObject Win32_Product | Where-Object {$_.Name -eq "ePrescriptions" }
If ($null -eq $erx) {
  (New-Object Net.WebClient).DownloadFile('https://rmm.msinetworks.com/labtech/Transfer/Software/WinOMS/eRX/erxSetup.msi','C:\Users\Public\erxSetup.msi')
  $msiArgs = @(
    "/i",
    ("{0}" -f "C:\Users\Public\erxSetup.msi"),
    "/qn",
    "/norestart"
  )
  Start-Process "msiexec.exe" -ArgumentList $msiArgs -Wait -NoNewWindow
}
