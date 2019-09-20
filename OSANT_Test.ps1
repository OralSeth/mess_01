If (Test-RegistryValue -Path "HKLM:\SOFTWARE\Wow6432Node\PracticeWorks\WinOMS CS\IMAGES" -Name "PATH") {
  Get-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\PracticeWorks\WinOMS CS\IMAGES" -Name 'PATH'
}
If (Test-RegistryValue -Path "HKLM:\SOFTWARE\Wow6432Node\PracticeWorks\image\Database" -Name "ServerName") {
  Get-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\PracticeWorks\image\Database" -Name 'ServerName'
}
Get-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\PracticeWorks\image" -Name 'Path'
Get-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\PracticeWorks\image" -Name 'ServerPath'
Get-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\ODBC\ODBC.INI\mdcs" -Name 'CommLinks'
Get-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\PWInc\WINOMSCS" -Name 'ServerExeDir'
Get-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\PWInc\PWSvr" -Name 'PWSvrDir'
Get-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\PWInc\CS OMS Imaging" -Name 'ServerExeDir'
