<#	
	.NOTES
	===========================================================================
	 Created with: 	SAPIEN Technologies, Inc., PowerShell Studio 2020 v5.7.172
	 Created on:   	6/5/2020 1:34 PM
	 Created by:   	shayes
	 Organization: 	
	 Filename:     	
	===========================================================================
	.DESCRIPTION
		A description of the file.
#>
$os = (Get-WmiObject Win32_OperatingSystem).Caption
$log = @()

If (!(Test-Path HKC:\))
{
	New-PSDrive -Name HKC -PSProvider Registry -Root "HKEY_CLASSES_ROOT" | Out-Null
}

$redistQuery = Get-ItemPropertyValue "HKC:\Installer\Dependencies\VC,redist.x86,x86,14.25,bundle" -Name Version -ErrorAction SilentlyContinue

If (!($redistQuery) -or ($redistQuery -notlike '14.25.*'))
{
	(New-Object Net.WebClient).DownloadFile('https://rmm.msinetworks.com/labtech/Transfer/Utilities/VCRedist/2015-19_x86.exe', 'C:\Users\Public\2015-19_x86.exe')
	& cmd.exe /c "C:\Users\Public\2015-19_x86.exe /install /quiet /norestart"
}
Else
{
	
	$log += "Visual C++ Runtime Redistributables Already Installed"
}

If ($os -like '*10*')
{
	$odbcQuery = Get-OdbcDriver -Name "MySQL ODBC 8.0 ANSI Driver" -ErrorAction SilentlyContinue
	
	If (-Not $odbcQuery)
	{
		(New-Object Net.WebClient).DownloadFile('https://rmm.msinetworks.com/labtech/Transfer/Utilities/MySQL/odbc_8.0.20_x86.msi', 'C:\Users\Public\odbc_8.0.20_x86.msi')
		& cmd.exe /c "C:\Windows\System32\msiexec.exe /i C:\Users\Public\odbc_8.0.20_x86.msi /qn /norestart"
	}
	Else
	{
		$log = "MySQL ODBC 8.0 ANSI Driver Already Installed"
	}
	
	If (-Not (Get-OdbcDsn -Name 'FaxContacts' -Platform 32-bit -DsnType System -ErrorAction SilentlyContinue))
	{
		Add-OdbcDsn -Name "FaxContacts" -Platform '32-bit' -DsnType System -DriverName "MySQL ODBC 8.0.20 ANSI Driver" -SetPropertyValue @('Server=10.0.100.9', 'Port=3306', 'Database=faxContactsDB')
		New-ItemProperty -Path HKLM:\SOFTWARE\WOW6432Node\ODBC\ODBC.INI\FaxContacts -PropertyType String -Name UID -Value 'FaxUser'
		New-ItemProperty -Path HKLM:\SOFTWARE\WOW6432Node\ODBC\ODBC.INI\FaxContacts -PropertyType String -Name PWD -Value 'fax!'
	}
	Else
	{
		$log += "'FaxContacts' ODBC Data Source Name Already Exists"
	}
}
ElseIf ($os -like '*7*')
{
	$odbcQuery = Get-ItemPropertyValue "HKLM:\SOFTWARE\WOW6432Node\ODBC\ODBCINST.INI\ODBC Drivers" -Name "MySQL ODBC 8.0 ANSI Driver" -ErrorAction SilentlyContinue
	
	If (-Not $odbcQuery)
	{
		(New-Object Net.WebClient).DownloadFile('https://rmm.msinetworks.com/labtech/Transfer/Utilities/MySQL/odbc_8.0.20_x86.msi', 'C:\Users\Public\odbc_8.0.20_x86.msi')
		& cmd.exe /c "C:\Windows\System32\msiexec.exe /i C:\Users\Public\odbc_8.0.20_x86.msi /qn /norestart"
	}
	Else
	{
		$log = "MySQL ODBC 8.0 ANSI Driver Already Installed"
	}
	
	If (!(Test-Path "HKLM:\SOFTWARE\WOW6432Node\ODBC\ODBC.INI\FaxContacts"))
	{
		New-Item -Path "HKLM:\SOFTWARE\WOW6432Node\ODBC\ODBC.INI" -Name 'FaxContacts' | Out-Null
		
		$driver = Get-ItemPropertyValue 'HKLM:\SOFTWARE\Wow6432Node\ODBC\ODBCINST.INI\MySQL ODBC 8.0 ANSI Driver' -Name Driver -Er
		
		New-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\ODBC\ODBC.INI\FaxContacts" -Name 'DATABASE' -PropertyType String -Value "faxContactsDB" -Force | Out-Null
		New-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\ODBC\ODBC.INI\FaxContacts" -Name 'Driver' -PropertyType String -Value "$($driver)" -Force | Out-Null
		New-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\ODBC\ODBC.INI\FaxContacts" -Name 'PORT' -PropertyType String -Value "3306" -Force | Out-Null
		New-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\ODBC\ODBC.INI\FaxContacts" -Name 'PWD' -PropertyType String -Value 'fax!' -Force | Out-Null
		New-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\ODBC\ODBC.INI\FaxContacts" -Name 'SERVER' -PropertyType String -Value '10.0.100.9' -Force | Out-Null
		New-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\ODBC\ODBC.INI\FaxContacts" -Name 'UID' -PropertyType String -Value 'FaxUser' -Force | Out-Null
		
		New-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\ODBC\ODBC.INI\ODBC Data Sources" -Name "FaxContacts" -PropertyType String -Value "MySQL ODBC 8.0 ANSI Driver" -Force | Out-Null
	}
	Else
	{
		$log += "'FaxContacts' ODBC Data Source Name Already Exists"
	}
	
	$log | Out-File C:\Users\Public\ODBC_Log.txt
}
