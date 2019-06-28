Function Test-RegistryValue {
    param(
        [Alias("PSPath")]
        [Parameter(Position = 0, Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [String]$Path
        ,
        [Parameter(Position = 1, Mandatory = $true)]
        [String]$Name
        ,
        [Switch]$PassThru
    ) 

    process {
        if (Test-Path $Path) {
            $Key = Get-Item -LiteralPath $Path
            if ($Key.GetValue($Name, $null) -ne $null) {
                if ($PassThru) {
                    Get-ItemProperty $Path $Name
                } else {
                    $true
                }
            } else {
                $false
            }
        } else {
            $false
        }
    }
}

$domains = @{
    'DSH-GM' = 'amercaredomain.local'
    'ECSDC01' = 'englishcolor-hq.com'
    'ECSGS01' = 'englishcolor-hq.com'
    'GVDDC01' = 'dentistry'
    'HLDC-001' = 'achtec'
    'LGIDC01' = 'hq.lgidallas.net'
    'NCHASQL01' = 'nationalcutting.local'
    'OSANTDC01' = 'osant.care'
    'DCSRV02' = 'srm.com'
    'EXCHSRV01' = 'srm.com'
    'FPSRV' = 'srm.com'
    'SSRV' = 'srm.com'
    'TSRV' = 'srm.com'
    'UCDC01' = 'mct.local'
    'WAREDC01' = 'warepr.local'
    'ECSBDR01' = 'englishcolor-hq.com'
    'EACBDR01' = 'eac.local'
    'EACBDR02' = 'eac.local'
    'HLBDR-001' = 'achtec'
    'NCHA-AA01' = 'nationalcutting.local'
    'I-CAT-BDR' = 'osant.care'
    'OSANTBDR01' = 'osant.care'
    'SRMBDR01' = 'srm.com'
    'TXNONSUB-BDR' = 'texnonsub.local'
}

$users = @{
    'DSH-GM' = 'msi'
    'ECSDC01' = 'administrator'
    'ECSGS01' = 'administrator'
    'GVDDC01' = 'msi'
    'HLDC-001' = 'administrator'
    'LGIDC01' = 'msi'
    'NCHASQL01' = 'administrator'
    'OSANTDC01' = 'msi'
    'DCSRV02' = 'administrator'
    'EXCHSRV01' = 'administrator'
    'FPSRV' = 'administrator'
    'SSRV' = 'administrator'
    'TSRV' = 'administrator'
    'UCDC01' = 'administrator'
    'WAREDC01' = 'msi'
    'ECSBDR01' = 'administrator'
    'EACBDR01' = 'administrator'
    'EACBDR02' = 'administrator'
    'HLBDR-001' = 'administrator'
    'NCHA-AA01' = 'administrator'
    'I-CAT-BDR' = 'msi'
    'OSANTBDR01' = 'msi'
    'SRMBDR01' = 'administrator'
    'TXNONSUB-BDR' = 'msi'
}

$pwds = @{
    'DSH-GM' = 'ismp@$$w0rd'
    'ECSDC01' = 'ec&sp@!nt810'
    'ECSGS01' = 'ec&sp@!nt810'
    'GVDDC01' = 'ismp@$$w0rd'
    'HLDC-001' = '%J7!TCcQ'
    'LGIDC01' = 'ismp@$$w0rd'
    'NCHASQL01' = '%zmGM5nR'
    'OSANTDC01' = 'ismp@$$w0rd'
    'DCSRV02' = 'Smp@$$2011'
    'EXCHSRV01' = 'Smp@$$2011'
    'FPSRV' = 'Smp@$$2011'
    'SSRV' = 'Smp@$$2011'
    'TSRV' = 'Smp@$$2011'
    'UCDC01' = 'ismp@$$'
    'WAREDC01' = 'ismp@$$w0rd'
    'ECSBDR01' = 'ec&sp@!nt810'
    'EACBDR01' = 'LWF!0sbH'
    'EACBDR02' = 'LWF!0sbH'
    'HLBDR-001' = '%J7!TCcQ'
    'NCHA-AA01' = '%zmGM5nR'
    'I-CAT-BDR' = 'ismp@$$w0rd'
    'OSANTBDR01' = 'ismp@$$w0rd'
    'SRMBDR01' = 'Smp@$$2011'
    'TXNONSUB-BDR' = 'Vb&KYM6K'
}

$domain = $domains["$($env:COMPUTERNAME)"]
$user = $users["$($env:COMPUTERNAME)"]
$password = $pwds["$($env:COMPUTERNAME)"]

Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" -Name "NextStep" -Value "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -ExecutionPolicy Unrestricted -Command “(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/OralSeth/mess_01/master/651_2.ps1') | Invoke-Expression'"

If (!(Test-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\WinLogon" -Name "AutoAdminLogon")) {
    New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\WinLogon" -Name "AutoAdminLogon" -Value "1" -PropertyType "String" -Force -Confirm:$false | Out-Null
}
Else {
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\WinLogon" -Name "AutoAdminLogon" -Value "1" -Force -Confirm:$false | Out-Null
}

Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\WinLogon" -Name "DefaultDomain" -Value "$($domain)" -Force -Confirm:$false | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\WinLogon" -Name "DefaultUserName" -Value "$($user)" -Force -Confirm:$false | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\WinLogon" -Name "DefaultPassword" -Value "$($password)" -Force -Confirm:$false | Out-Null

(New-Object Net.WebClient).DownloadFile('https://rmm.msinetworks.com/labtech/Transfer/Software/StorageCraft/ShadowProtect_SPX-6.8.2-2_x64.msi','C:\Users\Public\spx_6.8.2.msi')
(New-Object Net.WebClient).DownloadFile('https://downloads.storagecraft.com/SP_Files/ShadowProtect_SPX-6.5.2.win64.msi','C:\Users\Public\spx_6.5.2.msi')

$aList = @(
    "/i"
    ('"{0}"' -f "C:\Users\public\spx_6.5.2.msi")
    "/qn"
    "IACCEPT=STORAGECRAFT.EULA"
)

Start-Process "msiexec.exe" -ArgumentList $aList -Wait -NoNewWindow
