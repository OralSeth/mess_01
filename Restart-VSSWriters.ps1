function Get-VSSWriters {
    [CmdletBinding()]

    $vssWriters = vssadmin list writers

    $RegEx = "writer name: '(.*?)'\r\n.*?writer id: (.*?)\r\n.*?writer instance id: (.*?)\r\n.*?state: (.*?)\r\n.*?last error:(.*)"

    $headers = @(
        'WriterName'
        'WriterID'
        'WriterInstanceID'
        'State'
        'LastError'
    )

    $VSSs = ($vssWriters | Out-String) -split "`r`n`r`n" | Select-Object -Skip 1

    $Data = $VSSs -Replace $regEx, '$1,$2,$3,$4,$5' | Out-String

    $vssObjects = (($headers -Join ','), $Data) -join "`r`n" | ConvertFrom-cSV

    $VSSObjects
}

$writerSVC = @{
    'ASR Writer' = "VSS"
    'BITS Writer' = "BITS"
    'Certificate Authority' = "CertSvc"
    'COM+ REGDB Writer' = "VSS"
    'DFS Replication Service Writer' = "DFSR"
    'DHCP Jet Writer' = "DHCPServer"
    'FRS Writer' = "NtFrs"
    'FSRM Writer' = "srmsvc"
    'IIS Config Writer' = "AppHostSvc"
    'IIS Metabase Writer' = "IISADMIN"
    'Microsoft Exchange Replica Writer' = "MSExchangeRepl"
    'Microsoft Exchange Writer' = "MSExchangeIS"
    'MSMQ Writer (MSMQ)' = "MSMQ"
    'MSSearch Service Writer' = "WSearch"
    'NTDS' = "NTDS"
    'OSearch VSS Writer' = "OSearch"
    'Registry Writer' = "VSS"
    'Shadow Copy Optimization Writer' = "VSS"
    'SPSearch VSS Writer' = "SPSearch"
    'SqlServerWriter' = "SQLWriter"
    'System Writer' = "CryptSvc"
    'TermServLicensing' = "TermServLicensing"
    'WINS Jet Writer' = "WINS"
    'WMI Writer' = "Winmgmt"
}

$failed = Get-VSSWriters | Where {$_.LastError -ne "No Error"}

$SVCs = @()

ForEach ($f in $failed) {
    $writer = $f.WriterName
    $SVCs += $writerSVC["$($writer)"]
}

$restart = $SVCs | Select -Unique

ForEach ($r in $restart) {
    $svc = Get-Service $r
    
    If ($svc.Status -ne "Stopped") {
        Stop-Service $r -Force -Confirm:$false
    }

    Start-Service $r -Confirm:$false
}
