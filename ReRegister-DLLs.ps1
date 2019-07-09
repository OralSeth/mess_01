$dlls = @()
$dllNames = @("ATL","comsvcs","credui","CRYPTNET","CRYPTUI","dhcpqec","dssenh","eapec","esscli","FastProx","FirewallAPI","kmsvc","lsmproxy","MSCTF","msi","msxml3","ncprov","ole32","OLEACC","OLEAUT32","PROPSYS","QAgent","qagentrt","QUtil","raschap","RASQEC","rastls","repdrvfs","RPCRT4","rsaenh","SHELL32","shsvcs","swprv","tschannel","USERENV","vss_ps","wbemcons","wbemcore","wbemess","wbemsvc","WINHTTP","WINTRUST","wmiprvsd","wmisvc","wmiutils","wuaueng")
$baseNames = @()

ForEach ($dllName in $dllNames) {
    $dn = "$dllName.DLL"
    $baseNames += "$($dn)"
}

ForEach ($bn in $baseNames) {
    $dlls += Get-ChildItem C:\Windows\System32 -Recurse -ErrorAction SilentlyContinue | Where-Object {$_.Name -eq "$($bn)"}
}


$svcs = @("SENS","BITS","EventSystem","swprv","VSS")
ForEach ($svc in $svcs) {
    Stop-Service $svc -Force -Confirm:$false
}

ForEach ($dll in $dlls) {
    If ($dll.Name -eq "swprv.DLL") {
        cmd.exe /c "regsvr32 /s /i $($dll.FullName)"
    }
    Else {
        cmd.exe /c "regsvr32 /s $($dll.FullName)"
    }
}

$scans = @("catsrv.DLL","catsrvut.DLL","CLBCatQ.DLL")

$scans | % { cmd.exe /c "sfc /SCANFILE=C:\Windows\System32\$($_)" }

Start-Service EventSystem -Confirm:$false

Write-Output "DLL's have been re-registered.  If problems persist, a reboot may be required."
