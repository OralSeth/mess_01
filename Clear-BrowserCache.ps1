[CmdletBinding()]
Param (
    [Parameter(Mandatory=$true)]
    [ValidateNotNull()]
    [ValidateSet('Chrome','Firefox','Explorer','All')]
    [string[]]$Browser,
    [Parameter(Mandatory=$false,ValueFromPipeline=$true)]
    [string[]]$Users
)

If (-not $users) {
  $users = Get-ChildItem "C:\Users" | Where-Object {$_.PSIsContainer} | Select-Object @{n='Name';e={$_.BaseName}}
}

If ("Chrome" -in $Browser -or "ALL" -in $Browser) {
    ForEach ($u in $users) {
        Remove-Item -Path "C:\Users\$($u.Name)\AppData\Local\Google\Chrome\User Data\Default\Cache\*" -Recurse -Force -Confirm:$false -ErrorAction SilentlyContinue -Verbose
        Remove-Item -Path "C:\Users\$($u.Name)\AppData\Local\Google\Chrome\User Data\Default\Cache2\entries\*" -Recurse -Force -Confirm:$false -ErrorAction SilentlyContinue -Verbose
        Remove-Item -Path "C:\Users\$($u.Name)\AppData\Local\Google\Chrome\User Data\Default\Cookies" -Recurse -Force -Confirm:$false -ErrorAction SilentlyContinue -Verbose
        Remove-Item -Path "C:\Users\$($u.Name)\AppData\Local\Google\Chrome\User Data\Default\Media Cache" -Recurse -Force -Confirm:$false -ErrorAction SilentlyContinue -Verbose
        Remove-Item -Path "C:\Users\$($u.Name)\AppData\Local\Google\Chrome\User Data\Default\Cookies-Journal" -Recurse -Force -Confirm:$false -ErrorAction SilentlyContinue -Verbose
        Remove-Item -Path "C:\Users\$($u.Name)\AppData\Local\Google\Chrome\User Data\Default\Cookies" -Recurse -Force -Confirm:$false -ErrorAction SilentlyContinue -Verbose

        # Remove the '#' From in front of the following line, if you want to Remove the Chrome Write Font Cache, too
        # Remove-Item -Path "C:\Users\$($u.Name)\AppData\Local\Google\Chrome\User Data\Default\ChromeDWriteFontCache" -Recurse -Force -Confirm:$false -ErrorAction SilentlyContinue -Verbose
    }
}

If ("FireFox" -in $Browser -or "ALL" -in $Browser) {
    ForEach ($u in $users) {
        $defaultFolder = Get-ChildItem -Path "C:\Users\$($u.Name)\AppData\Local\Mozilla\Firefox\Profiles" | Where-Object {($_.PSIsContainer) -and ($_.BaseName -like "*.default*")}
        Remove-Item "$($defaultFolder)\cache2\entries\*" -Recurse -Force -Confirm:$false -ErrorAction SilentlyContinue -Verbose
    }
}

If ("Explorer" -in $Browser -or "ALL" -in $Browser) {
    ForEach ($u in $users) {
        Remove-Item -Path "C:\Users\$($u.Name)\AppData\Local\Microsoft\Windows\Temporary Internet Files\*" -Recurse -Force -ErrorAction SilentlyContinue -Verbose
        Remove-Item -Path "C:\Users\$($u.Name)\AppData\Local\Microsoft\Windows\WER\*" -Recurse -Force -ErrorAction SilentlyContinue -Verbose
        Remove-Item -Path "C:\Users\$($u.Name)\AppData\Local\Temp\*" -Recurse -Force -ErrorAction SilentlyContinue -Verbose
        
        # Remove the '#' From in fron of the following line(s), if you want to Remove Temp Files and/or Recycle Bin Files, too
        # Remove-Item -Path "C:\Windows\Temp\*" -Recurse -Force -ErrorAction SilentlyContinue -Verbose
        # Remove-Item -Path "C:\`$recycle.bin\" -Recurse -Force -ErrorAction SilentlyContinue -Verbose
    }
}
