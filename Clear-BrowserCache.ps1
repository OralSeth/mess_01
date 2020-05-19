Function Clear-BrowserCache {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true)]
        [ValidateNotNull()]
        [ValidateSet('Chrome','Firefox','Explorer','All')]
        [string[]]$Browser,
        [Parameter(Mandatory=$false,ValueFromPipeline=$true)]
        [string[]]$Users
    )
    
    filter Get-FileSize {
        "{0:2} {1}" -f $(
            If ($_ -lt 1kb) {($_/1kb), 'Bytes'}
            ElseIf ($_ -lt 1mb) {($_/1mb), 'KB'}
            ElseIf ($_ -lt 1gb) {($_/1gb), 'MB'}
            Else {($_/1gb), 'GB'}
        )
    }
    
    If (-not $users) {
      $users = Get-ChildItem "C:\Users" | Where-Object {$_.PSIsContainer} | Select-Object @{n='Name';e={$_.BaseName}}
    }
    
    $total1 = 0
    $total2 = 0
    
    If ("Chrome" -in $Browser -or "ALL" -in $Browser) {
        $gcTotal1 = 0
        $gcTotal2 = 0
        
        ForEach ($u in $users) {
            $gcSize1 = (Get-ChildItem "C:\Users\$($u.Name)\AppData\Local\Google\Chrome\User Data\Default" -Recurse | Measure-Object -Property Length -Sum -ErrorAction SilentlyContinue).Sum
            $gcTotal1 = $gcTotal1 + $gcSize1
            $total1 = $total1 + $gcSize1
            
            Remove-Item -Path "C:\Users\$($u.Name)\AppData\Local\Google\Chrome\User Data\Default\Cache\*" -Recurse -Force -Confirm:$false -ErrorAction SilentlyContinue -Verbose
            Remove-Item -Path "C:\Users\$($u.Name)\AppData\Local\Google\Chrome\User Data\Default\Cache2\entries\*" -Recurse -Force -Confirm:$false -ErrorAction SilentlyContinue -Verbose
            Remove-Item -Path "C:\Users\$($u.Name)\AppData\Local\Google\Chrome\User Data\Default\Cookies" -Recurse -Force -Confirm:$false -ErrorAction SilentlyContinue -Verbose
            Remove-Item -Path "C:\Users\$($u.Name)\AppData\Local\Google\Chrome\User Data\Default\Media Cache" -Recurse -Force -Confirm:$false -ErrorAction SilentlyContinue -Verbose
            Remove-Item -Path "C:\Users\$($u.Name)\AppData\Local\Google\Chrome\User Data\Default\Cookies-Journal" -Recurse -Force -Confirm:$false -ErrorAction SilentlyContinue -Verbose
            Remove-Item -Path "C:\Users\$($u.Name)\AppData\Local\Google\Chrome\User Data\Default\Cookies" -Recurse -Force -Confirm:$false -ErrorAction SilentlyContinue -Verbose
    
            # Remove the '#' From in front of the following line, if you want to Remove the Chrome Write Font Cache, too
            # Remove-Item -Path "C:\Users\$($u.Name)\AppData\Local\Google\Chrome\User Data\Default\ChromeDWriteFontCache" -Recurse -Force -Confirm:$false -ErrorAction SilentlyContinue -Verbose
            
            $gcSize2 = (Get-ChildItem "C:\Users\$($u.Name)\AppData\Local\Google\Chrome\User Data\Default" -Recurse | Measure-Object -Property Length -Sum -ErrorAction SilentlyContinue).Sum
            $gcTotal2 = $gcTotal2 + $gcSize2
            $total2 = $total2 + $gcSize2
            
            $gcDiff = ($gcSize1 - $gcSize2) | Get-FileSize
            $gcBefore = $gcSize1 | Get-FileSize
            $gcAfter = $gcSize2 | Get-FileSize
            
            Write-Output "Google Cache for User: $($u.Name) WAS $($gcBefore)"
            Write-Output "Google Cache for User: $($u.Name) is NOW $($gcAfter)"
            Write-Output "Clearing the Google Cache for User: $($u.Name) Freed up $($gcDiff)"
        }
        
        $gcTotalDiff = ($gcTotal1 - $gcTotal2) | Get-FileSize
        $gcTotalBefore = $gcTotal1 | Get-FileSize
        $gcTotalAfter = $gcTotal2 | Get-FileSize
        
        Write-Output "Total Google Cache for ALL Users WAS $($gcTotalBefore)"
        Write-Output "Total Google Cache for ALL Users is NOW $($gcTotalAfter)"
        Write-Output "Clearing the Google Cache for ALL Users Freed up $($gcTotalDiff)"
    }
    
    If ("FireFox" -in $Browser -or "ALL" -in $Browser) {
        $ffTotal1 = 0
        $ffTotal2 = 0
        
        ForEach ($u in $users) {
            $defaultFolder = Get-ChildItem -Path "C:\Users\$($u.Name)\AppData\Local\Mozilla\Firefox\Profiles" | Where-Object {($_.PSIsContainer) -and ($_.BaseName -like "*.default*")} | Select-Object FullName
            $ffSize1 = (Get-ChildItem "$($defaultFolder)\cache2\entries" -Recurse | Measure-Object -Property Length -Sum -ErrorAction SilentlyContinue).Sum
            $ffTotal1 = $ffTotal1 + $ffSize1
            $total1 = $total1 + $ffSize1
            
            Remove-Item "$($defaultFolder)\cache2\entries\*" -Recurse -Force -Confirm:$false -ErrorAction SilentlyContinue -Verbose
            
            $ffSize2 = (Get-ChildItem "$($defaultFolder)\cache2\entries" -Recurse | Measure-Object -Property Length -Sum -ErrorAction SilentlyContinue).Sum
            $ffTotal2 = $ffTotal2 + $ffSize2
            $total2 = $total2 + $ffSize2
            
            $ffDiff = ($ffSize1 - $ffSize2) | Get-FileSize
            $ffBefore = $ffSize1 | Get-FileSize
            $ffAfter = $ffSize2 | Get-FileSize
            
            Write-Output "FireFox Cache for User: $($u.Name) WAS $($ffBefore)"
            Write-Output "FireFox Cache for User: $($u.Name) is NOW $($ffAfter)"
            Write-Output "Clearing the FireFox Cache for User: $($u.Name) Freed up $($ffDiff)"
        }
        
        $ffTotalDiff = ($ffTotal1 - $ffTotal2) | Get-FileSize
        $ffTotalBefore = $ffTotal1 | Get-FileSize
        $ffTotalAfter = $ffTotal2 | Get-FileSize
        
        Write-Output "Total FireFox Cache for ALL Users WAS $($ffTotalBefore)"
        Write-Output "Total FireFox Cache for ALL Users is NOW $($ffTotalAfter)"
        Write-Output "Clearing the FireFox Cache for ALL Users Freed up $($ffTotalDiff)"
    }
    
    If ("Explorer" -in $Browser -or "ALL" -in $Browser) {
        $ieTotal1 = 0
        $ieTotal2 = 0
        
        ForEach ($u in $users) {
            $tfSize1 = (Get-ChildItem "C:\Users\$($u.Name)\AppData\Local\Microsoft\Windows\Temporary Internet Files" -Recurse | Measure-Object -Property Length -Sum -ErrorAction SilentlyContinue).Sum
            $werSize1 = (Get-ChildItem "C:\Users\$($u.Name)\AppData\Local\Microsoft\Windows\WER" -Recurse | Measure-Object -Property Length -Sum -ErrorAction SilentlyContinue).Sum
            $appSize1 = (Get-ChildItem "C:\Users\$($u.Name)\AppData\Local\Temp" -Recurse | Measure-Object -Property Length -Sum -ErrorAction SilentlyContinue).Sum
            $ieSize1 = $tfSize1 + $werSize1 + $appSize1
            
            Remove-Item -Path "C:\Users\$($u.Name)\AppData\Local\Microsoft\Windows\Temporary Internet Files\*" -Recurse -Force -ErrorAction SilentlyContinue -Verbose
            Remove-Item -Path "C:\Users\$($u.Name)\AppData\Local\Microsoft\Windows\WER\*" -Recurse -Force -ErrorAction SilentlyContinue -Verbose
            Remove-Item -Path "C:\Users\$($u.Name)\AppData\Local\Temp\*" -Recurse -Force -ErrorAction SilentlyContinue -Verbose
            
            # Remove the '#' From in fron of the following line(s), if you want to Remove Temp Files and/or Recycle Bin Files, too
            # Remove-Item -Path "C:\Windows\Temp\*" -Recurse -Force -ErrorAction SilentlyContinue -Verbose
            # Remove-Item -Path "C:\`$recycle.bin\" -Recurse -Force -ErrorAction SilentlyContinue -Verbose
            
            $tfSize2 = (Get-ChildItem "C:\Users\$($u.Name)\AppData\Local\Microsoft\Windows\Temporary Internet Files" -Recurse | Measure-Object -Property Length -Sum -ErrorAction SilentlyContinue).Sum
            $werSize2 = (Get-ChildItem "C:\Users\$($u.Name)\AppData\Local\Microsoft\Windows\WER" -Recurse | Measure-Object -Property Length -Sum -ErrorAction SilentlyContinue).Sum
            $appSize2 = (Get-ChildItem "C:\Users\$($u.Name)\AppData\Local\Temp" -Recurse | Measure-Object -Property Length -Sum -ErrorAction SilentlyContinue).Sum
            $ieSize2 = $tfSize2 + $werSize2 + $appSize2
            
            $ieDiff = ($ieSize1 - $ieSize2) | Get-FileSize
            $ieBefore = $ieSize1 | Get-FileSize
            $ieAfter = $ieSize2 | Get-FileSize
            
            Write-Output "Internet Explorer Cache for User: $($u.Name) WAS $($ieBefore)"
            Write-Output "Internet Explorer Cache for User: $($u.Name) is NOW $($ieAfter)"
            Write-Output "Clearing the Internet Explorer Cache for User: $($u.Name) Freed up $($ieDiff)"
        }
        
        $ieTotalDiff = ($ieTotal1 - $ieTotal2) | Get-FileSize
        $ieTotalBefore = $ieTotal1 | Get-FileSize
        $ieTotalBefore = $ieTotal2 | Get-FileSize
        
        Write-Output "Total Internet Explorer Cache for ALL Users WAS $($ieTotalBefore)"
        Write-Output "Total Internet Explorer Cache for ALL Users is NOW $($ieTotalAfter)"
        Write-Output "Clearing the Internet Explorer Cache for ALL Users Freed up $($ieTotalDiff)"
    }
    
    $totalDiff = ($total1 - $total2) | Get-FileSize
    $totalBefore = $total1 | Get-FileSize
    $totalAfter = $total2 | Get-FileSize
    
    Write-Output "Total Browser Cache Before: $($totalBefore)"
    Write-Output "Total Browser Cache After: $($totalAfter)"
    Write-Output "Total Space Freed Up: $($totalDiff)"
}
