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

$pcKeys = @{
    "BELTONDOCPC02" = "0/w6CKjJG9pq2iShpp+rxEblP7D6UboSk6HqLwJabzIqxwz2c4SmxFivrnLrpSl63eH/mMBbMwYR3tOdogT7sOq33jOHQcQbcHYhCeBvJj//eMOpXLThlD0dmfRAt23urYK9e8XhwluQMZeadUSTh9VxAPLVQBCmZx5ThhyRMyVs="
    "OMSA35"        = "0+lsb2pYO7L1HI1pQA7KDQPHptUGNnrpxvWzcgNQ39/STHn2tZNeRdidpgTyBdFiHBm5aAF/zu/XE0g0d76oVsQmtljJko2W3aFzP8D4qllqCFS0XGzTU/I7ExVZOxOy9k8YMEKWwnkr1OIFLIJWdp/JzwEoNALutZhvdkb4bAUs="
    "WOS01"         = "032XuIVfcCTwmq25Wx6v2Gmr3NqCjFf3Bv7Yn8o+5Pj1rFWJyUvz9VOQh1zCdghKq8MKOVq9U8++oD2oYa+oH+YpFc9rv44G+HM44W8n/0tXtG3Gu1Q0KPBjp4zOpPW0SxMUM7NeWZnGs3MRB0bwXtL2rsxN4qm52yQ2oNeAynDo="
    "WOS02"         = "0zOX5BL+ONtAJSEWlEYX96cYCQGDKiE0qK3Z9+ZKR4JlbbbvQMONAK3n6AKlm4TXSY4MTR/FpemBZjXqeE2Y1C9q2UZTEbTNGugn8L1s7ojaIlGNwldTc5FUj8YCxmyuPU1DX5HJ6qI8lGuBBGR3vT4bSVIMlQW6e415rJ6cbLRc="
    "WOS03"         = "0Lt+Jrf53F0F1A83aT+olznwo2RYiNbYN1w2aBErdsiAco9dndJ//vXHBQcTcPhu2jubElupCr233zC9sym8HE7SaxCWHbyjDdBGlh5yJCrNvVofmj57p9k3L+xKMwvrWF69upyD8Oa01p8d78f+4qSxqHrRErxr36mquz/fH0kg="
    "WOS04"         = "0GtueC0qQLKkiYQ+h+dbk9gHhHZg0WQGBDLi0MoO0RhP2Z/NxAHBSOOwygVt9FWHN+z0r1UVoxJe9cUIP9KJfCW7tl0O96srLZEUpFjKgbPdclMP6xqXgLdnAXDw1rgcTAYV+lahBAi7NWGhTNCUtwY9dxRWzdMjypll5kFYNCHM="
    "WOSE1"         = "0MzbMaJ68LLU2krqSfLzuwz9/2Qm1yECltTRvrhhgHxdvc51fJN7B1gK8W7Pa6/ZcQl6aib2UDTBM7nfv+tu3bJkVBk3rOTHbpbQE4oB1Qj1zb7XHMcg2bI0EP6PQDrmAc+eBTJnoHz4P70OsTRFnIRnzsPauvRXjqwon7pDgu0I="
    "WOS05"         = "0V3slywLrL4RE9FsgyclL4c+MJtkkA8IUlsCCO9HDG9SZHRa0hEjgHF5F8whRatK294tn4rD7x7S3WhiYzbfh+cvnRLyFmP1nkyW817FDrfakXcTTpS0+/Fse1OY4e8cC11aiHwpRUeQqoOyAN/8S+ltDiRvwdhSW5QiDfnHwDQw="
    "WOSLT1"        = "0BWOEzaeBi8xO3LcaaoUV1q+KgmpEuhYdrXhwXRmQuOwNtoFOYBxFLeRU/Qrrh3SE6h9NiDkl1IF2d7asktqWkbQKGfrmFWbjbIHP3ZTEbp8JkHTtHybF0e2uHmxBgj8hjn2wURzR9cxkl1+9Ag89SgzOwSAEdE8d8zRWeEMVjyU="
    "WOSLT2"        = "0zr5H6aRJ9z53QPE/oWxJ+eAhV+mdiQml/LawYGuocof7Iz6p2/00VW/MmeDKjPENzipcodvMHSWr5wuTgcg3wPep31THd36fGLRnz8bn2L+QTS+FgE14bs+2RGWY3zsEG8sgLPM0a+4YKnq0DUA2ot7V3R+rP4hAdZX7CY6a7yY="
    "WOSLT3"        = "08sSUUBfGHUgGvqaKaCOutFEcGLh9NK1GbaTw2WGdGydA/w6IZmucNS71f9ulm/+HDwa7qeL+oyYUbXmCFeL+Xy5EEobjNPxP9R/6Z8uZktVYPAqiu9BzIbtzZWuyGWdt8Za7U2dRXSWOr0VyNrukule+AQaPidefRhpzqIUH0mQ="
    "WOSLT4"        = "07WxLdeb0s+5U8ZCri5QYZ1RA5OUD0URmHRpEERaXkWH8MLzzX43epbmQQrhX400IH7+u/pMn8op2mpXzM/4ex7B0fXmbko/kvJJ1joMt17wJm26yeMk37QP14Qrs/k7mhEIQyxlHDqLQl4dnQrkt3Bk7qw5jdPvJfrwbx1nLDj4="
}

$user = 'OMSA'
$user = "C:\Users\$($user)"
$uSID = ""
$SIDs = Get-ChildItem -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList"
ForEach ($sid in $SIDs) {
    $sidName = $sid | Split-Path -Leaf
    $piPath = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$($sidName)" | Select-Object ProfileImagePath).ProfileImagePath
    If ($piPath -eq "$($user)") {
        $uSID = $sidName
    }
}

$key = $pcKeys["$($env:COMPUTERNAME)"]


(New-Object Net.WebClient).DownloadFile('https://rmm.msinetworks.com/labtech/Transfer/Software/LANTalk/lantalk-net.exe','C:\Users\Public\lantalk-net.exe')

& "C:\Users\Public\lantalk-net.exe" @('/VERYSILENT', '/NORESTART', '/SUPPRESSMSGBOXES', '/LOG=C:\Users\Public\LANTalk_LOG.txt', '/NOCANCEL')

If (Test-Path "C:\Program Files (x86)\CEZEO software") {

    If (!(Test-Path HKU:)) {
        New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS | Out-Null
    }

    If (!(Test-Path "HKU:\$($uSID)\SOFTWARE\CEZEO software")) {
        New-Item -Path "HKU:\$($uSID)\SOFTWARE" -Name "CEZEO software" -Force -Confirm:$false | Out-Null
        New-Item -Path "HKU:\$($uSID)\SOFTWARE\CEZEO software" -Name "LanTalk.NET" -Force -Confirm:$false | Out-Null
        New-ItemProperty -Path "HKU:\$($uSID)\SOFTWARE\CEZEO software\LanTalk.NET" -Name 'Key' -Value "$($key)" -Force -Confirm:$false | Out-Null
    }
    ElseIf (!(Test-Path "HKU:\$($uSID)\SOFTWARE\CEZEO software\LanTalk.NET")) {
        New-Item -Path "HKU:\$($uSID)\SOFTWARE\CEZEO software" -Name "LanTalk.NET" -Force -Confirm:$false | Out-Null
        New-ItemProperty -Path "HKU:\$($uSID)\SOFTWARE\CEZEO softwar\LanTalk.NET" -Name 'Key' -Value "$($key)" -Force -Confirm:$false | Out-Null
    }
    ElseIf (!(Test-RegistryValue -Path "HKU:\$($uSID)\SOFTWARE\CEZEO software\LanTalk.NET" -Name "Key")) {
        New-ItemProperty -Path "HKU:\$($uSID)\SOFTWARE\CEZEO software\LanTalk.NET" -Name 'Key' -Value "$($key)" -Force -Confirm:$false | Out-Null
    }
    Else {
        Set-ItemProperty -Path "HKU:\$($uSID)\SOFTWARE\CEZEO software\LanTalk.NET" -Name 'Key' -Value "$($Key)" -Force -Confirm:$false
    }
}
Else {
    Write-Output "LanTalk doesn't look like it installed. Try again"
}
