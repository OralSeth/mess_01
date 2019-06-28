Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" -Name "NextStep" -Value "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -ExecutionPolicy Unrestricted -Command “(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/OralSeth/mess_01/master/651_3.ps1') | Invoke-Expression'"

Function Get-UninstallString {
    [CmdletBinding(DefaultParameterSetName = "ByName")]
    [OutputType([PSCustomObject])]
    Param (
        [Parameter(
            ParameterSetName = "ByName",
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [Alias(
            "DisplayName"
        )]
        [String[]]$Name,
        [Parameter(
            ParameterSetName = "ByFilter"
        )]
        [String]$Filter = "*",
        [Parameter()]
        [Switch]$showNulls
    )

    begin {
        try {
            If (Test-Path -Path "HKLM:\SOFTWARE\Wow6432Node") {
                $programs = Get-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction Stop
            }
            $programs += Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction Stop
            $programs += Get-ItemProperty -Path "Registry::\HKEY_USERS\*\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction SilentlyContinue
        }
        catch {
            Write-Error $_
            break
        }
    }

    process {
        If ($PSCmdlet.ParameterSetName -eq "ByName") {
            ForEach ($nameValue in $Name) {
                $programs = $programs.Where({
                    $_.DisplayName -eq $nameValue
                })
            }
        }
        Else {
            $programs = $programs.Where({
                $_.DisplayName -like "*$Filter*"
            })
        }

        If ($null -ne $programs) {
            If (-not ($showNulls.IsPresent)) {
                $programs = $programs.Where({
                    -not [String]::IsNullOrEmpty(
                        $_.UninstallString
                    )
                })
            }

            $output = $programs.ForEach({
                [PSCustomObject]@{
                    Name = $_.DisplayName
                    Version = $_.DisplayVersion
                    GUID = $_.PSChildName
                    UninstallString = $_.UninstallString
                }
            })

            Write-Output -InputObject $output
        }
    }
}

$guid = (Get-UninstallString -Filter "*SPX*").GUID

$aList = @(
    "/x"
    ('"{0}"' -f "$($guid)")
    "/qn"
)

Start-Process "msiexec.exe" -ArgumentList $aList -Wait -NoNewWindow
