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
$hours = @{
    0 = '12:00am'
    1 = '1:00am'
    2 = '2:00am'
    3 = '3:00am'
    4 = '4:00am'
    5 = '5:00am'
    6 = '6:00am'
    7 = '7:00am'
    8 = '8:00am'
    9 = '9:00am'
    10 = '10:00am'
    11 = '11:00am'
    12 = '12:00pm'
    13 = '1:00pm'
    14 = '2:00pm'
    15 = '3:00pm'
    16 = '4:00pm'
    17 = '5:00pm'
    18 = '6:00pm'
    19 = '7:00pm'
    20 = '8:00pm'
    21 = '9:00pm'
    22 = '10:00pm'
    23 = '11:00pm'
}
$auOptions = @{
    0 = 'Not Configured'
    1 = 'Never Check for Updates'
    2 = 'Notify Before Download'
    3 = 'Notify Before Installation'
    4 = 'Install Updates Automatically'
}
$regPath1 = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
$regKeys1 = @("NoAutoUpdate","UseWUServer","AUOptions","NoAutoRebootWithLoggedOnUsers","RebootRelaunchTimeoutEnabled","RebootRelaunchTimeout","RebootWarningTimeoutEnabled","RebootWarningTimeout","AutoInstallMinorUpdates","ScheduledInstallDay","ScheduledInstallTime")
$regPath2 = "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings"
$regKeys2 = @("DeferFeatureUpdatesPeriodInDays","DeferQualityUpdatesPeriodInDays","DeferUpgrade","ExcludeWUDriversInQualityUpdate","FlightCommitted","UxOption","ActiveHoursEnd","ActiveHoursStart","AllowAutoWindowsUpdateDownloadOverMeteredNetwork","BranchReadinessLevel","LastToastAction","RestartNotificationsAllowed2","SmartActiveHoursStart","SmartActiveHoursEnd","SmartActiveHoursSuggestionState","SmartActiveHoursTimestamp","InsiderProgramEnabled","SchedulePickerOption","PendingRebootStartTime")

Function isServer {
    If ((Get-WmiObject Win32_OperatingSystem | Select-Object Caption).Caption -like '*Server*') {
        return $true
    }
    Else {
        return $false
    }
}

$os = (Get-WmiObject Win32_OperatingSystem | Select-Object Version).Version
$serial = (Get-WmiObject Win32_BIOS | Select-Object SerialNumber).SerialNumber

$result = New-Object PSObject
$result | Add-Member NoteProperty -Name "ComputerName" -Value $env:ComputerName
$result | Add-Member NoteProperty -Name "Service Tag" -Value $serial

$keys = New-Object PSObject

ForEach ($key in $regKeys1) {
    If (Test-RegistryValue -Path $regPath1 -Name $key) {
        $value = (Get-ItemProperty -Path $regPath1 -Name $key).$key
    }
    Else {
        $value = "N/A"
    }
    $Keys | Add-Member NoteProperty -Name "$($key)" -Value $value
}

ForEach ($key in $regKeys2) {
    If (Test-RegistryValue -Path $regPath2 -Name $key) {
        $value = (Get-ItemProperty -Path $regPath2 -Name $key).$key
    }
    Else {
        $value = "N/A"
    }
    $Keys | Add-Member NoteProperty -Name "$($key)" -Value $value
}

If ($keys.NoAutoUpdate -eq '1') {
    $result | Add-Member NoteProperty -Name "AutomaticUpdates" -Value "Disabled"
}
ElseIf ($keys.NoAutoUpdate -eq '0') {
    $result | Add-Member NoteProperty -Name "AutomaticUpdates" -Value "Enabled"
}
Else {
    $result | Add-Member NoteProperty -Name "AutomaticUpdates" -Value "N/A"
}

If ($keys.UseWUServer -eq '1') {
    $result | Add-Member NoteProperty -Name "UsesWUServer" -Value "Yes"
}
ElseIf ($keys.UseWUServer -eq '0') {
    $result | Add-Member NoteProperty -Name "UsesWUServer" -Value "No"
}
Else {
    $result | Add-Member NoteProperty -Name "UsesWUServer" -Value "N/A"
}

If ($keys.AUOptions -eq "N/A") {
    $result | Add-Member NoteProperty -Name "UpdateOptions" -Value "N/A"
}
Else {
    $result | Add-Member NoteProperty -Name "UpdateOptions" -Value $auOptions[[int]$keys.AUOptions]
}

If ($keys.NoAutoRebootWithLoggedOnUsers -eq '1') {
    $result | Add-Member NoteProperty -Name "AutoReboot-LoggedIn" -Value "Will NOT Reboot while there are users logged on."
}
ElseIf ($keys.NoAutoRebootWithLoggedOnUsers -eq '0') {
    $result | Add-Member NoteProperty -Name "AutoReboot-LoggedIn" -Value "Will Reboot, even if users are logged on."
}
Else {
    $result | Add-Member NoteProperty -Name "AutoReboot-LoggedIn" -Value "N/A"
}

If ($keys.RebootRelaunchTimeoutEnabled -eq '1') {
    $timeout = $keys.RebootRelaunchTimeout
    If ($timeout -gt '60') {
        $timeout = ($timeout /60)
        $timeout = "$($timeout) hours"
    }
    Else {
        $timeout = "$($timeout) minutes"
    }
    $result | Add-Member NoteProperty -Name "RebootRelaunchTimeout" -Value $timeout
}
Else {
    $result | Add-Member NoteProperty -Name "RebootRelaunchTimeout" -Value "N/A"
}

If ($keys.RebootWarningTimeoutEnabled -eq '1') {
    $timeout = $keys.RebootWarningTimeout
    If ($timeout -gt '60') {
        $timeout = ($timeout / 60)
        $timeout = "$($timeout) hours"
    }
    Else {
        $timeout = "$($timeout) minutes"
    }
    $result | Add-Member NoteProperty -Name "RebootWarningTimeout" -Value $timeout
}
Else {
    $result | Add-Member NoteProperty -Name "RebootWarningTimeout" -Value "N/A"
}

If ($keys.AutoInstallMinorUpdates -eq '1') {
    $result | Add-Member NoteProperty -Name "MinorUpdates" -Value "Minor Updates will be Automatically Installed"
}
ElseIf ($keys.AutoInstallMinorUpdates -eq '0') {
    $result | Add-Member NoteProperty -Name "MinorUpdates" -Value "Minor Updates will NOT be Automatically Installed"
}
Else {
    $result | Add-Member NoteProperty -Name "MinorUpdates" -Value "N/A"
}

If ($keys.ScheduledInstallDay -eq 'N/A') {
    $result | Add-Member NoteProperty -Name "InstallDay" -Value "N/A"
}
ElseIf ($keys.ScheduledInstallDay -eq '0') {
    $time = $hours[[int]$keys.ScheduledInstallTime]
    $result | Add-Member NoteProperty -Name "InstallDay" -Value "Updates are set to install any/every day at $($time)"
}
Else {
    $time = $hours[[int]$keys.ScheduledInstallTime]
    $days = @{
        1 = 'Sunday'
        2 = 'Monday'
        3 = 'Tuesday'
        4 = 'Wednesday'
        5 = 'Thursday'
        6 = 'Friday'
        7 = 'Saturday'
    }

    $day = $days[[int]$keys.ScheduledInstallDay]
    $result | Add-Member NoteProperty -Name "InstallDay" -Value "Updates are set to install on $($day) at $($time)"
}

If ($keys.DeferFeatureUpdatesPeriodInDays -eq 'N/A') {
    $result | Add-Member NoteProperty -Name "DeferFeaturedUpdates" -Value "N/A"
}
Else {
    If ($keys.DeferFeautreUpdatesPeriodInDays -lt '7') {
        $period = "$($keys.DeferFeatureUpdatesPeriodInDays) Days"
    }
    ElseIf ($keys.DeferFeatureUpdatesPeriodInDays -lt '30') {
        $period = ($keys.DeferFeatureUpdatesPeriodInDays / 7)
        $period = "$($period) Weeks"
    }
    Else {
        $period = ($keys.DeferFeatureUpdatesPeriodInDays / 30)
        $period = "$($period) Months"
    }
    $result | Add-Member NoteProperty -Name "DeferFeaturedUpdates" -Value "Featured Updates will be deferred $($period)"
}

If ($keys.DeferQualityUpdatesPeriodInDays -eq 'N/A') {
    $result | Add-Member NoteProperty -Name "DeferQualitydUpdates" -Value "N/A"
}
Else {
    If ($keys.DeferQualityUpdatesPeriodInDays -lt '7') {
        $period = "$($keys.DeferQualityUpdatesPeriodInDays) Days"
    }
    ElseIf ($keys.DeferQualityUpdatesPeriodInDays -lt '30') {
        $period = ($keys.DeferQualityUpdatesPeriodInDays / 7)
        $period = "$($period) Weeks"
    }
    Else {
        $period = ($keys.DeferQualityUpdatesPeriodInDays / 30)
        $period = "$($period) Months"
    }
    $result | Add-Member NoteProperty -Name "DeferQualityUpdates" -Value "Quality Updates will be deferred $($period)"
}

If ($keys.DeferUpgrade -eq '1') {
    $result | Add-Member NoteProperty -Name "DeferUpgrade" -Value "Upgrades are deferred"
}
ElseIf ($keys.DeferUpgrade -eq '0') {
    $result | Add-Member NoteProperty -Name "DeferUpgrade" -Value "Upgrades are NOT deferred"
}
Else {
    $result | Add-Member NoteProperty -Name "DeferUpgrade" -Value "N/A"
}

If ($keys.UxOption -eq '1') {
    $result | Add-Member NoteProperty -Name "RebootPrompt" -Value "Windows Updates will Prompt for Reboot"
}
ElseIf ($keys.UxOption -eq '0') {
    $result | Add-Member NoteProperty -Name "RebootPrompt" -Value "Windows Updates will NOT Prompt for Reboot"
}
Else {
    $result | Add-Member NoteProperty -Name "RebootPrompt" -Value "N/A"
}

If ($keys.ActiveHoursEnd -eq 'N/A') {
    If (!($keys.SmartActiveHoursEnd -eq 'N/A')) {
        $start = $hours[[int]$keys.SmartActiveHoursStart]
        $end = $hours[[int]$keys.SmartActiveHoursEnd]
        $result | Add-Member NoteProperty -Name "ActiveHours" -Value "Active Hours have NOT been set, but are presumed to be from $($start) to $($end)"
    }
    Else {
        $result | Add-Member NoteProperty -Name "ActiveHours" -Value "N/A"
    }
}
Else {
    $start = $hours[[int]$keys.ActiveHoursStart]
    $end = $hours[[int]$keys.ActiveHoursEnd]
    $result | Add-Member NoteProperty -Name "ActiveHours" -Value "Active Hours have been set from $($start) to $($end)"
}

If ($keys.PendingRebootStartTime -eq 'N/A') {
    $result | Add-Member NoteProperty -Name "PendingReboot" -Value "N/A"
}
Else {
    $difference = (Get-Date) - ($keys.PendingRebootStartTime | Get-Date)
    $difference = "$($difference.Days) Days, $($difference.Hours) Hours, $($difference.Minutes) Minutes, $($difference.Seconds) Seconds"
    $result | Add-Member NoteProperty -Name "PendingReboot" -Value "Windows Updates have been waiting $($difference) to Reboot"
}

$result
