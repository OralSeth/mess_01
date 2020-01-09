Function Decode {
    If ($args[0] -is [System.Array]) {
        [System.Text.Encoding]::ASCII.GetString($args[0])
    }
    Else {
        "Not Found"
    }
}

echo "Manufacturer, Model, Serial"

ForEach ($monitor in Get-WmiObject WmiMonitorID -Namespace root\wmi) {
    $Manufacturer = Decode $monitor.ManufacturerName -notmatch 0
    $Name = Decode $monitor.UserFriendlyName -notmatch 0
    $Serial = Decode $monitor.SerialNumberID -notmatch 0

    echo "$Manufacturer, $Name, $Serial"
}
