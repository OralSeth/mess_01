strComputer = "." 
Set objWMIService = GetObject("winmgmts:" _ 
    & "{impersonationLevel=impersonate}!\\" & strComputer & "\root\cimv2") 
 
Set colItems = objWMIService.ExecQuery("Select * from Win32_DesktopMonitor") 
 
For Each objItem in colItems
    Wscript.Echo "Monitor Manufacturer: " & objItem.MonitorManufacturer 
    Wscript.Echo "Name: " & objItem.Name
    Wscript.Echo "Serial: " & objItem.SerialNumberID
Next
