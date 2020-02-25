$os = (Get-WmiObject Win32_OperatingSystem | Select-Object OSArchitecture).OSArchitecture

If ($os -like '*32*') {
    $file = "kb4538483_86.msu"
}
Else {
    $file = "kb4538483_64.msu"
}

(New-Object Net.WebClient).DownloadFile("https://rmm.msinetworks.com/labtech/Transfer/Software/ESU/$file","C:\Users\Public\kb4538483.msu")

& cmd.exe /c "wusa.exe C:\Users\Public\kb4538483.msu /silent /norestart"
