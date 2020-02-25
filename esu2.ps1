$os = (Get-WmiObject Win32_OperatingSystem | Select-Object OSArchitecture).OSArchitecture

If ($os -like '*32*') {
    If (!(Test-Path C:\Users\Public\kb4538483.msu)) {
        (New-Object Net.WebClient).DownloadFile('http://download.windowsupdate.com/c/msdownload/update/software/secu/2020/02/windows6.1-kb4538483-x86_ad01b9ae3388f75bf3280a5b7574a66e319c43bc.msu','C:\Users\Public\kb4538483.msu')
    }
    If (!(Get-HotFix -Id 4490628 -ErrorAction SilentlyContinue)) {
        (New-Object Net.WebClient).DownloadFile('http://download.windowsupdate.com/c/msdownload/update/software/secu/2019/03/windows6.1-kb4490628-x86_3cdb3df55b9cd7ef7fcb24fc4e237ea287ad0992.msu','C:\Users\Public\kb4490628.msu')
        
        & cmd.exe /c "wusa.exe C:\Users\Public\kb4490628.msu /quiet /norestart"
    }
    Else {
        & cmd.exe /c "wusa.exe C:\Users\Public\kb4538483.msu /quiet /norestart"
    }
}
Else {
    (New-Object Net.WebClient).DownloadFile('http://download.windowsupdate.com/c/msdownload/update/software/secu/2020/02/windows6.1-kb4538483-x64_5c1336947b1d530b1d7adc2c1fe966edb71aed6b.msu','C:\Users\Public\kb4538483.msu')
    
    If (!(Get-HotFix -Id 4490628 -ErrorAction SilentlyContinue)) {
        (New-Object Net.WebClient).DownloadFile('http://download.windowsupdate.com/c/msdownload/update/software/secu/2019/03/windows6.1-kb4490628-x64_d3de52d6987f7c8bdc2c015dca69eac96047c76e.msu','C:\Users\Public\kb4490628.msu')
        
        & cmd.exe /c "wusa.exe C:\Users\Public\kb4490628.msu /quiet /norestart"
    }
    Else {
        & cmd.exe /c "wusa.exe C:\Users\Public\kb4538483.msu /quiet /norestart"
    }
}
