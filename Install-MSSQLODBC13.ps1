(New-Object Net.WebClient).DownloadFile('https://rmm.msinetworks.com/labtech/Transfer/Utilities/msodbcsql_13_x86.msi','C:\Users\Public\msodbcsql_13_x86.msi')
(New-Object Net.WebClient).DownloadFile('https://rmm.msinetworks.com/labtech/Transfer/Utilities/msodbcsql_13_x64.msi','C:\Users\Public\msodbcsql_13_x64.msi')

& cmd.exe /c "msiexec /qn /norestart /i C:\Users\Public\msodbcsql_13_x86.msi IACCEPTMSODBCSQLLICENSETERMS=YES"
& cmd.exe /c "msiexec /qn /norestart /i C:\Users\Public\msodbcsql_13_x64.msi IACCEPTMSODBCSQLLICENSETERMS=YES"
