$imPath = "C:\Program Files (x86)\StorageCraft\ImageManager"
  
If (Test-Path $imPath) {

  If (!(Test-Path "$($imPath)\Configuration Backups")) {
    New-Item -Path "$($imPath)" -Name "Configuration Backups" -ItemType Directory | Out-Null
  }

  Copy-Item "$($imPath)\ImageManager.mdb" "$($imPath)\Configuration Backups\ImageManager.mdb"
  & cmd.exe /c "REG EXPORT `"HKLM\SYSTEM\CurrentControlSet\Services\StorageCraft ImageManager`" `"$($imPath)\Configuration Backups\ImageManager.reg`""
}

If (!(Test-Path "C:\Users\Public\IM_7.5.28.exe")) {
    (New-Object Net.WebClient).DownloadFile('https://downloads.storagecraft.com/SP_Files/ImageManager_Setup_7.5.28.exe','C:\Users\Public\IM_7.5.28.exe')
  }

& cmd.exe /c "C:\Users\Public\IM_7.5.28.exe /quiet IACCEPT=STORAGECRAFT.EULA Reboot=Yes"
