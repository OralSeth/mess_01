param($global:RestartRequired=0,
	$global:MoreUpdates=0,
	$global:MaxCycles=20
)

Function Check-ContinueRestartOrEnd() {
    $RegistryKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
    $RegistryEntry = "InstallWindowsUpdates"
    switch ($global:RestartRequired) {
        0 {			
            $prop = (Get-ItemProperty $RegistryKey).$RegistryEntry
            If ($prop) {
                Write-Host "Restart Registry Entry Exists - Removing It"
                Remove-ItemProperty -Path $RegistryKey -Name $RegistryEntry -ErrorAction SilentlyContinue
            }      

            Write-Host "No Restart Required"
            Check-WindowsUpdates
           
            If (($global:MoreUpdates -eq 1) -and ($script:Cycles -le $global:MaxCycles)) {
                Stop-Service $script:ServiceName -Force
                Set-Service -Name $script:ServiceName -StartupType Disabled -Status Stopped 
                Install-WindowsUpdates
            } 
            Elseif ($script:Cycles -gt $global:MaxCycles) {
                Write-Host "Exceeded Cycle Count - Stopping"
			}
			Else {
                Write-Host "Done Installing Windows Updates"
                Set-Service -Name $script:ServiceName -StartupType Automatic -Status Running         
            }
        }
        1 {
            $prop = (Get-ItemProperty $RegistryKey).$RegistryEntry
            If (-not $prop) {
                Write-Host "Restart Registry Entry Does Not Exist - Creating It"
                Set-ItemProperty -Path $RegistryKey -Name $RegistryEntry -Value "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -File $($script:ScriptPath)"
            } 
			Else {
                Write-Host "Restart Registry Entry Exists Already"
            }
           
            Write-Host "Restart Required - Restarting..."
            Restart-Computer
        }
        default { 
            Write-Host "Unsure If A Restart Is Required" 
            break
        }
    }
}

Function Install-WindowsUpdates() {
    $script:Cycles++
    Write-Host 'Evaluating Available Updates:'
    $UpdatesToDownload = New-Object -ComObject 'Microsoft.Update.UpdateColl'
    ForEach ($Update in $SearchResult.Updates) {
        If (($Update -ne $null) -and (!$Update.IsDownloaded)) {
            [bool]$addThisUpdate = $false
            If ($Update.InstallationBehavior.CanRequestUserInput) {
                Write-Host "> Skipping: $($Update.Title) because it requires user input"
        	}
			Else {
            	If (!($Update.EulaAccepted)) {
                    Write-Host "> Note: $($Update.Title) has a license agreement that must be accepted. Accepting the license."
                    $Update.AcceptEula()
                    [bool]$addThisUpdate = $true
                } 
				Else {
                    [bool]$addThisUpdate = $true
                }
            }
      
            If ([bool]$addThisUpdate) {
                Write-Host "Adding: $($Update.Title)"
                $UpdatesToDownload.Add($Update) |Out-Null
            }
		}
    }
   
    If ($UpdatesToDownload.Count -eq 0) {
        Write-Host "No Updates To Download..."
    }
	Else {
        Write-Host 'Downloading Updates...'
        $Downloader = $UpdateSession.CreateUpdateDownloader()
        $Downloader.Updates = $UpdatesToDownload
        $Downloader.Download()
    }
	
    $UpdatesToInstall = New-Object -ComObject 'Microsoft.Update.UpdateColl'
    [bool]$rebootMayBeRequired = $false
    Write-Host 'The following updates are downloaded and ready to be installed:'
    ForEach ($Update in $SearchResult.Updates) {
        If (($Update.IsDownloaded)) {
            Write-Host "> $($Update.Title)"
            $UpdatesToInstall.Add($Update) |Out-Null
             
            If ($Update.InstallationBehavior.RebootBehavior -gt 0){
                [bool]$rebootMayBeRequired = $true
            }
        }
    }
    
    If ($UpdatesToInstall.Count -eq 0) {
        Write-Host 'No updates available to install...'
        $global:MoreUpdates=0
        $global:RestartRequired=0
        break
    }

    If ($rebootMayBeRequired) {
        Write-Host 'These updates may require a reboot'
        $global:RestartRequired=1
    }
	
    Write-Host 'Installing updates...'
  
    $Installer = $script:UpdateSession.CreateUpdateInstaller()
    $Installer.Updates = $UpdatesToInstall
    $InstallationResult = $Installer.Install()
  
    Write-Host "Installation Result: $($InstallationResult.ResultCode)"
    Write-Host "Reboot Required: $($InstallationResult.RebootRequired)"
    Write-Host 'Listing of updates installed and individual installation results:'
    If ($InstallationResult.RebootRequired) {
        $global:RestartRequired=1
    }
	Else {
        $global:RestartRequired=0
    }
    
    For($i=0; $i -lt $UpdatesToInstall.Count; $i++) {
        New-Object -TypeName PSObject -Property @{
            Title = $UpdatesToInstall.Item($i).Title
            Result = $InstallationResult.GetUpdateResult($i).ResultCode
        }
    }
	
    Check-ContinueRestartOrEnd
}

Function Check-WindowsUpdates() {
    Write-Host "Checking For Windows Updates"
    $Username = $env:USERDOMAIN + "\" + $env:USERNAME
 
    New-EventLog -Source $ScriptName -LogName 'Windows Powershell' -ErrorAction SilentlyContinue
    $Message = "Script: " + $ScriptPath + "`nScript User: " + $Username + "`nStarted: " + (Get-Date).toString()

    Write-EventLog -LogName 'Windows Powershell' -Source $ScriptName -EventID "104" -EntryType "Information" -Message $Message
    Write-Host $Message

    $script:UpdateSearcher = $script:UpdateSession.CreateUpdateSearcher()
    $script:SearchResult = $script:UpdateSearcher.Search("IsInstalled=0 and Type='Software' and IsHidden=0")      

    If ($SearchResult.Updates.Count -ne 0) {
        $script:SearchResult.Updates |Select-Object -Property Title, Description, SupportUrl, UninstallationNotes, RebootRequired, EulaAccepted |Format-List
        $global:MoreUpdates=1
    } 
    Else {
        Write-Host 'There are no applicable updates'
        $global:RestartRequired=0
        $global:MoreUpdates=0
    }
}

$script:ScriptName = $MyInvocation.MyCommand.ToString()
$script:ScriptPath = $MyInvocation.MyCommand.Path
$script:UpdateSession = New-Object -ComObject 'Microsoft.Update.Session'
$script:UpdateSession.ClientApplicationID = 'Packer Windows Update Installer'
$script:UpdateSearcher = $script:UpdateSession.CreateUpdateSearcher()
$script:SearchResult = New-Object -ComObject 'Microsoft.Update.UpdateColl'
$script:Cycles = 0
$script:ServiceName = "OpenSSHd"

Stop-Service $script:ServiceName -Force
Set-Service -Name $script:ServiceName -StartupType Disabled -Status Stopped 

Check-WindowsUpdates

If ($global:MoreUpdates -eq 1) {
    Install-WindowsUpdates
}
Else {
    Check-ContinueRestartOrEnd
}
