Function Get-NetConnectionProfile {
  [CmdletBinding()]
  [OutputType([PSObject])]
  Param (
    [Parameter(Mandatory=$false,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true,ValueFromRemainingArguments=$false,Position=0)]
    [ValidateNotNull()]
    [ValidateNotNullOrEmpty()]
    [string]$Name,

    [Parameter(Mandatory=$false,Position=1)]
    [ValidateSet('Public','Private','Domain')]
    $NetworkCategory
  )

  Begin {
    Write-Verbose 'Creating Network List Manager Instance.'

    $nlmType = [Type]::GetTypeFromCLSID('DCB00C01-570F-4A9B-8D69-199FDBA5723B')
    $networkListManager = [Activator]::CreateInstance($nlmType)

    $categories = @{
      0 = "Public"
      1 = "Private"
      2 = "Domain"
    }

    If ($NetworkCategory) {
      Write-Verbose "Filtering Results to Match Category '$networkCategory'."
      $networks = $Networks | Where-Object {$_.GetCategory() -eq $NetworkCategory}
    }
  }

  Process {
    If ($Name) {
      Write-Verbose "Filtering Results to Match '$Name'."
      $Networks = $Networks | Where-Object {$_.GetName -eq $Name}
    }

    ForEach ($network in $Networks) {
      Write-Verbose "Creating Output Object for Network $($Network.GetName())."
      
      New-Object -TypeName PSObject -Property @{
        Category = $Categories[($Network.GetCategory())]
        Description = $Network.GetDescription()
        Name = $Network.GetName()
        IsConnected = $Network.IsConnected
        IsConnectedToInternet = $Network.IsConnectedToInternet
      }
    }
  }

  End {  }
}

Function Set-NetConnectionProfile {
  [CmdletBinding(SupportsShouldProcess=$true,PositionalBinding=$false,ConfirmImpact='Medium')]
  [Alias()]
  [OutputType([string])]
  Param (
    [Parameter(Mandatory=$false,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true,ValueFromRemainingArguments=$false,Position=0)]
    [ValidateNotNull()]
    [ValidateNotNullOrEmpty()]
    [string]$Name,
    
    [Parameter(Mandatory=$true,Position=1)]
    [ValidateSet('Public','Private','Domain')]
    $NetworkCategory
  )
  
  Begin {
    Write-Verbose 'Creating Network List Manager Instance.'
    
    $nlmType = [Type]::GetTypeFromCLSID('DCB00C01-570F-4A9B-8D69-199FDBA5723B')
    $networkListManager = [Activator]::CreateInstance($nlmType)
    
    $Categories = @{
      'Public' = 0x00
      'Private' = 0x01
      'Domain' = 0x02
    }
    
    ReverseCategories = @{
      0 = 'Public'
      1 = 'Private'
      2 = 'Domain'
    }
    
    Write-Verbose 'Retrieving Network Connections.'
    $allNetworks = $networkListManager.GetNetworks(1)
  }
  
  Process {
    If ($Name) {
      Write-Verbose "Filtering Results to Match Name '$Name'."
      $Networks = $allNetworks | Where-Object {$_.GetName() -eq $Name}
    }
    Else {
      $networks = $allNetworks
    }
    
    ForEach ($network in $networks) {
      $Name = $Network.GetName()
      
      Write-Verbose "Processing Network Connection '$Name'."
      
      $CurrentCategory = $ReverseCategories[$Network.GetCategory()]
      
      Write-Verbose "Current Category is '$CurrentCategory'."
      
      If ($NetworkCategory -eq $CurrentCategory) {
        Write-Warning "Skipping Network Connection '$Name': Category Already Set to '$NetworkCategory'."
        Continue
      }
      
      If ($PSCMDLet.ShouldProcess($Name, "Set Network Category to $NetworkCategory")) {
        Write-Verbose "Changing Network Category to '$NetworkCategory'."
        
        $Network.SetCategory($Categories[$NetworkCategory])
        
        Write-Verbose "Creating Output Object for Network '$Name'."
        
        New-Object -TypeName PSObject -Property @{
          Category = $ReverseCategories[($Network.GetCategory())]
          Description = $Network.GetDescription()
          Name = $Network.GetName()
          IsConnected = $Network.IsConnected
          IsConnectedToInternet = $Network.IsConnectedToInternet
        }
      }
    }
  }
  
  End { }
}
