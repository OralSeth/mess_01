Function SecureStringToString($value) {
  [System.IntPtr]$bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($value)
  
  Try {
    [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
  }
  
  Finally {
    [System.Runtime.InteropServices.Marshal]::FreeBSTR($bstr);
  }
  
}

Function SplitProperties($value) {
  $split1 = "$($value.Split('{')[1])"
  $split2 = "$($split1.Split('}')[0])"
  $global:split3 = $split2 -Split ";\s"
  
  $obj = New-Object PSCustomObject
  
  ForEach ($line in $global:split3) {
    $n = ($line | Select-String -Pattern '^.*?(?==)' | % {$_.Matches}).Value
    $v = ($line | Select-String -Pattern '(?<==).*$' | % {$_.Matches}).Value
    
    $obj | Add-Member -MemberType NoteProperty -Name "$($n)" -Value "$($v)"
  }
  
  return $obj
}

Function Get-KeyInfo {
  $global:keyRequest = "$($global:baseURL)/request_$($global:RequestAs)/?email=$($global:ppUsername)&password=$($global:ppPassword)&passphrase=$($global:orgKey)&app=$($global:apiKey)"
  $keyResponse = (Invoke-RestMethod "$($keyRequest)").results
  
  $global:key = $keyResponse.key
  $global:secret = $keyResponse.secret
  $global:passphrase = $keyResponse.passphrase
  
  [PSCustomObject]@{
    Key = $keyResponse.key
    Secret = $keyResponse.secret
    PassPhrase = $keyResponse.passphrase
  }
}

Function Get-Token {
  $tokenRequest = "$($global:baseURL)/auth?key=$($global:key)&secret=$($global:secret)&app=$global:apiKey)"
  $tokenResponse = (Invoke-RestMethod "$($tokenRequest)").results
  
  $global:token = $tokenResponse.token
  
  $tokenResponse.token
}

Function Get-ClientList($Credential) {
  $clientRequest = "$($global:baseURL)/client/?token=$($global:token)"
  $clientResponse = (Invoke-WebRequest "$($clientRequest)").Content
  
  $clientData = ($clientResponse | ConvertFrom-Json).results | Get-Member -MemberType NoteProperty
  
  $clients = @()
  
  ForEach ($client in $clientData) {
    $data = SplitProperties("$($client.Definition)")
    
    $clientInfo = [PSCustomObject]@{
      ID = "$($data.id)"
      Name = "$($data.Name)"
    }
    
    $clients += $clientInfo
  }
  
  $global:Clients = $clients
  $global:Clients = $global:Clients | Sort-Object Name
  
  $clients
}

Function Get-CredentialTypes {
  $typeRequest = "$($global:baseURL)/credential/?token=$($global:token)"
  $typeResponse = (Invoke-WebRequest "$($typeRequest)").Content
  
  $typeData = ($typeResponse | ConvertFrom-Json).results | Get-Member -MemberType NoteProperty
  
  $types = @()
  
  ForEach ($type in $typeData) {
    $data = SplitProperties("$($type.Definition)")
    
    $typeInfo = [PSCustomObject]@{
      ID = "$($data.id)"
      Name = "$($data.Name)"
    }
    
    $types += $typeInfo
  }
  
  $global:Types = $types
  $global:Types = $global:Types | Sort-Object Name
  
  $types
}

Function Get-PassPortalData {
  [CmdletBinding()]
  Param (
    [Parameter(Mandatory=$false)]
    [Alias("As")]
    [string]$RequestAs = "$($global:RequestAs)",
    
    [Parameter(Mandatory=$true)]
    [string]$APIKey,
    
    [Parameter(Mandatory=$false)]
    [string]$OrgKey = "m$!P@55p0rt@l",
    
    [Parameter(Mandatory=$false)]
    [string]$BaseURL = "https://us.passportalmsp.com/api",
    
    [Parameter()]
    [ValidateNotNull()]
    [System.Management.Automation.PSCredential]
    [System.Management.Automation.Credential()]
    $Credential = [System.Management.Automation.PSCredential]::Empty    
  )
  
  $global:apiKey = "$($APIKey)"
  $global:baseURL = "$($BaseURL)"
  $global:orgKey = "$($OrgKey)"
  
  If ($Credential -eq [System.Management.Automation.PSCredential]::Empty) {
    $Credential = Get-Credential -Message "Please Enter your PassPortal Username/Password"
  }
  
  $global:ppCredential = $Credential
  $global:ppUsername = $Credential.UserName
  $global:ppPassword = SecureStringToString($Credential.Password)
  
  $global:ppData = [PSCustomObject]@{
    KeyData = (Get-KeyInfo)
    Token = (Get-Token)
    ClientData = (Get-ClientList)
    TypeData = (Get-CredentialTypes)
  }
}

#==============================================================================================
# The next function is the bread & butter of the whole she-bang
# That said, it's batting about .500 - so, clearly it needs some work.
# But hey, that 50% of the time it DOES work...is pretty sweet!
#==============================================================================================

Function Get-ClientCredential {
  [CmdletBinding()]
  Param (
    [Parameter(Mandatory=$true)]
    [ValidateSet("user","client","org")]
    [string]$RequestAs,
    
    [Parameter(Mandatory=$true)]
    [ValidateNotNull()]
    [string[]]$ClientName,
    
    [Parameter(Mandatory=$false)]
    [string[]]$Type,
    
    [Parameter(Mandatory=$true)]
    [string]$APIKey,
    
    [Parameter(Mandatory=$false)]
    [string]$OrgKey = "m$!P@55p0rt@l",
    
    [Parameter(Mandatory=$false)]
    [string]$BaseURL = "https://us.passportalmsp.com/api",
    
    [Parameter(Mandatory=$false)]
    [ValidateNotNull()]
    [System.Management.Automation.PSCredential]
    [System.Management.Automation.Credential()]
    $Credential = [System.Management.Automation.PSCredential]::Empty
  )
  
  #===========================================BEGIN============================================
   
  $global:RequestAs = $RequestAs
  
  If (!($global:ppData)) {
    $ppHash = @{
      RequestAs  = $RequestAs
      APIKey     = $APIKey
      BaseURL    = $BaseURL
      OrgKey     = $OrgKey
      Credential = $Credential
    }
    
    Get-PassPortalData @ppHash
  }
  
  If ($null -eq $type) {
    $global:Type = ($global:Types.Name).Trim()
  }
  Else {
    $global:Type = $type
  }
  
  $global:ClientName = $ClientName
  
  $global:ClientIDs = @()
  
  ForEach ($cli in $global:ClientName) {
    If ($cli -in ($global:Clients.Name).Trim()) {
      $global:ClientIDs += ($global:Clients | Where-Object {($_.Name).Trim() -eq "$($cli)"}).ID
    }
  }
  
  #==========================================PROCESS===========================================  

  $global:allPWs = @()
  $global:pwData = @()
  
  ForEach ($ClientID in $global:ClientIDs) {
    $global:PasswordRequest = "$($global:baseURL)/password/?token=$($global:token)&passphrase=$($global:orgKey)&phrase=$($global:passPhrase)&client_id=$($clientID)"
    $passwordResponse = (Invoke-WebRequest "$($global:PasswordRequest)").Content
    
    $global:pwData += ($passwordResponse | ConvertFrom-Json).results | Get-Member -MemberType NoteProperty -ErrorAction SilentlyContinue
  }
  
  $ClientPWs = @()
  
  ForEach ($pw in $global:pwData) {
    $data = SplitProperties("$($pw.Definition)")
    
    If ("$($data.Credential_Name)" -in $global:Type) {
      $pwInfo = [PSCustomObject]@{
        id = "$($data.id)"
        client = "$($data.Client_Name)"
        type = "$($data.Credential_Name)"
        user = "$($data.Username)"
        password = "$($data.Password)"
      }
      
      $global:allPWs += $pwInfo
    }
  }
  
  #============================================END=============================================
  
  $global:allPWs
}

#==============================================================================================
# The next function was a Work In Progress from before May 2020.
# It has not been finished.
# Hell, the stuff that has been written for it hasn't even been tested.
#==============================================================================================

Function Get-CredentialCount {
  [CmdletBinding()]
  Param (
    [Parameter(Mandatory=$true)]
    [ValidateSet("user","client","org")]
    [string]$RequestAs,
    
    [Parameter(Mandatory=$false)]
    [string[]]$ClientName,
    
    [Parameter(Mandatory=$false)]
    [string[]]$Type,
    
    [Parameter(Mandatory=$true)]
    [string]$APIKey,
    
    [Parameter(Mandatory=$false)]
    [string]$BaseURL = "https://us.passportalmsp.com/api",
    
    [Parameter(Mandatory=$false)]
    [string]$OrgKey = "m$!P@55p0rt@l",
    
    [Parameter(Mandatory=$false)]
    [ValidateNotNull()]
    [System.Management.Automation.PSCredential]
    [System.Management.Automation.Credential()]
    $Credential = [System.Management.Automation.PSCredential]::Empty
  )
  
  #===========================================BEGIN============================================
  
  If (-Not $global:ppData) {
    $ppHash = @{
      RequestAs  = $RequestAs
      APIKey     = $APIKey
      BaseURL    = $BaseURL
      OrgKey     = $OrgKey
      Credential = $Credential
    }
    
    Get-PassPortalData @ppHash
  }
  
  If (-Not $Type) {
    $Type = $global:Types
  }
  
  If (-Not $ClientName) {
    $ClientName = ($global:Clients).Name
  }
  
  $ClientIDs = @()
  
  ForEach ($cli in $ClientName) {
    If ($cli -in $global:Clients.Name) {
      $clientIDs += ($global:Clients | Where-Object {$_.Name -eq "$($cli)"}).ID
    }
  }
  
  #==========================================PROCESS===========================================
  
  $countData = @()
  
  $totalCountClient = @()
  $totalCountType = @()
  
  ForEach ($clientID in $clientIDs) {
    $countRequest = "$($global:baseURL)/password/?token=$($global:token)&passphrase=$($global:orgKey)&phrase=$($global:passPhrase)&client_id=$($clientID)"
    $countResponse = (Invoke-WebRequest "$($countRequest)").Content
    
    $countData += ($countResposne | ConvertFrom-Json).results | Get-Member -MemberType NoteProperty -ErrorAction SilentlyContinue
    
    $typeCount = @()
    
    ForEach ($cred in $countData) {
      $data = SplitProperties("$($cred)")
    }
    
    $clientCount = [PSCustomObject]@{
      Client = ($global:Clients | Where-Object {$_.ID -eq "$($clientID)"}).Name
      Count = $countData.Count
    }
  }
  
  $totalCountClient += $clientCount
}
