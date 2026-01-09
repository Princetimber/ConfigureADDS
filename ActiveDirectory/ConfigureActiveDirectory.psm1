  # ...existing code...
  # End of Install-ADDomainForest.psm1
  # This module contains functions to install and configure Active Directory Domain Services, including creating organizational units and groups, and managing group memberships.
  # It also includes functions to install the AD module and set the Safe Mode Administrator password.
  # The functions are designed to be used in a PowerShell environment with appropriate permissions and prerequisites.
  # This module is intended for use in a Windows Server environment where Active Directory Domain Services is available.
  # The functions handle errors gracefully and provide informative messages to the user.
  # This module is part of a larger script for setting up and managing an Active Directory environment.
  # It is designed to be modular and reusable, allowing for easy integration into larger scripts or automation workflows.
  # The functions utilize PowerShell's advanced features such as parameter validation, error handling, and cmdlet binding to ensure robust and user-friendly operation.
  # The module is structured to allow for easy expansion and modification, with clear parameter definitions and error handling.
  # The functions are designed to be efficient and effective, leveraging PowerShell's capabilities to interact with Active Directory.
  # The module is intended to be used by system administrators and IT professionals who need to manage Active Directory environments.


function Install-ADModule {
  <#
    .SYNOPSIS
        Installs the specified Windows feature if not already installed.
    .PARAMETER ModuleName
        The name of the Windows feature to install. Defaults to 'AD-Domain-Services'.
    #>
  param(
    [Parameter(Mandatory = $false)]
    [string]$ModuleName = "AD-Domain-Services"
  )
  try {
    $feature = Get-WindowsFeature -Name $ModuleName
    if (-not $feature.Installed) {
      Write-Verbose "Installing $ModuleName module..."
      Install-WindowsFeature -Name $ModuleName -IncludeManagementTools -ErrorAction Stop
      Write-Host "$ModuleName module installed successfully."
    }
    else {
      Write-Host "$ModuleName module is already installed."
    }
  }
  catch {
    Write-Error "Failed to install $ModuleName module: $_"
  }
}

function Add-SafeModeAdministratorPassword {
  <#
    .SYNOPSIS
        Sets the Safe Mode Administrator password.
    .PARAMETER Password
        The new password as a SecureString.
    #>
  param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [securestring]$Password
  )
  try {
    $adminAccount = [ADSI]"WinNT://./Administrator, user"
    $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password)
    $plainPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
    $adminAccount.SetPassword($plainPassword)
    $adminAccount.SetInfo()
    Write-Host "Safe Mode Administrator password set successfully."
  }
  catch {
    Write-Error "Failed to set Safe Mode Administrator password: $_"
  }
  return $SafeModeAdministratorPassword
}

function Install-ADDomainForest {
  <#
    .SYNOPSIS
        Installs a new Active Directory Domain Services forest.
    .PARAMETER DomainName
        The fully qualified domain name for the new forest.
    .PARAMETER SafeModeAdministratorPassword
        The Safe Mode Administrator password as a SecureString.
    .PARAMETER DatabasePath
        Optional. Path for the AD DS database.
    .PARAMETER LogPath
        Optional. Path for the AD DS log files.
    .PARAMETER SysvolPath
        Optional. Path for the SYSVOL folder.
    .PARAMETER DomainMode
        Optional. Domain functional level.
    .PARAMETER ForestMode
        Optional. Forest functional level.
    .PARAMETER Force
        Optional. Suppress confirmation prompts.
    #>
  [CmdletBinding(SupportsShouldProcess)]
  param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$DomainName,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [securestring]$SafeModeAdministratorPassword,

    [string]$DatabasePath,
    [string]$LogPath,
    [string]$SysvolPath,
    [ValidateSet("Win2008", "Win2008R2", "Win2012", "Win2012R2", "Win2025", "Default", "WinThreshold")][string]$DomainMode = "Win2025",
    [ValidateSet("Win2008", "Win2008R2", "Win2012", "Win2012R2", "Win2025", "Default", "WinThreshold")][string]$ForestMode = "Win2025",
    [boolean]$InstallDNS,
    [string]$DomainNetbiosName,
    [switch]$Force
  )
  try {
    # Check if the AD module is installed
    Install-ADModule
    if ($PSCmdlet.ShouldProcess("Install AD DS Forest for $DomainName")) {

      $params = @{
        DomainName                    = $DomainName
        SafeModeAdministratorPassword = $SafeModeAdministratorPassword
        InstallDNS                    = $InstallDNS
      }
      # Add optional parameters if provided
      foreach ($param in 'DatabasePath', 'LogPath', 'SysvolPath', 'DomainMode', 'ForestMode', 'DomainNetbiosName') {
        if ($PSBoundParameters.ContainsKey($param)) {
          $params[$param] = $PSBoundParameters[$param]
        }
      }
      # Suppress confirmation prompts if Force is specified
      if ($Force.IsPresent) {
        $params['Force'] = $true
      }

      Install-ADDSForest @params
      Write-Host "AD DS Forest installation complete."
    }
  }
  catch {
    Write-Error "Failed to install AD DS Forest: $_"
  }
}

function Install-ADDomainController {
  <#
    .SYNOPSIS
        Installs a new Active Directory Domain Services forest.
    .PARAMETER DomainName
        The fully qualified domain name for the new forest.
    .PARAMETER SiteName
        The name of the site in which the domain controller will be created.
    .PARAMETER DomainAdministrator
        The domain administrator account that will be used to install the domain controller.
    .PARAMETER SafeModeAdministratorPassword
        The Safe Mode Administrator password as a SecureString.
    .PARAMETER DatabasePath
        Optional. Path for the AD DS database.
    .PARAMETER LogPath
        Optional. Path for the AD DS log files.
    .PARAMETER SysvolPath
        Optional. Path for the SYSVOL folder.
    .PARAMETER InstallDNS
        Optional. Indicates whether to install the DNS server role.
    .PARAMETER Force
        Optional. Suppress confirmation prompts.
    #>
  [CmdletBinding(SupportsShouldProcess)]
  param(
    [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$DomainName,
    [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$siteName,
    [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$DomainAdministrator,
    [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][securestring]$SafeModeAdministratorPassword,
    [string]$DatabasePath,
    [string]$LogPath,
    [string]$SysvolPath,
    [bool]$InstallDNS,
    [switch]$Force
  )
  try {
    # Check if the AD module is installed
    Install-ADModule
    # create allowed credential object
    $credential = New-Object System.Management.Automation.PSCredential($DomainAdministrator, $SafeModeAdministratorPassword)
    # Install the AD DS role
    if ($PSCmdlet.ShouldProcess("Installing additional AD Domain Controller for $DomainName in site $siteName")) {
      $params = @{
        DomainName                    = $DomainName
        SiteName                      = $siteName
        SafeModeAdministratorPassword = $SafeModeAdministratorPassword
        credential                    = $credential
        InstallDNS                    = $InstallDNS
      }
      # Add optional parameters if provided
      foreach ($param in 'DatabasePath', 'LogPath', 'SysvolPath', 'DomainMode') {
        if ($PSBoundParameters.ContainsKey($param)) {
          $params[$param] = $PSBoundParameters[$param]
        }
      }
      # Suppress confirmation prompts if Force is specified
      if ($Force.IsPresent) {
        $params['Force'] = $true
      }
      Install-ADDSDomainController @params -ErrorAction Stop
      Write-Host "installed additional AD Domain Controller for $DomainName in site $siteName successfully."
      return
    }
  }
  catch {
    Write-Error "Failed to install additional AD Domain Controller for $DomainName in site $siteName : ${_}"
  }
}
function New-OrganizationalUnit {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $true, ValueFromPipeline = $true)][ValidateNotNullOrEmpty()]
    [ValidateScript({
      if (-not (Get-ADOrganizationalUnit -Filter "Name -eq '$_'" -ErrorAction SilentlyContinue)) {
        $true
      } else {
        throw "Organizational unit '$_' already exists."
      }
    })]
    [string]$Name,

    [Parameter(Mandatory = $true, ValueFromPipeline = $true)][ValidateNotNullOrEmpty()]
    [string]$Path,

    [Parameter(Mandatory = $false)]
    [string]$Description,

    [Parameter(Mandatory = $false)]
    [string]$City,

    [Parameter(Mandatory = $false)][ValidatePattern('^[A-Z]{2,3}$')]
    [string]$Country,

    [Parameter(Mandatory = $false)][ValidatePattern('^(^[A-Z]{1,2}\d[A-Z\d]?\s?\d[A-Z]{2}$)|(^\d{5}(-\d{4})?$)')]
    [string]$PostalCode,

    [Parameter(Mandatory = $false)][ValidatePattern('^[A-Z][a-z]+$')]
    [string]$State,

    [Parameter(Mandatory = $false)]
    [string]$StreetAddress,

    [Parameter(Mandatory = $false)]
    [string]$ManagedBy,

    [Parameter(Mandatory = $false)]
    [bool]$ProtectedFromAccidentalDeletion
  )

  # Validate the Path parameter.
  if ($Path -notmatch '^(OU=[^,]+,)*DC=[^,]+(,DC=[^,]+)*$') {
    throw "The Path parameter must be in the format OU=?,DC=?,DC=?"
  }

  # Build parameters for New-ADOrganizationalUnit
  $createParams = @{
    Name = $Name
    Path = $Path
  }
  foreach ($param in 'Description','City','Country','PostalCode','State','StreetAddress','ManagedBy') {
    if ($PSBoundParameters.ContainsKey($param)) {
      $createParams[$param] = $PSBoundParameters[$param]
    }
  }
  if ($PSBoundParameters.ContainsKey('ProtectedFromAccidentalDeletion')) {
    $createParams['ProtectedFromAccidentalDeletion'] = [bool]$ProtectedFromAccidentalDeletion
  }

  try {
    $ou = New-ADOrganizationalUnit @createParams
    return "$($ou.Name) $($ou.DistinguishedName)"
  } catch {
    throw "Failed to create organizational unit '$Name' in '$Path'. Error: $($_.Exception.Message)"
  }
}

function New-Group {
  [CmdletBinding(SupportsShouldProcess = $true)]
  param(
    [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
    [ValidateScript({
      if (-not (Get-ADGroup -Filter "Name -eq '$_'" -ErrorAction SilentlyContinue)) {
        $true
      } else {
        throw "Group '$_' already exists."
      }
    })]
    [string]$Name,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^(OU=[^,]+,?)*(DC=[^,]+,?)*$')]
    [string]$Path,

    [Parameter(Mandatory = $true)]
    [ValidateSet('Security', 'Distribution')]
    [string]$GroupCategory,

    [Parameter(Mandatory = $true)]
    [ValidateSet('Global', 'DomainLocal', 'Universal')]
    [string]$GroupScope,

    [Parameter()]
    [string]$DisplayName,

    [Parameter()]
    [string]$SamAccountName,

    [Parameter()]
    [string]$Description
  )

  $createParams = @{
    Name          = $Name
    Path          = $Path
    GroupCategory = $GroupCategory
    GroupScope    = $GroupScope
  }
  foreach ($param in 'DisplayName', 'SamAccountName', 'Description') {
    if ($PSBoundParameters.ContainsKey($param)) {
      $createParams[$param] = $PSBoundParameters[$param]
    }
  }

  try {
    if ($PSCmdlet.ShouldProcess($Name, 'Create a new group')) {
      New-ADGroup @createParams
    }
  } catch {
    throw "Failed to create group '$Name' in '$Path'. Error: $($_.Exception.Message)"
  }
}

function Update-ADPrincipalGroupMembership {
  [CmdletBinding(DefaultParameterSetName = 'AddPrincipalGroupMembership', SupportsShouldProcess = $true)]
  param(
    [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
    [ValidateScript({
      if (Get-ADGroup -Identity $_ -ErrorAction SilentlyContinue) {
        $true
      } else {
        throw "Group '$_' does not exist."
      }
    })]
    [string]$GroupName,

    [Parameter(Mandatory = $true)]
    [ValidateSet('Domain Admins', 'Enterprise Admins', 'Group Policy Creator Owners', 'Schema Admins')]
    [string]$SecurityGroup,

    [Parameter(Mandatory = $true, ParameterSetName = 'AddPrincipalGroupMembership')]
    [switch]$AddPrincipalGroupMembership,

    [Parameter(Mandatory = $true, ParameterSetName = 'RemovePrincipalGroupMembership')]
    [switch]$RemovePrincipalGroupMembership
  )

  $memberOf = (Get-ADGroup -Identity $SecurityGroup).DistinguishedName
  $identity = (Get-ADGroup -Identity $GroupName).DistinguishedName

  try {
    switch ($PSCmdlet.ParameterSetName) {
      'AddPrincipalGroupMembership' {
        if ($AddPrincipalGroupMembership.IsPresent -and $PSCmdlet.ShouldProcess($GroupName, "Add group '$GroupName' to '$SecurityGroup'")) {
          Add-ADGroupMember -Identity $memberOf -Members $identity
        }
      }
      'RemovePrincipalGroupMembership' {
        if ($RemovePrincipalGroupMembership.IsPresent -and $PSCmdlet.ShouldProcess($GroupName, "Remove group '$GroupName' from '$SecurityGroup'")) {
          Remove-ADGroupMember -Identity $memberOf -Members $identity
        }
      }
    }
  } catch {
    $action = if ($AddPrincipalGroupMembership) { 'add' } else { 'remove' }
    throw "Failed to $action group '$GroupName' to/from '$SecurityGroup'. Error: $($_.Exception.Message)"
  }
}

Export-ModuleMember -Function Install-ADModule, Add-SafeModeAdministratorPassword, Install-ADDomainForest, Install-ADDomainController, New-OrganizationalUnit, New-Group, Update-ADPrincipalGroupMembership
