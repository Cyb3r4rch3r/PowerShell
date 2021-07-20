<#
.SYNOPSIS
    Gather information about Active Directory Admin accounts and attempt to resolve any issues. Conforms to Best Practice and PingCastle reports.
.DESCRIPTION
    This script checks Active Directory Accounts for the adminCount attribute, AccountnotDelegated attribute, active status, and offers remediation steps
.EXAMPLE
    .\AD-CheckAdmin -Credentials <Domain Admin account name>
.INPUTS
    Admin credentials
.COMPONENT
    PowerShell, Active Directory PowerShell Module, and sufficient rights to change admin accounts
.ROLE
    Domain Admin
.FUNCTIONALITY
    Gather information about Active Directory Admin accounts and attempt to resolve any issues
#>

function Show-Menu
{
     param (
           [string]$Title = 'Admin Account Security Check'
     )
     Clear-Host
     Write-Host "              ================ $Title ================"

     Write-Host "         |   |||||||||||||||||||||||||||||||||||||||||||    | "
 	   Write-Host "         |   |                                         |    | "
 	   Write-Host "         |   | Author - Cyb3r4rch3r                    |    | "
 	   Write-Host "         |   |                                         |    | "
     Write-Host "         |   |||||||||||||||||||||||||||||||||||||||||||    | " 
     Write-Host ""
     Write-Host ""
     Write-Host "            adminCount attributes greater than '0' indicates"
     Write-Host "            the account has administrative rights"
     Write-Host ""
     Write-Host "            AccountnotDelegated attributes should be set on"
     Write-Host "            any account that has elevated administrative rights"
     Write-Host "            for example - Domain Administrators"
     Write-Host ""
     Write-Host ""
     Write-Host "Press '1' to get all users with an adminCount attribute of greater than 0."
     Write-Host "Press '2' to find all disabled users with an adminCount of greater than 0."
     Write-Host "Press '3' to set all disabled users adminCount properties to 0 (non-admin)."
	 Write-Host "Press '4' to search for all elevated admin accounts with AccountnotDelegated unset (Domain Admin)."
	 Write-Host "Press '5' to set AccountnotDelegated for all elevated admin accounts (Domain Admin)."
	 Write-Host "Press '6' to find all members of Enterprise Administrators group."
	 Write-Host "Press '7' to remove all members of Enterprise Administrators group."
     Write-Host "Press '8' to find all members of Schema Administrators group."
	 Write-Host "Press '9' to remove all members of Schema Administrators group."
	 Write-Host "Press '10' to find all admin accounts with PasswordNeverExpires set."
	 Write-Host "Press '11' to remove PasswordNeverExpires from all admin accounts (sans Service Accounts)."
     Write-Host "Press '12' to find all disabled members of elevated groups (Domain Admins and Enterprise Admins)." 
     Write-Host "Press '13' to remove all disabled members of elevated groups (Domain Admins and Enterprise Admins)."
	 Write-Host "Press '14' to perform all tasks."
	 Write-Host "Press 'H' to Show Help."
     Write-Host "Press 'Q' to quit."
}

Function adminCount {
    Get-ADUser -filter {admincount -like "1"} -pr AccountNotDelegated, Title, Department, Manager, Description | Select-Object Name, SamAccountName, Title, Department, Manager
}

Function disabledAdmin {
    Get-ADUser -filter {admincount -like "1"} -pr AccountNotDelegated, Title, Department, Manager, Description | Where-Object {$_.enabled -eq $false} | Select-Object Name, SamAccountName, Title, Department, Manager
}

Function resetadminCount {
    Get-ADUser -filter {admincount -like "1"} -pr AccountNotDelegated, Title, Department, Manager, Description | Where-Object {$_.enabled -eq $false} | Select-Object Name, SamAccountName, Title, Department, Manager | set-aduser -replace @{admincount=0}
}

Function notDelegated {
    Get-ADGroupMember "Domain Admins" -Recursive | Get-ADUser -pr AccountNotDelegated, Title, Department, Manager, Description | Where-Object {($_.AccountNotDelegated -eq $false) -and ($_.name -notlike "svc_*")} | Select-Object Name, SamAccountName, Title, Department, Manager
}

Function SetnotDelegated {
    Get-ADGroupMember "Domain Admins" -Recursive | Get-ADUser -pr AccountNotDelegated, Title, Department, Manager, Description | Where-Object {($_.AccountNotDelegated -eq $false) -and ($_.name -notlike "svc_*")} | Set-ADUser -AccountNotDelegated $true
}

Function getEnterpriseAdmin {
    Get-ADGroup "Enterprise Admins" -pr Members | Select-Object -ExpandProperty Members | Get-ADUser -pr AccountNotDelegated, Title, Department, Manager, Description | Where-Object {($_.AccountNotDelegated -eq $false) -and ($_.name -notlike "svc_*")} | Select-Object name, samaccountname, title, department, manager
}

Function removeEnterpriseAdmin {
    Get-ADGroup "Enterprise Admins" -pr Members | Select-Object -ExpandProperty Members | Get-ADUser -pr AccountNotDelegated, Title, Department, Manager, Description | Where-Object {($_.AccountNotDelegated -eq $false) -and ($_.name -notlike "svc_*")} | Remove-ADGroupMember "Enterprise Admins"
}

Function getSchemaAdmin {
    Get-ADGroup "Schema Admins" -pr Members | Select-Object -ExpandProperty Members | Get-ADUser -pr AccountNotDelegated, Title, Department, Manager, Description | Where-Object {($_.AccountNotDelegated -eq $false) -and ($_.name -notlike "svc_*")} | Select-Object name, samaccountname, title, department, manager
}

Function removeSchemaAdmin {
    Get-ADGroup "Schema Admins" -pr Members | Select-Object -ExpandProperty Members | Get-ADUser -pr AccountNotDelegated, Title, Department, Manager, Description | Where-Object {($_.AccountNotDelegated -eq $false) -and ($_.name -notlike "svc_*")} | Remove-ADGroupMember "Schema Admins"
}
Function getPwdNeverExpires {
    Write-Output "Searching through Domain Admins"
    Get-ADGroupMember "Domain Admins" -Recursive | Get-ADUser -pr PasswordNeverExpires | Where-Object {($_.PasswordNeverExpires -eq $true) -and ($_.name -notlike "svc_*")} 
    Write-Output "Searching through Enterprise Admins"
    Get-ADGroup "Enterprise Admins" -pr Members | Select-Object -ExpandProperty Members | Get-ADUser -pr PasswordNeverExpires | Where-Object {($_.PasswordNeverExpires -eq $true) -and ($_.name -notlike "svc_*")}
    Write-Output "Searching through Schema Admins"
    Get-ADGroup "Schema Admins" -pr Members | Select-Object -ExpandProperty Members | Get-ADUser -pr PasswordNeverExpires | Where-Object {($_.PasswordNeverExpires -eq $true) -and ($_.name -notlike "svc_*")}
}

Function removePwdNeverExpires {
    Write-Output "Removing disabled users from Domain Admins"
    Get-ADGroupMember "Domain Admins" -Recursive | Get-ADUser -pr PasswordNeverExpires | Where-Object {($_.PasswordNeverExpires -eq $true) -and ($_.name -notlike "svc_*")} | Set-ADUser -PasswordNeverExpires $false
    Write-Output "Removing disabled users from Enterprise Admins"
    Get-ADGroup "Enterprise Admins" -pr Members | Select-Object -ExpandProperty Members | Get-ADUser -pr PasswordNeverExpires | Where-Object {($_.PasswordNeverExpires -eq $true) -and ($_.name -notlike "svc_*")} | Set-ADUser -PasswordNeverExpires $false
    Write-Output "Removing disabled users from Schema Admins"
    Get-ADGroup "Schema Admins" -pr Members | Select-Object -ExpandProperty Members | Get-ADUser -pr PasswordNeverExpires | Where-Object {($_.PasswordNeverExpires -eq $true) -and ($_.name -notlike "svc_*")} | Set-ADUser -PasswordNeverExpires $false
}

Function findDisabledAdmins {
    Write-Output "Searching through Domain Admins"
    Get-ADGroupMember "Domain Admins" -Recursive | Get-ADUser | Where-Object {($_.Enabled -eq $false)}
    Write-Output "Searching through Enterprise Admins"
    Get-ADGroup "Enterprise Admins" -pr Members | Select-Object -ExpandProperty Members | Get-ADUser | Where-Object {($_.Enabled -eq $false)}
    Write-Output "Searching through Schema Admins"
    Get-ADGroup "Schema Admins" -pr Members | Select-Object -ExpandProperty Members | Get-ADUser | Where-Object {$_.Enabled -eq $false}
}
Function removeDisabledAdmins {
    Write-Output "Removing disabled users from Domain Admins"
    Get-ADGroupMember "Domain Admins" -Recursive | Get-ADUser | Where-Object {($_.Enabled -eq $false)} | Remove-ADGroupMember "Domain Admins"
    Write-Output "Removing disabled users from Enterprise Admins"
    Get-ADGroup "Enterprise Admins" -pr Members | Select-Object -ExpandProperty Members | Get-ADUser | Where-Object {($_.Enabled -eq $false)} | Remove-ADGroupMember "Enterprise Admins"
    Write-Output "Removing disabled users from Schema Admins"
    Get-ADGroup "Schema Admins" -pr Members | Select-Object -ExpandProperty Members | Get-ADUser | Where-Object {($_.Enabled -eq $false)} | Remove-ADGroupMember "Schema Admins"
}

Function all {
    adminCount
    disabledAdmin
    resetadminCount
    notDelegated
    SetnotDelegated
    getEnterpriseAdmin
    removeEnterpriseAdmin
    getSchemaAdmin
    removeSchemaAdmin
    getPwdNeverExpires
    removePwdNeverExpires
    findDisabledAdmins
    removeDisabledAdmins
}

do
 {

    Show-Menu
    
    $selection = Read-Host "Please make a selection"
    
    switch ($selection)
        {
          '1' {
        'Checking for adminCount attribute greater than 0 on all users'
        adminCount
        } '2' {
        'Checking for Disabled Users with the adminCount attribute greather than 0'
        disabledAdmin
        } '3' {
        'Removing the adminCount values for Disabled Users with the adminCount attribute greather than 0'
        resetadminCount
        } '4' {
        'Checking for all elevated admin accounts with AccountnotDelegated unset (Domain Admin).'
        notDelegated
        } '5' {
        'Setting AccountnotDelegated for all elevated admin accounts (Domain Admin).'
        SetnotDelegated
        } '6' {
        'Searching for all members of Enterprise Administrators group.'
        getEnterpriseAdmin
        } '7' {
        'Removing membership for all members of Enterprise Administrators group.'
        removeEnterpriseAdmin
        } '8' {
        'Searching for all members of Schema Administrators group.'
        getEnterpriseAdmin
        } '9' {
        'Removing membership for all members of Schema Administrators group.'
        removeEnterpriseAdmin
        } '10' {
        'Searching for all admin accounts with PasswordNeverExpires set. (Excluding service accounts)'
        getPwdNeverExpires
        } '11' {
        'Removing flag for all admin accounts with PasswordNeverExpires set. (Excluding Service Accounts)'
        removePwdNeverExpires
        } '12' {
        'Searching for all disabled members of Domain Admins and Enterprise Admins groups'
        findDisabledAdmins
        } '13' {
        'Removing all disabled members of Domain Admins and Enterprise Admins groups'
        removeDisabledAdmins
        } '14' {
        'Running all Modules'
        all
        } 'H' {
        Help
        }
        }
        pause
 }
 until ($selection -eq 'q')
