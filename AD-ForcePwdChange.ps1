<#
.SYNOPSIS
    Change users password, remove the PasswordNeverExpires flag, and set ChangePasswordAtLogon to force a password change
.DESCRIPTION
    Change users password, remove the PasswordNeverExpires flag, and set ChangePasswordAtLogon to force a password change
.INPUTS
    Username is required
.COMPONENT
    PowerShell Active Directory Module
.ROLE
    Sufficient AD rights to manage user objects
.FUNCTIONALITY
    Change users password, remove the PasswordNeverExpires flag, and set ChangePasswordAtLogon to force a password change
#>


function Pass { 

#Generate Password

Add-Type -AssemblyName 'System.Web'
$minLength = 90 ## characters
$maxLength = 120 ## characters
$length = Get-Random -Minimum $minLength -Maximum $maxLength
$nonAlphaChars = 5
$password = [System.Web.Security.Membership]::GeneratePassword($length, $nonAlphaChars)

Write-Host "The new password is" $password

$password2 = convertto-securestring $password -AsPlainText -Force

Return $password2

}


$user = Read-Host -Prompt "Enter User SAMAccountName"


$uName = Get-ADUser $user


Set-ADAccountPassword -Identity $uName -NewPassword (Pass)

Set-ADUser $uName -PasswordNeverExpires $false

Set-ADUser $uName -ChangePasswordAtLogon $true

