<#
.SYNOPSIS
    Change kerberos account password to a randomly generated password
.DESCRIPTION
    Change kerberos account password to a randomly generated password
.COMPONENT
    PowerShell Active Directory Module
.ROLE
    Domain Admin
.FUNCTIONALITY
    Change kerberos account password to a randomly generated password
#>


function Pass { 

#Generate Password

Add-Type -AssemblyName 'System.Web'
$minLength = 120 ## characters
$maxLength = 128 ## characters
$length = Get-Random -Minimum $minLength -Maximum $maxLength
$nonAlphaChars = 10
$password = [System.Web.Security.Membership]::GeneratePassword($length, $nonAlphaChars)

Write-Output "The new password is" $password

$password2 = convertto-securestring $password -AsPlainText -Force

Return $password2

}


Function KrbtgtPwChange {
    Set-ADAccountPassword -Identity krbtgt -NewPassword (Pass)
    }

KrbtgtPwChange
