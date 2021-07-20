<#
.SYNOPSIS
    Create Managed Service Account
.EXAMPLE
    .\AD-MSA-Create -Name <Service Account Name> –Servers "<Server name (Must have $ at the end of the name) or Security Group>"
.INPUTS
    The Name and Servers parameters are required to create the Managed Service Account
.COMPONENT
    PowerShell Active Directory Module
.ROLE
    You MUST enter your Domain Admin credentials to use this script
.FUNCTIONALITY
    Create Managed Service Account
#>

param (
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$true)]
    [string] $Name,

    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$true)]
    [string] $Servers
)

$DNSname = $Name + "." + (get-addomain).dnsroot

Function MakeSVCAccount {
    New-ADServiceAccount -Name $Name -DNSHostName $DNSname -PrincipalsAllowedToRetrieveManagedPassword $Servers
}

MakeSVCAccount
