<#
.SYNOPSIS
    Find NTLM Version of Logon Events on Domian Controllers
.DESCRIPTION
    Check Event Logs on Domain Controllers to Identify the NTLM Version Used in Authentication on the Network
.EXAMPLE
    ./AD-NTLMv1Auth.ps1
.COMPONENT
    PowerShell, Domain Admin Credentials, Domain Joined Machine
.ROLE
    Domain Admin Rights 
.FUNCTIONALITY
    Find NTLM Version of Logon Events on Domian Controllers by Searching for Event ID 4624 Where the Message Contains NTLM V1
#>

#Get Credentials

$creds = Get-Credential -Message "Please enter your Domain Admin credentials:"

#Get all Domain Controllers in the Environment
$DCs = Get-ADDomainController -Filter * | Select-Object name


########################### Let the magic begin! ###########################
#Loop through all the Domain Controllers and find Logon Events (Event ID 4624) with PackageName NTLM V1 in the Message Field
Foreach ($DC in $DCs.name){Invoke-Command -ComputerName $DC -Credential $creds {Get-WinEvent -FilterHashtable @{logname='security'; id=4624} | Where-Object {$_.message -like "*NTLM V1*"}}}

