<#
.SYNOPSIS
    Change users password, remove the PasswordNeverExpires flag, and set ChangePasswordAtLogon to force a password change for all stale user accounts that haven't logged in for 90 days or more
.DESCRIPTION
    Change users password, remove the PasswordNeverExpires flag, and set ChangePasswordAtLogon to force a password change for all stale user accounts that haven't logged in for 90 days or more
.INPUTS
    Username is required
.COMPONENT
    PowerShell Active Directory Module
.ROLE
    Sufficient AD rights to manage user objects
.FUNCTIONALITY
    Change users password, remove the PasswordNeverExpires flag, and set ChangePasswordAtLogon to force a password change for all stale user accounts that haven't logged in for 90 days or more
#>


$date = (Get-Date).AddDays(-90) 

$staleUsers = Get-ADUser -Filter {enabled -eq $true} | Where-Object {$_.lastlogondate -le $date}

function Generate-Pass { 

#Generate Password

Add-Type -AssemblyName 'System.Web'
$minLength = 90 ## characters
$maxLength = 120 ## characters
$length = Get-Random -Minimum $minLength -Maximum $maxLength
$nonAlphaChars = 5
$password = [System.Web.Security.Membership]::GeneratePassword($length, $nonAlphaChars)

Write-Output "The new password is" $password

$password2 = convertto-securestring $password -AsPlainText -Force

Return $password2

}


Function Start-Cleanup {
    foreach ($uName in $staleUsers) {
        Set-ADAccountPassword -Identity $uName.samaccountname -NewPassword (Generate-Pass)
        Set-ADUser $uName.samaccountname -PasswordNeverExpires $false
        Set-ADUser $uName.samaccountname -ChangePasswordAtLogon $true
        
        $grpMemberships = Get-ADPrincipalGroupMembership $uName.samaccountname  | where-object {$_.name -ne "Domain Users"} | Select-Object name

		foreach ($grpMembership in $grpMemberships.name) {
			Write-Output "$grpMembership found!"
			get-adgroup -filter "name -like '$grpMembership'" | Remove-ADGroupMember -members $uName.samaccountname -Confirm:$false
			Write-Output "Removing $($uName.name) from: $grpMembership"
			"$($uName.name) is a member of: $grpMembership" | out-file -filepath Disabled-Accounts-$(get-date -f yyy-MM-dd).txt -Append
			Write-Output ""
			}


        #Disable user
		Write-Output "Disabling $uName.name"
		Disable-ADAccount -identity $uName.samaccountname

        #Add Description
		$day = Get-Date -Format g
		Set-ADUser $uName.samaccountname -Description "Disabled by $admin on $day"
    }
}

Start-Cleanup
