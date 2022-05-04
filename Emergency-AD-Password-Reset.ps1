<#
.SYNOPSIS
    Emergency Active Directory Password Reset - All users, Built-In Admin, Guest and Kerberos accounts included.
.DESCRIPTION
    Change users password, remove the PasswordNeverExpires flag, and set ChangePasswordAtLogon to force a password change for standard users, reset passwords for Built-In accounts
.INPUTS
    None
.COMPONENT
    PowerShell Active Directory Module
.ROLE
    Sufficient AD rights to manage user objects
.FUNCTIONALITY
    Change users password, remove the PasswordNeverExpires flag, and set ChangePasswordAtLogon to force a password change for standard users, reset passwords for Built-In accounts
#>


$builtin = @()
    
$SIDs = @("S-1-5-21-3647345944-1387174294-491510967-501","S-1-5-21-3647345944-1387174294-491510967-500","S-1-5-21-3647345944-1387174294-491510967-502")

Foreach ($SID in $SIDs){
    $builtin += Get-AdUser -filter {SID -eq $SID}
}
Function Kerberos-Set {
    Foreach ($account in $builtin.samaccountName){
        function Pass { 
            #Generate Password
            Add-Type -AssemblyName 'System.Web'
            $minLength = 120 ## characters
            $maxLength = 128 ## characters
            $length = Get-Random -Minimum $minLength -Maximum $maxLength
            $nonAlphaChars = 5
            $password = [System.Web.Security.Membership]::GeneratePassword($length, $nonAlphaChars)
            
            Write-Host "New password for $($account) is $password"

            $password2 = ConvertTo-SecureString -AsPlainText $password -Force
            
            Return $password2
            
            }

        Set-ADAccountPassword -Identity $account -NewPassword (Pass)
    }
 }


    
Function User-Set {
    $users = @()

    $min = Read-Host -Prompt "Enter the minimum number of characters"
    $max = Read-Host -Prompt "Enter the maximum number of characters"

        $allUsers = Get-AdUser -Filter *
		
		ForEach ($acct in $allUsers){
			If ($SIDs -notcontains $acct.SID){
				$users += $acct
				}
			}
		
    
        ForEach ($user in $users){
            function Pass { 
                #Generate Password
                Add-Type -AssemblyName 'System.Web'
                $minLength = $min
                $maxLength = $max
                $length = Get-Random -Minimum $minLength -Maximum $maxLength
                $nonAlphaChars = 5
                $password = [System.Web.Security.Membership]::GeneratePassword($length, $nonAlphaChars)
                
                Write-Host "New Password for $($user.samaccountName) is $password"

                $password2 = convertto-securestring $password -AsPlainText -Force
                
                Return $password2
                
                }

            Set-ADAccountPassword -Identity $user.samaccountName -NewPassword (Pass)

            Set-ADUser $user.samaccountName -PasswordNeverExpires $false

            Set-ADUser $user.samaccountName -ChangePasswordAtLogon $true
        }
    }
}

User-Set

Kerberos-Set