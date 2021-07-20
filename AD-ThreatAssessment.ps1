#Present the user with a menu of options
function Show-Menu
{
     param (
           [string]$Title = 'Active Directory Threat Assessment'
     )
     cls
     Write-Host "================ $Title ================"
	 
 	 Write-Host "    .o oOOOOOOOo                                            OOOo"
	 Write-Host "    Ob.OOOOOOOo  OOOo.      oOOo.                      .adOOOOOOO"
	 Write-Host "    OboO`"`"`"`"`"`"`"`"`"`"`"`".OOo. .oOOOOOo.    OOOo.oOOOOOo..`"`"`"`"`"`"`"`"`"'OO"
	 Write-Host "    OOP.oOOOOOOOOOOO `"POOOOOOOOOOOo.   `"OOOOOOOOOP,OOOOOOOOOOOB'"
	 Write-Host "    `O'OOOO'     `OOOOo`"OOOOOOOOOOO` .adOOOOOOOOO`"oOOO'    `OOOOo"
	 Write-Host "    .OOOO'            `OOOOOOOOOOOOOOOOOOOOOOOOOO'            `OO"
	 Write-Host "    OOOOO                 '`"OOOOOOOOOOOOOOOO`"`                oOO"
	 Write-Host "   oOOOOOba.                .adOOOOOOOOOOba               .adOOOOo."
	 Write-Host "  oOOOOOOOOOOOOOba.    .adOOOOOOOOOO@^OOOOOOOba.     .adOOOOOOOOOOOO"
	 Write-Host " OOOOOOOOOOOOOOOOO.OOOOOOOOOOOOOO`"`  '`"OOOOOOOOOOOOO.OOOOOOOOOOOOOO"
	 Write-Host " `"OOOO`"       `"YOoOOOOMOIONODOO`"`  .   '`"OOROAOPOEOOOoOY`"     `"OOO`""
	 Write-Host "    Y           'OOOOOOOOOOOOOO: .oOOo. :OOOOOOOOOOO?'         :"
	 Write-Host "    :            .oO%OOOOOOOOOOo.OOOOOO.oOOOOOOOOOOOO?         ."
	 Write-Host "    .            oOOP`"%OOOOOOOOoOOOOOOO?oOOOOO?OOOO`"OOo"
	 Write-Host "                 '%o  OOOO`"%OOOO%`"%OOOOO`"OOOOOO`"OOO':"
	 Write-Host "                      `$`"  `OOOO' `O`"Y ' `OOOO'  o             ."
	 Write-Host "    .                  .     OP`"          : o     ."
	 Write-Host "                              :"
	 Write-Host "                              ."	 
    
     Write-Host "1: Press '1' for All users with PasswordNotRequired flag."
     Write-Host "2: Press '2' for ll users with Non-Expiring Passwords."
     Write-Host "3: Press '3' for all users with AdminCount Flag."
	 Write-Host "4: Press '4' to find all Computers added to Domain by User."
	 Write-Host "5: Press '5' to find all Kerberoastable Acccounts."
	 Write-Host "6: Press '6' to find all users who can reset passwords."
	 Write-Host "7: Press '7' to find all users with passwords stored using Reversible Encryption."
	 Write-Host "8: Press '8' to find all users vulnerable to AS-REP Roasting."
	 Write-Host "9: Press '9' to find all Admins with passwords older than 120 days."
	 Write-Host "10: Press '10' to find stored credentials in SYSVOL network share folders."
	 Write-Host "11: Press '11' for All Modules."
     Write-Host "Q: Press 'Q' to quit."
}

################ BEGIN FUNCTIONS ################

#1
Function PasswordNotRequired {
	#Find all users with PasswordNotRequired Flag
	Write-host "Searching for all accounts with the PasswordNotRequired flag set."
	Get-ADUser -Filter {UserAccountControl -band 0x0020}
	}
	
#2	
Function PasswordNeverExpires {	
	#Find all users with Non-Expiring Passwords
	Get-ADUser -filter * -properties Name, SAMAccountName, PasswordNeverExpires, Description, Title, Department | where { $_.passwordNeverExpires -eq "true" } | where {$_.enabled -eq "true" }
	}
	
#3	
Function AdminFlagSet {	
	#Find all users with AdminCount Flag
	Get-AdObject -ldapfilter "(admincount=1)" -properties admincount
	}
	
#4	
Function DomainJoined {	
	#Find all Computers added to Domain by User
	Get-ADComputer -LDAPFilter "(ms-DS-CreatorSID=*)" -Properties ms-DS-CreatorSID
	}
	
#5	
Function Kerberoastable {	
	#Find all Kerberoastable Acccounts
	get-aduser -filter * -pr ServicePrincipalNames | ? {$_.ServicePrincipalNames -like "*"} | select name, samaccountname, ServicePrincipalNames
	}
	
#6	
Function PasswordReset {	
	#Find all users who can reset passwords
	dsacls (Get-addomain) | select-string "Reset Password"
	}
	
#7
Function ReversibleEncryption {	
	#Find all users with passwords stored using Reversible Encryption
	Get-ADUser -Filter 'userAccountControl -band 128' -Properties userAccountControl
	}
	
#8	
Function AS-REP {	
	#Find all users vulnerable to AS-REP Roasting
	Get-ADuser -filter * -properties DoesNotRequirePreAuth | where {($_.DoesNotRequirePreAuth -eq $true) -and ($_.Enabled -eq $true)} | select Name
	}
	
#9		
Function AdminswithOldPasswords {	
	#Find all Admins with passwords older than 120 days
	$admins = Get-AdObject -ldapfilter "(admincount=1)"

	foreach ($admin in $admins) {
		$ErrorActionPreference = "silentlycontinue"
		$admins = Get-ADUser $admin -Properties PasswordLastSet | Where-Object {$_.PasswordLastSet -lt (Get-Date).adddays(-120)} | select Name,enabled,SamAccountName,PasswordLastSet
		$admins | FT -AutoSize
		}
	}
	
#10	
Function HardCodedCreds {
	#Find stored credentials in SYSVOL network share folders
	$domain = Get-addomain | select Forest
	
	findstr /s /n /i /p password \\$domain\sysvol\$domain\*
	}
	
	
#11
Function ALL {
	PasswordNotRequired
	PasswordNeverExpires
	AdminFlagSet
	DomainJoined
	Kerberoastable
	PasswordReset
	ReversibleEncryption
	AS-REP
	AdminswithOldPasswords
	HardCodedCreds
	}
	
################ BEGIN MENU ################

#Menu choices
do
{
     Show-Menu
     $input = Read-Host "Please make a selection. (Default is "ALL")"
     switch ($input)
     {
           '1' {
                cls
				'Running PasswordNotRequired Module'
				PasswordNotRequired
           } '2' {
                cls
                'Running Non-Expiring Passwords Module'
				PasswordNeverExpires
           } '3' {
                cls
                'Running AdminCount Flag Module'
				AdminFlagSet
           } '4' {
                cls
                'Running Computers added to Domain Module'
				DomainJoined
           } '5' {
                cls
                'Running Kerberoastable Acccounts Module'
				Kerberoastable
		   } '6' {
                cls
                'Running Delegated Password Resets Module'
				PasswordReset
           } '7' {
                cls
                'Running Reversible Encryption Module'
				ReversibleEncryption
           } '8' {
                cls
                'Running AS-REP Roasting Module'
				AS-REP
           } '9' {
                cls
                'Running Admins with Old Passwords Module'
				AdminswithOldPasswords
           } '10' {
                cls
                'Running Stored Credentials Module'
				HardCodedCreds
           } '11' {
                cls
                'Running All Modules'
				ALL
           } 'q' {
                return
           }
     }
     pause
}
until ($input -eq 'q')
