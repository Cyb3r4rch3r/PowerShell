<#
.SYNOPSIS
    Restrict Azure Active Directory and Microsoft Graph PowerShell Modules to Explicilty Assigned Users
.DESCRIPTION
    Restrict Azure Active Directory and Microsoft Graph PowerShell Modules to Explicilty Assigned Users
.INPUTS
    Directory Role or File Path
.COMPONENT
    PowerShell Azure Active Directory Module
.ROLE
    Sufficient rights in Azure AD
.FUNCTIONALITY
    Restrict Azure Active Directory and Microsoft Graph PowerShell Modules to Explicilty Assigned Users
#>


<#
Credit where credit is due:
  Scripts modified from originals by BillSluss here - https://github.com/OfficeDev/O365-EDU-Tools/tree/master/SDS%20Scripts/Block%20PowerShell
#>


function Show-Menu
{
     param (
           [string]$Title = 'Azure Active Directory and Microsoft Graph PowerShell Restrictions'
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
     Write-Host ""
     Write-Host "Press '1' to choose an Azure Active Directory Directory Role."
     Write-Host "Press '2' to provide a csv file with a list of admins."
     Write-Host "Press 'Q' to quit."
}

Function Confirm-Applications {
    #Define the applications to restrict
    $aad = "1b730954-1685-4b74-9bfd-dac224a7b894"

    $msGraph = "14d82eec-204b-4c2f-b7e8-296a70dab67e"

    $appIds = @($aad, $msGraph)

    Foreach ($appId in $appIds){
        Get-AzureADServicePrincipal -Filter "appId eq '$appId'"

        $global:servicePrincipal = Get-AzureADServicePrincipal -Filter "appId eq '$appId'"
        
        #Create a Service Principal for the application if it does not already exist
        if (-not $global:servicePrincipal) {
            $servicePrinciple = New-AzureADServicePrincipal -AppId $appId
        }
    
    #Require Application Assignment
    Set-AzureADServicePrincipal -ObjectId $global:servicePrincipal.ObjectId -AppRoleAssignmentRequired $true
    }
}

Function Confirm-DirRole{
    #Define the allowed users/roles
    $DirectoryRole = Read-Host -Prompt "Please Enter the DisplayName Property for the Chosen Role (eg Global Administrator)"

    $admins = Get-AzureADDirectoryRole | ? {$_.DisplayName -like "$DirectoryRole"} | Get-AzureADDirectoryRoleMember

    #Call the Applications to Restrict
    Confirm-Applications
    
    #Assign the Admins to the Applications
    foreach ($admin in $admins){
        New-AzureADServiceAppRoleAssignment -ObjectId $global:servicePrincipal.ObjectId -ResourceId $global:servicePrincipal.ObjectId -Id ([Guid]::Empty.ToString()) -PrincipalId $admin.ObjectID
        }
}

Function Confirm-ListAdmins {
    #Define the allowed users/roles
    $path = Read-Host "Please Enter the Path to the File Containing your List of Admin Accounts"

    $admins = import-csv $path
    
    #Call the Applications to Restrict
    Confirm-Applications

    #Assign the Admins to the Applications
    Foreach ($admin in $admins) {
        $user = Get-AzureADUser -objectId $admin.userprincipalname
        New-AzureADServiceAppRoleAssignment -ObjectId $global:servicePrincipal.ObjectId -ResourceId $global:servicePrincipal.ObjectId -Id ([Guid]::Empty.ToString()) -PrincipalId $user.ObjectId
    }
}


do
{
    Show-Menu
    
    $selection = Read-Host "Please make a selection"
    
    switch ($selection)
        {
          '1' {
        'Restricting Azure AD and Microsoft Graph PowerShell Modules to a Directory Role'
        Confirm-DirRole
        } '2' {
        'Restricting Azure AD and Microsoft Graph PowerShell Modules to a list of admins'
        Confirm-ListAdmins
        } 
        }
        pause
 }
 until ($selection -like '*')
