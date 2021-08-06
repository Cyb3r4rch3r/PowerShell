<#
.SYNOPSIS
    Force Password Change for All Users Who Haven't Changed Their Passwords in 'N' Number of Days
.EXAMPLE
    ./AD-ExpirePasswords.ps1 
.INPUTS
    None
.COMPONENT
    PowerShell, Active Directory Module
.ROLE
    Sufficient Rights to Query AD
.FUNCTIONALITY
    Force Password Change for All Users Who Haven't Changed Their Passwords in 'N' Number of Days
#>

$username = $env:username

$file = "C:\Users\$username\Documents\users.txt"

Function Gather{
    $days = Read-Host -Prompt "Enter number of days you wish to exclude"
    $date = (get-date).adddays(-$days)
    Get-aduser -filter {(enabled -eq $true) -and (passwordlastset -lt $date) -and (name -notlike "*$")} | Select-Object samaccountname | Out-File $file
    }
    
$Answer = Read-Host -Prompt "Do you already have a file to work from? (Y|N)"

if ($Answer -eq "n"){
    Gather
    }

#Create Open File Dialogue to get path for Users.txt file
Function OpenFile{
    Add-Type -AssemblyName System.Windows.Forms
    $FileBrowser = New-Object System.Windows.Forms.OpenFileDialog -Property @{ InitialDirectory = [Environment]::GetFolderPath('MyDocuments') ; Filter = 'Documents (*.txt)|*.txt'}
    $null = $FileBrowser.ShowDialog()
    $path = $FileBrowser.FileName
    Return $path
  }

Function GetInfo {
    $count = Get-Content $file
    
    Write-Output "`n $($count.Count) users in file. `n"
    
    $chunk = Read-Host -Prompt "How many users do you want to apply this to? (Numerical values only)"
    
    $forceChange = $count | Select-Object -first $chunk
    
    foreach ($account in $forceChange){set-aduser $account -changepasswordatlogon $true -whatif}
    
    foreach ($user in $forceChange){write-output $user; Set-Content -Path $file -value(Get-Content $file | Select-String -Pattern $user -NotMatch)}
    
    $count = Get-Content $file
    
    Write-Output "`n $($count.Count) users Remaining"
}

if ((Test-Path $file) -eq $true){
    GetInfo
}
Else {
    Write-Error "File does not Exist. Please choose the correct path."
    $file = OpenFile

    GetInfo

}
