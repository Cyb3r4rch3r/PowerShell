<#
.SYNOPSIS
    Test for overly permissive ACLs on SAM and SYSTEM files in C:\Windows\System32\config\SAM and Volume Shadow Copies
.DESCRIPTION
    Test for overly permissive ACLs on SAM and SYSTEM files in C:\Windows\System32\config\SAM and Volume Shadow Copies
.EXAMPLE
    .\SeriousSam.ps1
.COMPONENT
    PowerShell, and sufficient rights to become admin
.ROLE
    Domain Admin or local administrator
#>

if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))  
{  
  $arguments = "& '" +$myinvocation.mycommand.definition + "'"
  Start-Process powershell -Verb runAs -ArgumentList $arguments
  Break
}

$paths = @("C:\Windows\System32\config\SAM","C:\Windows\System32\config\SYSTEM","C:\Windows\System32\config\SECURITY","\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SAM","\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM","\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SECURITY")

foreach ($path in $paths){
    Write-Output "Testing the following path for vulnerable permissions: `n$path"
    icacls $path /dbg
    Write-Output ""
}

Write-Output "Checking for existing Shadow Volumes"

Write-Output ""

vssadmin.exe list shadows

Write-Output ""

$fix = Read-Host -Prompt "Would you like to attempt remediation of the vulnerability? (Y|N)"

if ($fix -like 'y'){
    foreach ($path in $paths){
        icacls $path /reset
        $vss = Read-Host -Prompt "Would you like to attempt to delete existing shadow volumes? (Y|N) `nNOTICE: This may trigger EDR actions and be blocked. `nPlease be sure to work with your administrator to properly assess the value of this action."
        if ($vss -like 'y'){
            vssadmin.exe delete shadows /all /quiet
        }
        else {
            Write-Output "Shadow volumes remain intact. Please contact your administrator for next steps."
        }
    }
}
    else {
        Write-Output "Please consult your administrator for next steps."
    }
