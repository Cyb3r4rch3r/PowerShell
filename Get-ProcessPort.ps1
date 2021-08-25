<#
.Description
 Queries a list of machines for the specified process running and returns network port information
.Example
 ./Get-ProcessPort.ps1 -FileName computers.txt -Output Results.txt -Process explorer.exe

#>


param (
	[Parameter(Mandatory = $true,
		HelpMessage = 'Input file containing list of computer names')]
	[string] $FileName,
	[Parameter(Mandatory = $true,
		HelpMessage = 'Output path for report')]
	[string] $OutPath,
    [Parameter(Mandatory = $true,
		HelpMessage = 'Specified Process to investigate')]
	[string] $Process
)

$file = $FileName

$output = $OutPath

$global:servicename = $Process

$computers = get-content $file


foreach ($computer in $computers){ 
    if (((Test-Connection -computername $computer) -notlike "") -or ((Test-Connection -computername $computer) -notlike $null)){
        Write-Output "$computer is online."
        invoke-command -computername $computer {
            $proc = Get-WmiObject -Class Win32_Service -Filter "Name like '$servicename'" | Select-Object name, processid
            $target = Get-NetTCPConnection | Where-Object {$_.owningprocess -eq $proc.processid} | Select-Object LocalAddress, LocalPort, RemoteAddress
            Write-Output "Target machine is running $($proc.name), with PID $($proc.processid), on the following port $($target.LocalPort)`n"} 
            out-file $output -Append
        }
    Else {
        Write-Output "$computer is not online.`n" | Out-File $output -Append
    }
}
