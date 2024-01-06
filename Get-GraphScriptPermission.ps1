<#
.SYNOPSIS
This function retrieves the possible Microsoft Graph permissions used in a PowerShell script.
.DESCRIPTION
The Get-GraphScriptPermission function takes a scriptblock as input and parses it to extract a list of command elements and their associated parameters. It then filters the list to include only the commands sourced from Microsoft.Graph. For each Microsoft.Graph command, it calls the Find-MgGraphCommand function to retrieve the permissions associated with that command. The function returns an object containing the command, its source, verb, noun, and the list of permissions with their names and whether they require admin privileges.
.PARAMETER Script
The scriptblock to be analyzed for Microsoft Graph commands and their permissions.
.EXAMPLE
$script = {
    Get-MgUser -Filter "Department eq 'Sales'"
    New-MgGroup -DisplayName 'Marketing Group' -Description 'Group for marketing team'
    Get-MGApplication -Filter "DisplayName eq 'My Application'"
}
Get-GraphScriptPermission -Script $script
This example retrieves the Microsoft Graph permissions used in the provided scriptblock.
.OUTPUTS
The function returns an object with the following properties for each Microsoft.Graph command:
- Cmdlet: The name of the command.
- Source: The source of the command.
- Verb: The verb of the command.
- Type: The noun of the command.
- AllPriviledges: An array of objects representing the permissions associated with the command. Each object has the following properties:
    - Name: The name of the permission.
    - IsAdmin: Indicates whether the permission requires admin privileges.
#>

function Get-GraphScriptPermission {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, Position = 0)]
        [scriptblock] $Script
    )
    
    begin {

        $ast = [System.Management.Automation.Language.Parser]::ParseInput($Script.ToString(), [ref]$null, [ref]$null)

        # Extract a list of command elements and their associated parameters from the AST
        $commandElementList = $ast.FindAll({$args[0].GetType().Name -like 'CommandAst'}, $true) | ForEach-Object {
            $Cmdlet = $_.CommandElements[0].Value
            $Command = Get-Command -Name $Cmdlet
            [pscustomobject]@{
                Cmdlet = $Cmdlet = $_.CommandElements[0].Value
                Source = $Command.Source
                Verb = $Command.Verb
                Type = $Command.Noun
                AllPriviledges = $null
                leastPriviledges = $null
            }
        }
    }
    
    process {
        foreach($GraphCommand in ($commandElementList | Where-Object Source -like 'Microsoft.Graph*')){            
            $GraphCommand.AllPriviledges = ((Find-MgGraphCommand -Command $GraphCommand.Cmdlet).Permissions | Sort-Object -Unique -Property Name).ForEach({
                [PSCustomObject]@{
                    Name = $_.Name
                    IsAdmin = $_.IsAdmin
                }
            })
            $GraphCommand.leastPriviledges = $GraphCommand.AllPriviledges | where-object {
                ($GraphCommand.Source).split(".")[-1] -eq $_.Name.split(".")[0] -or 
                ($GraphCommand.Source).split(".")[-1] -eq "$($_.Name.split(".")[0])s"
            }
            if($GraphCommand.Verb -eq "Get"){
                $GraphCommand.leastPriviledges = $GraphCommand.leastPriviledges | where-object Name -notlike "*Write*"
            }
            $GraphCommand
        }
    }
    
    end {
    }
}