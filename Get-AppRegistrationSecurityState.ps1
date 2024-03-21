function Get-AppRegistrationSecurityState {
    [CmdletBinding()]
    param (
        [switch]$Advices,
        [switch]$isConnected
    )
    
    begin {
        if(-not ($isConnected)){
            try {
                Import-Module Microsoft.Graph.Applications, ExchangeOnlineManagement
                Connect-ExchangeOnline -ShowBanner:$false
                Connect-MGGraph -Scopes "Application.Read.All" -NoWelcome
            }
            catch {
                Write-Error -Message "Unable to connect to Exchange Online or Microsoft Graph API. Please make sure you have the appropriate permissions to access the Microsoft Graph API."
                return
            }
        }
        $AppRoles = (Get-MgServicePrincipal -All | Where-Object AppId -eq '00000003-0000-0000-c000-000000000000').AppRoles
    }
    
    process {
        $States = $(foreach($App in $(Get-MgApplication)){
            $ServicePrincipalID = (Get-MgServicePrincipalByAppId -AppId $App.AppId).ID
            $Scopes = $((Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $ServicePrincipalID).AppRoleId.ForEach({
                ($AppRoles | Where-Object Id -eq $_).Value
            }))
            if($Scopes -match "mail.|contacts.|calendar.|mailboxsettings."){
                [PSCustomObject]@{
                    DisplayName = $App.DisplayName
                    AppId = $App.AppId
                    ID = $App.ID
                    ServicePrincipalID = $ServicePrincipalID
                    Scopes = $Scopes 
                    ApplicationAccessPolicyActive = -not [string]::IsNullOrEmpty(@(Get-ApplicationAccessPolicy | Where-Object AppID -eq $App.AppID))
                    RBACForApplicationActive = -not [string]::IsNullOrEmpty(@(Get-ManagementRoleAssignment | Where-Object App -eq $ServicePrincipalID))
                }
            }
        })
    }
    
    end {
        $States
        if($Advices){
            Switch ($States) {
                {$_.ApplicationAccessPolicyActive -and $_.RBACForApplicationActive} {
                    Write-Warning -Message "Application $($_.DisplayName) has RBAC role assignment and an Application Access Policy configured. Consider to switch to RBAC only."
                }
                {$_.ApplicationAccessPolicyActive -and -not $_.RBACForApplicationActive} {
                    Write-Warning -Message "Application $($_.DisplayName) is configured with an Application Access Policy, but no RBAC role assignment. Consider to switch to RBAC only."
                }
                {-not $_.ApplicationAccessPolicyActive -and $_.RBACForApplicationActive} {
                    Write-Information -Message "Application $($_.DisplayName) is configured with only an RBAC role assignment."
                }
                {-not $_.ApplicationAccessPolicyActive -and -not $_.RBACForApplicationActive} {
                    Write-Warning -Message "Application $($_.DisplayName) is not configured correctly. Please configure an RBAC role assignment."
                }
            }
        }
    }
}