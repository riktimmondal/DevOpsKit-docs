
Import-Module Az #-Scope CurrentUser -AllowClobber -Repository PSGallery -Force

function Get-AzSKLSASScanStatus
{
    Param(
        
    [string]
    [Parameter(Mandatory = $true, HelpMessage="SubscriptionId")]
    $SubscriptionId,

    [string]
    $Scope = "/subscriptions/$SubscriptionId"

    )
    
    Begin
    {
        $currentContext = $null
        $contextHelper = [ContextHelper]::new()
        $currentContext = $contextHelper.SetContext($SubscriptionId)
        #Connect-AzureAD
        if(-not $currentContext)
        {
            return;
        }
    }

    Process
    {

        Write-Host $([Constants]::DoubleDashLine)
        Write-Host "Running LSAS Security Scan...`n" -ForegroundColor $([Constants]::MessageType.Info)
        Write-Host $([Constants]::InstallSolutionInstructionMsg ) -ForegroundColor $([Constants]::MessageType.Info)
        Write-Host $([Constants]::SingleDashLine)

        Write-Host "Getting subscription RBAC details. This may take a while...`n" -ForegroundColor $([Constants]::MessageType.Info)

        # Get all role assignments
        $allRAs = Get-AzRoleAssignment
        
        # Unknown identities at all scopes
        $unknownRAsAllScope = $allRAs | ? {$_.ObjectType -eq 'Unknown'}

        #All currently assigned roles in sub (all scopes)
        $uniqueRoles = $allRAs |% {$_.RoleDefinitionName} | Sort-Object -Unique


        #Just get RAs at sub scope (not incl MG or RG or Rsrc level RAs)
        $allRAsSubScope = $allRAs | ? {$_.Scope -eq $Scope}

        $unknownRAs = $allRAsSubScope | ? {$_.ObjectType -eq 'Unknown'}
        $allValidRAs = $allRAsSubScope | ? {$_.ObjectType -ne 'Unknown'}

        $privilegedRoles = @('Owner','Contributor','User Access Administrator')

        $allPrivRAs = $allValidRAs | ? {$privilegedRoles -contains $_.RoleDefinitionName}

        $allPrivSPNRAs = $allPrivRAs | ? {$_.ObjectType -eq 'ServicePrincipal'}

        #caad
        $allPrivSPNOwners = @()
        $spnWithoutOwners = @()
        $spnWithoutApps =  @()
        
        $identityModel 

        #Build list of owners of privileged SPNs
        $allPrivSPNRAs | % {
            $spnOid = $_.ObjectId
            $spnOwner = Get-AzureADServicePrincipalOwner -ObjectId $spnOid

            if(($spnOwner | Measure-Object).Count -gt 0)
            {

                $allPrivSPNOwners += $spnOwner
            }
            else{
               
               #Check if linked AD application has any Owner
               # Skip MSPIM applications
               if($_.DisplayName -ine 'MS-PIM')
               {

                    $spnDetails = Get-AzADServicePrincipal -ObjectId $_.ObjectId

                    $appDetails = Get-AzADApplication -ApplicationId $spnDetails.ApplicationId  -ErrorAction SilentlyContinue

                    if(($appDetails | Measure-Object).Count -gt 0)
                    {
                        $appOwners = Get-AzureADApplicationOwner -ObjectId  $appDetails.ObjectId

                        if(  ($appOwners | Measure-Object).Count -eq 0)
                        {
                            $spnWithoutOwners +=  $_
                        }
                    }
                    # SPN without application details can be enterprise apps which does not get returned with the help of Get-AzADApp
                    else
                    {
                        $spnWithoutApps +=  $_
                    }
               
                    
               }
              
            }
            
        }


        #Sort unique, this is list of (end user) owners of privileged SPNs
        $allPrivSPNOwners = $allPrivSPNOwners | Sort-Object ObjectId -Unique

 

        #Get all users in privileged roles
        $allPrivUserRAs = $allPrivRAs | ? {$_.ObjectType -eq 'User'}

 

        #Sort unique, this is list of end users with privileged roles
        $allPrivUserRAs = $allPrivUserRAs | Sort-Object ObjectId -Unique
        $allPrivUsersOids = $allPrivUserRAs.ObjectId

 

        #Get all SPNs whose owners are themselves *not* in privileged roles in the sub.
        $lsasUsers = $allPrivSPNOwners | ? { $allPrivUsersOids -notcontains $_.ObjectId}

        # exclude MS-PIM SPNs
        Write-Host $([Constants]::SingleDashLine)

        #*****Step 1*****: Check for deleted application objects having access on subscription

        Write-Host "Deleted application object(s) having access on subscription:" -ForegroundColor $([Constants]::MessageType.Info)

        if(($unknownRAsAllScope | Measure-Object).Count -gt 0)
        {
           Write-Host  ($unknownRAsAllScope | Select-Object ObjectId, ObjectType,@{label="RoleDefinitionName";expression={if($_.RoleDefinitionName.Length -gt 20) { $_.RoleDefinitionName.Substring(0,17) + "..." } else {$_.RoleDefinitionName }}} , Scope | FT -Wrap | Out-String)         
        }
        else
        {
             Write-Host "No deleted application object(s) found." -ForegroundColor $([Constants]::MessageType.Update)
        }

         #*****Step 2*****: Check for deleted application objects having access on subscription
        Write-Host $([Constants]::SingleDashLine)

        Write-Host "Service principal(s) without owner(s) having access on subscription:" -ForegroundColor $([Constants]::MessageType.Info)

        if(($spnWithoutOwners | Measure-Object).Count -gt 0)
        {
          #Write-Host  ($spnWithoutOwners | Select ObjectId, DisplayName, RoleDefinitionName, Scope | FT -Wrap | Out-String)
          Write-Host  ($spnWithoutOwners | Select @{label="ObjectId";expression={$_.ObjectId}} , @{label="DisplayName";expression={$_.DisplayName}}, @{label="RoleDefinitionName";expression={if($_.RoleDefinitionName.Length -gt 20) { $_.RoleDefinitionName.Substring(0,17) + "..." } else {$_.RoleDefinitionName }}}, @{label="Scope";expression={$_.Scope}} | FT -Wrap | Out-String)
        }
        else
        {
             Write-Host "No Service principal(s) found without owner(s)" -ForegroundColor $([Constants]::MessageType.Update)
        }

        #*******Step 3******* Check for application privileged roles but owner does not have role in subscription
        Write-Host $([Constants]::SingleDashLine)

        Write-Host "Application(s) with privileged roles but owner does not have role in subscription:" -ForegroundColor $([Constants]::MessageType.Info)

        if(($lsasUsers | Measure-Object).Count -gt 0)
        {
            Write-Host  ($lsasUsers | Select @{label="ObjectId";expression={$_.ObjectId}} , @{label="DisplayName";expression={if($_.DisplayName.Length -gt 15) { $_.DisplayName.Substring(0,15) + "..." } else {$_.DisplayName}}}, @{label="UserPrincipalName";expression={$_.UserPrincipalName}}, UserType | FT -Wrap | Out-String)
        }
        else
        {
             Write-Host "No Service principal(s) found without owner(s)" -ForegroundColor $([Constants]::MessageType.Update)
        }

        #*******Step 4****** Check for inactive identities 

        # Get workspace id from Security Center
        Write-Host $([Constants]::SingleDashLine)

        Write-Host "Users and service principal(s) with no control plane activity on subscription in last 90 days:" -ForegroundColor $([Constants]::MessageType.Info)

        
        $workspaceAPI = "https://management.azure.com/subscriptions/$($SubscriptionId)/providers/Microsoft.Security/workspaceSettings/default?api-version=2017-08-01-preview"
        $accessToken = $contextHelper.GetAccessToken(  "https://management.azure.com")
        try
        {
            $wapiResponse = Invoke-WebRequest -Method GET -Uri $workspaceAPI  -Headers @{"Authorization" = "Bearer $accessToken"; "Content-Type"= "application/json"} -ErrorAction Ignore
            $workspaceDetails = $wapiResponse.Content | ConvertFrom-Json
            if($workspaceDetails.properties -and $workspaceDetails.properties.workspaceId)
            {
                
                $wrDetail =Get-AzResource -ResourceId $workspaceDetails.properties.workspaceId

                if(($wrDetail | Measure-Object).Count -gt 0 )
                {
                    $workspaceId = $wrDetail.Properties.customerId
                    $workspaceAPI = "https://api.loganalytics.io/v1/workspaces/$WorkSpaceID/query"
                    $accessToken = $contextHelper.GetAccessToken(  "https://api.loganalytics.io/")
                    $activeIdentitiesQuery = "{'query': 'AzureActivity\r\n| where TimeGenerated > ago(90d) and  Type == \'AzureActivity\' and SubscriptionId == \'$($SubscriptionID)\'\r\n| summarize arg_max(TimeGenerated, *) by Caller \r\n| project Caller, TimeGenerated\r\n'}" | ConvertFrom-Json
                    $apiResponse = Invoke-WebRequest -Method POST -Uri $workspaceAPI -Headers @{"Authorization" = "Bearer $accessToken"; "Content-Type"= "application/json"} -Body ($activeIdentitiesQuery | ConvertTo-Json -Depth 10 -Compress)
                
                    $activeIdentitiesDetails = $apiResponse.Content | ConvertFrom-Json

                    $activeIdentities =@()

                    $activeIdentitiesDetails.tables.rows | foreach-object { 
                        [Guid] $validatedId = [Guid]::Empty;
                        if([Guid]::TryParse($_[0], [ref] $validatedId))
		                {
                            $activeIdentities += @{ "SignInName" = ""; "LastActivityDate" = $_[1]; "ObjectId" = $_[0];"ObjectType"= "ServicePrincipal" }
                        }
                        else
                        {
                            $activeIdentities += @{ "SignInName" = $_[0]; "LastActivityDate" = $_[1]; "ObjectId" = "";"ObjectType"= "NonSPN" }
                        }                    
                     }

                     # Skip management group assignments + groups + MS-PIM 
                     $activeAssignments =  $allRAs | where {$_.Scope -notmatch "/providers/Microsoft.Management" -and $_.ObjectType -ne 'Unknown' -and $_.ObjectType -ne "Group" -and $_.DisplayName -notmatch "MS-PIM"} | Select-Object SignInName, ObjectId, ObjectType -Unique
                     $inactiveIdenties = @()
                     $activeAssignments | % {
                     $identity = $_
                         if($identity.ObjectType -eq "User")
                         {
                              $identityAssignment = $activeIdentities | Where-Object {$_.SignInName -eq $identity.SignInName}

                              if(($identityAssignment | Measure-Object).Count -eq 0)
                              {
                                $inactiveIdenties += $identity.ObjectId
                              }
                         }
                         elseif($_.ObjectType -eq "ServicePrincipal")
                         {
                            $identityAssignment = $activeIdentities | Where-Object {$_.ObjectId -eq $identity.ObjectId}

                              if(($identityAssignment | Measure-Object).Count -eq 0)
                              {
                                $inactiveIdenties += $identity.ObjectId
                              }
                         }
                         else{
                            Write-Debug "Type $($identity.ObjectType) not supported for validation"   
                         }
                     }

                     if(($inactiveIdenties | Measure-Object).Count -gt 0)
                     {
                        $inactiveIdenties = $inactiveIdenties | Select-Object -Unique
                        $inactiveIdentityAssignments = $allRAs | Where-Object { $_.ObjectId -in $inactiveIdenties} | Select-Object DisplayName, ObjectId, ObjectType, @{label="RoleDefinitionName";expression={if($_.RoleDefinitionName.Length -gt 20) { $_.RoleDefinitionName.Substring(0,17) + "..." } else {$_.RoleDefinitionName }}}, Scope

                        Write-Host  ($inactiveIdentityAssignments | Select @{label="ObjectId";expression={$_.ObjectId}} , @{label="DisplayName";expression={if($_.DisplayName.Length -gt 15) { $_.DisplayName.Substring(0,15) + "..." } else {$_.DisplayName}}} ,ObjectType, @{label="RoleDefinitionName";expression={if($_.RoleDefinitionName.Length -gt 20) { $_.RoleDefinitionName.Substring(0,17) + "..." } else {$_.RoleDefinitionName }}}, @{label="Scope";expression={$_.Scope}} | FT -Wrap | Out-String)
                     }
                     else
                        {
                                Write-Host "No inactive users and service principal(s) found" -ForegroundColor $([Constants]::MessageType.Update)
                        }
                }
                else
                {
                    Write-Host "Activity logs workspace resource not found to validate active identities." -ForegroundColor $([Constants]::MessageType.Warning)
                }
            
            }
            else
            {
                Write-Host "Activity logs workspace not found to validate active identities." -ForegroundColor $([Constants]::MessageType.Warning)
            }

        }
        catch{
             Write-Host "Activity logs can not be checked. $($_.ErrorDetails.Message)." -ForegroundColor $([Constants]::MessageType.Warning)
        }

        Write-Host "$([Constants]::DoubleDashLine)" #-ForegroundColor $([Constants]::MessageType.Info)
                Write-Host "$([Constants]::NextSteps)" -ForegroundColor $([Constants]::MessageType.Info)
                Write-Host "$([Constants]::DoubleDashLine)"

    }

}

class Constants
{
    static [Hashtable] $MessageType = @{
        Error = [System.ConsoleColor]::Red
        Warning = [System.ConsoleColor]::Yellow
        Info = [System.ConsoleColor]::Cyan
        Update = [System.ConsoleColor]::Green
	    Default = [System.ConsoleColor]::White
    }

    static [string] $InstallSolutionInstructionMsg = "This command will perform 4 important checks on identities having access on sub. It will:`r`n`n" + 
					"   [1] Check for deleted application objects having access on subscription  `r`n" +
                    "   [2] Check for applications having access on subscription but no owners `r`n" +
                    "   [3] Check for applications with privileged roles but owner does not have role in subscription `r`n" +
					"   [4] Check for users and applications having with no control plane activity using activity logs `r`n`n"
                    
    static [string] $DoubleDashLine    = "================================================================================"
    static [string] $SingleDashLine    = "--------------------------------------------------------------------------------"
    
    static [string] $NextSteps = "** Next steps **`r`n" + 
    "        a) Review highlighted identities access and remove all unwanted roles.`r`n" +
    "        b) For more details refer: http://aka.ms/DevOpsKit/LSAS .`r`n" +
    "        c) For any feedback contact us at: azsksupext@microsoft.com .`r`n"
}


class ContextHelper
{

    [PSObject] $currentContext;

    [PSObject] SetContext([string] $SubscriptionId)
    {
            $this.currentContext = $null
            if(-not $SubscriptionId)
            {

                Write-Host "The argument 'SubscriptionId' is null. Please specify a valid subscription id." -ForegroundColor $([Constants]::MessageType.Error)
                return $null;
            }

            # Login to Azure and set context
            try
            {
                if(Get-Command -Name Get-AzContext -ErrorAction Stop)
                {
                    $this.currentContext = Get-AzContext -ErrorAction Stop
                    $isLoginRequired = (-not $this.currentContext) -or (-not $this.currentContext | GM Subscription) -or (-not $this.currentContext | GM Account)
                    
                    # Request login if context is empty
                    if($isLoginRequired)
                    {
                        Write-Host "No active Azure login session found. Initiating login flow..." -ForegroundColor $([Constants]::MessageType.Warning)
                        $this.currentContext = Connect-AzAccount -ErrorAction Stop # -SubscriptionId $SubscriptionId
                    }
            
                    # Switch context if the subscription in the current context does not the subscription id given by the user
                    $isContextValid = ($this.currentContext) -and ($this.currentContext | GM Subscription) -and ($this.currentContext.Subscription | GM Id)
                    if($isContextValid)
                    {
                        # Switch context
                        if($this.currentContext.Subscription.Id -ne $SubscriptionId)
                        {
                            $this.currentContext = Set-AzContext -SubscriptionId $SubscriptionId -ErrorAction Stop -Force
                        }
                    }
                    else
                    {
                        Write-Host "Invalid PS context. ErrorMessage [$($_)]" -ForegroundColor $([Constants]::MessageType.Error)
                    }

                    #TODO: do it one time
                    
                }
                else
                {
                    Write-Host "Az command not found. Please run the following command 'Install-Module Az -Scope CurrentUser -Repository 'PSGallery' -AllowClobber -SkipPublisherCheck' to install Az module." -ForegroundColor $([Constants]::MessageType.Error)
                }
            }
            catch
            {
                Write-Host "Error occured while logging into Azure. ErrorMessage [$($_)]" -ForegroundColor $([Constants]::MessageType.Error)
                return $null;
            }

            return $this.currentContext;
    
    }

    [string] GetAccessToken([string] $resourceAppIdUri, [string] $tenantId) 
    {
        $rmContext = $this.currentContext
        if (-not $rmContext) {
        throw ("No Azure login found")
        }
        
        
        $tenantId = $rmContext.Tenant.Id
        
        
        $authResult = [Microsoft.Azure.Commands.Common.Authentication.AzureSession]::Instance.AuthenticationFactory.Authenticate(
        $rmContext.Account,
        $rmContext.Environment,
        $tenantId,
        [System.Security.SecureString] $null,
        "Never",
        $null,
        $resourceAppIdUri);
        
        if (-not ($authResult -and (-not [string]::IsNullOrWhiteSpace($authResult.AccessToken)))) {
          throw "Unable to get access token. Authentication Failed."
        }
        return $authResult.AccessToken;
    }

    [string] GetAccessToken([string] $resourceAppIdUri) {
        return $this.GetAccessToken($resourceAppIdUri, "");
    }
    
}
