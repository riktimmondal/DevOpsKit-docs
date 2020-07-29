
#Install-Module AzureAD -Scope CurrentUser -AllowClobber -Repository PSGallery -Force

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
        
        $identityModel 

        #Build list of owners of privileged SPNs
        $allPrivSPNRAs | % {
            $spnOid = $_.ObjectId
            $spnOwner = Get-AzureADServicePrincipalOwner -ObjectId $spnOid

            if($spnOwner)
            {

                $allPrivSPNOwners += $spnOwner
            }
            else{
               if($_.DisplayName -ine 'MS-PIM')
               {
                    $spnWithoutOwners +=  $_
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

        Write-Host "Deleted application object(s) having access on subscription:" -ForegroundColor $([Constants]::MessageType.Info)

        if(($unknownRAsAllScope | Measure-Object).Count -gt 0)
        {
           Write-Host  ($unknownRAsAllScope | Select-Object ObjectId, ObjectType, RoleDefinitionName, Scope | FT -Wrap | Out-String)         
           }
        else
        {
             Write-Host "No deleted application object(s) found." -ForegroundColor $([Constants]::MessageType.Update)
        }

        Write-Host $([Constants]::SingleDashLine)

        Write-Host "Service principal(s) without owner(s) having access on subscription:" -ForegroundColor $([Constants]::MessageType.Info)

        if(($spnWithoutOwners | Measure-Object).Count -gt 0)
        {
          Write-Host  ($spnWithoutOwners | Select ObjectId, DisplayName, RoleDefinitionName, Scope | FT -Wrap | Out-String)
        }
        else
        {
             Write-Host "No Service principal(s) found without owner(s)" -ForegroundColor $([Constants]::MessageType.Update)
        }

        Write-Host $([Constants]::SingleDashLine)

        Write-Host "Application(s) with privileged roles but owner does not have role in subscription:" -ForegroundColor $([Constants]::MessageType.Info)

        if(($lsasUsers | Measure-Object).Count -gt 0)
        {
             $lsasUsers
        }
        else
        {
             Write-Host "No Service principal(s) found without owner(s)" -ForegroundColor $([Constants]::MessageType.Update)
        }
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
					"   [4] Check for users and applications having with no control plane activity using activity logs `r`n`n" +
                    "More details about resources created can be found in the link: http://aka.ms/DevOpsKit/LSAS `r`n"
    static [string] $DoubleDashLine    = "================================================================================"
    static [string] $SingleDashLine    = "--------------------------------------------------------------------------------"
    
    static [string] $NextSteps = "** Next steps **`r`n" + 
    "        a) Review highlighted identities access and remove all unwanted roles.`r`n" +
    "        b) You can create compliance monitoring Power BI dashboard using link: http://aka.ms/DevOpsKit/TenantSecurityDashboard .`r`n" +
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
                            $this.currentContext = Set-AzContext -SubscriptionId $SubscriptionId -ErrorAction Stop
                        }
                    }
                    else
                    {
                        Write-Host "Invalid PS context. ErrorMessage [$($_)]" -ForegroundColor $([Constants]::MessageType.Error)
                    }
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





 



 



