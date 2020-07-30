# LSAS - Latent Security Access Scan [In Preview]

## Latent Security Access Scan
### Contents
- [Overview](Readme.md#overview)
- [Using Latent Security Access Scan - Step by Step](Readme.md#setting-up-tenant-security-solution---step-by-step)
- [Feedback](Readme.md#feedback)

-----------------------------------------------------------------
## Overview 
We have a very user account centric view of granting and revoking access.

When someone moves out of our team or project, we tend to remove them from various security groups or roles and relax with the thought that the user will not be able to access our project resources, services and other assets any more. However, we rarely truly assess all the indirect pathways of access from the person into the resources. For instance, in Azure, a user may own (or co-own) one or more applications or service principals and those may be configured with access to the subscription. So you may remove the person from the subscription RBAC (e.g., remove from Owner or Contributor) but that person may still own or possess credential of an SPN that has privileged access to the subscription. Similarly, in ADO, the same person may have created one or more service connections. Even though the person is removed from the project, they may retain access indirectly through those service connections.

By identifying and cleaning up such inadvertent vectors of access, the risks from accidental or malicious misuse via this attack vector can be reduced. Moreover, apart from minimizing risk and security hygiene, these sort of issues will be very important to be careful about -- especially for the sovereign projects that we have to deliver in the upcoming years.

In this project, we will create a tool to warn the corresponding asset owners (e.g., an Azure subscription owner) if their service/subscription/project is at risk due to such 'latent security access' pathways. We may cover Azure (and perhaps ADO) in the initial PoC...however, the concept will be extensible to other services (Office, Power Platform, AAD, etc.).



## Using Latent Security Access Scan - Step by Step
In this section, we will walk through the steps of Latent Security Access Scan

To get started, we need the following prerequisites:


**Prerequisite:**

**Note:** Currently LSAS scan is supported only for Azure subscriptions. Scan for other assets types will be added soon.

**1.** Installation steps are supported using following OS options: 	

- Windows 10
- Windows Server 2016

**2.** PowerShell 5.0 or higher

 Ensure that you are using Windows OS and have PowerShell version 5.0 or higher by typing **$PSVersionTable** in the PowerShell ISE console window and looking at the PSVersion in the output as shown below.) 
 If the PSVersion is older than 5.0, update PowerShell from [here](https://www.microsoft.com/en-us/download/details.aspx?id=54616).  

   ![PowerShell Version](../Images/00_PS_Version.PNG)   

**3.** Install Az and AzureAD modules. For more details of Az installation refer [link](https://docs.microsoft.com/en-us/powershell/azure/install-az-ps)

``` Powershell
# Install Az Modules
Install-Module -Name Az -AllowClobber -Scope CurrentUser

#Install managed identity service module
Install-Module -Name AzureAD -AllowClobber -Scope CurrentUser
```

**5.** Reader access on scanning subscription

**6.** Download LSAS scan script from [here](./Scripts/LSAS.ps1) to your local machine.  will help to unblock files. 

[Back to top…](Readme.md#contents)

**Scan:** 

1. Open the PowerShell ISE and login to your Azure account, AD account  and Set the context to subscription where solution needs to be installed.

``` PowerShell
# Login to Azure 
Connect-AzAccount 

# Connect to Azure AD account
Connect-AzureAD

# Set the context to hosting subscription
Set-AzContext -SubscriptionId <SubscriptionId>
```

2. Run scan command with required parameters given. 

``` PowerShell

# Step 1: Point current path to extracted folder location and load setup script from deploy folder 

. "<ScriptFolderPath>\LSAS.ps1"

# Note: Make sure you copy  '.' present at the start of line.

# Step 2: Run LSAS command. 

Get-AzSKLSASScanStatus -SubscriptionId '<SubscriptionId>'

```


## Feedback

For any feedback contact us at: azsksupext@microsoft.com 
