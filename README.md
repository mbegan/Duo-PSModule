# Duo-PSModule Documentation
======================

This is a basic powershell wrapper intended to expose the capabilities of the Duo Admin API [Duo Admin API](https://duo.com/support/documentation/adminapi#overview).

--------
## A note about TLS 1.2

Momentum is shifting to clients and servers supporting TLS 1.2.  This plugin is capable of connecting to Duo with TLS 1.2 but doesn't do anything to direct the protocol used rather it relies on the SystemDefault configured for [schannel on the host](https://msdn.microsoft.com/en-us/library/system.net.securityprotocoltype(v=vs.110).aspx)

If you want to force TLS 1.2 make sure your system can actually [support it](https://blogs.perficient.com/microsoft/2016/04/tsl-1-2-and-net-support/).

### force TLS 1.2

If you decide you want to force this module to use TLS1.2 add this code block to your Duo_org.ps1 or your $PROFILE script.

```powershell
try
{
   [Net.ServicePointManager]::SecurityProtocol  = [Net.SecurityProtocolType]::Tls12
}
catch
{
   Write-Warning $_.Exception.Message
}
```

## Getting Started

### Installation:

1. Download the module (git clone or download the zip)
1. Place the module in your PSModulePath hint [Read more about PSModulePath Here](https://msdn.microsoft.com/en-us/library/dd878324%28v=vs.85%29.aspx)

```powershell
Write-Host $env:PSModulePath
```

1. Get the Integration Key, Secret Key and API Hostname for your Admin API Integration [First Steps](https://duo.com/support/documentation/adminapi#first-steps)
*optional* The directory_key for a directory can be found by navigating to Users → Directory Sync in the [Duo Admin Panel](https://admin.duosecurity.com/), and then clicking on the configured directory. This is required for manually syncing users.
1. Create a file called Duo_org.ps1 (example content below) and save it in the directory with the Duo.psd1 and Duo.psm1 files.

``` powershell
<# Duo_org.ps1 #>
# define the default Duo Org/Instance you want to use, useful if you have more than one.
[string]$DuoDefaultOrg = "prod"

[Hashtable]$DuoOrgs = @{
                        prod = [Hashtable]@{
                                iKey  = [string]"DIxxxxxxxxxxxxxxxxxx"
                                sKey = [string]"YourSecretsHere"
                                apiHost = [string]"api-nnnnnxnx.duosecurity.com"
                                directory_key = [string]"XXXXXXXXXXXXXXXXXXXX"
                               }
                        etst = [Hashtable]@{
                                iKey  = [string]"DIxxxxxxxxxxxxxxxxxx"
                                sKeyEnc = [string]"Big Long protected string on 1 line here"
                                apiHost = [string]"api-nnnnnxnx.duosecurity.com"
                                directory_key = [string]"XXXXXXXXXXXXXXXXXXXX"
							   }
                       }
```
#### if you'd like and added layer of protection to this key sitting in your file you can encrypt the string! After you've loaded the duo module you can use helper function **_duoEncskey_**. Paste your plaintext key into the dialog and paste the resulting output into the value for sKeyEnc in the configuration block (see etst above)

### Example Installation:

1. Open a command prompt

```
cd %userprofile%\Documents\WindowsPowerShell\Modules
git clone https://github.com/mbegan/Duo-PSModule.git Duo
cd Duo
notepad Duo_org.ps1
```

1. Paste the basic format for the Duo_org.ps1 file listed Above.
1. Modify file as required \(Update yourdomain, API Token you generated for that org etc\)
1. Optionally after the Duo module is imported generate the encrypted string and replace the plaintext value
1. Save the file
  
### Basic Usage:

1. Launch powershell \(or even better, the powershell ise\)
1. Import the Duo Module
1. Use

```powershell 
PS C:\> Import-Module Duo
PS C:\> $users = duoGetUser
PS C:\> $users.Count
10

PS C:\> foreach ($u in $users) {Write-Host $u.username `t $u.user_id `t $u.phones[0].number}
user1 	 DUxxxxxxxxxxxxxxxxx0 	 +15556543210
user2 	 DUxxxxxxxxxxxxxxxxx1 	 +15556543211
user3 	 DUxxxxxxxxxxxxxxxxx2 	 +15556543212
user4 	 DUxxxxxxxxxxxxxxxxx3 	 +15556543213
user5 	 DUxxxxxxxxxxxxxxxxx4 	 +15556543214
user6 	 DUxxxxxxxxxxxxxxxxx5 	 
user7 	 DUxxxxxxxxxxxxxxxxx6 	 +15556543215
user8 	 DUxxxxxxxxxxxxxxxxx7 	 
user9 	 DUxxxxxxxxxxxxxxxxx8 	 +15556543216
user10 	 DUxxxxxxxxxxxxxxxxx9 	 +15556543217
```

When elements are returned in the API they are powershell objects, you can treat them as such.

```powershell
PS C:\> $u | gm

   TypeName: System.Management.Automation.PSCustomObject

Name          MemberType   Definition                                      
----          ----------   ----------                                      
Equals        Method       bool Equals(System.Object obj)                  
GetHashCode   Method       int GetHashCode()                               
GetType       Method       type GetType()                                  
ToString      Method       string ToString()                               
desktoptokens NoteProperty System.Object[] desktoptokens=System.Object[]   
email         NoteProperty System.String email=first.last@company.tld
groups        NoteProperty System.Object[] groups=System.Object[]          
last_login    NoteProperty System.Int32 last_login=1453410816              
notes         NoteProperty System.String notes=                            
phones        NoteProperty System.Object[] phones=System.Object[]          
realname      NoteProperty System.String realname=First Last        
status        NoteProperty System.String status=active                     
tokens        NoteProperty System.Object[] tokens=System.Object[]          
username      NoteProperty System.String username=user1                 
user_id       NoteProperty System.String user_id=DUxxxxxxxxxxxxxxxxx0      

```

The commands implimented are listed below, if you have a specific use case ask away i'll post an example.  If you are handy with powershell feel free to impliment additional functionality and send a PR.

#### NOTE in most cases the Create* functions also serve to Modify if the object identifier of an existing object is provided

#### Current Commands

- duoAssocUserToGroup
- duoAssocUserToPhone
- duoAssocUserToToken
- duoCreateActivationCode
- duoCreateAdmin
- duoCreateAdminActivationLink
- duoCreateIntegration
- duoCreatePhone
- duoCreateToken
- duoCreateUser
- duoDeleteAdmin
- duoDeleteGroup
- duoDeleteIntegration
- duoDeletePhone
- duoDeletePendingAdminActivation
- duoDeleteToken
- duoDeleteUser
- duoEnrollUser
- duoGetAdmin
- duoGetGroup
- duoGetInfo
- duoGetIntegration
- duoGetLog
- duoGetPhone
- duoGetToken
- duoGetUser
- duoGetUserBypass
- duoSendSMSCodes
- duoSoftTotpClient
- duoSyncUser
