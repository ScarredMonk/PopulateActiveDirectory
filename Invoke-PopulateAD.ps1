<#
================================================================================================
    AD Builder Script: PopulateAD.ps1

    Powershell script to build active directory forest and populate AD with random AD objects 
    including AD users objects, computers objects, groups objects, GPOs and network shares required. 
    Also adds ASREProast account, kerberoastable account, and misconfigured ACLs to the domain. 

    Also has the option to remove the data added after the test is done and once it is not required.

    Author: Scarred Monk (@ScarredMonk)

================================================================================================
#>

<#
.Synopsis
   This script populates AD lab environment with some interesting stuff to get started.
.DESCRIPTION
   The goal of AD Builder is to populate the AD environment with bulk user objects, computer objects, ACLs 
   and few misconfigurations that help to simulate a real looking AD LAB for attack and defense simulations.
.EXAMPLE
   Import-Module .\ADBuilder.ps1; Invoke-LoadADObjects -DomainName rootdse.org -LimitUsers 100
   Invoke-UnLoadADObjects -DomainName roootdse.org
#>

Write-Host ""
#Info about Domain
$Global:Domain = "";
$Global:AddedUsers = @();
$Global:AddedGroups = @('Corporate','Finance Team', 'DB Administrators', 'Engineering Operations', 'Sales Team');
$Global:Sharenames = @('Corporate Files','Salary Details', 'DBA Backup', 'Operations Team', 'Sales Data', 'IT Tools', 'Old Backup');
$Global:ShareDesc = @('Corporate Files data for 2020','Finance Team 2020', 'Romania DB Backup', 'Engineering Operations daily data', 'Latest Sales Team Shared folder', 'IT Team Important Tools', 'All Backup'); 
$Global:UserTitle = @('IT Admin','DB Admin', 'Software Developer', 'Systems Engineer', 'Project Manager', 'Application Support Executive', 'IT Support Executive', 'Security Analyst', 'Business Analyst', 'Quality Analyst','Chief Finance Officer','Accountant', 'HR Executive'); 
$Global:BaseDir = "C:\ADShares"
$Global:BaseDirCreated = If(!(test-path $Global:BaseDir)){New-Item -ItemType Directory -Force -Path $Global:BaseDir};
$Global:Child_Folders = (Get-ChildItem -Path $Global:BaseDir -Recurse).FullName

#Default password
$Global:default_password = "password@123";

#Random AD User Accounts
$Global:UserNames = @('Michael', 'Christopher', 'Jessica', 'Matthew', 'Ashley', 'Jennifer', 'Joshua', 'Amanda', 'Daniel', 'David', 'James', 'Robert', 'John', 'Joseph', 'Andrew', 'Ryan', 'Brandon', 'Jason', 'Justin', 'Sarah', 'William', 'Jonathan', 'Stephanie', 'Brian', 'Nicole', 'Nicholas', 'Anthony', 'Heather', 'Eric', 'Elizabeth', 'Adam', 'Megan', 'Melissa', 'Kevin', 'Steven', 'Thomas', 'Timothy', 'Christina', 'Kyle', 'Rachel', 'Laura', 'Lauren', 'Amber', 'Brittany', 'Danielle', 'Richard', 'Kimberly', 'Jeffrey', 'Amy', 'Crystal', 'Michelle', 'Tiffany', 'Jeremy', 'Benjamin', 'Mark', 'Emily', 'Aaron', 'Charles', 'Rebecca', 'Jacob', 'Stephen', 'Patrick', 'Sean', 'Erin', 'Zachary', 'Jamie', 'Kelly', 'Samantha', 'Nathan', 'Sara', 'Dustin', 'Paul', 'Angela', 'Tyler', 'Scott', 'Katherine', 'Andrea', 'Gregory', 'Erica', 'Mary', 'Travis', 'Lisa', 'Kenneth', 'Bryan', 'Lindsey', 'Kristen', 'Jose', 'Alexander', 'Jesse', 'Katie', 'Lindsay', 'Shannon', 'Vanessa', 'Courtney', 'Christine', 'Alicia', 'Cody', 'Allison', 'Bradley', 'Samuel', 'Shawn', 'April', 'Derek', 'Kathryn', 'Kristin', 'Chad', 'Jenna', 'Tara', 'Maria', 'Krystal', 'Jared', 'Anna', 'Edward', 'Julie', 'Peter', 'Holly', 'Marcus', 'Kristina', 'Natalie', 'Jordan', 'Victoria', 'Jacqueline', 'Corey', 'Keith', 'Monica', 'Juan', 'Donald', 'Cassandra', 'Meghan', 'Joel', 'Shane', 'Phillip', 'Patricia', 'Brett', 'Ronald', 'Catherine', 'George', 'Antonio', 'Cynthia', 'Stacy', 'Kathleen', 'Raymond', 'Carlos', 'Brandi', 'Douglas', 'Nathaniel', 'Ian', 'Craig', 'Brandy', 'Alex', 'Valerie', 'Veronica', 'Cory', 'Whitney', 'Gary', 'Derrick', 'Philip', 'Luis', 'Diana', 'Chelsea', 'Leslie', 'Caitlin', 'Leah', 'Natasha', 'Erika', 'Casey', 'Latoya', 'Erik', 'Dana', 'Victor', 'Brent', 'Dominique', 'Frank', 'Brittney', 'Evan', 'Gabriel', 'Julia', 'Candice', 'Karen', 'Melanie', 'Adrian', 'Stacey', 'Margaret', 'Sheena', 'Wesley', 'Vincent', 'Alexandra', 'Katrina', 'Bethany', 'Nichole', 'Larry', 'Jeffery', 'Curtis', 'Carrie', 'Todd');
#Domain-Controller
$Global:dc=(Get-ADDomainController).Name
$Global:templateComp= get-adcomputer $dc -properties Location, OperatingSystem, OperatingSystemHotfix, OperatingSystemServicePack, OperatingSystemVersion
$Global:domainname = (Get-ADDomain).DNSRoot

#AD Computer Names
$Global:CompNames = @('APPSRV01', 'APPSRV02', 'APPSRV03', 'APPSRV04', 'APPSRV05', 'SQLSRV01', 'SQLSRV02', 'SQLSRV03', 'SQLSRV04', 'SQLSRV05', 'VNCSRV01', 'VNCSRV02', 'VNCSRV03', 'VNCSRV04', 'VNCSRV05', 'WEBSRV01', 'WEBSRV02', 'WEBSRV03', 'WEBSRV04', 'WEBSRV05', 'BCKUPSRV01', 'BCKUPSRV02', 'BCKUPSRV03', 'BCKUPSRV04', 'BCKUPSRV05');

#AD Group Names
$Global:Corp = "Corporate"
$Global:Finance = "Finance Team"
$Global:DBA = "DB Administrators"
$Global:Engineering = "Engineering Operations"
$Global:Sales = "Sales Team"
function DisplayInfo {
    $info = 'AD Builder Script by ScarredMonk'
    Write-Host $info -ForegroundColor "Yellow"
}

function InstallADRole {
    Write-Host "[+] Installing required AD Roles and features." -ForegroundColor 'Green'
    Install-windowsFeature AD-Domain-Services
    Add-windowsfeature RSAT-ADDS
    Import-Module ADDSDeployment
    Write-Host "`n`nAD Roles and features are installed.`n`n" -ForegroundColor "Gray"
    }

function ADforestInstall {
Write-Host "[+] Installing AD forest $DomainName" -ForegroundColor 'Green'
$DomainNetBiosName = $DomainName.split('.')[0]
Install-ADDSForest -CreateDnsDelegation:$false -DatabasePath "C:\\Windows\\NTDS" -DomainMode "7" -DomainName $DomainName -DomainNetbiosName $DomainNetBiosName -ForestMode "7" -InstallDns:$true -LogPath "C:\\Windows\\NTDS" -NoRebootOnCompletion:$false -SysvolPath "C:\\Windows\\SYSVOL" -Force:$true -SkipPreChecks -SafeModeAdministratorPassword $pass 
Write-Host "`n`n$DomainName has been installed successfully. Domain controller will restart`n`n" -ForegroundColor 'Gray'
}

function AD-GroupCreation {
    Write-Host "[+] Creating Domain Groups in $DomainName" -ForegroundColor 'Green'
    New-ADGroup -name $Global:Corp -GroupScope Global
    Write-Host "Creating group $Global:Corp" -ForegroundColor 'Gray'
    New-ADGroup -name $Global:DBA -GroupScope Global
    Write-Host "Creating group $Global:DBA" -ForegroundColor 'Gray'
    New-ADGroup -name $Global:Engineering -GroupScope Global
    Write-Host "Creating group $Global:Engineering" -ForegroundColor 'Gray'
    New-ADGroup -name $Global:Sales -GroupScope Global
    Write-Host "Creating group $Global:Sales" -ForegroundColor 'Gray'
    New-ADGroup -name $Global:Finance -GroupScope Global
    Write-Host "Creating group $Global:Finance" -ForegroundColor 'Gray'
}

function Fixed-UserCreation {
    Write-Host "[+] Creating Domain Users" -ForegroundColor 'Green'
    $firstname = "Frank"
    $lastname = "Monk"
    $fullname = "{0} {1}" -f ($firstname, $lastname)
    $SamAccountName = ("{0}.{1}" -f ($firstname.Substring(0,1), $lastname)).ToLower()
    $principalname = "{0}.{1}" -f ($firstname.Substring(0,1), $lastname)
    $password = "Phi11i35@44"
    New-ADUser -Name "$firstname $lastname" -GivenName $firstname -Surname $lastname -SamAccountName $SamAccountName -UserPrincipalName $principalname@$Global:Domain -AccountPassword (ConvertTo-SecureString $password -AsPlainText -Force) -PassThru | Enable-ADAccount
    Write-Host "$samAccountName added" -ForegroundColor 'Gray'

    $firstname = "Scarred"
    $lastname = "Monk"
    $fullname = "{0} {1}" -f ($firstname, $lastname)
    $SamAccountName = ("{0}.{1}" -f ($firstname.Substring(0,1), $lastname)).ToLower()
    $principalname = "{0}.{1}" -f ($firstname.Substring(0,1), $lastname)
    $password = "Summer2021!"
    New-ADUser -Name "$firstname $lastname" -GivenName $firstname -Surname $lastname -SamAccountName $SamAccountName -UserPrincipalName $principalname@$Global:Domain -AccountPassword (ConvertTo-SecureString $password -AsPlainText -Force) -PassThru | Enable-ADAccount
    Write-Host "$samAccountName added" -ForegroundColor 'Gray'
    Write-Host "Adding $samAccountName to $Global:Corp Group" -ForegroundColor 'Gray'
    Add-ADGroupMember -Identity $Global:Corp -Members $samAccountName
    Write-Host "Adding $samAccountName to Domain Administrators Group" -ForegroundColor 'Gray'
    Add-ADGroupMember -Identity "Domain Admins" -Members $samAccountName
}

function Bulk-UserCreation {Param([int]$UsersLimit =1)
    Add-Type -AssemblyName System.Web
    Write-Host "[+] Creating Bulk Domain Users in $DomainName" -ForegroundColor 'Green'
    for ($i=1; $i -le $UsersLimit; $i=$i+1 ) {
        $firstname = (Get-Random -InputObject $Global:UserNames);
        $lastname = (Get-Random -InputObject $Global:UserNames);
        $fullname = "{0} {1}" -f ($firstname , $lastname);
        $SamAccountName = ("{0}.{1}" -f ($firstname, $lastname)).ToLower();
        $principalname = "{0}.{1}" -f ($firstname, $lastname);
        if($SamAccountName.Length -le 20){
        try { 
            Write-Host "Creating user object: $SamAccountName" -ForegroundColor 'Gray'; 
            New-ADUser -Name "$firstname $lastname" -GivenName $firstname -Surname $lastname -SamAccountName $SamAccountName -UserPrincipalName $principalname@$Global:Domain -Title (Get-Random($Global:UserTitle)) -AccountPassword (ConvertTo-SecureString $Global:default_password -AsPlainText -Force) -PassThru | Enable-ADAccount
        } catch { 
            Write-Host "Error creating user object: $SamAccountName" -ForegroundColor 'Red'
        }
        }
        $Global:AddedUsers += $SamAccountName;
    }
}

function Bulk-CompCreation {
    foreach($computer in $Global:CompNames){
        $SamAccountName = "$computer"
        try { 
            Write-Host "Creating computer object: $($computer + "." + $Global:domainname)" -ForegroundColor 'Gray'; 
            New-ADComputer -Name $computer -SamAccountName $computer -Instance $Global:templateComp -DNSHostName $($computer + "." + $Global:domainname);
        } catch { 
            Write-Host "Error creating computer object" -ForegroundColor 'Red'
            }
    }
}
function AD-ASREPRoasting {
    $asrepUser = "s.monk"	
    Write-Host "[+] Modifying pre-authentication privileges" -ForegroundColor 'Green'
    Set-ADAccountControl -Identity $asrepUser -DoesNotRequirePreAuth 1
    Write-Host "ASREP privileges granted to $asrepUser" -ForegroundColor 'Gray'
}

function AD-Kerberoasting {
    $svc = "mssql_svc"
    $spn = "mssqlserver"
    $kerb_pass = "Password123!"
    Write-Host "[+] Adding Kerberoastable service account to domain" -ForegroundColor 'Green'
    New-ADServiceAccount -Name $svc -ServicePrincipalNames "$svc/$spn.$Global:domain" -RestrictToSingleComputer -AccountPassword (ConvertTo-SecureString $kerb_pass -AsPlainText -Force)
    Write-Host "mssql_svc service account added. Password is Password123!" -ForegroundColor 'Gray'
}

function AD-ACLs {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$Destination,

        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [System.Security.Principal.IdentityReference]$Source,

        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$Rights

    )
    $ADObject = [ADSI]("LDAP://" + $Destination)
    $identity = $Source
    $adRights = [System.DirectoryServices.ActiveDirectoryRights]$Rights
    $type = [System.Security.AccessControl.AccessControlType] "Allow"
    $inheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance] "All"
    $ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $identity,$adRights,$type,$inheritanceType
    $ADObject.psbase.ObjectSecurity.AddAccessRule($ACE)
    $ADObject.psbase.commitchanges()
}

function AD-RedACLs {
    Write-Host "[+] Granting $Global:DBA GenericAll rights on Domain Admins." -ForegroundColor 'Green'
    $DestinationGroup = Get-ADGroup -Identity "$Global:DBA"
    $SourceGroup = Get-ADGroup -Identity "Domain Admins"
    AD-ACLs -Source $SourceGroup.sid -Destination $DestinationGroup.DistinguishedName -Rights "GenericAll"
    Write-Host "$Global:DBA group granted GenericAll permissions for the Domain Admins group." -ForegroundColor 'Gray'
    Write-Host "[+] Adding misconfigured ACL rule for the $Global:Engineering group."	 -ForegroundColor 'Green'
    $DestinationGroup = Get-ADGroup -Identity $Global:Engineering
    $SourceGroup = Get-ADGroup -Identity $Global:DBA
    AD-ACLs -Source $SourceGroup.sid -Destination $DestinationGroup.DistinguishedName -Rights "GenericAll"
    Write-Host "GenericAll rights granted to $Global:Engineering group for $Global:DBA." -ForegroundColor 'Gray'
    Write-Host "[+] Adding misconfigured ACL rule for Frank Monk to the $Global:Engineering group." -ForegroundColor 'Green'
    $vulnAclUser = Get-ADUser -Identity "f.monk"
    AD-ACLs -Source $SourceGroup.sid -Destination $vulnAclUser.DistinguishedName -Rights "ExtendedRight"
    Write-Host "ExtendedRight granted to f.monk for the $Global:Engineering group." -ForegroundColor 'Gray'
}

function AD-PSRemoteGPO {
    Write-Host "[+] Configuring some GPO policies required for the domain." -ForegroundColor 'Green'
    import-module grouppolicy
    $domain = Get-ADDomain
    $forest = $domain.Forest
    $DN = $domain.DistinguishedName
    
    $FwRule = "Allow WinRM TCP 5985 To Domain Joined Systems"
    $GpoName = "WinRM Firewall TCP 5985"
    $TargetOU = $DN
    $PolicyStoreName = "$forest\" + $GpoName
    New-Gpo -Name $GpoName | New-Gplink -target $TargetOU
    $GpoSessionName = Open-NetGPO –PolicyStore $PolicyStoreName
    New-NetFirewallRule -DisplayName $FwRule -Profile Any -Direction Inbound -GPOSession $GpoSessionName -PolicyStore $GpoName -Protocol TCP -LocalPort 5985
    Save-NetGPO -GPOSession $GpoSessionName
    Write-Host "A GPO for PowerShell Remoting was created for authenticated users on the domain." -ForegroundColor 'Gray'
}

function Enable-WinRMService {
    Write-Host "[+] Configuring GPO policies to enable PowerShell remoting on hosts." -ForegroundColor 'Green'
        $domainGPO = Get-ADDomain
        $forest = $domainGPO.Forest
        $DN = $domainGPO.DistinguishedName
        $GpoName = "Enable PSRemoting Desktops"
        $TargetOU = $DN
        $PolicyStoreName = "$forest\" + $GpoName
        New-Gpo -Name $GpoName | New-Gplink -target $TargetOU
    
        $domain = (Get-ADDomain).forest
        $id = (Get-GPO -name $GpoName).id
        $RemotingParams = @{
                Name=$GpoName;
                Key = 'HKLM\Software\Policies\Microsoft\Windows\WinRM\Service';
                }
        
        try {
            Set-GPRegistryValue @RemotingParams -ValueName 'AllowAutoConfig' -Value 1 -Type DWord
            Set-GPRegistryValue @RemotingParams -ValueName 'IPv4Filter' -Value '*' -Type String
            Set-GPRegistryValue @RemotingParams -ValueName 'IPv6Filter' -Value '*' -Type String
            Write-Host "Registry setting for Powershell Remoting OK!" -ForegroundColor 'Gray'
            }
        catch { "Error enabling remoting policy" }
    
        $ServiceParams = @{
                Name=$GpoName;
                Key = 'HKLM\SYSTEM\CurrentControlSet\Services\WinRM';
                }
        
        try {
            Set-GPRegistryValue @ServiceParams -ValueName 'Start' -Value 2 -Type DWord
            Set-GPRegistryValue @ServiceParams -ValueName 'DelayedAutoStart' -Value 0 -Type DWord
            Write-Host "Service setting for Powershell Remoting OK!" -ForegroundColor 'Gray'
            }
        catch { "Error enabling remoting policy" }
}

function Bulk-ShareCreation {
$i=0;
    foreach($share in $Global:Sharenames){
    $fullsharename = "$Global:BaseDir\$share"
        try { 
            Write-Host "Creating local directory: $share" -ForegroundColor 'Gray'; 
            New-Item -ItemType Directory -Path $fullsharename;
            Write-Host "[+] Created object locally : $share" -ForegroundColor 'Green'; 
            Write-Host "Sharing the object on network: $share" -ForegroundColor 'Gray'; 
            New-SmbShare -Name $share -Path $fullsharename -FullAccess Everyone -Description $Global:ShareDesc.GetValue($i)
            Write-Host "[+] Created network share object: $share" -ForegroundColor 'Green'; 
            $i++;
        } catch { 
            Write-Host "Error creating share object" -ForegroundColor 'Red'
            }
    }
}

function Bulk-ShareFileCreation {
$Child_Folders = (Get-ChildItem -Path $Global:BaseDir -Recurse).FullName
    foreach ($foldername in $Child_Folders) {
   (get-date -Format G) | Out-File -FilePath "$($foldername)\Sharedfile.txt" -Force
    }
Write-Host "[+] Added files in shared directories" -ForegroundColor 'Green'; 
}

function Bulk-ShareRemoval {
    foreach($share in $Global:Sharenames){
        try { 
            Write-Host "Removing network share object: $share" -ForegroundColor 'Gray'; 
            Remove-SmbShare -Name $share -Force
            Write-Host "[+] Removed network share object: $share" -ForegroundColor 'Green'; 
        } catch { 
            Write-Host "Error removing share object" -ForegroundColor 'Red'
            }
    }Remove-Item $Global:BaseDir -Force -Recurse;
Write-Host "[+] Removed shared object locally" -ForegroundColor 'Green'; 
}

function Invoke-RemoveShare {
Write-Host "[+] All network share objects have been removed" -ForegroundColor 'Green'; 
Bulk-ShareRemoval
Write-Host "[+] All shared files have been removed locally" -ForegroundColor 'Green'; 
}

function Invoke-CreateShare {
Bulk-ShareCreation
Write-Host "[+] All network share objects have been created" -ForegroundColor 'Green'; 
Bulk-ShareFileCreation
Write-Host "[+] All shared files have been created locally" -ForegroundColor 'Green'; 
}

function AD-GroupRemoval {
    Write-Host "[+] Removing Domain Groups" -ForegroundColor 'Green'
    Remove-ADGroup $Global:Corp -Confirm:$false
    Write-Host "Removed Group $Global:Corp from $Global:domain" -ForegroundColor 'Gray'
    Remove-ADGroup $Global:DBA -Confirm:$false
    Write-Host "Removed Group $Global:DBA from $Global:domain" -ForegroundColor 'Gray'
    Remove-ADGroup $Global:Engineering -Confirm:$false
    Write-Host "Removed Group $Global:Engineering from $Global:domain" -ForegroundColor 'Gray'
    Remove-ADGroup $Global:Sales -Confirm:$false
    Write-Host "Removed Group $Global:Sales from $Global:domain" -ForegroundColor 'Gray'
    Remove-ADGroup $Global:Finance -Confirm:$false
    Write-Host "Removed Group $Global:Finance from $Global:domain" -ForegroundColor 'Gray'
}

function AD-UserRemoval {
    Write-Host "[+] Removing Domain Users" -ForegroundColor 'Green'
    foreach($user in $Global:AddedUsers){
        try { 
            Write-Host "Removing User object: $user" -ForegroundColor 'Gray'; 
            Remove-ADUser $user -Confirm:$false;
        } catch { 
            Write-Host "Error removing user object" -ForegroundColor 'Red'
            }
    }
    Write-Host "[+] Removed populated domain Users" -ForegroundColor 'Green'
}

function Fixed-UserRemoval {
    Write-Host "[+] Creating fixed Domain Users" -ForegroundColor 'Green'
    $firstname = "Frank"
    $lastname = "Monk"
    $SamAccountName = ("{0}.{1}" -f ($firstname.Substring(0,1), $lastname)).ToLower()
    Remove-ADUser $SamAccountName -Confirm:$false;
    $firstname = "Scarred"
    $lastname = "Monk"
    $fullname = "{0} {1}" -f ($firstname, $lastname)
    $SamAccountName = ("{0}.{1}" -f ($firstname.Substring(0,1), $lastname)).ToLower()
    Remove-ADUser $SamAccountName -Confirm:$false;
}

function Bulk-CompRemoval {
    foreach($computer in $Global:CompNames){
        $SamAccountName = "$computer"
        try { 
            Write-Host "Removing computer object: $($computer + "." + $Global:domainname)" -ForegroundColor 'Gray'; 
            Remove-ADComputer $computer -Confirm:$false;
        } catch { 
            Write-Host "Error removing computer object" -ForegroundColor 'Red'
            }
    }
    Write-Host "[+] Removed populated domain computers" -ForegroundColor 'Green'
}
function Remove-PSRemoteGPO {
    Write-Host "[+] Removing GPO policies created for WinRM." -ForegroundColor 'Green'
    $GpoName = "WinRM Firewall TCP 5985"
    try {
        Remove-Gpo -Name $GpoName 
        Write-Host "A GPO for PowerShell Remoting was deleted" -ForegroundColor 'Gray'
    }
    catch { 
        "Error removing remoting policy" 
    }
}
function Disable-WinRMService {
    Write-Host "[+] Configuring GPO policies to disable PowerShell remoting on hosts." -ForegroundColor 'Green'
    $GpoName = "Enable PSRemoting Desktops"
    try {
        Remove-Gpo -Name $GpoName 
        Write-Host "Registry setting for Powershell Remoting is disabled!" -ForegroundColor 'Gray'
    }
    catch { 
        "Error removing remoting policy" 
    }
}

function Remove-ASREPRoasting {
    $asrepUser = "s.monk"	
    Remove-ADUser $asrepUser -Confirm:$false
    Write-Host "ASREP user removed from AD" -ForegroundColor 'Gray'
}

function Remove-Kerberoasting {
    $svc = "mssql_svc"
    Write-Host "[+] Removing Kerberoastable service account from domain" -ForegroundColor 'Green'
    Remove-ADServiceAccount -Identity $svc -Confirm:$false;
    Write-Host "mssql_svc service account removed" -ForegroundColor 'Gray'
}


function Invoke-ADForest
{
    Param
    ([Parameter(Mandatory=$true, Position=0)] [string] $DomainName)
    $pass = Read-Host -Prompt "Set Safe Mode Administrator Password" -AsSecureString
    DisplayInfo
    InstallADRole
    ADforestInstall
}

function Invoke-UnLoadADObjects {
	Param(
	[Parameter(Mandatory=$True)]
	[ValidateNotNullOrEmpty()]
	[System.String]
	$DomainName
)
DisplayInfo
$Global:Domain = $DomainName
Bulk-CompRemoval
Write-Host "[+] Populated computer objects deletion completed." -ForegroundColor 'Green'
AD-GroupRemoval
Write-Host "[+] Group deletion completed." -ForegroundColor 'Green'
Fixed-UserRemoval
AD-UserRemoval
$Global:AddedUsers = @();
Write-Host "[+] User deletion completed" -ForegroundColor 'Green'
Remove-Kerberoasting
Write-Host "[+] Kerberoastable service deletion completed." -ForegroundColor 'Green'
# AD-RedACLs
# Write-Host "[+] ACL misconfigurations removed." -ForegroundColor 'Green'
Remove-PSRemoteGPO
Write-Host "[+] GPO configurations removed." -ForegroundColor 'Green'
Disable-WinRMService
Write-Host "[+] Domain-wide PowerShell Remoting GPO configuration removed." -ForegroundColor 'Green'
Bulk-ShareRemoval
Write-Host "[+] Domain-wide Network share objects have been removed." -ForegroundColor 'Green'
}


function Invoke-LoadADObjects {
	Param(
	[Parameter(Mandatory=$True)]
	[ValidateNotNullOrEmpty()]
	[System.String]
	$DomainName,
    [Parameter(Mandatory=$True,ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True,Position=1)]
    [ValidateNotNullOrEmpty()]
    [int]$LimitUsers
)

DisplayInfo
$Global:Domain = $DomainName
Bulk-UserCreation -UsersLimit $LimitUsers
Write-Host "[+] Bulk User objects creation completed." -ForegroundColor 'Green'
Bulk-CompCreation
Write-Host "[+] Bulk Computer objects creation completed." -ForegroundColor 'Green'
AD-GroupCreation
Write-Host "[+] Group creation completed." -ForegroundColor 'Green'
Fixed-UserCreation
Write-Host "[+] Fixed User creation completed" -ForegroundColor 'Green'
AD-ASREPRoasting
Write-Host "[+] ASREP settings update completed." -ForegroundColor 'Green'
AD-Kerberoasting
Write-Host "[+] Kerberoastable service creation completed." -ForegroundColor 'Green'
AD-RedACLs
Write-Host "[+] ACL misconfigurations completed." -ForegroundColor 'Green'
AD-PSRemoteGPO
Write-Host "[+] GPO configurations completed." -ForegroundColor 'Green'
Enable-WinRMService
Write-Host "[+] Domain-wide PowerShell Remoting GPO configuration completed." -ForegroundColor 'Green'
Bulk-ShareCreation 
Bulk-ShareFileCreation
Write-Host "[+] Network share objects creation has been completed." -ForegroundColor 'Green'
Write-Host "`n`n$DomainName has been populated successfully`n`n" -ForegroundColor 'Gray'
}