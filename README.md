# PopulateActiveDirectory
Powershell script to build active directory forest and populate AD with random AD objects including AD users objects, computers objects, groups objects, GPOs and network shares required. It also adds ASREProast account, kerberoastable account, and misconfigured ACLs to the domain for testing purposes

### Usage:

. .\Invoke-PopulateAD.ps1
Invoke-LoadADObjects -DomainName rootdse.org -LimitUsers 25

![ad_builder](https://user-images.githubusercontent.com/46210620/147859488-08b682ba-6780-4ec2-86f0-377705a26905.gif)
