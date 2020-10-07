Install-Module AuditPolicyDSC
Install-Module ComputerManagementDsc
Install-Module SecurityPolicyDsc

.\CIS_WindowsServer2016_v110.ps1

Set-Item -Path WSMan:\localhost\MaxEnvelopeSizeKb -Value 2048

winrm quickconfig

Start-DscConfiguration -Path .\CIS_WindowsServer2016_v110  -Force -Verbose -Wait
