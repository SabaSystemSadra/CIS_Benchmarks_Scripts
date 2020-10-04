-- 1.1
-- Ensure Latest SQL Server Service Packs and Hotfixes are Installed (Not Scored)
-- Install updates




-- 1.2
-- Uninstall excess tooling and/or remove unnecessary roles from the underlying operating system.




-- 2.1
-- Ensure 'Ad Hoc Distributed Queries' Server Configuration Option is set to '0' (Scored)
EXECUTE sp_configure 'show advanced options', 1;
RECONFIGURE;
EXECUTE sp_configure 'Ad Hoc Distributed Queries', 0;
RECONFIGURE;
GO




-- 2.2 Ensure 'CLR Enabled' Server Configuration Option is set to '0' (Scored)\
EXECUTE sp_configure 'clr enabled', 0;
RECONFIGURE;





-- 2.3 Ensure 'Cross DB Ownership Chaining' Server Configuration Option is set to '0' (Scored)
EXECUTE sp_configure 'cross db ownership chaining', 0;
RECONFIGURE;
GO





-- 2.4 Ensure 'Database Mail XPs' Server Configuration Option is set to '0' (Scored)
EXECUTE sp_configure 'show advanced options', 1;
RECONFIGURE;
EXECUTE sp_configure 'Database Mail XPs', 0;
RECONFIGURE;
GO
EXECUTE sp_configure 'show advanced options', 0;
RECONFIGURE;





-- 2.5 Ensure 'Ole Automation Procedures' Server Configuration Option is set to '0' (Scored)
EXECUTE sp_configure 'show advanced options', 1;
RECONFIGURE;
EXECUTE sp_configure 'Ole Automation Procedures', 0;
RECONFIGURE;
GO
EXECUTE sp_configure 'show advanced options', 0;
RECONFIGURE;


-- 2.6 Ensure 'Remote Access' Server Configuration Option is set to '0' (Scored)
EXECUTE sp_configure 'show advanced options', 1;
RECONFIGURE;
EXECUTE sp_configure 'remote access', 0;
RECONFIGURE;
GO
EXECUTE sp_configure 'show advanced options', 0;
RECONFIGURE;





-- 2.7 Ensure 'Remote Admin Connections' Server Configuration Option is set to '0' (Scored)
EXECUTE sp_configure 'remote admin connections', 0;
RECONFIGURE;
GO





-- 2.8 Ensure 'Scan For Startup Procs' Server Configuration Option is set to '0' (Scored)
EXECUTE sp_configure 'show advanced options', 1;
RECONFIGURE;
EXECUTE sp_configure 'scan for startup procs', 0;
RECONFIGURE;
GO
EXECUTE sp_configure 'show advanced options', 0;
RECONFIGURE;





-- 2.9 Ensure 'Trustworthy' Database Property is set to 'Off' (Scored)
ALTER DATABASE [<database_name>] SET TRUSTWORTHY OFF;





-- 2.10 Ensure Unnecessary SQL Server Protocols are set to 'Disabled' (Not Scored)
-- Open SQL Server Configuration Manager; go to the SQL Server Network Configuration.
-- Ensure that only required protocols are enabled. Disable protocols not necessary.





-- 2.11 Ensure SQL Server is configured to use non-standard ports (Not Scored)
/*

1. In SQL Server Configuration Manager, in the console pane,
expand SQL Server Network Configuration, expand Protocols for <InstanceName>, and then
doubleclick the TCP/IP protocol

2. In the TCP/IP Properties dialog box, on the IP Addresses tab, several IP addresses
appear in the format IP1, IP2, up to IPAll. One of these is for the IP address of the
loopback adapter, 127.0.0.1. Additional IP addresses appear for each IP Address on the computer.

3. Under IPAll, change the TCP Port field from 1433 to a non-standard port or leave
the TCP Port field empty and set the TCP Dynamic Ports value to 0 to enable
dynamic port assignment and then click OK.

4. In the console pane, click SQL Server Services.

5. In the details pane, right-click SQL Server (<InstanceName>) and then click
Restart, to stop and restart SQL Server.

*/






-- 2.12 Ensure 'Hide Instance' option is set to 'Yes' for Production SQL Server instances (Scored)
EXEC master.sys.xp_instance_regwrite
@rootkey = N'HKEY_LOCAL_MACHINE',
@key = N'SOFTWARE\Microsoft\Microsoft SQL
Server\MSSQLServer\SuperSocketNetLib',
@value_name = N'HideInstance',
@type = N'REG_DWORD',
@value = 1;





-- 2.13 Ensure the 'sa' Login Account is set to 'Disabled' (Scored)
USE [master]
GO
DECLARE @tsql nvarchar(max)
SET @tsql = 'ALTER LOGIN ' + SUSER_NAME(0x01) + ' DISABLE'
EXEC (@tsql)
GO





-- 2.14 Ensure the 'sa' Login Account has been renamed (Scored)
ALTER LOGIN sa WITH NAME = <different_user>;





-- 2.15 Ensure 'AUTO_CLOSE' is set to 'OFF' on contained databases (Scored)
ALTER DATABASE <database_name> SET AUTO_CLOSE OFF;






-- 2.16 Ensure no login exists with the name 'sa' (Scored)
USE [master]
GO
-- If principal_id = 1 or the login owns database objects, rename the sa
login
ALTER LOGIN [sa] WITH NAME = <different_name>;
GO
-- If the login owns no database objects, then drop it
-- Do NOT drop the login if it is principal_id = 1
DROP LOGIN sa






-- 3.1 Ensure 'Server Authentication' Property is set to 'Windows Authentication Mode' (Scored)
USE [master]
GO
EXEC xp_instance_regwrite N'HKEY_LOCAL_MACHINE',
N'Software\Microsoft\MSSQLServer\MSSQLServer', N'LoginMode', REG_DWORD, 1
GO





-- 3.2 Ensure CONNECT permissions on the 'guest' user is Revoked within
-- all SQL Server databases excluding the master, msdb and tempdb (Scored)
USE <database_name>;
GO
REVOKE CONNECT FROM guest;





-- 3.3 Ensure 'Orphaned Users' are Dropped From SQL Server Databases (Scored)
USE [<database_name>];
GO
DROP USER <username>;





-- 3.4 Ensure SQL Authentication is not used in contained databases (Scored)
SELECT name AS DBUser
FROM sys.database_principals
WHERE name NOT IN ('dbo','Information_Schema','sys','guest')
AND type IN ('U','S','G')
AND authentication_type = 2;
GO





-- 3.5 Ensure the SQL Server’s MSSQL Service Account is Not an Administrator (Not Scored)
/*
In the case where LocalSystem is used, use SQL Server Configuration Manager to change
to a less privileged account. Otherwise, remove the account or service SID from the
Administrators group. You may need to run the SQL Server Configuration Manager if
underlying permissions had been changed or if SQL Server Configuration Manager was
not originally used to set the service account.
*/





-- 3.6 Ensure the SQL Server’s SQLAgent Service Account is Not an Administrator (Not Scored)
/*
In the case where LocalSystem is used, use SQL Server Configuration Manager to change
to a less privileged account. Otherwise, remove the account or service SID from the
Administrators group. You may need to run the SQL Server Configuration Manager if
underlying permissions had been changed or if SQL Server Configuration Manager was
not originally used to set the service account.
*/





-- 3.7 Ensure the SQL Server’s Full-Text Service Account is Not an Administrator (Not Scored)
/*
In the case where LocalSystem is used, use SQL Server Configuration Manager to change
to a less privileged account. Otherwise, remove the account or service SID from the
Administrators group. You may need to run the SQL Server Configuration Manager if
underlying permissions had been changed or if SQL Server Configuration Manager was
not originally used to set the service account.
*/






-- 3.8 Ensure only the default permissions specified by Microsoft are granted to the public server role (Scored)
/*
1. Add the extraneous permissions found in the Audit query results to the specific
logins to user-defined server roles which require the access.

2. Revoke the <permission_name> from the public role as shown below
*/





-- 3.9 Ensure Windows BUILTIN groups are not SQL Logins (Scored)
/*

1. For each BUILTIN login, if needed create a more restrictive AD group containing only
the required user accounts.

2. Add the AD group or individual Windows accounts as a SQL Server login and grant it
the permissions required.

3. Drop the BUILTIN login using the syntax below after replacing <name> in
BUILTIN\<name>

USE [master]
GO DROP LOGIN [BUILTIN\<name>]
GO
*/







-- 3.10 Ensure Windows local groups are not SQL Logins (Scored)

/*

1. For each LocalGroupName login, if needed create an equivalent AD group containing
only the required user accounts.

2. Add the AD group or individual Windows accounts as a SQL Server login and grant it
the permissions required.

3. Drop the LocalGroupName login using the syntax below after replacing <name>.
USE [master]
GO DROP LOGIN [<name>]
GO

*/








-- 3.11 Ensure the public role in the msdb database is not granted access to SQL Agent proxies (Scored)
/*

1. Ensure the required security principals are explicitly granted access to the proxy
(use sp_grant_login_to_proxy).

2. Revoke access to the <proxyname> from the public role.

USE [msdb]
GO
EXEC dbo.sp_revoke_login_from_proxy @name = N'public', @proxy_name =
N'<proxyname>';
GO

*/






-- 4.1 Ensure 'MUST_CHANGE' Option is set to 'ON' for All SQL Authenticated Logins (Not Scored)
-- Set the MUST_CHANGE option for SQL Authenticated logins when creating a login initially:
CREATE LOGIN <login_name> WITH PASSWORD = '<password_value>' MUST_CHANGE,
CHECK_EXPIRATION = ON, CHECK_POLICY = ON;
-- Set the MUST_CHANGE option for SQL Authenticated logins when resetting a password:
ALTER LOGIN <login_name> WITH PASSWORD = '<password_value>' MUST_CHANGE;







-- 4.2 Ensure 'CHECK_EXPIRATION' Option is set to 'ON' for All SQL Authenticated Logins Within the Sysadmin Role (Scored)
-- For each <login_name> found by the Audit Procedure, execute the following T-SQL statement:
ALTER LOGIN <login_name> WITH CHECK_EXPIRATION = ON;







-- 4.3 Ensure 'CHECK_POLICY' Option is set to 'ON' for All SQL Authenticated Logins (Scored)
-- For each <login_name> found by the Audit Procedure, execute the following T-SQL statement:
ALTER LOGIN <login_name> WITH CHECK_POLICY = ON;







-- 5.1 Ensure 'Maximum number of error log files' is set to greater than or equal to '12' (Scored)
EXEC master.sys.xp_instance_regwrite
N'HKEY_LOCAL_MACHINE',
N'Software\Microsoft\MSSQLServer\MSSQLServer',
N'NumErrorLogs',
REG_DWORD,
<NumberAbove12>;






-- 5.2 Ensure 'Default Trace Enabled' Server Configuration Option is set to '1' (Scored)
EXECUTE sp_configure 'show advanced options', 1;
RECONFIGURE;
EXECUTE sp_configure 'default trace enabled', 1;
RECONFIGURE;
GO
EXECUTE sp_configure 'show advanced options', 0;
RECONFIGURE;








-- 5.3 Ensure 'Login Auditing' is set to 'failed logins' (Scored)
EXEC xp_instance_regwrite N'HKEY_LOCAL_MACHINE',
N'Software\Microsoft\MSSQLServer\MSSQLServer', N'AuditLevel',
REG_DWORD, 2







-- 5.4 Ensure 'SQL Server Audit' is set to capture both 'failed' and 'successful logins' (Scored)
CREATE SERVER AUDIT TrackLogins
TO APPLICATION_LOG;
GO
CREATE SERVER AUDIT SPECIFICATION TrackAllLogins
FOR SERVER AUDIT TrackLogins
ADD (FAILED_LOGIN_GROUP),
ADD (SUCCESSFUL_LOGIN_GROUP),
ADD (AUDIT_CHANGE_GROUP)
WITH (STATE = ON);
GO
ALTER SERVER AUDIT TrackLogins
WITH (STATE = ON);
GO







-- 6.1 Ensure Database and Application User Input is Sanitized (Not Scored)
/*
The following steps can be taken to remediate SQL injection vulnerabilities:

• Review TSQL and application code for SQL Injection
• Only permit minimally privileged accounts to send user input to the server
• Minimize the risk of SQL injection attack by using parameterized commands and
stored procedures
• Reject user input containing binary data, escape sequences, and comment
characters
• Always validate user input and do not use it directly to build SQL statements
*/







-- 6.2 Ensure 'CLR Assembly Permission Set' is set to 'SAFE_ACCESS' for All CLR Assemblies (Scored)
ALTER ASSEMBLY <assembly_name> WITH PERMISSION_SET = SAFE;







-- 7.1 Ensure 'Symmetric Key encryption algorithm' is set to 'AES_128' or higher in non-system databases (Scored)
/*
Refer to Microsoft SQL Server Books Online ALTER SYMMETRIC KEY entry:
https://docs.microsoft.com/en-us/sql/t-sql/statements/alter-symmetric-key-transact-sql
*/








-- 7.2 Ensure Asymmetric Key Size is set to 'greater than or equal to 2048' in non-system databases (Scored)
/*
Refer to Microsoft SQL Server Books Online ALTER ASYMMETRIC KEY entry:
https://docs.microsoft.com/en-us/sql/t-sql/statements/alter-asymmetric-key-transactsql
*/







-- 8.1 Ensure 'SQL Server Browser Service' is configured correctly (Not Scored)
-- Enable or disable the service as needed for your environment.
