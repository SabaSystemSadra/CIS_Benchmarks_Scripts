-- 1.1
-- Ensure Latest SQL Server Service Packs and Hotfixes are Installed (Not Scored)
SELECT SERVERPROPERTY('ProductLevel') as SP_installed,
SERVERPROPERTY('ProductVersion') as Version;
-- First column returns the installed Service Pack level, the second is the exact build number.



-- 1.2
-- Ensure Single-Function Member Servers are Used (Not Scored)
-- Ensure that no other roles are enabled for the underlying operating system and that no excess tooling is installed, per enterprise policy.




-- 2.1 Ensure 'Ad Hoc Distributed Queries' Server Configuration Option is set to '0' (Scored)
SELECT name, CAST(value as int) as value_configured,
CAST(value_in_use as int) as value_in_use
FROM sys.configurations
WHERE name = 'Ad Hoc Distributed Queries';
-- Both value columns must show 0 .




-- 2.2 Ensure 'CLR Enabled' Server Configuration Option is set to '0' (Scored)\
SELECT name,
CAST(value as int) as value_configured,
CAST(value_in_use as int) as value_in_use
FROM sys.configurations
WHERE name = 'clr enabled';
-- Run the following T-SQL command:




-- 2.3 Ensure 'Cross DB Ownership Chaining' Server Configuration Option is set to '0' (Scored)
SELECT name,
CAST(value as int) as value_configured,
CAST(value_in_use as int) as value_in_use
FROM sys.configurations
WHERE name = 'cross db ownership chaining';
-- Both value columns must show 0 to be compliant.





-- 2.4 Ensure 'Database Mail XPs' Server Configuration Option is set to '0' (Scored)
SELECT name,
CAST(value as int) as value_configured,
CAST(value_in_use as int) as value_in_use
FROM sys.configurations
WHERE name = 'Database Mail XPs';
-- Both value columns must show 0 to be compliant.




-- 2.5 Ensure 'Ole Automation Procedures' Server Configuration Option is set to '0' (Scored)
SELECT name,
CAST(value as int) as value_configured,
CAST(value_in_use as int) as value_in_use
FROM sys.configurations
WHERE name = 'Ole Automation Procedures';
-- Both value columns must show 0 to be compliant.




-- 2.6 Ensure 'Remote Access' Server Configuration Option is set to '0' (Scored)
SELECT name,
CAST(value as int) as value_configured,
CAST(value_in_use as int) as value_in_use
FROM sys.configurations
WHERE name = 'remote access';
-- Both value columns must show 0 .




-- 2.7 Ensure 'Remote Admin Connections' Server Configuration Option is set to '0' (Scored)
USE master;
GO
SELECT name,
CAST(value as int) as value_configured,
CAST(value_in_use as int) as value_in_use
FROM sys.configurations
WHERE name = 'remote admin connections'
AND SERVERPROPERTY('IsClustered') = 0;
-- If no data is returned, the instance is a cluster and this recommendation is not applicable.
-- Ifdata is returned, then both the value columns must show 0 to be compliant.




-- 2.8 Ensure 'Scan For Startup Procs' Server Configuration Option is set to '0' (Scored)
SELECT name,
CAST(value as int) as value_configured,
CAST(value_in_use as int) as value_in_use
FROM sys.configurations
WHERE name = 'scan for startup procs';
-- Both value columns must show 0 .




-- 2.9 Ensure 'Trustworthy' Database Property is set to 'Off' (Scored)
SELECT name
FROM sys.databases
WHERE is_trustworthy_on = 1
AND name != 'msdb';
-- No rows should be returned.




-- 2.10 Ensure Unnecessary SQL Server Protocols are set to 'Disabled' (Not Scored)
-- Open SQL Server Configuration Manager; go to the SQL Server Network Configuration.
--Ensure that only required protocols are enabled.




-- 2.11 Ensure SQL Server is configured to use non-standard ports (Not Scored)
DECLARE @value nvarchar(256);
EXECUTE master.dbo.xp_instance_regread
N'HKEY_LOCAL_MACHINE',
N'SOFTWARE\Microsoft\Microsoft SQL
Server\MSSQLServer\SuperSocketNetLib\Tcp\IPAll',
N'TcpPort',
@value OUTPUT,
N'no_output';
SELECT @value AS TCP_Port WHERE @value = '1433';
-- This should return no rows.




-- 2.12 Ensure 'Hide Instance' option is set to 'Yes' for Production SQL Server instances (Scored)
DECLARE @getValue INT;
EXEC master.sys.xp_instance_regread
@rootkey = N'HKEY_LOCAL_MACHINE',
@key = N'SOFTWARE\Microsoft\Microsoft SQL
Server\MSSQLServer\SuperSocketNetLib',
@value_name = N'HideInstance',
@value = @getValue OUTPUT;
SELECT @getValue;
 -- A value of 1 should be returned to be compliant.





 -- 2.13 Ensure the 'sa' Login Account is set to 'Disabled' (Scored)
SELECT name, is_disabled
FROM sys.server_principals
WHERE sid = 0x01
AND is_disabled = 0;

-- No rows should be returned to be compliant.




-- 2.14 Ensure the 'sa' Login Account has been renamed (Scored)
SELECT name
FROM sys.server_principals
WHERE sid = 0x01;
-- A name of sa indicates the account has not been renamed and therefore needs remediation.





-- 2.15 Ensure 'AUTO_CLOSE' is set to 'OFF' on contained databases (Scored)
SELECT name, containment, containment_desc, is_auto_close_on
FROM sys.databases
WHERE containment <> 0 and is_auto_close_on = 1;




-- 2.16 Ensure no login exists with the name 'sa' (Scored)
SELECT principal_id, name
FROM sys.server_principals
WHERE name = 'sa';
-- No rows should be returned




-- 3.1 Ensure 'Server Authentication' Property is set to 'Windows Authentication Mode' (Scored)
SELECT SERVERPROPERTY('IsIntegratedSecurityOnly') as [login_mode];
-- A login_mode of 1 indicates the Server Authentication property is set to Windows
-- Authentication Mode. A login_mode of 0 indicates mixed mode authentication




-- 3.2 Ensure CONNECT permissions on the 'guest' user is Revoked within
-- all SQL Server databases excluding the master, msdb and tempdb (Scored)
USE <database_name>;
GO
SELECT DB_NAME() AS DatabaseName, 'guest' AS Database_User,
[permission_name], [state_desc]
FROM sys.database_permissions
WHERE [grantee_principal_id] = DATABASE_PRINCIPAL_ID('guest')
AND [state_desc] LIKE 'GRANT%'
AND [permission_name] = 'CONNECT'
AND DB_NAME() NOT IN ('master','tempdb','msdb');
--No rows should be returned.





-- 3.3 Ensure 'Orphaned Users' are Dropped From SQL Server Databases (Scored)
USE [<database_name>];
GO
EXEC sp_change_users_login @Action='Report';
-- No rows should be returned.





-- 3.4 Ensure SQL Authentication is not used in contained databases (Scored)
SELECT name AS DBUser
FROM sys.database_principals
WHERE name NOT IN ('dbo','Information_Schema','sys','guest')
AND type IN ('U','S','G')
AND authentication_type = 2;
GO
-- No rows should be returned.




-- 3.5 Ensure the SQL Server’s MSSQL Service Account is Not an Administrator (Not Scored)
/*
Verify that the service account (in case of a local or AD account) and service SID
are not members of the Windows Administrators group.
*/




-- 3.6 Ensure the SQL Server’s SQLAgent Service Account is Not an Administrator (Not Scored)
/*
Verify that the service account (in case of a local or AD account)
and service SID are not members of the Windows Administrators group.
*/




-- 3.7 Ensure the SQL Server’s Full-Text Service Account is Not an Administrator (Not Scored)
/*
Verify that the service account (in case of a local or AD account) and service SID are not
members of the Windows Administrators group.
*/




-- 3.8 Ensure only the default permissions specified by Microsoft are granted to the public server role (Scored)
SELECT *
FROM master.sys.server_permissions
WHERE (grantee_principal_id = SUSER_SID(N'public') and state_desc LIKE
'GRANT%')
AND NOT (state_desc = 'GRANT' and [permission_name] = 'VIEW ANY DATABASE' and
class_desc = 'SERVER')
AND NOT (state_desc = 'GRANT' and [permission_name] = 'CONNECT' and
class_desc = 'ENDPOINT' and major_id = 2)
AND NOT (state_desc = 'GRANT' and [permission_name] = 'CONNECT' and
class_desc = 'ENDPOINT' and major_id = 3)
AND NOT (state_desc = 'GRANT' and [permission_name] = 'CONNECT' and
class_desc = 'ENDPOINT' and major_id = 4)
AND NOT (state_desc = 'GRANT' and [permission_name] = 'CONNECT' and
class_desc = 'ENDPOINT' and major_id = 5);
-- This query should not return any rows.





-- 3.9 Ensure Windows BUILTIN groups are not SQL Logins (Scored)
SELECT pr.[name], pe.[permission_name], pe.[state_desc]
FROM sys.server_principals pr
JOIN sys.server_permissions pe
ON pr.principal_id = pe.grantee_principal_id
WHERE pr.name like 'BUILTIN%';
-- This query should not return any rows.





-- 3.10 Ensure Windows local groups are not SQL Logins (Scored)
USE [master]
GO
SELECT pr.[name] AS LocalGroupName, pe.[permission_name], pe.[state_desc]
FROM sys.server_principals pr
JOIN sys.server_permissions pe
ON pr.[principal_id] = pe.[grantee_principal_id]
WHERE pr.[type_desc] = 'WINDOWS_GROUP'
AND pr.[name] like CAST(SERVERPROPERTY('MachineName') AS nvarchar) + '%';
-- This query should not return any rows.





-- 3.11 Ensure the public role in the msdb database is not granted access to SQL Agent proxies (Scored)
USE [msdb]
GO
SELECT sp.name AS proxyname
FROM dbo.sysproxylogin spl
JOIN sys.database_principals dp
ON dp.sid = spl.sid
JOIN sysproxies sp
ON sp.proxy_id = spl.proxy_id
WHERE principal_id = USER_ID('public');
GO
-- This query should not return any rows.





-- 4.1 Ensure 'MUST_CHANGE' Option is set to 'ON' for All SQL Authenticated Logins (Not Scored)

/*
1. Open SQL Server Management Studio.
2. Open Object Explorer and connect to the target instance.
3. Navigate to the Logins tab in Object Explorer and expand. Right click on the
desired login and select Properties.
4. Verify the User must change password at next login checkbox is checked.
*/





-- 4.2 Ensure 'CHECK_EXPIRATION' Option is set to 'ON' for All SQL Authenticated Logins Within the Sysadmin Role (Scored)

SELECT l.[name], 'sysadmin membership' AS 'Access_Method'
FROM sys.sql_logins AS l
WHERE IS_SRVROLEMEMBER('sysadmin',name) = 1
AND l.is_expiration_checked <> 1
UNION ALL
SELECT l.[name], 'CONTROL SERVER' AS 'Access_Method'
FROM sys.sql_logins AS l
JOIN sys.server_permissions AS p
ON l.principal_id = p.grantee_principal_id
WHERE p.type = 'CL' AND p.state IN ('G', 'W')
AND l.is_expiration_checked <> 1;

-- No rows should be returned.





-- 4.3 Ensure 'CHECK_POLICY' Option is set to 'ON' for All SQL Authenticated Logins (Scored)
SELECT name, is_disabled
FROM sys.sql_logins
WHERE is_policy_checked = 0;
-- No rows should be returned.






-- 5.1 Ensure 'Maximum number of error log files' is set to greater than or equal to '12' (Scored)
DECLARE @NumErrorLogs int;
EXEC master.sys.xp_instance_regread
N'HKEY_LOCAL_MACHINE',
N'Software\Microsoft\MSSQLServer\MSSQLServer',
N'NumErrorLogs',
@NumErrorLogs OUTPUT;
SELECT ISNULL(@NumErrorLogs, -1) AS [NumberOfLogFiles];
-- The NumberOfLogFiles returned should be greater than or equal to 12.





-- 5.2 Ensure 'Default Trace Enabled' Server Configuration Option is set to '1' (Scored)
SELECT name,
CAST(value as int) as value_configured,
CAST(value_in_use as int) as value_in_use
FROM sys.configurations
WHERE name = 'default trace enabled';






-- 5.3 Ensure 'Login Auditing' is set to 'failed logins' (Scored)
EXEC xp_loginconfig 'audit level';
/*
A config_value of failure indicates a server login auditing setting of Failed logins only.
If a config_value of all appears, then both failed and successful logins are being logged.
Both settings should also be considered valid, but as mentioned capturing successful logins
using this method creates lots of noise in the SQL Server Errorlog.
*/





-- 5.4 Ensure 'SQL Server Audit' is set to capture both 'failed' and 'successful logins' (Scored)
SELECT
S.name AS 'Audit Name'
, CASE S.is_state_enabled
WHEN 1 THEN 'Y'
WHEN 0 THEN 'N' END AS 'Audit Enabled'
, S.type_desc AS 'Write Location'
, SA.name AS 'Audit Specification Name'
, CASE SA.is_state_enabled
WHEN 1 THEN 'Y'
WHEN 0 THEN 'N' END AS 'Audit Specification Enabled'
, SAD.audit_action_name
, SAD.audited_result
FROM sys.server_audit_specification_details AS SAD
JOIN sys.server_audit_specifications AS SA
ON SAD.server_specification_id = SA.server_specification_id
JOIN sys.server_audits AS S
ON SA.audit_guid = S.audit_guid
WHERE SAD.audit_action_id IN ('CNAU', 'LGFL', 'LGSD');
/*
The result set should contain 3 rows, one for each of the following audit_action_names:

• AUDIT_CHANGE_GROUP
• FAILED_LOGIN_GROUP
• SUCCESSFUL_LOGIN_GROUP
*/





-- 6.1 Ensure Database and Application User Input is Sanitized (Not Scored)
/*
Check with the application teams to ensure any database interaction is through the use of
stored procedures and not dynamic SQL. Revoke any INSERT, UPDATE, or DELETE privileges
to users so that modifications to data must be done through stored procedures. Verify that
there's no SQL query in the application code produced by string concatenation.
*/



-- 6.2 Ensure 'CLR Assembly Permission Set' is set to 'SAFE_ACCESS' for All CLR Assemblies (Scored)
SELECT name,
permission_set_desc
FROM sys.assemblies
WHERE is_user_defined = 1;
-- All the returned assemblies should show SAFE_ACCESS in the permission_set_desc column.





-- 7.1 Ensure 'Symmetric Key encryption algorithm' is set to 'AES_128' or higher in non-system databases (Scored)
USE <database_name>
GO
SELECT db_name() AS Database_Name, name AS Key_Name
FROM sys.symmetric_keys
WHERE algorithm_desc NOT IN ('AES_128','AES_192','AES_256')
AND db_id() > 4;
GO
-- For compliance, no rows should be returned.





-- 7.2 Ensure Asymmetric Key Size is set to 'greater than or equal to 2048' in non-system databases (Scored)
USE <database_name>
GO
SELECT db_name() AS Database_Name, name AS Key_Name
FROM sys.asymmetric_keys
WHERE key_length < 2048
AND db_id() > 4;
GO
-- For compliance, no rows should be returned.




-- 8.1 Ensure 'SQL Server Browser Service' is configured correctly (Not Scored)
-- Check the SQL Browser service's status via services.msc or similar methods.
