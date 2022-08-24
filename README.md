# mssql_enum

## Interactive MSSQL Server Enumeration Tool

* Connects to a database via Windows Authentication.
* Can to trigger authentication back to your ip with xp_dirtree to capture NetNTLM hash with Responder.
* Can attempt to execute code via xp_cmdshell or OLE Procedure.
* Can attempt to impersonate users such as 'sa' account.
* Can find linked MSSQL servers and execute code on those as well.

_Command execution does not return the command output. Best to use it to execute a reverse shell._
