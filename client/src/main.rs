use std::io::stdin;

use zkp::{zkp_auth_client::ZkpAuthClient, ZkpAuthRequest};

pub mod zkp {
  tonic::include_proto!("zkp");
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
  let mut client = ZkpAuthClient::connect("http://[::1]:8080").await?;
  loop {
    println!("\nPlease vote for a particular url");
    let mut u = String::new();
    let mut vote: String = String::new();
    println!("Please provide a url: ");
    stdin().read_line(&mut u).unwrap();
    let u = u.trim();
    println!("Please vote (d)own or (u)p: ");
    stdin().read_line(&mut vote).unwrap();
    let v = match vote.trim().to_lowercase().chars().next().unwrap() {
      'u' => 0,
      'd' => 1,
      _ => break,
    };
    let request = tonic::Request::new(ZkpAuthRequest {
      url: String::from(u),
      vote: v,
    });
    let response = client.vote(request).await?;
    println!("Got: '{}' from service", response.into_inner().confirmation);
  }
  Ok(())
}