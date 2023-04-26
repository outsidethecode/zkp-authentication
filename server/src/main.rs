mod parameters;

use tonic::{transport::Server, Request, Response, Status};
use zkp::{ZkpAuthRequest, ZkpAuthResponse, zkp_auth_server::{ZkpAuth, ZkpAuthServer}};
use parameters::public;

pub mod zkp {
  tonic::include_proto!("zkp");
}

#[derive(Debug, Default)]
pub struct ZkpAuthService {}

#[tonic::async_trait]
impl ZkpAuth for ZkpAuthService {
    async fn vote(&self, request: Request<ZkpAuthRequest>) -> Result<Response<ZkpAuthResponse>, Status> {
        let r = request.into_inner();
        match r.vote {
            0 => Ok(Response::new(zkp::ZkpAuthResponse { confirmation: { 
                format!("Happy to confirm that you upvoted for {}", r.url)
            }})),
            1 => Ok(Response::new(zkp::ZkpAuthResponse { confirmation: { 
                format!("Confirmation that you downvoted for {}", r.url)
            }})), 
            _ => Err(Status::new(tonic::Code::OutOfRange, "Invalid vote provided"))
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
  let address = "[::1]:8080".parse().unwrap();
  let zkp_auth_service = ZkpAuthService::default();


  println!("Got: '{}' from service", 1);

  let (p, q, g, h) = public();

  println!(" --- Public parameters --- ");
  println!("p = {}", &p);
  println!("q = {}", &q);
  println!("g = {}", &g);
  println!("h = {}", &h);
  println!(" ------------------------- ");


  Server::builder().add_service(ZkpAuthServer::new(zkp_auth_service))
    .serve(address)
    .await?;
  Ok(())
     
}

