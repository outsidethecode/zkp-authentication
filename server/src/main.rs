mod parameters;
mod zkp_utils;
pub mod zkp_auth {
  tonic::include_proto!("zkp_auth");
}

use num::Num;
use num_bigint::{BigInt, ToBigInt};
use tonic::{transport::Server, Request, Response, Status};
use sqlx::postgres::PgPoolOptions;
use sqlx::Row;
use colored::Colorize;

use parameters::{public_params, DATABASE_URL};
use zkp_utils::{
  mod_exp,
  random_big_int,
  random_string,
  default_hash
};
use zkp_auth::auth_server::{Auth, AuthServer};
use zkp_auth::{
    RegisterRequest, 
    RegisterResponse,
    AuthenticationChallengeRequest,
    AuthenticationChallengeResponse,
    AuthenticationAnswerRequest,
    AuthenticationAnswerResponse
};

#[derive(Debug, Default)]
pub struct AuthService {}

#[tonic::async_trait]
impl Auth for AuthService {
  
  // Implementing the Register method that allows registering users by providing username, y1 and y2
  async fn register(&self, request:Request<RegisterRequest>) -> Result<Response<RegisterResponse>, Status> {

    println!("Request={:?}", request);

    let user = &request.get_ref().user;
    let y1 = &request.get_ref().y1;
    let y2 = &request.get_ref().y2;

    let pool = PgPoolOptions::new()
    .max_connections(1)
    .connect(DATABASE_URL)
    .await
    .expect("connection error");

    // user_is_registered is boolean to determine if the user is registered. 
    // The column register_request:auth_id contains the hash of the usernames. 
    // We can determine if the user is registered by checking if the hash of the username exists in that column.  
    let user_is_registered = sqlx::query(
        "select exists(select 1 from register_request where auth_id=($1))")
        .bind(&default_hash(user).to_str_radix(16))
        .fetch_one(&pool)
        .await
        .expect("Check User registered failed")
        .get::<bool, usize>(0)
    ;

    if user_is_registered == false {

        // Add the user into the database
        sqlx::query(
            "insert into register_request (auth_id, y1, y2) values ($1, $2, $3)")
            .bind(&default_hash(user).to_str_radix(16))
            .bind(y1)
            .bind(y2)
            .execute(&pool)
            .await
            .expect("user insertion error")
        ;
        println!("{}", "Registration successful!".green());
    }
    else {
        println!("{}", "Already registered. Please login instead".red());
    }

    pool.close().await;

    Ok(Response::new(RegisterResponse{}))
}

// Implementing the CreateAuthenticationChallenge challenge which creates the challenge c based on username, r1, and r2
async fn create_authentication_challenge(&self, request:Request<AuthenticationChallengeRequest>) -> Result<Response<AuthenticationChallengeResponse>, Status> {

    println!("Request={:?}", request);

    let q = public_params().1;
    let user = &request.get_ref().user;
    let r1 = &request.get_ref().r1;
    let r2 = &request.get_ref().r2;

    let c_hex = random_big_int(2.to_bigint().unwrap(), &q - 1).to_str_radix(16);

    let pool = PgPoolOptions::new()
    .max_connections(1)
    .connect(DATABASE_URL)
    .await
    .expect("Database pool connection failed");

    let user_is_registered = sqlx::query(
        "select exists(select 1 from register_request where auth_id= ($1))")
        .bind(&default_hash(user).to_str_radix(16))
        .fetch_one(&pool)
        .await
        .expect("Check User registered failed")
        .get::<bool, usize>(0)
    ;
        
    // Set register_request:auth_id to hash(user)
    // If user is not registered, set register_request:auth_id to UserNotRegistered
    let mut auth_id = String::new();

    if user_is_registered == false {
        auth_id.push_str("UserNotRegistered");
    }
    else {
        auth_id.push_str(&default_hash(user).to_str_radix(16));

        // Add the commitment into the database
        sqlx::query(
            "insert into auth_commitment (auth_id, r1, r2) values ($1, $2, $3) 
            on conflict (auth_id) do update set r1 = $2, r2 = $3")
            .bind(&auth_id)
            .bind(r1)
            .bind(r2)
            .execute(&pool)
            .await
            .expect("Commitment insertion error");

        // Add the challenge into the database
        sqlx::query(
            "insert into auth_challenge (auth_id, c) values ($1, $2) 
            on conflict (auth_id) do update set c = $2")
            .bind(&auth_id)
            .bind(&c_hex)
            .execute(&pool)
            .await
            .expect("Challenge insertion error");
    }

    pool.close().await;

    // Send back the random challenge c
    Ok(Response::new(AuthenticationChallengeResponse{
        auth_id: auth_id,
        c: c_hex,
    }))
}

// Implementing the VerifyAuthentication method based on the received s
async fn verify_authentication(&self, request:Request<AuthenticationAnswerRequest>) -> Result<Response<AuthenticationAnswerResponse>, Status> {
    
    println!("Request={:?}", request);

    let auth_id = &request.get_ref().auth_id;
    let s = &request.get_ref().s;

    let pool = PgPoolOptions::new()
    .max_connections(1)
    .connect(DATABASE_URL)
    .await
    .expect("Database pool connection failed");

    // Retrieving the required parameters (y1, y2, r1 and r2) based on the auth_id for verification
    let y1 = sqlx::query(
        "select y1 from register_request where auth_id = ($1)")
        .bind(auth_id).fetch_one(&pool).await.expect("Error retrieving y1")
        .get::<String, usize>(0)
    ;
    let y2 = sqlx::query(
        "select y2 from register_request where auth_id = ($1)")
        .bind(auth_id).fetch_one(&pool).await.expect("Error retrieving y2")
        .get::<String, usize>(0)
    ;
    let r1 = sqlx::query(
        "select r1 from auth_commitment where auth_id = ($1)")
        .bind(auth_id).fetch_one(&pool).await.expect("Error retrieving r1")
        .get::<String, usize>(0)
    ;
    let r2 = sqlx::query(
        "select r2 from auth_commitment where auth_id = ($1)")
        .bind(auth_id).fetch_one(&pool).await.expect("Error retrieving r2")
        .get::<String, usize>(0)
    ;
    
    // We can delete the commitment after retrieving it because it is not going to be used anymore
    sqlx::query(
        "delete from auth_commitment where auth_id = ($1)")
        .bind(auth_id).execute(&pool).await.expect("Error deleting commitment")
    ;
    let c = sqlx::query(
        "select c from auth_challenge where auth_id = ($1)")
        .bind(auth_id).fetch_one(&pool).await.expect("Error retrieving c")
        .get::<String, usize>(0)
    ;

    sqlx::query(
        "delete from auth_challenge where auth_id = ($1)")
        .bind(auth_id).execute(&pool).await.expect("Error deleting challenge")
    ;

    pool.close().await;

    // Convert parameters back to BigInt
    let y1: BigInt = Num::from_str_radix(&y1, 16).unwrap();
    let y2: BigInt = Num::from_str_radix(&y2, 16).unwrap();
    let r1: BigInt = Num::from_str_radix(&r1, 16).unwrap();
    let r2: BigInt = Num::from_str_radix(&r2, 16).unwrap();
    let c: BigInt = Num::from_str_radix(&c, 16).unwrap();
    let s: BigInt = Num::from_str_radix(s, 16).unwrap();

    let (p, _q, g, h) = public_params();

    let part1 = ((mod_exp(&g.to_bigint().unwrap(), &s, &p ) * mod_exp(&y1, &c, &p) % &p) + &p) % &p;
    let part2 = ((mod_exp(&h.to_bigint().unwrap(), &s, &p) * mod_exp(&y2, &c, &p) % &p) + &p) % &p;
    
    println!("r1 = {}", &r1);
    println!("g^s * y1^c = {}", part1);
    println!("r2 = {}", &r2);
    println!("h^s * y2^c = {}", part2);

    let mut session_id = String::new();

    // Verify if the calculated parts have the expected values
    match &r1 == &part1 && &r2 == &part2 {
        true => {
            println!("{}", "Authentication successful!".green());
            session_id.push_str(&random_string());
        }
        false => {
            println!("{}", "Authentication FAILED!".red());
            session_id.push_str("WrongCredentials");
        }
    }

    Ok(Response::new(AuthenticationAnswerResponse{
        session_id: session_id
    }))
  }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
  let address = "[::1]:8080".parse().unwrap();
  let zkp_auth_service = AuthService::default();

  println!("Server listening on {}", address);
  Server::builder().add_service(AuthServer::new(zkp_auth_service))
    .serve(address)
    .await?;
  Ok(())
     
}

