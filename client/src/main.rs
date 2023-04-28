mod parameters;
mod zkp_utils;

use std::io::stdin;
use tonic::Response;
use num_bigint::{BigInt, ToBigInt};
use num::Num;
use colored::Colorize;

use parameters::{public_params};
use zkp_utils::{
    random_big_int,
    get_user_credentials,
    zkp_register, 
    zkp_authentication_challenge, 
    zkp_verify_authentication};
    
use zkp_auth::{
    auth_client::AuthClient,
    RegisterResponse,
    AuthenticationChallengeResponse,
    AuthenticationAnswerResponse
};

pub mod zkp_auth {
  tonic::include_proto!("zkp_auth");
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
  let mut client = AuthClient::connect("http://[::1]:8080").await?;

  let (p, q, g, h) = public_params();

  println!("{}", "Public parameters".cyan());
  println!("p = {}", &p);
  println!("q = {}", &q);
  println!("g = {}", &g);
  println!("h = {}", &h);
  println!("");

  let mut finish = false;
  let mut option = String::new();

  while !finish {

    println!("");
    println!("{}", "Please choose a number: 1. Register | 2. Login | 3. Exit".yellow());
    println!("");

        option.clear();
        stdin()
            .read_line(&mut option)
            .expect("Error reading the option number");


        let option: u32 = option.trim().parse().expect("could not convert {option}");

        match option {
            1 => {
                let (username, x) = get_user_credentials();

                // Send the parameters: user, y1 and y2 to the server
                let register_request = zkp_register(&username, &x);
                println!("Request={:?}", register_request);

                // Response is an empty struct as per the protobuf. Therefore there is no way to know from the server 
                // if the user is already registered. For now we can show the response to the user. Later on, we need to update 
                // RegisterResponse to include the registration outcome. 
                let register_response:Response<RegisterResponse> = client.register(register_request).await?;
                println!("Response={:?}", register_response);
            }
            2 => {
                let (username, x) = get_user_credentials();

                // Generate random k in the range {2, ..., q - 2}
                let k = random_big_int(2.to_bigint().unwrap(), &q - 2);

                // Send the parameters: user, r1 and r2 to the server
                let authentication_challenge_request = zkp_authentication_challenge(&username, &k);
                let authentication_challenge_response:Response<AuthenticationChallengeResponse> = client
                    .create_authentication_challenge(authentication_challenge_request)
                    .await?;
                let auth_id = &authentication_challenge_response.get_ref().auth_id;

                // If user was not registered, notify the user and continue the loop
                if auth_id == "UserNotRegistered" {
                    println!("");
                    println!("{}", "You are not registered yet".red());
                    println!("");
                    continue;
                }

                // Receive challenge c
                let c: BigInt = Num::from_str_radix(
                    &authentication_challenge_response.get_ref().c, 
                    16)
                    .unwrap();
    
                println!("{}", "Challenge".cyan());
                println!("c = {}", &c);
                println!("");

                // Compute s = k - c * x (mod q)
                let s = (((&k - &c * &x) % (&q)) + (&q)) % (&q);

                println!("{}", "Answer".cyan());
                println!("s = {}", &s);
                println!("");

                let authentication_answer_request = zkp_verify_authentication(&s, auth_id);
                let verify_authentication_response:Response<AuthenticationAnswerResponse> = client
                    .verify_authentication(authentication_answer_request)
                    .await?;

                let session_id = &verify_authentication_response.get_ref().session_id;

                if session_id == "WrongCredentials" {
                    println!("{}", "Wrong credentials. Please retry again".red());
                    continue;
                }
                else {
                    println!("{}", "Login succeeded!".green());
                }

            }
            3 => { finish = true;}
            _ => {println!("Invalid input!")}
        }
    }

  Ok(())
}