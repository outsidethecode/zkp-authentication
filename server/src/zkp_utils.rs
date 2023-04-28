#![allow(unused)]

use std::hash::{Hash, Hasher};
use std::collections::hash_map::DefaultHasher;
use std::io;
use std::io::Write;
use rpassword::read_password;
use num_bigint::{BigInt, ToBigInt, RandBigInt, Sign};
use num_traits::{Zero, One};
use rand::{distributions::Alphanumeric, Rng}; 
use tonic::Request;
use crate::parameters::public_params;
use crate::zkp_auth::{
    RegisterRequest, 
    AuthenticationChallengeRequest,
    AuthenticationAnswerRequest};


// A method to calculate the modular exponentiation
pub fn mod_exp(g: &BigInt, x: &BigInt, q: &BigInt) -> BigInt {

    let one: BigInt = One::one();
    let zero: BigInt = Zero::zero();
    let two: BigInt = &one + &one;

    if q == &one { return zero }
    let mut result = 1.to_bigint().unwrap();

    let mut base = g % q;
    let mut exp = x.clone();
    while &exp > &zero {
        if &exp % &two == one {
            result = result * &base % q;
        }        
        exp = exp >> 1;
        base = &base * &base % q
    }

    (result + q) % q
}

// Generate a random BigInt
pub fn random_big_int(from: BigInt, to: BigInt) -> BigInt {
    rand::thread_rng().gen_bigint_range(&from, &to)
}

// Generate a random String
pub fn random_string() -> String {
    return rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(7)
        .map(char::from)
        .collect();
}

// Generate a hash of a String
pub fn default_hash<T>(obj: T) -> BigInt where T: Hash, {

    let mut hasher = DefaultHasher::new();
    obj.hash(&mut hasher);
    hasher.finish().to_bigint().unwrap()

}
