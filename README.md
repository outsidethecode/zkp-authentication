# ZKP Chaum Pedersen protocol implementation in Rust

## Context
ZKP is a viable alternative to hashing in an authentication schema. This repo implements the ZKP Protocol and a Proof-of-Concept
application that utilizes the protocol to register and authenticate users.

## The ZKP Protocol
The ZKP protocol is described in the book "[Cryptography: An Introduction (3rd Edition) Nigel Smart](https://www.cs.umd.edu/~waa/414-F11/IntroToCrypto.pdf)" page 377 section "3. Sigma Protocols" subsection "3.2. Chaum–Pedersen Protocol.". This source code adapts this protocol to support 1-factor authentication, that is, the exact matching of a number (registration password) stored during registration and another number (login password) generated during the login process. 

## Repo structure
This repo contains two projects: client and server.

## Run the applicaton

1. Launch Postgres database. The url of the database is configured in the file server/src/parameters.rs via the parameter DATABASE_URL.

2. Run the server
          ``` /server$ cargo run ```

3. Run the client 
          ``` /client$ cargo run ```

![image](https://user-images.githubusercontent.com/49871473/235252373-eba0c5f7-3f32-4fca-b7a6-340367b4f324.png)
