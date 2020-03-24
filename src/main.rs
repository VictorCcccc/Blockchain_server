#[macro_use]
extern crate hex_literal;

pub mod api;
pub mod block;
pub mod blockchain;
pub mod crypto;
pub mod miner;
pub mod network;
pub mod transaction;
pub mod txgenerator;

use clap::clap_app;
use crossbeam::channel;
use log::{error, info};
use api::Server as ApiServer;
use network::{server, worker};
use std::net;
use std::process;
use std::thread;
use std::time;
use std::sync::Mutex;
use std::sync::Arc;
use crate::blockchain::Blockchain;
use std::collections::HashMap;
use crate::network::worker::OrphanBuffer;
use crate::txgenerator::TxMempool;
use crate::crypto::key_pair;
use ring::signature::Ed25519KeyPair;
use ring::signature::KeyPair;
use crate::crypto::hash::{H256, H160};
use crate::network::peer::ReadResult::Message;

fn main() {
    // parse command line arguments
    let matches = clap_app!(Bitcoin =>
     (version: "0.1")
     (about: "Bitcoin client")
     (@arg verbose: -v ... "Increases the verbosity of logging")
     (@arg peer_addr: --p2p [ADDR] default_value("127.0.0.1:6000") "Sets the IP address and the port of the P2P server")
     (@arg api_addr: --api [ADDR] default_value("127.0.0.1:7000") "Sets the IP address and the port of the API server")
     (@arg known_peer: -c --connect ... [PEER] "Sets the peers to connect to at start")
     (@arg p2p_workers: --("p2p-workers") [INT] default_value("4") "Sets the number of worker threads for P2P server")
    )
    .get_matches();

    // init logger
    let verbosity = matches.occurrences_of("verbose") as usize;
    stderrlog::new().verbosity(verbosity).init().unwrap();
    let new_chain = Arc::new(Mutex::new(Blockchain::new()));
    let new_buf = Arc::new(Mutex::new(OrphanBuffer::new()));
    let new_txpool = Arc::new(Mutex::new(TxMempool::new()));
    let mut state = Arc::new(Mutex::new(HashMap::new()));
    let mut block_state = Arc::new(Mutex::new(HashMap::new()));
    // parse p2p server address
    let p2p_addr = matches
        .value_of("peer_addr")
        .unwrap()
        .parse::<net::SocketAddr>()
        .unwrap_or_else(|e| {
            error!("Error parsing P2P server address: {}", e);
            process::exit(1);
        });

    // parse api server address
    let api_addr = matches
        .value_of("api_addr")
        .unwrap()
        .parse::<net::SocketAddr>()
        .unwrap_or_else(|e| {
            error!("Error parsing API server address: {}", e);
            process::exit(1);
        });

    // create channels between server and worker
    let (msg_tx, msg_rx) = channel::unbounded();

    // start the p2p server
    let (server_ctx, server) = server::new(p2p_addr, msg_tx).unwrap();
    server_ctx.start().unwrap();

    // start the worker
    let p2p_workers = matches
        .value_of("p2p_workers")
        .unwrap()
        .parse::<usize>()
        .unwrap_or_else(|e| {
            error!("Error parsing P2P workers: {}", e);
            process::exit(1);
        });

    let key = key_pair::random();
    let trusted_public = key.public_key().as_ref().to_vec();
    let public_hash: H256 = ring::digest::digest(&ring::digest::SHA256, &trusted_public).into();
    let address: H160 = public_hash.into();
    state.lock().unwrap().insert(address.clone(),(0,100));

    // start transcation generator
    let (txpool_ctx, generator) = txgenerator::new(
        &server,
        &new_txpool,
        key,
        &state,
        &block_state,
        &new_chain,
    );
    txpool_ctx.start();

    // start worker
    let worker_ctx = worker::new(
        p2p_workers,
        msg_rx,
        &server,
        &new_chain,
        &new_buf,
        &new_txpool,
        &state,
        address.clone(),
        &block_state
    );
    worker_ctx.start();



    // start the miner
    let (miner_ctx, miner) = miner::new(
        &server,
        &new_chain,
        &new_txpool,
        &state,
        &block_state,
        address,
    );
    miner_ctx.start();


    // connect to known peers
    if let Some(known_peers) = matches.values_of("known_peer") {
        let known_peers: Vec<String> = known_peers.map(|x| x.to_owned()).collect();
        let server = server.clone();
        thread::spawn(move || {
            for peer in known_peers {
                loop {
                    let addr = match peer.parse::<net::SocketAddr>() {
                        Ok(x) => x,
                        Err(e) => {
                            error!("Error parsing peer address {}: {}", &peer, e);
                            break;
                        }
                    };
                    match server.connect(addr) {
                        Ok(_) => {
                            info!("Connected to outgoing peer {}", &addr);
                            server.broadcast(network::message::Message::NewPeer(address));
                            break;
                        }
                        Err(e) => {
                            error!(
                                "Error connecting to peer {}, retrying in one second: {}",
                                addr, e
                            );
                            thread::sleep(time::Duration::from_millis(1000));
                            continue;
                        }
                    }
                }
            }
        });
    }


    // start the API server
    ApiServer::start(
        api_addr,
        &generator,
        &miner,
        &server,
    );

    loop {
        std::thread::park();
    }
}
