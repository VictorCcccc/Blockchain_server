use crate::network::server::Handle as ServerHandle;
use std::sync::Arc;
use crate::blockchain::Blockchain;
use std::sync::Mutex;
use log::info;
use crossbeam::channel::{unbounded, Receiver, Sender, TryRecvError};
use std::time;
use crate::block;
use std::thread;
use crate::crypto::hash::{H160, H256, Hashable};
use std::time::{SystemTime, UNIX_EPOCH};
use super::block::{Content, Header};
use super::transaction::{Transaction, SignedTransaction, sign};
use crate::crypto::merkle::MerkleTree;
use crate::block::Block;
use serde::{Serialize, Deserialize};
use super::network::message::Message;
use std::collections::{HashMap, VecDeque, HashSet};
use crate::crypto::key_pair;
use ring::signature::Ed25519KeyPair;
use ring::signature::KeyPair;
extern crate rand;
use rand::Rng;

enum ControlSignal {
    Start(u64), // the number controls the lambda of interval between block generation
    Exit,
}

enum OperatingState {
    Paused,
    Run(u64),
    ShutDown,
}

pub struct Context {
    /// Channel for receiving control signal
    control_chan: Receiver<ControlSignal>,
    operating_state: OperatingState,
    server: ServerHandle,
    mempool_buf: Arc<Mutex<TxMempool>>,
    key: Ed25519KeyPair,
    public: Vec<u8>,
    address: H160,
    init_state: Arc<Mutex<HashMap<H160,(u32, u32)>>>,
    block_state:Arc<Mutex<HashMap<H256,HashMap<H160,(u32,u32)>>>>,
    blockchain: Arc<Mutex<Blockchain>>,
}

#[derive(Clone)]
pub struct TxMempool{
    pub buf: VecDeque<SignedTransaction>,
    pub map: HashMap<H256,SignedTransaction>,
}

impl TxMempool{
    pub fn new() -> Self{
        let new_buf = VecDeque::new();
        let new_map = HashMap::new();
        TxMempool {
            buf : new_buf,
            map : new_map,
        }
    }

    pub fn push_tx(&mut self, signed_transaction: &SignedTransaction){
        let mut curr_buf = &mut self.buf;
        curr_buf.push_back(signed_transaction.clone());
        let mut curr_map = &mut self.map;
        curr_map.insert(signed_transaction.hash(),signed_transaction.clone());
    }

    pub fn pop_tx(&mut self, signed_transaction: &SignedTransaction){
        let mut curr_buf = &mut self.buf;
        let mut index = 0;
        for tx in curr_buf.clone(){
            if tx.hash() == signed_transaction.hash(){
                break;
            }
            index += 1;
        }
        curr_buf.remove(index);
        //println!("Poped tx : {:?}", signed_transaction.hash());
        let mut curr_map = &mut self.map;
        curr_map.remove(&signed_transaction.hash());
    }

    pub fn pop_multi_tx(&mut self, topN: &u32){
        let mut curr_buf = &mut self.buf;
        let mut curr_map = &mut self.map;
        for _x in 0..*topN {
            let pop_tx = curr_buf.pop_front();
            curr_map.remove(&pop_tx.unwrap().hash());
        }
    }
}

#[derive(Clone)]
pub struct Handle {
    /// Channel for sending signal to the miner thread
    control_chan: Sender<ControlSignal>,
}

pub fn new(
    server: &ServerHandle,
    tx_pool: &Arc<Mutex<TxMempool>>,
    key: Ed25519KeyPair,
    state: &Arc<Mutex<HashMap<H160,(u32, u32)>>>,
    block_state: &Arc<Mutex<HashMap<H256,HashMap<H160,(u32,u32)>>>>,
    blockchain: &Arc<Mutex<Blockchain>>,
) -> (Context, Handle) {
    let (signal_chan_sender, signal_chan_receiver) = unbounded();
    let mempool_buf = tx_pool.clone();
    let trusted_public = key.public_key().as_ref().to_vec();
    let public_hash: H256 = ring::digest::digest(&ring::digest::SHA256, &trusted_public).into();
    let address: H160 = public_hash.into();
    let mut block_state = block_state.clone();
    let blockchain = blockchain.clone();
    let ctx = Context {
        control_chan: signal_chan_receiver,
        operating_state: OperatingState::Paused,
        server: server.clone(),
        mempool_buf: mempool_buf,
        key: key,
        public: trusted_public,
        address: address,
        init_state: state.clone(),
        block_state: block_state,
        blockchain: blockchain,
    };

    let handle = Handle {
        control_chan: signal_chan_sender,
    };

    (ctx, handle)
}

impl Handle {
    pub fn exit(&self) {
        self.control_chan.send(ControlSignal::Exit).unwrap();
    }

    pub fn start(&self, lambda: u64) {
        self.control_chan
            .send(ControlSignal::Start(lambda))
            .unwrap();
    }

}

impl Context {
    pub fn start(mut self) {
        thread::Builder::new()
            .name("generator".to_string())
            .spawn(move || {
                self.generate_loop();
            })
            .unwrap();
        info!("Generator initialized into paused mode");
    }

    fn handle_control_signal(&mut self, signal: ControlSignal) {
        match signal {
            ControlSignal::Exit => {
                info!("Generator shutting down");
                self.operating_state = OperatingState::ShutDown;
            }
            ControlSignal::Start(i) => {
                info!("Generator starting in continuous mode with lambda {}", i);
                self.operating_state = OperatingState::Run(i);
            }
        }
    }
    fn generate_loop(&mut self) {
        let mut count  = 1;

        // main mining loop
        loop {
            //check and react to control signals
            match self.operating_state {
                OperatingState::Paused => {
                    let signal = self.control_chan.recv().unwrap();
                    self.handle_control_signal(signal);
                    continue;
                }
                OperatingState::ShutDown => {
                    return;
                }
                _ => match self.control_chan.try_recv() {
                    Ok(signal) => {
                        self.handle_control_signal(signal);
                    }
                    Err(TryRecvError::Empty) => {}
                    Err(TryRecvError::Disconnected) => panic!("Transaction generator control channel detached"),
                },
            }
            if let OperatingState::ShutDown = self.operating_state {
                return;
            }

            // TODO :: FIGURE OUT THE RECIPIENT

            let init_state = self.init_state.lock().unwrap();
            let mut peer_vec = Vec::new();
            for key in init_state.keys() {
                peer_vec.push(key);
            }

            let mut rand_num =  0;
            //println!("Current peer number: {:?}", peer_vec.len());
            while peer_vec[rand_num].eq( &self.address){
                let mut rng = rand::thread_rng();
                rand_num =  rng.gen_range(0, peer_vec.len());
                //println!("Rand number {:?}, Process number : {:?}", rand_num, peer_vec.len());
            }


            let peer_add = peer_vec[rand_num].clone();
            let current_block_state = self.block_state.lock().unwrap();
            let current_chain = self.blockchain.lock().unwrap();
            let current_state = current_block_state.get(&current_chain.tail).unwrap();
            let current_nonce = current_state.get(&self.address).unwrap().0;
            if init_state.len() >= 2 && count == current_nonce + 1{
                println!("New tx: Sender is: {:?}, Receiver is : {:?}", self.address, peer_add);
                println!("---------------------");
                let mut txpool = self.mempool_buf.lock().unwrap();
                let trans = Transaction {
                    address: peer_add, // should be recipient address
                    value: 1,
                    nonce: count,
                };
                count = count + 1;
                let signature = sign(&trans, &self.key);
                let trusted_sign = signature.as_ref().to_vec();
                let signed_trans = SignedTransaction {
                    public_key: self.public.clone(),
                    signature: trusted_sign.clone(),
                    transaction: trans.clone(),
                };
                txpool.push_tx(&signed_trans);
                let mut tx_vec = Vec::new();
                tx_vec.push(signed_trans.hash());
                self.server.broadcast(Message::NewTransactionHashes(tx_vec));
                //println!("NEW TX");
                std::mem::drop(txpool);
            } else {
                //println!("current peers number {:?}", init_state.len());
                //println!("current nonce number {:?}", init_state.get(&self.address).unwrap().0);
            }
            std::mem::drop(init_state);
            std::mem::drop(current_chain);
            std::mem::drop(current_block_state);

            let interval = time::Duration::from_micros(1000000);
            thread::sleep(interval);
        }
    }
}
