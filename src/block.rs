extern crate chrono;
use serde::{Serialize, Deserialize};
use crate::crypto::hash::{H256, Hashable};
use crate::crypto::merkle::MerkleTree;
use super::transaction::{Transaction, SignedTransaction};
use chrono::prelude::*;
use std::time::{SystemTime, UNIX_EPOCH};
use super::*;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Header {
    pub parent_hash: H256,
    pub nonce: u32,
    pub difficulty: H256,
    pub timestamp: u128,
    pub merkle_root: MerkleTree,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Content {
    pub content: Vec<SignedTransaction>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Block {
    pub head: Header,
    pub content: Content,
}

impl Hashable for Transaction {
    fn hash(&self) -> H256 {
        ring::digest::digest(&ring::digest::SHA256, &(bincode::serialize(self).unwrap())).into()
    }
}

impl Hashable for SignedTransaction {
    fn hash(&self) -> H256 {
        self.transaction.hash()
    }
}

impl Hashable for Header {
    fn hash(&self) -> H256 {
        ring::digest::digest(&ring::digest::SHA256, &(bincode::serialize(self).unwrap())).into()
    }
}

impl Hashable for Block {
    fn hash(&self) -> H256 {
        self.head.hash()
    }
}

// #[cfg(any(test, test_utilities))]
// pub mod test {
//     use super::*;
//     use crate::crypto::hash::H256;

//     pub fn generate_random_block(parent: &H256) -> Block {
//         let now = SystemTime::now().duration_since(UNIX_EPOCH).expect("").as_millis();
//         let mut content_test = Content{
//             content: Vec::<Transaction>::new(),
//         };
//         let array: [u8; 16]  = rand::random();
//         let trans = Transaction {
//             content: array.to_vec(),
//         };
//         content_test.content.push(trans);
//         let rand_diff_arr: [u8;32] = rand::random();
//         let diff_h256: H256 = hex!("0010000000000000000000000000000000000000000000000000000000000000").into();
//         let rand_nounce: u32 = rand::random();
//         let head_rand = Header{
//             parent_hash: *parent,
//             nonce: rand_nounce,
//             difficulty: diff_h256,
//             timestamp: now,
//             merkle_root: MerkleTree::new(&(content_test.content)),
//         };
//         Block {
//             head: head_rand,
//             content: content_test.clone(),
//         }
//     }
// }
