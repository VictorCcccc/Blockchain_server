extern crate chrono;
use crate::block::Block;
use crate::crypto::hash::{H160, H256, Hashable};
use std::collections::HashMap;
use chrono::prelude::*;
use super::block::{Content, Header};
use super::transaction::{Transaction, SignedTransaction};
use crate::crypto::merkle::MerkleTree;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use serde::{Serialize, Deserialize};


pub struct Blockchain {
    pub chain: HashMap<H256, (Block,usize)>,
    pub tail: H256,
    pub diff: H256,
}

impl Blockchain {
    /// Create a new blockchain, only containing the genesis block
    pub fn new() -> Self {
        let mut content_genesis = Content{
            content: Vec::<SignedTransaction>::new(),
        };
        let public_basic: H256 = hex!("0000000000000000000000000000000000000000000000000000000000000000").into();
        let address: H160 = public_basic.into();
        let public_key = public_basic.as_ref().to_vec();
        let trans = Transaction {
            address: address.clone(),
            value: 0,
            nonce: 0,
        };
        let signed = SignedTransaction {
            public_key: public_key.clone(),
            signature: public_key.clone(),
            transaction: trans,
        };
        content_genesis.content.push(signed);

        let diff_h256: H256 = hex!("0001000000000000000000000000000000000000000000000000000000000000").into();
        let zero_nonce: u32 = 0;
        let phash: H256 = hex!("0000000000000000000000000000000000000000000000000000000000000000").into();
        let head_rand = Header{
            parent_hash: phash,
            nonce: zero_nonce,
            difficulty: diff_h256,
            timestamp: 0,
            merkle_root: MerkleTree::new(&(content_genesis.content)),
        };
        let mut chain_map = HashMap::new();
        let genesis_block = Block {
            head: head_rand,
            content: content_genesis.clone(),
        };
        chain_map.insert(genesis_block.hash(), (genesis_block.clone(),0));
        Blockchain{
            chain: chain_map,
            tail: genesis_block.hash(),
            diff: diff_h256,
        }
    }

    /// Insert a block into blockchain
    pub fn insert(&mut self, block: &Block) {
        let tip_height = self.chain.get(&self.tip()).unwrap().1;
        if self.chain.contains_key(&block.head.parent_hash) {
            let par_height = self.chain.get(&block.head.parent_hash).unwrap().1;
            if par_height >= tip_height {
                self.tail = (*block).hash();
            }
            self.chain.insert((*block).hash(), ((*block).clone(), par_height + 1));
        }
    }

    /// Get the last block's hash of the longest chain
    pub fn tip(&self) -> H256 {
        self.tail
    }

    pub fn height(&self) -> usize{self.chain.get(&self.tip()).unwrap().1}

    /// Get the last block's hash of the longest chain
    pub fn all_blocks_in_longest_chain(&self) -> Vec<H256> {
        let mut all_hash: Vec<H256> = Vec::new();
        let mut tail = self.tail;
        while self.chain.get(&tail).unwrap().1 != 0{
            all_hash.insert(0,tail);
            tail = self.chain.get(&tail).unwrap().0.head.parent_hash;
        }
        all_hash.insert(0,tail);
        all_hash
    }
}

// #[cfg(any(test, test_utilities))]
// mod tests {
//     use super::*;
//     use crate::block::test::generate_random_block;
//     use crate::crypto::hash::Hashable;

//     #[test]
//     fn insert_one() {
//         let mut blockchain = Blockchain::new();
//         let genesis_hash = blockchain.tip();
//         let block = generate_random_block(&genesis_hash);
//         blockchain.insert(&block);
//         assert_eq!(blockchain.tip(), block.hash());

//     }
// }
