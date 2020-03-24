use serde::{Serialize, Deserialize};
use super::hash::{Hashable, H256};
use std::mem;


#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct Node {
    leaf_hash: H256,
    combined_hash: H256,
    childs: Vec<Node>,
}

impl Node {
    pub fn new(single: H256, combined: H256) -> Node {
        Node {
            leaf_hash: single,
            combined_hash: combined,
            childs: Vec::new(),
        }
    }
}
/// A Merkle tree.
#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct MerkleTree {
    root: Node,
    pub height: u32,
}


impl MerkleTree {
    pub fn new<T>(data: &[T]) -> Self where T: Hashable, {
        let length = data.len();
        let mut cur_layer = Vec::with_capacity(length);
        for element in data {
            let new_nodes = Node::new(element.hash(), element.hash());
            // println!("{}", new_nodes.combined_hash);
            cur_layer.push(new_nodes);
        }
        let mut height = 0;
        while cur_layer.len()>1 {
            let mut nxt_layer = Vec::new();
            while !cur_layer.is_empty() {
                let left = cur_layer.remove(0);
                let mut right = left.clone();
                if cur_layer.len() >= 1 {
                    right = cur_layer.remove(0);
                }
            
                let leftarr: [u8; 32] = left.combined_hash.into();
                let rightarr: [u8; 32] = right.combined_hash.into();
                let mut concatenated: Vec<u8> = Vec::with_capacity(512);
                concatenated.extend_from_slice(&leftarr);
                concatenated.extend_from_slice(&rightarr);
                let newarr_hash = ring::digest::digest(&ring::digest::SHA256, &concatenated);
                let parent_hash: H256 = newarr_hash.into();
                let mut node = Node::new(parent_hash, parent_hash);
                node.childs.push(left);
                node.childs.push(right);
                nxt_layer.push(node);
            }
            cur_layer = nxt_layer;
            height+=1;
        }
        let rootnode = cur_layer.remove(0);
        //println!("{}", rootnode.combined_hash);
        MerkleTree {
            root: rootnode,
            height: height,
        }
    }

    pub fn root(&self) -> H256 {
        self.root.combined_hash
    }

    /// Returns the Merkle Proof of data at index i
    pub fn proof(&self, index: usize) -> Vec<H256> {
        let mut cur_height = 1;
        let indexu32 = index as u32;
        let mut cmp_boundry = 2u32.pow(self.height-1);
        let mut node = self.root.clone();
        // let mut nodes = Vec::new();
        // nodes.push(self.root.clone());
        let mut path:Vec<H256> = Vec::new();
        while cur_height <= self.height {
            if indexu32<cmp_boundry {
                path.push(node.childs[1].combined_hash);
                node = node.childs[0].clone();
                if self.height>cur_height {
                    cmp_boundry -= 2u32.pow(self.height-cur_height-1);
                }
            } else {
                path.push(node.childs[0].combined_hash);
                node = node.childs[1].clone();
                if self.height>cur_height {
                    cmp_boundry += 2u32.pow(self.height-cur_height-1);
                }
            }
            cur_height+=1;
        }
        println!("{}", path.len());
        path.into()
    }
}

/// Verify that the datum hash with a vector of proofs will produce the Merkle root. Also need the
/// index of datum and `leaf_size`, the total number of leaves.
pub fn verify(root: &H256, datum: &H256, proof: &[H256], index: usize, leaf_size: usize) -> bool {
    let mut merged_hash = *datum;
    let mut side = index as u32;
    for partner in proof.iter().rev() {
        let mut left: [u8; 32] = merged_hash.into();
        let mut right: [u8; 32] = partner.into();
        if side&1 != 0 {
            mem::swap(&mut left, &mut right);
        }
        let mut concatenated: Vec<u8> = Vec::with_capacity(512);
        concatenated.extend_from_slice(&left);
        concatenated.extend_from_slice(&right);
        let newarr_hash = ring::digest::digest(&ring::digest::SHA256, &concatenated);
        // let parent_hash: H256 = newarr_hash.into();
        merged_hash = newarr_hash.into();
        side /= 2;
    }
    *root == merged_hash
}

#[cfg(test)]
mod tests {
    use crate::crypto::hash::H256;
    use super::*;

    macro_rules! gen_merkle_tree_data {
        () => {{
            vec![
                (hex!("0a0b0c0d0e0f0e0d0a0b0c0d0e0f0e0d0a0b0c0d0e0f0e0d0a0b0c0d0e0f0e0d")).into(),
                (hex!("0101010101010101010101010101010101010101010101010101010101010202")).into(),
            ]
        }};
    }

    #[test]
    fn root() {
        let input_data: Vec<H256> = gen_merkle_tree_data!();
        let merkle_tree = MerkleTree::new(&input_data);
        let root = merkle_tree.root();
        assert_eq!(
            root,
            (hex!("6b787718210e0b3b608814e04e61fde06d0df794319a12162f287412df3ec920")).into()
        );
        // "b69566be6e1720872f73651d1851a0eae0060a132cf0f64a0ffaea248de6cba0" is the hash of
        // "0a0b0c0d0e0f0e0d0a0b0c0d0e0f0e0d0a0b0c0d0e0f0e0d0a0b0c0d0e0f0e0d"
        // "965b093a75a75895a351786dd7a188515173f6928a8af8c9baa4dcff268a4f0f" is the hash of
        // "0101010101010101010101010101010101010101010101010101010101010202"
        // "6b787718210e0b3b608814e04e61fde06d0df794319a12162f287412df3ec920" is the hash of
        // the concatenation of these two hashes "b69..." and "965..."
        // notice that the order of these two matters
    }

    #[test]
    fn proof() {
        let input_data: Vec<H256> = gen_merkle_tree_data!();
        let merkle_tree = MerkleTree::new(&input_data);
        let proof = merkle_tree.proof(0);
        assert_eq!(proof,
                   vec![hex!("965b093a75a75895a351786dd7a188515173f6928a8af8c9baa4dcff268a4f0f").into()]
        );
        // "965b093a75a75895a351786dd7a188515173f6928a8af8c9baa4dcff268a4f0f" is the hash of
        // "0101010101010101010101010101010101010101010101010101010101010202"
    }

    #[test]
    fn verifying() {
        let input_data: Vec<H256> = gen_merkle_tree_data!();
        let merkle_tree = MerkleTree::new(&input_data);
        let proof = merkle_tree.proof(0);
        assert!(verify(&merkle_tree.root(), &input_data[0].hash(), &proof, 0, input_data.len()));
    }
}
