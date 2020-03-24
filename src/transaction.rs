use serde::{Serialize,Deserialize};
use ring::signature::{Ed25519KeyPair, Signature, KeyPair, VerificationAlgorithm, EdDSAParameters};
use ring::signature;
use crate::crypto::hash::{H160, H256, Hashable};

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct Transaction {
    pub address: H160,
    pub value: u32,
    pub nonce: u32,
}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct SignedTransaction {
    pub public_key: Vec<u8>,
    pub signature: Vec<u8>,
    pub transaction: Transaction,
}

/// Create digital signature of a transaction
pub fn sign(t: &Transaction, key: &Ed25519KeyPair) -> Signature {
    key.sign(&(bincode::serialize(t).unwrap()))
}

/// Verify digital signature of a transaction, using public key instead of secret key
pub fn verify(t: &SignedTransaction) -> bool {
    let public_key = &t.public_key[..];
    let signature = &t.signature[..];
    let peer_public_key = signature::UnparsedPublicKey::new(&signature::ED25519, public_key);
    peer_public_key.verify(&(bincode::serialize(&t.transaction).unwrap()), signature.as_ref()).is_ok()
}

// #[cfg(any(test, test_utilities))]
// mod tests {
//     use super::*;
//     use crate::crypto::key_pair;

//     pub fn generate_random_transaction() -> Transaction {
//         // Default::default()
//         let array: [u8; 16]  = rand::random();
//         Transaction {
//             content: array.to_vec(),
//         }
//     }

//     #[test]
//     fn sign_verify() {
//         let t = generate_random_transaction();
//         let key = key_pair::random();
//         let signature = sign(&t, &key);
//         assert!(verify(&t, &(key.public_key()), &signature));
//     }
// }
