use crate::rsa::Pkcs1v15Encrypt;
use crate::rsa::RsaPublicKey;
use aes_gcm_siv::aead::Aead;
use aes_gcm_siv::Aes256GcmSiv;
use aes_gcm_siv::KeyInit;
use aes_gcm_siv::Nonce;
use array::Array;
use arrayref::array_refs;
use base64;
use fips204::{
    ml_dsa_65::{self},
    traits::SerDes as _,
};
use generic_array::GenericArray;
use ml_kem::kem::Decapsulate;
use ml_kem::kem::Encapsulate;
use ml_kem::kem::EncapsulationKey;
use ml_kem::EncodedSizeUser;
use ml_kem::KemCore;
use ml_kem::MlKem1024;
use ml_kem::MlKem768;
use ml_kem::*;
use rand::Rng;
use rand::RngCore;
use rsa;
use rsa::pkcs1::DecodeRsaPublicKey;
use rsa::pkcs1::EncodeRsaPrivateKey;
use rsa::pkcs1::EncodeRsaPublicKey;
use rsa::pkcs8::DecodePrivateKey;
use rsa::pkcs8::EncodePrivateKey;
use rsa::RsaPrivateKey;
use std::io::Read;
use std::time::Instant;

pub const STATIC_PK_LEN: usize = 1184 + 32 + ml_dsa_65::PK_LEN + 32;

struct PrivateKey {
    rsa_private_key: Vec<u8>,
    ml_kem_dk: Vec<u8>,
}

impl PrivateKey {
    fn as_base64(&self) -> String {
        let rsa_pk = base64::encode(&self.rsa_private_key);
        let separator = ".";
        let ml_kem_dk = base64::encode(&self.ml_kem_dk);

        format!("{}{}{}", rsa_pk, separator, ml_kem_dk)
    }
}

struct PublicKey {
    rsa_public_key: Vec<u8>,
    ml_kem_ek: Vec<u8>,
}

impl PublicKey {
    // base64 string
    fn as_base64(&self) -> String {
        let rsa_pk = base64::encode(&self.rsa_public_key);
        let separator = ".";
        let ml_kem_ek = base64::encode(&self.ml_kem_ek);

        format!("{}{}{}", rsa_pk, separator, ml_kem_ek)
    }
}

fn generate_keypair() -> (PrivateKey, PublicKey) {
    let mut rng = rand::thread_rng();
    let bits = 3072;
    println!("generating rsa key");
    let priv_key = RsaPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
    println!("generated rsa key");
    let pub_key = RsaPublicKey::from(&priv_key);
    println!("generating mlkem key");
    let (dk, ek) = MlKem1024::generate(&mut rng);
    println!("generated mlkem key");

    let pk_pkcs8 = priv_key.to_pkcs8_der().unwrap();
    let pubkey_spki = pub_key.to_pkcs1_der().unwrap();
    let priv_key = PrivateKey {
        rsa_private_key: pk_pkcs8.as_bytes().to_vec(),
        ml_kem_dk: dk.as_bytes().to_vec(),
    };
    let pub_key = PublicKey {
        rsa_public_key: pubkey_spki.as_bytes().to_vec(),
        ml_kem_ek: ek.as_bytes().to_vec(),
    };

    (priv_key, pub_key)
}

fn encrypt(plaintext: Vec<u8>, public_key: PublicKey) -> Vec<u8> {
    let encoded = <[u8; 1568]>::try_from(public_key.ml_kem_ek.as_ref());
    if encoded.is_err() {
        println!("error {}", encoded.err().unwrap());
    }

    let encoded = encoded.unwrap();
    let ek_pq =
        ml_kem::kem::EncapsulationKey::<ml_kem::MlKem1024Params>::from_bytes((&encoded).into());

    let (encapsulated_sharedkey, sharedkey) = ek_pq.encapsulate(&mut rand::thread_rng()).unwrap();

    let key = <[u8; 32]>::try_from(sharedkey.as_ref()).unwrap();
    let cipher = Aes256GcmSiv::new((&key).into());
    let nonce = Nonce::from_slice(b"unique nonce");
    let sharedkey_encrypted_plaintext = cipher.encrypt(&nonce, plaintext.as_slice()).unwrap();

    let rsa_pub_key = RsaPublicKey::from_pkcs1_der(&public_key.rsa_public_key).unwrap();
    let mut rng = rand::thread_rng();
    let rsa_encrypted_pq_encrypted_plaintext = rsa_pub_key
        .encrypt(
            &mut rng,
            Pkcs1v15Encrypt,
            sharedkey_encrypted_plaintext.as_slice(),
        )
        .unwrap();

    let encapsulated_sharedkey_b64 = base64::encode(&encapsulated_sharedkey);
    let ciphertext_b64 = base64::encode(&rsa_encrypted_pq_encrypted_plaintext);
    let ciphertext_total = format!("{}.{}", encapsulated_sharedkey_b64, ciphertext_b64);

    return ciphertext_total.as_bytes().to_vec();
}

fn decrypt(ciphertext: Vec<u8>, private_key: PrivateKey) -> Vec<u8> {
    let encoded = <[u8; 3168]>::try_from(private_key.ml_kem_dk.as_ref()).unwrap();
    let dk =
        ml_kem::kem::DecapsulationKey::<ml_kem::MlKem1024Params>::from_bytes((&encoded).into());

    // println!("dklen {}", dk.as_bytes().len());

    let encapsulated_sharedkey_b64 = ciphertext.split(|&c| c == b'.').next().unwrap();
    let encapsulated_sharedkey = base64::decode(encapsulated_sharedkey_b64).unwrap();
    let key = <[u8; 1568]>::try_from(encapsulated_sharedkey.as_ref()).unwrap();

    let shared_key = dk.decapsulate((&key).into()).unwrap();
    let shared_key_b64 = base64::encode(&shared_key);

    let ciphertext_b64 = ciphertext.split(|&c| c == b'.').last().unwrap();
    let ciphertext = base64::decode(ciphertext_b64).unwrap();

    let rsa_priv_key = RsaPrivateKey::from_pkcs8_der(&private_key.rsa_private_key).unwrap();
    let rsa_decrypted = rsa_priv_key
        .decrypt(Pkcs1v15Encrypt, ciphertext.as_slice())
        .unwrap();
    let nonce = Nonce::from_slice(b"unique nonce");
    let key = <[u8; 32]>::try_from(shared_key.as_ref()).unwrap();
    let cipher = Aes256GcmSiv::new((&key).into());
    let plaintext = cipher.decrypt(&nonce, rsa_decrypted.as_slice()).unwrap();

    return plaintext;
}

fn main() {
    let start = Instant::now();
    let keypair = generate_keypair();
    println!("keypair generation took {:?}", start.elapsed());

    let start = Instant::now();
    let ciphertext = encrypt(b"hello".to_vec(), keypair.1);
    println!("encryption took {:?}", start.elapsed());

    let start = Instant::now();
    let plaintext = decrypt(ciphertext.clone(), keypair.0);
    println!("decryption took {:?}", start.elapsed());

    println!("ciphertext: {:?}", String::from_utf8(ciphertext).unwrap());
    println!("plaintext: {:?}", String::from_utf8(plaintext).unwrap());
}
