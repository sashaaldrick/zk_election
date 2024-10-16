
//use k256::ecdsa::{Signature, signature::Verifier,  VerifyingKey};
use risc0_zkvm::guest::env;
use k256::sha2::{Sha256 as ksha256, Digest};
use crypto_bigint::{Encoding, NonZero, U2048, U256, U64};
use crypto_bigint::modular::runtime_mod::DynResidueParams;
use crypto_bigint::modular::runtime_mod::DynResidue;
use hex;
use k256::{
    ecdsa::{signature::Verifier, Signature as EcdsaSignature,SigningKey, VerifyingKey as EcdsaVerifyingKey},
    EncodedPoint,
};
use rsa::{RsaPublicKey, pkcs1v15::{VerifyingKey as RsaVerifyingKey, Signature as RsaSignature}, pkcs1v15};
use rsa::signature::{Verifier as RsaVerifier, SignatureEncoding, DigestVerifier};
use sha2::Sha256;

use rand_core::OsRng;

/*
fn verify_rsa_signature(
    modulus_bytes: &[u8],
    exp_bytes: &[u8],
    signature_bytes: &[u8],
    msg: &[u8],
) -> bool {
    // Costruisci la chiave pubblica RSA
    let modulus = rsa::BigUint::from_bytes_be(modulus_bytes);
    let exponent = rsa::BigUint::from_bytes_be(exp_bytes);

    // Crea la chiave pubblica
    let pub_key = match RsaPublicKey::new(modulus, exponent) {
        Ok(key) => key,
        Err(_) => return false, // Gestisci parametri chiave non validi
    };

    // Decodifica la firma applicando la chiave pubblica
    match pub_key.verify(
        pkcs1v15::PaddingScheme::new_pkcs1v15_sign::<Sha256>(),
        msg,
        signature_bytes,
    ) {
        Ok(_) => true,
        Err(_) => false,
    }
    
}*/
/*
fn verify_rsa_signature(
    modulus_bytes: &[u8],
    exp_bytes: &[u8],
    signature_bytes: &[u8],
    msg: &[u8],
) -> bool {
    // Construct the RSA public key
    let modulus = rsa::BigUint::from_bytes_be(modulus_bytes);
    let exponent = rsa::BigUint::from_bytes_be(exp_bytes);

    let pub_key = match RsaPublicKey::new(modulus, exponent) {
        Ok(key) => key,
        Err(_) => return false, // Gestisci parametri chiave non validi
    };

    // PKCS#1 v1.5 e SHA-256
    let verifying_key = VerifyingKey::<Sha256>::new(pub_key);

    let signature = match RsaSignature::try_from(signature_bytes) {
        Ok(sig) => sig,
        Err(e) => {
            println!("failed to create RsaSignature: {:?}", e);
            return false;
        }
    };

    /*if let Ok(decrypted_hash) = verifying_key.decrypt(&signature) {
        println!("Hash estratto dalla firma: {:?}", decrypted_hash);
    } else {
        println!("failed to decode signature");
        return false;
    }*/

    let mut hasher = Sha256::new();
    hasher.update(msg);
    let digest = hasher.finalize();

    println!("Digest calcolato: {:?}", digest);

    let res = verifying_key.verify_digest(Sha256::new_with_prefix(digest), &signature).is_ok();
    println!("Risultato della verifica: {}", res);
    res
}*/

/* MANUALLY VERIFY */

fn verify_rsa(
    modulus_bytes: &[u8],
    exp_bytes: &[u8],
    signature_bytes: &[u8],
    digest: &[u8],
) -> bool {

    let modulus = U2048::from_be_slice(modulus_bytes);
    let signature = U2048::from_be_slice(signature_bytes);

    let exponent = {
        // Pad l'esponente a 8 byte (64 bit)
        let mut exp_padded = [0u8; 8];
        exp_padded[8 - exp_bytes.len()..].copy_from_slice(exp_bytes);
        U64::from_be_bytes(exp_padded)
    };

    //println!("mod: {:?}\nsig: {:?}\nexp: {:?}",modulus,signature,exponent);

    let modul = NonZero::new(modulus).unwrap();
    let params = DynResidueParams::new(&modul);
    let signature_residue = DynResidue::new(&signature, params);

    //  m = s^e mod n
    let decrypted_residue = signature_residue.pow(&exponent);
    let decrypted_signature = decrypted_residue.retrieve();

    let decrypted_bytes = decrypted_signature.to_be_bytes();

    //println!("\ndecrypted bytes: {:?}",decrypted_bytes);

    // Verifica il padding PKCS#1 v1.5
    // il formato dovrebbe essere: 0x00 0x01 PS 0x00 T
    // dove PS è il padding 0xFF e T è l'ASN.1 DER encoding di DigestInfo

    // primo byte 00, secondo 01
    if decrypted_bytes[0] != 0x00 || decrypted_bytes[1] != 0x01 {
        println!("1");
        return false;
    }

    // indice di 0x00 dopo il padding
    let mut index = 2;
    while index < decrypted_bytes.len() && decrypted_bytes[index] == 0xFF {
        index += 1;
    }

    if index >= decrypted_bytes.len() || decrypted_bytes[index] != 0x00 {
        println!("2");
        return false;
    }
    index += 1; 

    //  ASN.1 DER di DigestInfo
    let digest_info = &decrypted_bytes[index..];

    // ASN.1 DER encoding per DigestInfo con SHA-256
    let expected_digest_info_prefix: [u8; 19] = [
        0x30, 0x31,       // SEQUENCE, lunghezza 49
        0x30, 0x0d,       // SEQUENCE, lunghezza 13
        0x06, 0x09,       // OID, lunghezza 9
        0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, // OID per SHA-256
        0x05, 0x00,       // NULL
        0x04, 0x20        // OCTET STRING, lunghezza 32
    ];

    // Verifica che il digest_info inizi con il prefisso atteso
    if digest_info.len() < expected_digest_info_prefix.len() + 32 {
        println!("3");
        return false;
    }

    if &digest_info[0..expected_digest_info_prefix.len()] != expected_digest_info_prefix {
        println!("4");
        return false;
    }

    let hash_from_signature = &digest_info[expected_digest_info_prefix.len()..expected_digest_info_prefix.len() + 32];    
    println!("\n\n---\nhash_from sig: {:?}\n\ndigest: {:?}",hex::encode(&hash_from_signature), hex::encode(&digest));

    // Confronta gli hash
    let res = hash_from_signature == digest;
    println!("res {}",res);
    res

}


fn verify_ecdsa(
    key_bytes: &[u8],
    signature_bytes: &[u8],
    msg: &[u8],
) -> bool {


    if key_bytes.len() != 33 && key_bytes.len() != 65 {
        println!("error");
    }

    let verifying_key = EcdsaVerifyingKey::from_sec1_bytes(key_bytes).expect("failed to create verifying_key");
    let signature = EcdsaSignature::from_slice(&signature_bytes).unwrap();
    println!("-------------\nverkey {:?}\nsignature {:?}",verifying_key,signature);

    let res = verifying_key.verify(&msg, &signature).is_ok();
    println!("\nres: {:?}",res);
    res
}



fn main() {

    let (msg_len, algoid_len, signature_len, pubkey_mod_len, pubkey_exp_len): (usize,usize,usize,usize,usize) = env::read();

    let mut msg: Vec<u8> = vec![0; msg_len];
    let mut algo_oid: Vec<u8> = vec![0; algoid_len];
    let mut signature: Vec<u8> = vec![0; signature_len];
    let mut pubkey_mod: Vec<u8> = vec![0; pubkey_mod_len];
    //let mut pubkey_exp: Vec<u8> = vec![0; pubkey_exp_len];

    env::read_slice(&mut msg);
    env::read_slice(&mut algo_oid);
    env::read_slice(&mut signature);
    env::read_slice(&mut pubkey_mod);
    //env::read_slice(&mut pubkey_exp);

    let pubkey_exp = if pubkey_exp_len > 0 {
        let mut pubkey_exp_vec: Vec<u8> = vec![0; pubkey_exp_len];
        env::read_slice(&mut pubkey_exp_vec);
        Some(pubkey_exp_vec)
    } else {
        None
    };

    //let pubkey_mod_hex: String = pubkey_mod.iter().map(|b| format!("{:02X}", b)).collect();
    //let signature_hex: String = signature.iter().map(|b| format!("{:02X}", b)).collect();
    //println!("----------------------------------------------------------\n");
    //println!("msg {:?}\n\n",msg);


    /*let digest = match algo_oid.as_slice() {
        // OID for SHA-1
        /*[0x2B, 0x0E, 0x03, 0x02, 0x1A] => {
            //let mut hasher = Sha1::new();
            //hasher.update(&msg);
            //hasher.finalize().to_vec()
            
        },*/
        // OID for SHA-256
        [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01] => {
            let mut hasher = Sha256::new();
            hasher.update(&msg);
            hasher.finalize().as_slice()
        },
        _ => panic!("Unsupported digest algorithm OID"),
    };*/
    /*let mut hasher = ksha256::new();
    hasher.update(&msg);
    let digest = hasher.finalize();
    println!("\n[*] calculated digest on msg: {:?}\nresult: {:?}",msg, digest);

    let res: bool = verify_rsa_signature(
        &pubkey_mod,
        &pubkey_exp,
        &signature,
        &digest );*/
    
    let mut hasher = ksha256::new();
    hasher.update(&msg);
    let digest = hasher.clone().finalize();
    println!("\n\n-----------------------\nhashing msg: {:?}\nhasher: \ndigest: {:?}",hex::encode(msg.clone()),hex::encode(digest));


    // verify RSA or ECDSA
    let res = if let Some(exp) = pubkey_exp {
        //println!("[guest - main] Sending to verify_rsa:\npubkey_mod: {:?}\nsignature: {:?}\nmsg: {:?}",pubkey_mod,signature,hex::encode(&msg));
        verify_rsa(&pubkey_mod, &exp, &signature, &digest)
    }
    else {
        println!("[guest - main] Sending to verify_ecdsa:\npubkey: {:?}\n\nsignature: {:?}\n\nmsg: {:?}",hex::encode(&pubkey_mod),hex::encode(&signature),hex::encode(&digest));
        verify_ecdsa(&pubkey_mod, &signature, &msg)
        
    };

    // commit to journal
    println!("\n\nRES: {}",res);
    env::commit(&res);
}