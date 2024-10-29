//use k256::ecdsa::{Signature, signature::Verifier,  VerifyingKey};

use hex;
use k256::ecdsa::{
    signature::Verifier, Signature as EcdsaSignature, VerifyingKey as EcdsaVerifyingKey,
};
use k256::sha2::{Sha256 as ksha256};
use risc0_zkvm::guest::env;
use rsa::{pkcs1v15::{Signature as RsaSignature, VerifyingKey as RsaVerifyingKey}, RsaPublicKey,};
use tiny_keccak::{Hasher, Keccak};

use pkcs7_core::{CertificateData, PublicKey};

const ECONTENT_MAX_LEN: usize = 128;
const SALT_MAX_LEN: usize = 16;
const MSG_MAX_LEN: usize = 256;
//const ALGO_OID_MAX_LEN: usize = 9;
const SIGNATURE_MAX_LEN: usize = 256;
const PUBKEY_MOD_MAX_LEN: usize = 256;
const PUBKEY_EXP_MAX_LEN: usize = 4;

// 3 bytes oid + 0x0c + len (quando estraggo cf len=0x10)
const CN_OID_BYTES: &[u8] = &[0x55, 0x04, 0x03, 0x0c, 0x10];

fn keccak256(bytes: &[u8], salt: &[u8]) -> [u8; 32] {
    let mut digest = [0u8; 32];
    let mut hasher = Keccak::v256();
    hasher.update(bytes);
    hasher.update(salt);
    hasher.finalize(&mut digest);
    digest
}

fn verify_rsa(modulus_bytes: &[u8], exp_bytes: &[u8], signature_bytes: &[u8], msg: &[u8]) -> bool {
    let modulus = rsa::BigUint::from_bytes_be(modulus_bytes);
    let exponent = rsa::BigUint::from_bytes_be(exp_bytes);

    let pub_key = match RsaPublicKey::new(modulus, exponent) {
        Ok(key) => key,
        Err(_) => return false,
    };

    let verifying_key = RsaVerifyingKey::<ksha256>::new(pub_key);

    let signature = match RsaSignature::try_from(signature_bytes) {
        Ok(sig) => sig,
        Err(_) => return false,
    };

    verifying_key.verify(msg, &signature).is_ok()
}

/* MANUALLY VERIFY */
/*
fn verify_rsa(
    modulus_bytes: &[u8],
    exp_bytes: &[u8],
    signature_bytes: &[u8],
    msg: &[u8],
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

    let mut hasher = ksha256::new();
    hasher.update(&msg);
    let digest = hasher.finalize();

    println!("\n\n---\nhash_from sig: {:?}\n\ndigest: {:?}",hex::encode(&hash_from_signature), hex::encode(&digest));

    *hash_from_signature == *digest
}*/
/*
fn verify_ecdsa(key_bytes: &[u8], signature_bytes: &[u8], msg: &[u8]) -> bool {
    if key_bytes.len() != 33 && key_bytes.len() != 65 {
        println!("error");
    }

    let verifying_key =
        EcdsaVerifyingKey::from_sec1_bytes(key_bytes).expect("failed to create verifying_key");
    let signature = EcdsaSignature::from_slice(&signature_bytes).unwrap();
    println!(
        "-------------\nverkey {:?}\nsignature {:?}",
        verifying_key, signature
    );

    let res = verifying_key.verify(&msg, &signature).is_ok();
    println!("\nres: {:?}", res);
    res
}*/

fn verify_chain(chain: &[CertificateData]) -> &[u8] {
    let mut root_pk: &[u8] = &[];
    chain.iter().all(|cert| match &cert.issuer_pk {
        PublicKey::Rsa { modulus, exponent } => {
            if cert.subject == cert.issuer {
                root_pk = modulus.as_ref();
            }
            /*let mut mod_sign = cert.signature.to_vec();
            if let Some(first_byte) = mod_sign.get_mut(0) {
                *first_byte = first_byte.wrapping_add(1);
            }*/
            verify_rsa(modulus, exponent, &cert.signature, &cert.tbs_bytes)
        }
        PublicKey::Ecdsa { point: _ } => true,
    });
    root_pk
}

// brutal function to extract cf
// TODO: verificare se è meglio cosi, o passare il cf al guest code
fn extract_cf_field(subject: &[u8]) -> Result<&[u8], &'static str> {
    // Find the position of the sequence in the subject
    if let Some(pos) = subject
        .windows(CN_OID_BYTES.len())
        .position(|window| window == CN_OID_BYTES)
    {
        // Calculate the start index of the field (after the OID sequence)
        let start = pos + CN_OID_BYTES.len();
        // Ensure there are enough bytes remaining
        if subject.len() >= start + 16 {
            // Extract the 16 bytes following the sequence
            return Ok(&subject[start..start + 16]);
        } else {
            return Err("Not enough bytes after OID sequence");
        }
    }
    Err("OID sequence not found in subject")
}

fn main() {
    let start = env::cycle_count();

    let cert_chain: Vec<CertificateData> = env::read();
    let (
        econtent_len,
        salt_len,
        msg_len,
        //algoid_len,
        signature_len,
        pubkey_mod_len,
        pubkey_exp_len,
    ): (usize, usize, usize, usize, usize, usize) = env::read();

    assert!(econtent_len <= ECONTENT_MAX_LEN);
    assert!(salt_len <= SALT_MAX_LEN);
    assert!(msg_len <= MSG_MAX_LEN);
    //assert!(algoid_len <= ALGO_OID_MAX_LEN);
    assert!(signature_len <= SIGNATURE_MAX_LEN);
    assert!(pubkey_mod_len <= PUBKEY_MOD_MAX_LEN);
    assert!(pubkey_exp_len <= PUBKEY_EXP_MAX_LEN);

    // allocate fixed size array (stack)
    let mut econtent = [0u8; ECONTENT_MAX_LEN];
    let mut salt = [0u8; SALT_MAX_LEN];
    let mut msg = [0u8; MSG_MAX_LEN];
    //let mut algo_oid = [0u8; ALGO_OID_MAX_LEN];
    let mut signature = [0u8; SIGNATURE_MAX_LEN];
    let mut pubkey_mod = [0u8; PUBKEY_MOD_MAX_LEN];
    let mut pubkey_exp = [0u8; PUBKEY_EXP_MAX_LEN];

    // read effective bytes of each array
    env::read_slice(&mut econtent[..econtent_len]);
    env::read_slice(&mut salt[..salt_len]);
    env::read_slice(&mut msg[..msg_len]);
    //env::read_slice(&mut algo_oid[..algoid_len]);
    env::read_slice(&mut signature[..signature_len]);
    env::read_slice(&mut pubkey_mod[..pubkey_mod_len]);
    env::read_slice(&mut pubkey_exp[..pubkey_exp_len]);

    // slice the array at the effective size
    let econtent = &econtent[..econtent_len];
    let salt = &salt[..salt_len];
    let msg = &msg[..msg_len];
    //let algo_oid = &algo_oid[..algoid_len];
    let signature = &signature[..signature_len];
    let pubkey_mod = &pubkey_mod[..pubkey_mod_len];
    let pubkey_exp = &pubkey_exp[..pubkey_exp_len];

    //let mut pubkey_exp: Vec<u8> = vec![0; pubkey_exp_len];
    //env::read_slice(&mut pubkey_exp);
    /* CHECK FOR DIFFERENT DIGEST ALGORITHM
    let digest = match algo_oid.as_slice() {
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

    assert!(
        verify_rsa(&pubkey_mod, &pubkey_exp, &signature, &msg),
        "Signature is not valid!"
    );

    // verify RSA or ECDSA
    /*let is_signature_valid = if let Some(exp) = pubkey_exp {
        //println!("[guest - main] Sending to verify_rsa:\npubkey_mod: {:?}\nsignature: {:?}\nmsg: {:?}",pubkey_mod,signature,hex::encode(&msg));
        verify_rsa(&pubkey_mod, &exp, &signature, &msg)
    }
    else {
        //println!("[guest - main] Sending to verify_ecdsa:\npubkey: {:?}\n\nsignature: {:?}\n\nmsg: {:?}",hex::encode(&pubkey_mod),hex::encode(&signature),hex::encode(&digest));
        verify_ecdsa(&pubkey_mod, &signature, &msg)

    };*/

    let trusted_pk = verify_chain(&cert_chain);
    let subject = &cert_chain[0].subject;
    let common_name = extract_cf_field(subject).expect("failed to extract common_name field value");
    println!("salt: {:?}\n",salt);
    println!("\ncn {:?}", common_name);
    let salted_cf = keccak256(common_name, salt);
    println!("\nsaltedCF: {:?}",hex::encode(&salted_cf));

    /*
        COMMIT:
            - address/msg (se commit solo address so che è lungo esattamente 42 caratteri)
            - hash (cf+salt) = 32 byte
            - root pk = tutto il resto (solitamente 256 byte)
    */
    //let fake_journal: &[u8] = &[0u8; 308];
    //println!("\nfake journal: {:?}",fake_journal);
    assert!(!trusted_pk.is_empty(), "Certificate chain is not valid!");
    //println!("\nguest. committing data:\necontent (eth address): {:?}\nsalted cf: {:?}\ntrusted_pk: {:?}",hex::encode(&econtent),hex::encode(&salted_cf), hex::encode(&trusted_pk));
    env::commit_slice(&econtent); //20 byte eth address (_to)
    env::commit_slice(&salted_cf); //32 byte
    env::commit_slice(trusted_pk);
    //env::commit_slice(fake_journal);
    let end = env::cycle_count();
    //println!("my_operation_to_measure: {}", end - start);
}
