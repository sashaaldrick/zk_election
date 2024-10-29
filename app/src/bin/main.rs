use pkcs7_core::{load_pkcs7, Certificate, CertificateData, PublicKey};

use alloy::{
    network::{EthereumWallet, TransactionBuilder},
    primitives::{Address, Bytes},
    providers::{Provider, ProviderBuilder},
    rpc::types::TransactionRequest,
    signers::local::PrivateKeySigner,
    sol,
};
use anyhow::{Context, Result};
use clap::Parser;
use ethers::prelude::*;
use methods::PKCS7_VERIFY_ELF;
use risc0_ethereum_contracts::encode_seal;
use risc0_ethereum_contracts::groth16;
use risc0_zkvm::{
    compute_image_id, default_prover, ExecutorEnv, ProverOpts, Receipt, VerifierContext,
};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use url::Url;
use std::error::Error;
use std::sync::Arc;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::process::Command;
use tempfile::NamedTempFile;
use tokio::task::spawn_blocking;

// 3 bytes oid + 0x0c + len (quando estraggo cf len=0x10)
const CN_OID_BYTES: &[u8] = &[0x55, 0x04, 0x03, 0x0c, 0x10];

// `ICFWallet` interface automatically generated via the alloy `sol!` macro.
sol! {
    interface CfWallet {
        function verifyAndTransfer(bytes calldata journal, bytes calldata seal) public;
    }
}
/// Arguments of the publisher CLI.
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// Ethereum chain ID
    //#[clap(long)]
    //chain_id: u64,

    /// Ethereum Node endpoint.
    #[clap(long, env)]
    eth_wallet_private_key: PrivateKeySigner,

    /// Ethereum Node endpoint.
    #[clap(long)]
    rpc_url: Url,

    /// Application's contract address on Ethereum
    #[clap(long)]
    contract: Address,

    /// The input to provide to the guest binary
    #[clap(long)]
    p7_path: String,

    //salt value, priveded as hex string
    #[clap(long)]
    salt: String,
}



fn prove_pkcs7_verification(
    chain_data: &Vec<CertificateData>, //Vec<CertificateData>,
    econtent: &Vec<u8>,
    salt: &Vec<u8>,
    msg: &Vec<u8>,
    //algo_oid: &AlgorithmIdentifier, 
    signature: &Vec<u8>,
    pub_key: &Vec<u8>,
    exponent: Option<&Vec<u8>>, // only for RSA
                                //prec_receipt: &Receipt,
) -> Receipt {
    // if RSA, send exp lenght, if ECDSA exp.len = 0
    let lengths = if let Some(exp) = exponent {
        (
            econtent.len(),
            salt.len(),
            msg.len(),
            //algo_oid.len(),
            signature.len(),
            pub_key.len(),
            exp.len(),
        )
    } else {
        (
            econtent.len(),
            salt.len(),
            msg.len(),
            //algo_oid.len(),
            signature.len(),
            pub_key.len(),
            0,
        )
    };

    println!("lengs: {:?}", lengths);
    let mut env_builder = ExecutorEnv::builder();

    env_builder.write(&chain_data).unwrap();
    env_builder.write(&lengths).unwrap();
    env_builder.write_slice(&econtent);
    env_builder.write_slice(&salt);
    env_builder.write_slice(&msg);
    //env_builder.write_slice(&algo_oid);
    env_builder.write_slice(&signature);
    env_builder.write_slice(&pub_key);

    if let Some(exp) = exponent {
        env_builder.write_slice(&exp);
    }

    let env = env_builder.build().unwrap();

    let receipt = default_prover()
        .prove_with_ctx(
            env,
            &VerifierContext::default(),
            PKCS7_VERIFY_ELF,
            &ProverOpts::groth16(),
        )
        .unwrap()
        .receipt;

    receipt
}

fn extract_certificate_data(
    certs: &[Certificate],
    subj_cert: &Certificate,
) -> Vec<CertificateData> {
    let mut certs_chain_data: Vec<CertificateData> = Vec::new();

    // hashmap for easily map a subject to his cert
    let cert_map: HashMap<Vec<u8>, &Certificate> = certs
        .iter()
        .map(|cert| (cert.tbs_certificate.subject.to_der(), cert))
        .collect();

    let mut current_cert = subj_cert;

    // WARNING: POSSIBLE LOOP, must handle this
    loop {
        // find the issuer's certificate in the map
        let issuer_cert = cert_map
            .get(&current_cert.tbs_certificate.issuer.to_der())
            .ok_or_else(|| {
                format!(
                    "Issuer certificate not found for cert {:?}",
                    current_cert.tbs_certificate.subject
                )
            })
            .expect("failed to get issuer_cert");

        //println!("\ncurrent cert: {:?} \nissuer cert: {:?}",current_cert.tbs_certificate.serial_number,issuer_cert.tbs_certificate.serial_number);

        let cert_data = current_cert.extract_data(issuer_cert);
        certs_chain_data.push(cert_data);

        // if root CA, stop
        if current_cert.tbs_certificate.subject == current_cert.tbs_certificate.issuer {
            break;
        }

        current_cert = issuer_cert;
    }
    certs_chain_data
}

fn convert_to_bytes(str_bytes: Vec<u8>) -> Vec<u8> {
    let mut econtent_str =
        String::from_utf8(str_bytes).expect("Failed to convert from bytes to string");
    econtent_str = econtent_str.trim().to_string();
    let econtent_hex = econtent_str.trim_start_matches("0x");
    let address_bytes = hex::decode(econtent_hex).expect("Failed to decode hex");
    assert_eq!(address_bytes.len(), 20, "ETH address must be 20 bytes long");
    address_bytes
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

/*
fn deploy_contract(
    rpc_url: &str,
    cf: &[u8],
    salt: &[u8],
) -> Result<(), Box<dyn Error>> {
    let project_dir = env::current_dir()?;
    // create temp file to pass value for constructor to contract deploy script
    let mut cf_temp_file = NamedTempFile::new_in(&project_dir)?;
    cf_temp_file.as_file_mut().write_all(&cf)?;
    let cf_temp_path = cf_temp_file.path().to_str().unwrap().to_string();

    let mut salt_temp_file = NamedTempFile::new_in(&project_dir)?;
    salt_temp_file.as_file_mut().write_all(&salt)?;
    let salt_temp_path = salt_temp_file.path().to_str().unwrap().to_string();

    std::fs::set_permissions(&salt_temp_path, std::fs::Permissions::from_mode(0o600))?;
    std::fs::set_permissions(&salt_temp_path, std::fs::Permissions::from_mode(0o600))?;

    // Pass the file paths to the deploy script via environment variables
    let mut cmd = Command::new("forge");
    cmd.arg("script")
        .arg("--rpc-url")
        .arg(rpc_url)
        .arg("--broadcast")
        .arg("script/Deploy.s.sol")
        //.arg("RiscZeroCFWalletDeploy")
        .env("CF_FILE_PATH", &cf_temp_path)
        .env("SALT_FILE_PATH", &salt_temp_path);

    let status = cmd.status().expect("Failed to start deploy process");
    if !status.success() {
        return Err(format!("Deploy script exited with status: {}",status).into());
    }
    Ok(())
}*/

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Parse CLI Arguments: The application starts by parsing command-line arguments provided by the user.
    let args = Args::parse();


    // Create an alloy provider for that private key and URL.
    let wallet = EthereumWallet::from(args.eth_wallet_private_key);
    let provider = ProviderBuilder::new()
        .with_recommended_fillers()
        .wallet(wallet)
        .on_http(args.rpc_url);



        
    //let salt: &[u8] = &[0x01,0x02,0x03,0x04];

    let pkcs7 = load_pkcs7(&args.p7_path)?;

    // Wrap the entire pkcs7 struct in Arc if multiple parts are needed
    let pkcs7 = Arc::new(pkcs7);
    //let signer_info = &pkcs7.content.signer_infos[0];
    let signer_info = Arc::new(pkcs7.content.signer_infos[0].clone());
    //let signer_serial_number = signer_info.signer_identifier.serial_number;

    // use serial number to find user certificate
    let subject_cert = pkcs7
        .content
        .certs
        .iter()
        .find(|cert| &cert.tbs_certificate.serial_number == &signer_info.signer_identifier.serial_number)
        .expect("Subject certificate not found in certificate list");
        //.clone();

    let subject_cert = Arc::new(subject_cert);

    // is ok to extract here CF ???
    let subj = subject_cert.tbs_certificate.subject.to_der();
    let cf = extract_cf_field(&subj).expect("failed to extract common_name field value");

    let salt = hex::decode(&args.salt)?;
    println!("\nsalt: {:?}",salt);
    if salt.len() > 32 {
        eprintln!("Salt must be max 16 bytes (32 hex characters)");
        std::process::exit(1);
    }
    let salt = Arc::new(salt);
    //deploy_contract(&rpc_url_str, &cf, &salt)?;

    // SIGNATURE
    //extracting value of: signature, algorithm used, public key and message to be signed
    let signature = Arc::new(signer_info.signature.clone());
    let digest_algorithm_oid = Arc::new(signer_info.digest_algorithm.algorithm.clone());
    let _signature_algorithm_oid = &signer_info.signature_algorithm.algorithm;
    let public_key = Arc::new(subject_cert
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .clone());

    let msg_data = if signer_info.auth_attributes.is_some() {
        signer_info.auth_bytes.clone()
    } else {
        pkcs7.content_bytes.clone() //this is the data of the signed document
    };
    let msg = Arc::new(msg_data);
    // VERIFY CHAIN
    let chain_data = extract_certificate_data(&pkcs7.content.certs, &subject_cert);
    let chain_data = Arc::new(chain_data);

    let econtent_addr_bytes = convert_to_bytes(pkcs7.content.content_info.e_content.clone());
    let econtent_addr_bytes = Arc::new(econtent_addr_bytes);
    //println!("\n--main--\nsending to guest...\n econtent: {:?}\nsubject: {:?}\nsalt:len {:?}",hex::encode(&econtent_addr_bytes),hex::encode(&subject_cert.tbs_certificate.subject.to_der()),salt.len() );

    // Clone `Arc` pointers for use in the closure
    let chain_data_cloned = Arc::clone(&chain_data);
    let econtent_addr_bytes_cloned = Arc::clone(&econtent_addr_bytes);
    let salt_cloned = Arc::clone(&salt);
    let msg_cloned = Arc::clone(&msg);
    let digest_algorithm_oid_cloned = Arc::clone(&digest_algorithm_oid);
    let signature_cloned = Arc::clone(&signature);
    let public_key_cloned = Arc::clone(&public_key);

    // tokio::task::spawn_blocking
    let receipt = spawn_blocking(move || {
        match &*public_key_cloned {
            PublicKey::Rsa { modulus, exponent } => {
                prove_pkcs7_verification(
                    &*chain_data_cloned,              
                    &*econtent_addr_bytes_cloned,    
                    &*salt_cloned,                    
                    &*msg_cloned,                     
                    //&*digest_algorithm_oid_cloned,    
                    &*signature_cloned,               
                    modulus,  
                    Some(exponent),
                )
            }
            PublicKey::Ecdsa { point } => {
                prove_pkcs7_verification(
                    &*chain_data_cloned,              // &CertificateData
                    &*econtent_addr_bytes_cloned,    // &Vec<u8>
                    &*salt_cloned,                    // &Vec<u8>
                    &*msg_cloned,                     // &Vec<u8>
                    //&*digest_algorithm_oid_cloned,    // &AlgorithmIdentifier
                    &*signature_cloned,               // &Vec<u8>
                    point,                             // &Vec<u8>
                    None, 
                )
            }
        }
    })
    .await
    .context("Blocking task panicked (receipt)")?;

    /*let imgid = compute_image_id(PKCS7_VERIFY_ELF);
    println!("imagID {:?}\n",imgid);*/

    let seal = encode_seal(&receipt)?;
    let journal = receipt.journal.bytes.clone();

    // build calldata to send to smart contract
    let calldata = CfWallet::verifyAndTransferCall {
        journal: journal.into(),
        seal: seal.into(), 
    };

    println!("\ncalldata[ \njournal: {:?}\nseal: {:?}\n]\n",calldata.journal,calldata.seal);

    //send transaction
    let contract = args.contract;
    let tx = TransactionRequest::default()
        .with_to(contract)
        .with_call(&calldata);
    
    println!("sending transaction {:?}\n",tx);
    let tx_hash = provider
        .send_transaction(tx)
        .await
        .context("Failed to send transaction")?;

    println!("Transaction sent with hash: {:?}", tx_hash);


    Ok(())
}
