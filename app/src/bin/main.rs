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
//use apps::parser::Certificate;
use clap::Parser;
use ethers::prelude::*;
use methods::{PERIOD_VERIFIER_ELF, PKCS7_VERIFY_ELF};
use risc0_ethereum_contracts::encode_seal;
use risc0_ethereum_contracts::groth16;
use risc0_zkvm::{default_prover, ExecutorEnv, ProverOpts, Receipt, VerifierContext,compute_image_id};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
//use crate::IRiscZeroElection::verifyAndCommitVoteCall;
use url::Url;



// `IRiscZeroElection` interface automatically generated via the alloy `sol!` macro.
sol! {
    interface IRiscZeroElection {
        function verifyAndCommitVote(bytes calldata seal, bytes calldata journal) public;
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

    #[clap(long)]
    salt: u8,
}

fn prove_validity_period(not_before: u64, not_after: u64, now: u64) -> Receipt {
    let validity = (not_before, not_after, now);

    let env = ExecutorEnv::builder()
        .write(&validity)
        .unwrap()
        .build()
        .unwrap();
    //, &ProverOpts::groth16(),

    let prover = default_prover();
    prover
        .prove_with_ctx(
            env,
            &VerifierContext::default(),
            PERIOD_VERIFIER_ELF,
            &ProverOpts::groth16(),
        )
        .unwrap()
        .receipt
}

/*use bcder::oid::Oid;

const OID_SHA1: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x05];
const OID_SHA256: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];

fn select_digest_algorithm(algo_oid: &[u8]) -> &'static str {
    match algo_oid {
        OID_SHA1 => "SHA-1",
        OID_SHA256 => "SHA-256",
        _ => panic!("Unsupported digest algorithm OID"),
    }
}


    // Implementazione per SHA-256
    let digest = match algorithm {
        "SHA-1" => {
           println!("sha1");
        }
        "SHA-256" => {
            println!("sha256");
        }
        _ => unreachable!(), // Questo non dovrebbe mai accadere
    };*/



fn prove_pkcs7_verification(
    chain_data: Vec<CertificateData>,
    econtent: &[u8],
    salt: &[u8],
    msg: &[u8],
    algo_oid: &[u8],
    signature: &[u8],
    pub_key: &[u8],
    pub_key_exp: Option<&[u8]>, // only for RSA
                                //prec_receipt: &Receipt,
) -> Receipt {
    // if RSA, send exp lenght, if ECDSA exp.len = 0
    let lengths = if let Some(exp) = pub_key_exp {
        (
            econtent.len(),
            salt.len(),
            msg.len(),
            algo_oid.len(),
            signature.len(),
            pub_key.len(),
            exp.len(),
        )
    } else {
        (
            econtent.len(),
            salt.len(),
            msg.len(),
            algo_oid.len(),
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
    env_builder.write_slice(&algo_oid);
    env_builder.write_slice(&signature);
    env_builder.write_slice(&pub_key);

    if let Some(exp) = pub_key_exp {
        env_builder.write_slice(&exp);
    }

    let env = env_builder.build().unwrap();

    let receipt = default_prover()
        .prove_with_ctx(
            env,
            &VerifierContext::default(),
            PKCS7_VERIFY_ELF,
            &ProverOpts::groth16(),
        ).unwrap()
        .receipt;

    receipt
}

fn extract_certificate_data(
    certs: &[Certificate],
    subj_cert: &Certificate,
) -> Vec<CertificateData> {
    println!(
        "\n---extract_certificate_data---\ncerts len: {}\n",
        certs.len()
    );

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
    println!("\n\ncert cahin data: {:?}",certs_chain_data);
    certs_chain_data
}

fn convert_to_bytes(str_bytes: Vec<u8>) -> Vec<u8> {

    let mut econtent_str = String::from_utf8(str_bytes).expect("Failed to convert from bytes to string");
    econtent_str = econtent_str.trim().to_string();
    let econtent_hex = econtent_str.trim_start_matches("0x");
    let address_bytes = hex::decode(econtent_hex).expect("Failed to decode hex");
    assert_eq!(address_bytes.len(), 20, "ETH address must be 20 bytes long");
    address_bytes
}

//#[tokio::main]
fn main() -> Result<()> {

    // Parse CLI Arguments: The application starts by parsing command-line arguments provided by the user.
    //let args = Args::parse();

    // Create a new transaction sender using the parsed arguments.
    /*let tx_sender = TxSender::new(
        args.chain_id,
        &args.rpc_url,
        &args.eth_wallet_private_key,
        &args.contract,
    )?;*/

    // Create an alloy provider for that private key and URL.
    /*let wallet = EthereumWallet::from(args.eth_wallet_private_key);
    let provider = ProviderBuilder::new()
        .with_recommended_fillers()
        .wallet(wallet)
        .on_http(args.rpc_url);*/


    let salt: &[u8] = &[0x01,0x02,0x03];





    match load_pkcs7("/home/moz/tesi/cert/rsa/cf_signed.p7m") {
        //match load_pkcs7("/home/moz/tesi/cert/ecdsa/buono/signed_doc.p7m") {
        Ok(pkcs7) => {
            println!("PKCS7 file loaded successfully!");

            let signer_infos = &pkcs7.content.signer_infos;
            let signer_serial_number = &pkcs7.content.signer_infos[0]
                .signer_identifier
                .serial_number;

            // use serial number to find user certificate
            let subject_cert = pkcs7
                .content
                .certs
                .iter()
                .find(|cert| &cert.tbs_certificate.serial_number == signer_serial_number)
                .expect("Subject certificate not found in certificate list");

            
                /* VERIFICATION PROCESS: (use proof composition)
               - verify validity period
               - verify message digest (not tampered msg)
               - verify chain?
                   - check CA in eIDAS Trusted List
            */

            // VALIDITY
            // extracting validity value and pass to guest to verify period
            /*let validity = &subject_cert.tbs_certificate.validity;
            let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
            let period_receipt = prove_validity_period(validity.not_before, validity.not_after, now);

            let seal = encode_seal(&period_receipt)?;
            let journal = period_receipt.journal.bytes.clone();

            println!("***PERIOD***\nseal: {:?}\njournal: {:?}\n",seal,journal);*/

            // SIGNATURE
            //extracting value of: signature, algorithm used, public key and message to be signed
            let signer_info = &signer_infos[0];
            let signature = &signer_info.signature;
            let digest_algorithm_oid = &signer_info.digest_algorithm.algorithm;
            let _signature_algorithm_oid = &signer_info.signature_algorithm.algorithm;
            let public_key = &subject_cert.tbs_certificate.subject_public_key_info.subject_public_key;
            let msg = if signer_info.auth_attributes.is_some() {
                &signer_info.auth_bytes
            } else {
                &pkcs7.content_bytes //this is the data of the signed document
            };

            // VERIFY CHAIN
            let chain_data = extract_certificate_data(&pkcs7.content.certs, &subject_cert);

            let econtent_addr_bytes = convert_to_bytes(pkcs7.content.content_info.e_content);
            println!("\n--main--\nsending econtent: {:?}\nsubject: {:?}\nsalt:len {:?}",hex::encode(&econtent_addr_bytes),hex::encode(&subject_cert.tbs_certificate.subject.to_der()),salt.len());
            
            let receipt = match &public_key {
                PublicKey::Rsa { modulus, exponent } => {
                    prove_pkcs7_verification(
                        chain_data,
                        //pkcs7.content.content_info.e_content.as_ref(),
                        econtent_addr_bytes.as_ref(),
                        salt,
                        msg.as_ref(),
                        digest_algorithm_oid.as_ref(),
                        signature.as_ref(),
                        modulus.as_ref(),
                        Some(exponent.as_ref()),
                        //&period_receipt,
                    )
                }
                PublicKey::Ecdsa { point } => {
                    prove_pkcs7_verification(
                        chain_data,
                        //pkcs7.content.content_info.e_content.as_ref(),
                        econtent_addr_bytes.as_ref(),
                        salt,
                        msg.as_ref(),
                        digest_algorithm_oid.as_ref(),
                        signature.as_ref(),
                        point.as_ref(),
                        None,
                        //&period_receipt,
                    )
                }
            };

            let seal = encode_seal(&receipt)?;
            //let journal = receipt.journal.bytes.clone();
            let journal = receipt.journal.bytes.clone();
            println!("\njournal: {:?}\nseal: {:?}", journal,seal);

            // TODO
            // write a decode function for journal, extract (econtent, subject, root_pk)


            /*let calldata = IRiscZeroElection::verifyAndCommitVoteCall {
                seal: seal.into(),
                journal: journal.into(),
            };

            let contract = args.contract;
            let tx = TransactionRequest::default()
                .with_to(contract)
                .with_call(&calldata);

            let tx_hash = provider
                .send_transaction(tx)
                .await
                .context("Failed to send transaction")?;

            println!("Transaction sent with hash: {:?}", tx_hash);*/

            //let runtime = tokio::runtime::Runtime::new()?;

            // Send transaction: Finally, the TxSender component sends the transaction to the Ethereum blockchain,
            // calling function verifyAndCommitVote of RiscZeroElection
            //runtime.block_on(tx_sender.send(calldata))?;

            Ok(())
        }
        Err(e) => {
            println!("Failed to load PKCS7 file: {}", e);
            Err(anyhow::Error::msg(format!("{}", e)))
        }
    }
}
