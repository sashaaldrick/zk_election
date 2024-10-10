use alloy_primitives::U256;
use alloy_sol_types::{sol, /*SolInterface, SolValue,*/ SolCall};
use anyhow::{Context, Result};
use apps::parser::Certificate;
use clap::Parser;
use ethers::prelude::*;
use methods::{PERIOD_VERIFIER_ELF, SIGNATURE_VERIFIER_ELF};
use risc0_ethereum_contracts::groth16;
use risc0_ethereum_contracts::encode_seal;
use risc0_zkvm::{default_prover, ExecutorEnv, ProverOpts, VerifierContext, Receipt};
use std::time::{SystemTime, UNIX_EPOCH};
use apps::parser::{load_pkcs7, PublicKey};
//use crate::IRiscZeroElection::verifyAndCommitVoteCall;
use hex;

// `IRiscZeroElection` interface automatically generated via the alloy `sol!` macro.
sol! {
    interface IRiscZeroElection {
        function verifyAndCommitVote(bytes calldata seal, bytes calldata journal);
    }
}

/// Wrapper of a `SignerMiddleware` client to send transactions to the given
/// contract's `Address`.
pub struct TxSender {
    chain_id: u64,
    client: SignerMiddleware<Provider<Http>, Wallet<k256::ecdsa::SigningKey>>,
    contract: Address,
}

impl TxSender {
    /// Creates a new `TxSender`.
    pub fn new(chain_id: u64, rpc_url: &str, private_key: &str, contract: &str) -> Result<Self> {
        let provider = Provider::<Http>::try_from(rpc_url)?;
        let wallet: LocalWallet = private_key.parse::<LocalWallet>()?.with_chain_id(chain_id);
        let client = SignerMiddleware::new(provider.clone(), wallet.clone());
        let contract = contract.parse::<Address>()?;

        Ok(TxSender {
            chain_id,
            client,
            contract,
        })
    }

    /// Send a transaction with the given calldata.
    pub async fn send(&self, seal: Vec<u8>, journal: Vec<u8>) -> Result<Option<TransactionReceipt>> {
        
        let calldata = IRiscZeroElection::verifyAndCommitVoteCall {
            seal: seal.into(),
            journal: journal.into(),
        };

        let encoded_calldata = calldata.abi_encode();
        
        let tx = TransactionRequest::new()
            .chain_id(self.chain_id)
            .to(self.contract)
            .from(self.client.address())
            .data(encoded_calldata);

        log::info!("Transaction request: {:?}", &tx);

        let tx = self.client.send_transaction(tx, None).await?.await?;

        log::info!("Transaction receipt: {:?}", &tx);

        Ok(tx)
    }
}

/// Arguments of the publisher CLI.
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// Ethereum chain ID
    #[clap(long)]
    chain_id: u64,

    /// Ethereum Node endpoint.
    #[clap(long, env)]
    eth_wallet_private_key: String,

    /// Ethereum Node endpoint.
    #[clap(long)]
    rpc_url: String,

    /// Application's contract address on Ethereum
    #[clap(long)]
    contract: String,

    /// The input to provide to the guest binary
    #[clap(long)]
    p7_path: String,
}


fn prove_validity_period (not_before: u64, not_after: u64, now: u64) -> Receipt {

    let validity = (not_before,not_after, now);

    let env = ExecutorEnv::builder()
        .write(&validity).unwrap()
        .build().unwrap();
    //, &ProverOpts::groth16(),

    let prover = default_prover();
    prover.prove_with_ctx(
        env,
        &VerifierContext::default(),
        PERIOD_VERIFIER_ELF,
        &ProverOpts::groth16(),
    ).unwrap().receipt
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


fn prove_rsa_verification(
    msg: &[u8],
    algo_oid: &[u8], 
    signature: &[u8], 
    pub_key_mod: &[u8], 
    pub_key_exp: &[u8],
    prec_receipt: &Receipt,
) -> Receipt {

    //sending lenghts to create fixed size arrays in guest 
    let lenghts = (msg.len(), algo_oid.len(), signature.len(), pub_key_mod.len(), pub_key_exp.len());

    let env = ExecutorEnv::builder()
        //.add_assumption(prec_receipt)
        .write(&lenghts).unwrap()
        .write_slice(&msg)
        .write_slice(&algo_oid)
        .write_slice(&signature)
        .write_slice(&pub_key_mod)
        .write_slice(&pub_key_exp)
        .build().unwrap();

    let prover = default_prover();
    prover.prove_with_ctx(
        env,
        &VerifierContext::default(),
        SIGNATURE_VERIFIER_ELF,
        &ProverOpts::groth16(),
    ).unwrap().receipt

}


fn prove_signature_verification(
    msg: &[u8],
    algo_oid: &[u8], 
    signature: &[u8], 
    pub_key: &[u8], 
    pub_key_exp: Option<&[u8]>, // only for RSA
    prec_receipt: &Receipt,
) -> Receipt {

    // if RSA, send exp lenght, if ECDSA exp.len = 0
    let lengths = if let Some(exp) = pub_key_exp {
        (msg.len(), algo_oid.len(), signature.len(), pub_key.len(), exp.len())
    } else {
        (msg.len(), algo_oid.len(), signature.len(), pub_key.len(), 0)
    };

    let mut env_builder = ExecutorEnv::builder();

    env_builder.write(&lengths).unwrap();
    env_builder.write_slice(&msg);
    env_builder.write_slice(&algo_oid);
    env_builder.write_slice(&signature);
    env_builder.write_slice(&pub_key);

    if let Some(exp) = pub_key_exp {
        env_builder.write_slice(&exp);
    }

    let env = env_builder.build().unwrap();

    let prover = default_prover();
    prover.prove_with_ctx(
        env,
        &VerifierContext::default(),
        SIGNATURE_VERIFIER_ELF,
        &ProverOpts::groth16(),
    ).unwrap().receipt

}



fn main() -> Result<()> {
    env_logger::init();
    // Parse CLI Arguments: The application starts by parsing command-line arguments provided by the user.
    /*let args = Args::parse();

    // Create a new transaction sender using the parsed arguments.
    let tx_sender = TxSender::new(
        args.chain_id,
        &args.rpc_url,
        &args.eth_wallet_private_key,
        &args.contract,
    )?;*/
    match load_pkcs7("/home/moz/tesi/sdoc.p7b") {
    //match load_pkcs7("/home/moz/tesi/cert/ecdsa/signed_doc_pem.p7m") {
        Ok(pkcs7) => {
            println!("PKCS7 file loaded successfully!");

            let signer_infos = &pkcs7.content.signer_infos;

            let signer_serial_number = &pkcs7.content.signer_infos[0].signer_identifier.serial_number;

            // use serial number to find user certificate
            let subject_cert = pkcs7.content.certs.iter()
                .find(|cert| &cert.tbs_certificate.serial_number == signer_serial_number)
                .expect("Subject certificate not found in certificate list");

            println!("-----------------------------------\n");
            println!("subject serial number: {:?}",subject_cert.tbs_certificate.serial_number);
            let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();

            /* VERIFICATION PROCESS:
                - verify validity period
                - verify message digest (not tampered msg)
                - verify chain? (proof composition)
             */
            
            // VALIDITY
            // extracting validity value and pass to guest to verify period
            let validity = &subject_cert.tbs_certificate.validity;
            let period_receipt = prove_validity_period(validity.not_before, validity.not_after, now);
            
            let seal = encode_seal(&period_receipt)?;
            let journal = period_receipt.journal.bytes.clone();

            //println!("***PERIOD***\nseal: {:?}\njournal: {:?}\n",seal,journal);

            // SIGNATURE
            //extracting value of: signature, algorithm used, public key and message to be signed
            let signer_info = &signer_infos[0];
            let signature = &signer_info.signature; 
            let digest_algorithm_oid = &signer_info.digest_algorithm.algorithm;
            let signature_algorithm_oid = &signer_info.signature_algorithm.algorithm;
            println!("signature oid: {:?}\n",signature_algorithm_oid);
            let public_key = &subject_cert.tbs_certificate.subject_public_key_info.subject_public_key;
            println!("\npublickey: {:?}",public_key);
            let msg = if signer_info.auth_attributes.is_some() { 
                &signer_info.auth_bytes 
            } else {
                &pkcs7.content_bytes //this is the data of the signed document
            };
            
            println!("-------------------------------------------\n\n");
            println!("msg {:?}\n",hex::encode(&msg));

            let signature_receipt = match &public_key {
                PublicKey::Rsa { modulus, exponent } => {
                    prove_signature_verification(
                        msg.as_ref(),
                        digest_algorithm_oid.as_ref(), 
                        signature.as_ref(), 
                        modulus.as_ref(), 
                        Some(exponent.as_ref()),
                        &period_receipt,
                    )
                }
                PublicKey::Ecdsa { point } => {
                    prove_signature_verification(
                        msg.as_ref(),
                        digest_algorithm_oid.as_ref(),
                        signature.as_ref(),
                        point.as_ref(),
                        None,
                        &period_receipt,
                    )
                }
            };
            
            /*let signature_receipt = prove_signature_verification(
                msg.as_ref(),
                digest_algorithm_oid.as_ref(), 
                signature.as_ref(), 
                public_key.modulus.as_ref(), 
                public_key.exp.as_ref(),
                &period_receipt,
            );*/

            //let seal_sig = encode_seal(&signature_receipt)?;
            //let journal_sig = signature_receipt.journal.bytes.clone();
            

            //println!("***SIGNATURE***\nseal: {:?}\njournal: {:?}\n",seal_sig,journal_sig);

            /*let calldata = IRiscZeroElection::verifyAndCommitVoteCall {
                seal: seal.into(),
                journal: journal.into(),
            };*/

            //slet runtime = tokio::runtime::Runtime::new()?;

            // Send transaction: Finally, the TxSender component sends the transaction to the Ethereum blockchain,
            // calling function verifyAndCommitVote of RiscZeroElection
            //runtime.block_on(tx_sender.send(seal, journal))?;

            Ok(())

        },
        Err(e) => {
            println!("Failed to load PKCS7 file: {}",e);
            Err(anyhow::Error::msg(format!("{}",e)))
        }   
    }
}
