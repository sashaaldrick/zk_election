use alloy_primitives::U256;
use alloy_sol_types::{sol, SolInterface, SolValue, SolCall};
use anyhow::{Context, Result};
use clap::Parser;
use ethers::prelude::*;
use methods::ZK_VERIFIER_ELF;
use risc0_ethereum_contracts::groth16;
use risc0_zkvm::{default_prover, ExecutorEnv, ProverOpts, VerifierContext};
use std::time::{SystemTime, UNIX_EPOCH};
use apps::parser::load_pkcs7;
//use crate::IRiscZeroElection::verifyAndCommitVoteCall;

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

    match load_pkcs7("sdoc.p7b") {
        Ok(pkcs7) => {
            println!("PKCS7 file loaded successfully!");

            let signer_info = &pkcs7.content.signer_infos;
            let certificate = &pkcs7.content.certs[0].tbs_certificate;

            let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();

            // NEED TO VERIFY DIGEST ALSO
            // proof composition per verificare la catena di certificati ?
            let validity = (
                certificate.validity.not_before,
                certificate.validity.not_after,
                now
            );

            println!("not before: {}",certificate.validity.not_before);
            
            let env = ExecutorEnv::builder()
                .write(&validity).unwrap()
                .build().unwrap();
            //, &ProverOpts::groth16(),

            let receipt = default_prover()
                .prove_with_ctx(
                    env,
                    &VerifierContext::default(),
                    ZK_VERIFIER_ELF,
                    &ProverOpts::groth16(),
                )?.receipt;
            
            println!("receipt {:?}",receipt);
            
            let seal = groth16::encode(receipt.inner.groth16()?.seal.clone())?;
            
            let journal = receipt.journal.bytes.clone();

            println!("seal: {:?}\njournal: {:?}",seal,journal);
            
            /*let calldata = IRiscZeroElection::verifyAndCommitVoteCall {
                seal: seal.into(),
                journal: journal.into(),
            };*/

            let runtime = tokio::runtime::Runtime::new()?;

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
