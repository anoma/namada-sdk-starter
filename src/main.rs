use namada::types::chain::ChainId;
use tendermint_rpc::HttpClient;
use tendermint_config::net::Address as TendermintAddress;
use std::str::FromStr;
use namada::ledger::{tx, masp, rpc};
use namada::ledger::wallet::SdkWalletUtils;
use namada::ledger::args;
use std::path::PathBuf;
use namada::ledger::wallet::Wallet;
use std::path::Path;
use namada::ledger::wallet::Store;
use namada::types::address::Address;
use namada::types::masp::TransferSource;
use namada::types::masp::TransferTarget;
use borsh::BorshSerialize;
use borsh::BorshDeserialize;
use masp_proofs::prover::LocalTxProver;
use std::{env, vec};
use std::fs::File;
use std::fs::OpenOptions;
use std::io::Read;
use std::io::Write;

use namada::types::key::common::{SecretKey, PublicKey};

/// Shielded context file name
const FILE_NAME: &str = "shielded.dat";
const TMP_FILE_NAME: &str = "shielded.tmp";

#[derive(Debug, BorshSerialize, BorshDeserialize, Clone)]
pub struct FuzzerShieldedUtils {
    #[borsh_skip]
    context_dir: PathBuf,
}

impl FuzzerShieldedUtils {
    /// Initialize a shielded transaction context that identifies notes
    /// decryptable by any viewing key in the given set
    pub fn new(context_dir: PathBuf) -> masp::ShieldedContext<Self> {
        // Make sure that MASP parameters are downloaded to enable MASP
        // transaction building and verification later on
        let params_dir = masp::get_params_dir();
        let spend_path = params_dir.join(masp::SPEND_NAME);
        let convert_path = params_dir.join(masp::CONVERT_NAME);
        let output_path = params_dir.join(masp::OUTPUT_NAME);
        if !(spend_path.exists()
            && convert_path.exists()
            && output_path.exists())
        {
            println!("MASP parameters not present, downloading...");
            masp_proofs::download_parameters()
                .expect("MASP parameters not present or downloadable");
            println!("MASP parameter download complete, resuming execution...");
        }
        // Finally initialize a shielded context with the supplied directory
        let utils = Self { context_dir };
        masp::ShieldedContext {
            utils,
            ..Default::default()
        }
    }
}

impl Default for FuzzerShieldedUtils {
    fn default() -> Self {
        Self {
            context_dir: PathBuf::from(FILE_NAME),
        }
    }
}

impl masp::ShieldedUtils for FuzzerShieldedUtils {
    type C = tendermint_rpc::HttpClient;

    fn local_tx_prover(&self) -> LocalTxProver {
        if let Ok(params_dir) = env::var(masp::ENV_VAR_MASP_PARAMS_DIR) {
            let params_dir = PathBuf::from(params_dir);
            let spend_path = params_dir.join(masp::SPEND_NAME);
            let convert_path = params_dir.join(masp::CONVERT_NAME);
            let output_path = params_dir.join(masp::OUTPUT_NAME);
            LocalTxProver::new(&spend_path, &output_path, &convert_path)
        } else {
            LocalTxProver::with_default_location()
                .expect("unable to load MASP Parameters")
        }
    }

    /// Try to load the last saved shielded context from the given context
    /// directory. If this fails, then leave the current context unchanged.
    fn load(self) -> std::io::Result<masp::ShieldedContext<Self>> {
        // Try to load shielded context from file
        let mut ctx_file = File::open(self.context_dir.join(FILE_NAME))?;
        let mut bytes = Vec::new();
        ctx_file.read_to_end(&mut bytes)?;
        let mut new_ctx = masp::ShieldedContext::deserialize(&mut &bytes[..])?;
        // Associate the originating context directory with the
        // shielded context under construction
        new_ctx.utils = self;
        Ok(new_ctx)
    }

    /// Save this shielded context into its associated context directory
    fn save(&self, ctx: &masp::ShieldedContext<Self>) -> std::io::Result<()> {
        // TODO: use mktemp crate?
        let tmp_path = self.context_dir.join(TMP_FILE_NAME);
        {
            // First serialize the shielded context into a temporary file.
            // Inability to create this file implies a simultaneuous write is in
            // progress. In this case, immediately fail. This is unproblematic
            // because the data intended to be stored can always be re-fetched
            // from the blockchain.
            let mut ctx_file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(tmp_path.clone())?;
            let mut bytes = Vec::new();
            ctx.serialize(&mut bytes)
                .expect("cannot serialize shielded context");
            ctx_file.write_all(&bytes[..])?;
        }
        // Atomically update the old shielded context file with new data.
        // Atomicity is required to prevent other client instances from reading
        // corrupt data.
        std::fs::rename(tmp_path.clone(), self.context_dir.join(FILE_NAME))?;
        // Finally, remove our temporary file to allow future saving of shielded
        // contexts.
        std::fs::remove_file(tmp_path)?;
        Ok(())
    }
}

#[tokio::main]
async fn main() -> std::io::Result<()> {

    let mut shielded_ctx = FuzzerShieldedUtils::new(Path::new("./").to_path_buf());
    let mut wallet = Wallet::new(
        Path::new("wallet.toml").to_path_buf(),
        Store::default(),
    );
    println!("stuff");
    // Namada native token
    // let native_token = Address::from_str("atest1v4ehgw36x3prswzxggunzv6pxqmnvdj9xvcyzvpsggeyvs3cg9qnywf589qnwvfsg5erg3fkl09rg5")
    //     .expect("Unable to construct native token");
    // // Address of the faucet
    // let faucet_addr = Address::from_str("atest1v4ehgw36x4pngsfc8y6rzdjyx5c5vdzzgcerxd3exyuyzdfjgcerzv2rgyengs33gdq5xw2rmr7s5u")
    //     .expect("Unable to construct source");
    // let target_addr = Address::from_str("atest1v4ehgw36xeprxvjpgycnssf3xcenqvpjgyur2djx8pprzdj9x565gdjy8ycyxvf4x3qns3fney8mtj").expect("stuff");
    // // Key to withdraw funds from the faucet
    // let target_key = SecretKey::from_str("00c4ed3c491c56030cbb406f943b4f50261b4eda7b642fb9eb76323ef2b80feb8a").expect("Invalid secret key");
    // // Construct out shielding transaction
    // let transfer_tx = args::TxTransfer {
    //     amount: 23000000.into(),
    //     native_token: native_token.clone(),
    //     source: TransferSource::Address(target_addr.clone()),
    //     target: TransferTarget::Address(faucet_addr.clone()),
    //     token: native_token.clone(),
    //     sub_prefix: None,
    //     tx_code_path: vec![],
    //     tx: args::Tx {
    //         dry_run: false,
    //         dump_tx: false,
    //         force: false,
    //         broadcast_only: false,
    //         ledger_address: (),
    //         initialized_account_alias: None,
    //         wallet_alias_force: false,
    //         fee_amount: 0.into(),
    //         fee_token: native_token,
    //         gas_limit: 0.into(),
    //         expiration: None,
    //         chain_id: None,
    //         signing_key: Some(target_key),
    //         signer: None,
    //         tx_code_path: vec![],
    //         password: None,
    //     },
    // };

    let native_token = Address::from_str("atest1v4ehgw36x3prswzxggunzv6pxqmnvdj9xvcyzvpsggeyvs3cg9qnywf589qnwvfsg5erg3fkl09rg5")
        .expect("Unable to construct native token");
    let target_addr = Address::from_str("atest1v4ehgw36xeprxvjpgycnssf3xcenqvpjgyur2djx8pprzdj9x565gdjy8ycyxvf4x3qns3fney8mtj").expect("stuff");
    // Key to withdraw funds from the faucet
    let target_key = SecretKey::from_str("00c4ed3c491c56030cbb406f943b4f50261b4eda7b642fb9eb76323ef2b80feb8a").expect("Invalid secret key");
    let pub_key = PublicKey::from_str("00478117b44415df4546e533f56e6ab5f9f033de158417c5a4b23bae496e3eaa57").unwrap();

    let transfer_tx = args::TxInitAccount {
        source: target_addr.clone(),
        vp_code: std::fs::read(PathBuf::from("wasm/vp_user.bf4688574c26db2e2d55fa033a2d6a98f8c13c03dcaeaefbbb9bd59589187881.wasm")).unwrap(),
        vp_code_path: "vp_user.wasm".to_string().into_bytes(),
        tx_code_path: std::fs::read(PathBuf::from("wasm/tx_init_account.c867276c833b39cbe0da42ef09e84c4288c4a9e42f52446eaaa0cca5d3f16f89.wasm")).unwrap(),
        public_key: pub_key, 
        tx: args::Tx {
            dry_run: false,
            dump_tx: false,
            force: false,
            broadcast_only: false,
            ledger_address: (),
            initialized_account_alias: Some("test".to_owned()),
            wallet_alias_force: false,
            fee_amount: 0.into(),
            fee_token: native_token,
            gas_limit: 0.into(),
            expiration: None,
            chain_id: Some(ChainId::from_str("public-testnet-8.0.b92ef72b820").unwrap()),
            signing_key: Some(target_key),
            signer: None,
            tx_code_path: vec![],
            password: None,
        },    
    };

    // Connect to an RPC
    let addr = TendermintAddress::from_str("127.0.0.1:26757")
        .expect("Unable to connect to RPC");
    let client = HttpClient::new(addr).unwrap();
    let res = rpc::query_block(&client).await;
    println!("Results: {:?}", res);
    // Now actually make the shielding transfer
    let res = tx::submit_init_account::<HttpClient, SdkWalletUtils<PathBuf>>(
        &client,
        &mut wallet,
        transfer_tx,
    ).await;
    println!("Results: {:?}", res);

    Ok(())

    // // Get the WASM to effect a transfer
    // let mut tx_transfer_wasm = File::open("/home/murisi/namada/wasm/tx_transfer.7bb6b5f6b2126372f68711f133ab7cee1656e0cb0f052490f681b9a3a71aa691.wasm")?;
    // let mut tx_transfer_bytes = vec![];
    // tx_transfer_wasm.read_to_end(&mut tx_transfer_bytes)?;
    // // Get the WASM to reveal PK
    // let mut tx_reveal_pk_wasm = File::open("/home/murisi/namada/wasm/tx_reveal_pk.a956c436553d92e1dc8afcf44399e95559b3eb19ca4df5ada3d07fc6917e0591.wasm")?;
    // let mut tx_reveal_pk_bytes = vec![];
    // tx_reveal_pk_wasm.read_to_end(&mut tx_reveal_pk_bytes)?;
    // // Make a wallet
    // let mut wallet = Wallet::new(
    //     Path::new("wallet.toml").to_path_buf(),
    //     Store::default(),
    // );
    // // Generate a spending key
    // let (alias, _spending_key) = wallet.gen_spending_key("joe".to_string(), None, false);
    // let viewing_key = wallet.find_viewing_key(alias.clone()).expect("A viewing key");
    // let (div, _g_d) = find_valid_diversifier(&mut OsRng);
    // // Payment address to transfer to
    // let payment_addr = ExtendedFullViewingKey::from(*viewing_key).fvk.vk.to_payment_address(div)
    //     .expect("a PaymentAddress");
    
    // let mut shielded_ctx = FuzzerShieldedUtils::new(Path::new("./").to_path_buf());
    // // Namada native token
    // let native_token = Address::from_str("atest1v4ehgw36x3prswzxggunzv6pxqmnvdj9xvcyzvpsggeyvs3cg9qnywf589qnwvfsg5erg3fkl09rg5")
    //     .expect("Unable to construct native token");
    // // Address of the faucet
    // let faucet_addr = Address::from_str("atest1v4ehgw36g9rygd6xgs65ydpsg9qnsv3sxuungwp5xaqnv333xu65gdfexcmng3fkgfryy3psdxyc4w")
    //     .expect("Unable to construct source");
    // // Key to withdraw funds from the faucet
    // let faucet_key = SecretKey::from_str("001c1002a48ba1075e2602028697c2bdf182e07636927f399b22ca99e07f92e04a").expect("Invalid secret key");
    // // Construct out shielding transaction
    // let transfer_tx = args::TxTransfer {
    //     amount: 23000000.into(),
    //     native_token: native_token.clone(),
    //     source: TransferSource::Address(faucet_addr.clone()),
    //     target: TransferTarget::PaymentAddress(payment_addr.clone().into()),
    //     token: native_token.clone(),
    //     sub_prefix: None,
    //     tx_code_path: tx_transfer_bytes,
    //     tx: args::Tx {
    //         dry_run: false,
    //         dump_tx: false,
    //         force: false,
    //         broadcast_only: false,
    //         ledger_address: (),
    //         initialized_account_alias: None,
    //         wallet_alias_force: false,
    //         fee_amount: 0.into(),
    //         fee_token: native_token,
    //         gas_limit: 0.into(),
    //         expiration: None,
    //         chain_id: None,
    //         signing_key: Some(faucet_key),
    //         signer: None,
    //         tx_code_path: tx_reveal_pk_bytes,
    //         password: None,
    //     },
    // };
    // // Connect to an RPC
    // let addr = TendermintAddress::from_str("127.0.0.1:27657")
    //     .expect("Unable to connect to RPC");
    // let client = HttpClient::new(addr).unwrap();
    // // Now actually make the shielding transfer
    // let res = tx::submit_transfer::<HttpClient, SdkWalletUtils<PathBuf>, _>(
    //     &client,
    //     &mut wallet,
    //     &mut shielded_ctx,
    //     transfer_tx,
    // ).await;
    // println!("Results: {:?}", res);
    // Ok(())
}
