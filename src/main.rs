use std::fs::File;
use std::fs::OpenOptions;
use std::io::Read;
use std::io::Write;
use std::marker::PhantomData;
use std::path::Path;
use std::path::PathBuf;
use std::str::FromStr;
use std::{env, vec};



use async_trait::async_trait;
use borsh::BorshDeserialize;
use borsh::BorshSerialize;
use namada::bip39::{Mnemonic, Seed};
use namada::ledger::masp::ShieldedContext;
use namada::ledger::wallet::alias::Alias;
use namada::ledger::wallet::derivation_path::DerivationPath;
use namada::types::key::SchemeType;
use namada::types::masp::PaymentAddress;
use zeroize::Zeroizing;

use namada::ledger::args;
use namada::ledger::wallet::Store;
use namada::ledger::wallet::Wallet;
use namada::ledger::wallet::{store, GenRestoreKeyError, WalletUtils};
use namada::ledger::{masp, rpc, tx};
use namada::types::address::Address;
use namada::types::chain::ChainId;
use namada::types::key::common::{PublicKey, SecretKey};
use namada::types::masp::TransferSource;
use namada::types::masp::TransferTarget;

use masp_proofs::prover::LocalTxProver;

use rand::Rng;
use rand_core::{OsRng, RngCore};
use tendermint_config::net::Address as TendermintAddress;
use tendermint_rpc::HttpClient;

/// Shielded context file name
const FILE_NAME: &str = "shielded.dat";
const TMP_FILE_NAME: &str = "shielded.tmp";

const MNEMONIC_CODE: &str = "cruise ball fame lucky fabric govern \
                            length fruit permit tonight fame pear \
                            horse park key chimney furnace lobster \
                            foot example shoot dry fuel lawn";
const DERIVATION_PATH_HARDENED_0: &str = "m/44'/877'/0'/0'/0'";
const DERIVATION_PATH_HARDENED_1: &str = "m/44'/877'/0'/0'/1'";
const DERIVATION_PATH_HARDENED_2: &str = "m/44'/877'/0'/0'/2'";

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let store = wallet::load_or_new(&PathBuf::from("wallet.toml")).unwrap();
    let mut wallet: Wallet<SdkWalletUtils> =
        Wallet::new(PathBuf::from("wallet.toml"), store);

    wallet.gen_spending_key("sdefault0".to_owned(), Some(Zeroizing::new("sdefault0".to_owned())), false);
    wallet::save(wallet.store(), wallet.store_dir()).unwrap();

    // let mnemonic = Mnemonic::from_phrase(MNEMONIC_CODE, namada::bip39::Language::English).unwrap();
    // let seed = Seed::new(&mnemonic, "");
    // let (key_alias_0, _) = wallet
    //     .gen_and_store_key(
    //         SchemeType::Ed25519,
    //         Some("default0".to_owned()),
    //         false,
    //         Some((
    //             seed.clone(),
    //             DerivationPath::from_path_str(SchemeType::Ed25519, DERIVATION_PATH_HARDENED_0)
    //                 .unwrap(),
    //         )),
    //         None,
    //     )
    //     .unwrap();
    // let (key_alias_1, _) = wallet
    //     .gen_and_store_key(
    //         SchemeType::Ed25519,
    //         Some("default1".to_owned()),
    //         false,
    //         Some((
    //             seed.clone(),
    //             DerivationPath::from_path_str(SchemeType::Ed25519, DERIVATION_PATH_HARDENED_1)
    //                 .unwrap(),
    //         )),
    //         None,
    //     )
    //     .unwrap();
    // let (key_alias_2, _) = wallet
    //     .gen_and_store_key(
    //         SchemeType::Ed25519,
    //         Some("default2".to_owned()),
    //         false,
    //         Some((
    //             seed.clone(),
    //             DerivationPath::from_path_str(SchemeType::Ed25519, DERIVATION_PATH_HARDENED_2)
    //                 .unwrap(),
    //         )),
    //         None,
    //     )
    //     .unwrap();
    // wallet::save(wallet.store(), wallet.store_dir()).unwrap();

    let key_alias_0 = "default0".to_owned();
    let key_alias_1 = "default1".to_owned();
    let key_alias_2 = "default2".to_owned();
    let shielded_key_alias_0 = "sdefault0".to_owned();
    let viewing_key = wallet.find_viewing_key(shielded_key_alias_0.clone()).unwrap().clone();

    let (_, payment_addr) = wallet.gen_payment_addr(shielded_key_alias_0.clone(), false, false, viewing_key);
    wallet::save(wallet.store(), wallet.store_dir()).unwrap();

    // println!(
    //     "Alias: {:?} :: Address: {:?}",
    //     &key_alias_0,
    //     wallet.find_address(&key_alias_0).unwrap()
    // );
    // println!(
    //     "Alias: {:?} :: Address: {:?}",
    //     &key_alias_1,
    //     wallet.find_address(&key_alias_1).unwrap()
    // );
    // println!(
    //     "Alias: {:?} :: Address: {:?}",
    //     &key_alias_2,
    //     wallet.find_address(&key_alias_2).unwrap()
    // );
    // println!(
    //     "Alias: {:?} :: Address: {:?}",
    //     &shielded_key_alias_0,
    //     wallet.find_payment_addr(&shielded_key_alias_0).unwrap()
    // );
    // println!(
    //     "Alias: {:?} :: Address: {:?}",
    //     &shielded_key_alias_0,
    //     &viewing_key
    // );
    // println!(
    //     "Alias: {:?} :: Address: {:?}",
    //     &shielded_key_alias_0,
    //     wallet.find_spending_key(&shielded_key_alias_0, Some(Zeroizing::new("sdefault0".to_owned())))
    // );

    let native_token = Address::from_str("atest1v4ehgw36x3prswzxggunzv6pxqmnvdj9xvcyzvpsggeyvs3cg9qnywf589qnwvfsg5erg3fkl09rg5")
    .expect("Unable to construct native token");
    let faucet = Address::from_str("atest1v4ehgw36gdzngvp5g3q5xvpexsuygvzyxsmyz3psxdqnzde4xscrg3pkgdz5gvfsxyenzd292jthnl").expect("Should work");
    let chain_id = ChainId::from_str("namada-test.46fe356079798c1689").unwrap();

    // let init_tx = args::TxInitAccount {
    //     tx: args::Tx {
    //         dry_run: false,
    //         dump_tx: false,
    //         force: false,
    //         broadcast_only: false,
    //         ledger_address: (),
    //         initialized_account_alias: Some("default0_account".to_owned()),
    //         wallet_alias_force: false,
    //         fee_amount: 0.into(),
    //         fee_token: native_token.clone(),
    //         gas_limit: 0.into(),
    //         expiration: None,
    //         chain_id: Some(chain_id.clone()),
    //         signing_key: Some(wallet.find_key(&key_alias_0, Some(Zeroizing::new("".to_owned()))).unwrap()),
    //         signer: None,
    //         tx_reveal_code_path: PathBuf::from("tx_reveal_pk.wasm"),
    //         password: None,
    //     },
    //     source: wallet.find_address(&key_alias_0).unwrap().clone(),
    //     vp_code_path: PathBuf::from("vp_user.wasm"),
    //     tx_code_path: PathBuf::from("tx_init_account.wasm"),
    //     public_key: wallet.find_key(&key_alias_0, Some(Zeroizing::new("".to_owned()))).unwrap().clone().to_public(),
    // };

    let tendermint_addr = TendermintAddress::from_str("127.0.0.1:27657").expect("Unable to connect to RPC");
    let http_client = HttpClient::new(tendermint_addr).unwrap();
    let block_res = rpc::query_block(&http_client).await;
    println!("Query Block: {:?}", block_res);

    // let init_acc_res = tx::submit_init_account(&http_client, &mut wallet, init_tx).await;
    // println!("Tx Result: {:?}", init_acc_res);

    let mut shielded_ctx = SdkShieldedUtils::new(Path::new("masp/").to_path_buf());

    // let transfer_tx = args::TxTransfer {
    //     tx: args::Tx {
    //         dry_run: false,
    //         dump_tx: false,
    //         force: false,
    //         broadcast_only: false,
    //         ledger_address: (),
    //         initialized_account_alias: None,
    //         wallet_alias_force: false,
    //         fee_amount: 0.into(),
    //         fee_token: native_token.clone(),
    //         gas_limit: 0.into(),
    //         expiration: None,
    //         chain_id: Some(chain_id.clone()),
    //         signing_key: Some(wallet.find_key(&key_alias_1, Some(Zeroizing::new("".to_owned()))).unwrap()),
    //         signer: None,
    //         tx_reveal_code_path: PathBuf::from("tx_reveal_pk.wasm"),
    //         password: None,
    //     },
    //     source: TransferSource::Address(faucet),
    //     target: TransferTarget::Address(wallet.find_address(&key_alias_1).unwrap().clone()),
    //     token: native_token.clone(),
    //     sub_prefix: None,
    //     amount: 444853442.into(),
    //     native_token: native_token.clone(),
    //     tx_code_path: PathBuf::from("tx_transfer.wasm"),
    // };

    // let transfer_tx_res = tx::submit_transfer(&http_client, &mut wallet, &mut shielded_ctx, transfer_tx).await;
    // println!("Tx Result: {:?}", transfer_tx_res);

    let balance_res = rpc::get_token_balance(&http_client, &native_token, wallet.find_address(&key_alias_1).unwrap()).await;
    println!("Balance {:?}", balance_res);

    // let transfer_tx_to_2 = args::TxTransfer {
    //     tx: args::Tx {
    //         dry_run: false,
    //         dump_tx: false,
    //         force: false,
    //         broadcast_only: false,
    //         ledger_address: (),
    //         initialized_account_alias: None,
    //         wallet_alias_force: false,
    //         fee_amount: 0.into(),
    //         fee_token: native_token.clone(),
    //         gas_limit: 0.into(),
    //         expiration: None,
    //         chain_id: Some(chain_id.clone()),
    //         // signing_key: Some(wallet.find_key(&key_alias_1, Some(Zeroizing::new("".to_owned()))).unwrap()),
    //         signing_key: None,
    //         signer: Some(Address::from(wallet.find_address(&key_alias_1).unwrap().clone())),
    //         tx_reveal_code_path: PathBuf::from("tx_reveal_pk.wasm"),
    //         password: Some(Zeroizing::new("".to_owned())),
    //     },
    //     source: TransferSource::Address(wallet.find_address(&key_alias_1).unwrap().clone()),
    //     target: TransferTarget::Address(wallet.find_address(&key_alias_2).unwrap().clone()),
    //     token: native_token.clone(),
    //     sub_prefix: None,
    //     amount: 4.into(),
    //     native_token: native_token.clone(),
    //     tx_code_path: PathBuf::from("tx_transfer.wasm"),
    // };

    // let transfer_tx_to_shielded = args::TxTransfer {
    //     tx: args::Tx {
    //         dry_run: false,
    //         dump_tx: false,
    //         force: false,
    //         broadcast_only: false,
    //         ledger_address: (),
    //         initialized_account_alias: None,
    //         wallet_alias_force: false,
    //         fee_amount: 0.into(),
    //         fee_token: native_token.clone(),
    //         gas_limit: 0.into(),
    //         expiration: None,
    //         chain_id: Some(chain_id.clone()),
    //         // signing_key: Some(wallet.find_key(&key_alias_1, Some(Zeroizing::new("".to_owned()))).unwrap()),
    //         signing_key: None,
    //         signer: Some(Address::from(wallet.find_address(&key_alias_1).unwrap().clone())),
    //         tx_reveal_code_path: PathBuf::from("tx_reveal_pk.wasm"),
    //         password: Some(Zeroizing::new("".to_owned())),
    //     },
    //     source: TransferSource::Address(wallet.find_address(&key_alias_1).unwrap().clone()),
    //     target: TransferTarget::PaymentAddress(payment_addr),
    //     token: native_token.clone(),
    //     sub_prefix: None,
    //     amount: 5.into(),
    //     native_token: native_token.clone(),
    //     tx_code_path: PathBuf::from("tx_transfer.wasm"),
    // };

    // let transfer_tx_res = tx::submit_transfer(&http_client, &mut wallet, &mut shielded_ctx, transfer_tx_to_shielded).await;
    // println!("Tx Result: {:?}", transfer_tx_res);

    wallet::save(wallet.store(), wallet.store_dir()).unwrap();

    Ok(())
}

mod wallet {
    use std::{path::PathBuf, fs};
    use std::io::prelude::*;

    use file_lock::{FileOptions, FileLock};
    use namada::ledger::wallet::Store;
    use thiserror::Error;

    #[derive(Error, Debug)]
    pub enum LoadStoreError {
        #[error("Failed decoding the wallet store: {0}")]
        Decode(toml::de::Error),
        #[error("Failed to read the wallet store from {0}: {1}")]
        ReadWallet(String, String),
        #[error("Failed to write the wallet store: {0}")]
        StoreNewWallet(String),
    }

    // /// Get the path to the wallet store.
    // pub fn wallet_file(store_dir: impl AsRef<Path>) -> PathBuf {
    //     store_dir.as_ref().join(FILE_NAME)
    // }

    /// Save the wallet store to a file.
    pub fn save(store: &Store, store_dir: &PathBuf) -> std::io::Result<()> {
        let data = store.encode();
        // let wallet_path = wallet_file(store_dir);
        // Make sure the dir exists
        let wallet_dir = store_dir.parent().unwrap();
        fs::create_dir_all(wallet_dir)?;
        // Write the file
        let options = FileOptions::new().create(true).write(true).truncate(true);
        let mut filelock =
            FileLock::lock(store_dir, true, options)?;
        filelock.file.write_all(&data)
    }

    /// Load the store file or create a new one without any keys or addresses.
    pub fn load_or_new(store_dir: &PathBuf) -> Result<Store, LoadStoreError> {
        load(store_dir).or_else(|_| {
            let store = Store::default();
            save(&store, store_dir)
                .map_err(|err| LoadStoreError::StoreNewWallet(err.to_string()))?;
            Ok(store)
        })
    }

    /// Attempt to load the store file.
    pub fn load(store_dir: &PathBuf) -> Result<Store, LoadStoreError> {
        // let wallet_file = wallet_file(store_dir);
        match FileLock::lock(
            store_dir,
            true,
            FileOptions::new().read(true).write(false),
        ) {
            Ok(mut filelock) => {
                let mut store = Vec::<u8>::new();
                filelock.file.read_to_end(&mut store).map_err(|err| {
                    LoadStoreError::ReadWallet(
                        store_dir.to_str().unwrap().parse().unwrap(),
                        err.to_string(),
                    )
                })?;
                Store::decode(store).map_err(LoadStoreError::Decode)
            }
            Err(err) => Err(LoadStoreError::ReadWallet(
                store_dir.to_string_lossy().into_owned(),
                err.to_string(),
            )),
        }
    }
}

/// A degenerate implementation of wallet interactivity
pub struct SdkWalletUtils;

impl WalletUtils for SdkWalletUtils {
    type Storage = PathBuf;
    type Rng = OsRng;

    fn read_decryption_password() -> Zeroizing<String> {
        panic!("attempted to prompt for password in non-interactive mode");
    }

    fn read_encryption_password() -> Zeroizing<String> {
        panic!("attempted to prompt for password in non-interactive mode");
    }

    fn read_alias(_prompt_msg: &str) -> String {
        panic!("attempted to prompt for alias in non-interactive mode");
    }

    fn read_mnemonic_code(
    ) -> Result<namada::bip39::Mnemonic, namada::ledger::wallet::GenRestoreKeyError> {
        Mnemonic::from_phrase(MNEMONIC_CODE, namada::bip39::Language::English)
            .map_err(|_| GenRestoreKeyError::MnemonicInputError)
        // panic!("attempted to prompt for alias in non-interactive mode");
    }

    fn read_mnemonic_passphrase(_confirm: bool) -> Zeroizing<String> {
        Zeroizing::new("".to_owned())
        // panic!("attempted to prompt for alias in non-interactive mode");
    }

    fn show_overwrite_confirmation(
        _alias: &Alias,
        _alias_for: &str,
    ) -> store::ConfirmationResponse {
        // Automatically replace aliases in non-interactive mode
        store::ConfirmationResponse::Replace
    }

    fn generate_mnemonic_code(
        mnemonic_type: namada::bip39::MnemonicType,
        rng: &mut Self::Rng,
    ) -> Result<namada::bip39::Mnemonic, namada::ledger::wallet::GenRestoreKeyError> {
        const BITS_PER_BYTE: usize = 8;

        // generate random mnemonic
        let entropy_size = mnemonic_type.entropy_bits() / BITS_PER_BYTE;
        let mut bytes = vec![0u8; entropy_size];
        rand::RngCore::fill_bytes(rng, &mut bytes);
        let mnemonic =
            namada::bip39::Mnemonic::from_entropy(&bytes, namada::bip39::Language::English)
                .expect("Mnemonic creation should not fail");

        Ok(mnemonic)
    }
}

#[derive(Debug, BorshSerialize, BorshDeserialize, Clone)]
pub struct SdkShieldedUtils {
    #[borsh_skip]
    context_dir: PathBuf,
}

impl SdkShieldedUtils {
    /// Initialize a shielded transaction context that identifies notes
    /// decryptable by any viewing key in the given set
    pub fn new(context_dir: PathBuf) -> masp::ShieldedContext<Self> {
        // Make sure that MASP parameters are downloaded to enable MASP
        // transaction building and verification later on
        let params_dir = masp::get_params_dir();
        let spend_path = params_dir.join(masp::SPEND_NAME);
        let convert_path = params_dir.join(masp::CONVERT_NAME);
        let output_path = params_dir.join(masp::OUTPUT_NAME);
        if !(spend_path.exists() && convert_path.exists() && output_path.exists()) {
            println!("MASP parameters not present, downloading...");
            masp_proofs::download_masp_parameters(None)
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

impl Default for SdkShieldedUtils {
    fn default() -> Self {
        Self {
            context_dir: PathBuf::from(FILE_NAME),
        }
    }
}

#[async_trait(?Send)]
impl masp::ShieldedUtils for SdkShieldedUtils {
    type C = tendermint_rpc::HttpClient;

    fn local_tx_prover(&self) -> LocalTxProver {
        if let Ok(params_dir) = env::var(masp::ENV_VAR_MASP_PARAMS_DIR) {
            let params_dir = PathBuf::from(params_dir);
            let spend_path = params_dir.join(masp::SPEND_NAME);
            let convert_path = params_dir.join(masp::CONVERT_NAME);
            let output_path = params_dir.join(masp::OUTPUT_NAME);
            LocalTxProver::new(&spend_path, &output_path, &convert_path)
        } else {
            LocalTxProver::with_default_location().expect("unable to load MASP Parameters")
        }
    }

    /// Try to load the last saved shielded context from the given context
    /// directory. If this fails, then leave the current context unchanged.
    async fn load(self) -> std::io::Result<masp::ShieldedContext<Self>> {
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
    async fn save(&self, ctx: &masp::ShieldedContext<Self>) -> std::io::Result<()> {
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

// let res = tx::submit_init_account::<HttpClient, SdkWalletUtils<PathBuf>>(
//     &client,
//     &mut wallet,
//     transfer_tx,
// ).await;
// println!("Results: {:?}", res);

// let mut shielded_ctx = FuzzerShieldedUtils::new(Path::new("./").to_path_buf());
// let mut wallet = Wallet::new(
//     Path::new("wallet.toml").to_path_buf(),
//     Store::default(),
// );
// println!("stuff");
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

// let native_token = Address::from_str("atest1v4ehgw36x3prswzxggunzv6pxqmnvdj9xvcyzvpsggeyvs3cg9qnywf589qnwvfsg5erg3fkl09rg5")
//     .expect("Unable to construct native token");
// let target_addr = Address::from_str("atest1v4ehgw36xeprxvjpgycnssf3xcenqvpjgyur2djx8pprzdj9x565gdjy8ycyxvf4x3qns3fney8mtj").expect("stuff");
// // Key to withdraw funds from the faucet
// let target_key = SecretKey::from_str("00c4ed3c491c56030cbb406f943b4f50261b4eda7b642fb9eb76323ef2b80feb8a").expect("Invalid secret key");
// let pub_key = PublicKey::from_str("00478117b44415df4546e533f56e6ab5f9f033de158417c5a4b23bae496e3eaa57").unwrap();

// let transfer_tx = args::TxInitAccount {
//     source: target_addr.clone(),
//     vp_code: std::fs::read(PathBuf::from("wasm/vp_user.bf4688574c26db2e2d55fa033a2d6a98f8c13c03dcaeaefbbb9bd59589187881.wasm")).unwrap(),
//     vp_code_path: "vp_user.wasm".to_string().into_bytes(),
//     tx_code_path: std::fs::read(PathBuf::from("wasm/tx_init_account.c867276c833b39cbe0da42ef09e84c4288c4a9e42f52446eaaa0cca5d3f16f89.wasm")).unwrap(),
//     public_key: pub_key,
//     tx: args::Tx {
//         dry_run: false,
//         dump_tx: false,
//         force: false,
//         broadcast_only: false,
//         ledger_address: (),
//         initialized_account_alias: Some("test".to_owned()),
//         wallet_alias_force: false,
//         fee_amount: 0.into(),
//         fee_token: native_token,
//         gas_limit: 0.into(),
//         expiration: None,
//         chain_id: Some(ChainId::from_str("namada-test.edab7c0b461096380f").unwrap()),
//         signing_key: Some(target_key),
//         signer: None,
//         tx_code_path: vec![],
//         password: None,
//     },
// };

// // Connect to an RPC
// let addr = TendermintAddress::from_str("127.0.0.1:27657")
//     .expect("Unable to connect to RPC");
// let client = HttpClient::new(addr).unwrap();
// let res = rpc::query_block(&client).await;
// println!("Results: {:?}", res);
// // Now actually make the shielding transfer
// let res = tx::submit_init_account::<HttpClient, SdkWalletUtils<PathBuf>>(
//     &client,
//     &mut wallet,
//     transfer_tx,
// ).await;
// println!("Results: {:?}", res);

// Ok(())

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
// }

// #[derive(Debug, BorshSerialize, BorshDeserialize, Clone)]
// pub struct FuzzerShieldedUtils {
//     #[borsh_skip]
//     context_dir: PathBuf,
// }

// impl FuzzerShieldedUtils {
//     /// Initialize a shielded transaction context that identifies notes
//     /// decryptable by any viewing key in the given set
//     pub fn new(context_dir: PathBuf) -> masp::ShieldedContext<Self> {
//         // Make sure that MASP parameters are downloaded to enable MASP
//         // transaction building and verification later on
//         let params_dir = masp::get_params_dir();
//         let spend_path = params_dir.join(masp::SPEND_NAME);
//         let convert_path = params_dir.join(masp::CONVERT_NAME);
//         let output_path = params_dir.join(masp::OUTPUT_NAME);
//         if !(spend_path.exists()
//             && convert_path.exists()
//             && output_path.exists())
//         {
//             println!("MASP parameters not present, downloading...");
//             masp_proofs::download_parameters()
//                 .expect("MASP parameters not present or downloadable");
//             println!("MASP parameter download complete, resuming execution...");
//         }
//         // Finally initialize a shielded context with the supplied directory
//         let utils = Self { context_dir };
//         masp::ShieldedContext {
//             utils,
//             ..Default::default()
//         }
//     }
// }

// impl Default for FuzzerShieldedUtils {
//     fn default() -> Self {
//         Self {
//             context_dir: PathBuf::from(FILE_NAME),
//         }
//     }
// }

// impl masp::ShieldedUtils for FuzzerShieldedUtils {
//     type C = tendermint_rpc::HttpClient;

//     fn local_tx_prover(&self) -> LocalTxProver {
//         if let Ok(params_dir) = env::var(masp::ENV_VAR_MASP_PARAMS_DIR) {
//             let params_dir = PathBuf::from(params_dir);
//             let spend_path = params_dir.join(masp::SPEND_NAME);
//             let convert_path = params_dir.join(masp::CONVERT_NAME);
//             let output_path = params_dir.join(masp::OUTPUT_NAME);
//             LocalTxProver::new(&spend_path, &output_path, &convert_path)
//         } else {
//             LocalTxProver::with_default_location()
//                 .expect("unable to load MASP Parameters")
//         }
//     }

//     /// Try to load the last saved shielded context from the given context
//     /// directory. If this fails, then leave the current context unchanged.
//     fn load(self) -> std::io::Result<masp::ShieldedContext<Self>> {
//         // Try to load shielded context from file
//         let mut ctx_file = File::open(self.context_dir.join(FILE_NAME))?;
//         let mut bytes = Vec::new();
//         ctx_file.read_to_end(&mut bytes)?;
//         let mut new_ctx = masp::ShieldedContext::deserialize(&mut &bytes[..])?;
//         // Associate the originating context directory with the
//         // shielded context under construction
//         new_ctx.utils = self;
//         Ok(new_ctx)
//     }

//     /// Save this shielded context into its associated context directory
//     fn save(&self, ctx: &masp::ShieldedContext<Self>) -> std::io::Result<()> {
//         // TODO: use mktemp crate?
//         let tmp_path = self.context_dir.join(TMP_FILE_NAME);
//         {
//             // First serialize the shielded context into a temporary file.
//             // Inability to create this file implies a simultaneuous write is in
//             // progress. In this case, immediately fail. This is unproblematic
//             // because the data intended to be stored can always be re-fetched
//             // from the blockchain.
//             let mut ctx_file = OpenOptions::new()
//                 .write(true)
//                 .create_new(true)
//                 .open(tmp_path.clone())?;
//             let mut bytes = Vec::new();
//             ctx.serialize(&mut bytes)
//                 .expect("cannot serialize shielded context");
//             ctx_file.write_all(&bytes[..])?;
//         }
//         // Atomically update the old shielded context file with new data.
//         // Atomicity is required to prevent other client instances from reading
//         // corrupt data.
//         std::fs::rename(tmp_path.clone(), self.context_dir.join(FILE_NAME))?;
//         // Finally, remove our temporary file to allow future saving of shielded
//         // contexts.
//         std::fs::remove_file(tmp_path)?;
//         Ok(())
//     }
// }
