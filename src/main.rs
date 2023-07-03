use async_std::fs;
use std::error::Error;
use std::fs::File;
use std::fs::OpenOptions;
use std::future::Future as StdFuture;
use std::io::Write;
use std::io::{Chain, Read};
use std::marker::PhantomData;
use std::path::Path;
use std::path::PathBuf;
use std::pin::Pin;
use std::str::FromStr;
use std::{env, thread, time, vec};

use async_trait::async_trait;
use borsh::BorshDeserialize;
use borsh::BorshSerialize;
use masp_primitives::memo::Memo::Future;
use masp_proofs::prover::LocalTxProver;
use rand::Rng;
use rand_core::{OsRng, RngCore};
use tendermint_config::net::Address as TendermintAddress;
use tendermint_rpc::HttpClient;
use zeroize::Zeroizing;

use futures::future::join_all;
use namada::bip39::{Mnemonic, Seed};
use namada::ledger::args;
use namada::ledger::args::TxTransfer;
use namada::ledger::masp::ShieldedContext;
use namada::ledger::wallet::alias::Alias;
use namada::ledger::wallet::derivation_path::DerivationPath;
use namada::ledger::wallet::Store;
use namada::ledger::wallet::Wallet;
use namada::ledger::wallet::{store, GenRestoreKeyError, WalletUtils};
use namada::ledger::{masp, rpc, tx};
use namada::types::address::Address;
use namada::types::chain::ChainId;
use namada::types::key::common::{PublicKey, SecretKey};
use namada::types::key::{common, SchemeType};
use namada::types::masp::PaymentAddress;
use namada::types::masp::TransferSource;
use namada::types::masp::TransferTarget;
use namada::types::token::Amount;
use tokio::join;

/// Shielded context file name
const FILE_NAME: &str = "shielded.dat";
const TMP_FILE_NAME: &str = "shielded.tmp";

const MNEMONIC_CODE: &str = "cruise ball fame lucky fabric govern \
                            length fruit permit tonight fame pear \
                            horse park key chimney furnace lobster \
                            foot example shoot dry fuel lawn";

const CHAIN_ID: &str = "public-testnet-10.3718993c3648";
const NATIVE_TOKEN: &str =
    "atest1v4ehgw36x3prswzxggunzv6pxqmnvdj9xvcyzvpsggeyvs3cg9qnywf589qnwvfsg5erg3fkl09rg5";
const FAUCET: &str =
    "atest1v4ehgw36gc6yxvpjxccyzvphxycrxw2xxsuyydesxgcnjs3cg9znwv3cxgmnj32yxy6rssf5tcqjm3";

/*

- generate X number of wallets
    - store them in the wallet.toml
    - load or generate them
- keep track of the balance for each wallet in memory
- if balance < 100 NAM request funds from the faucet
- send random amount to random address
    - source address is randomly picked from the array of accounts
    - randomly generate the amount
    - randomly pick from the array of accounts

- Actions
    - request funds from the faucet
    - send funds to another address

 */

fn gen_or_load_wallet(path: PathBuf) -> Wallet<SdkWalletUtils> {
    let store = wallet::load_or_new(&path).unwrap();
    let wallet: Wallet<SdkWalletUtils> = Wallet::new(path.clone(), store);
    wallet
}

#[derive(Clone)]
struct Account {
    key_alias: String,
    public_key: common::PublicKey,
    private_key: common::SecretKey,
    balance: Amount,
    revealed: bool,
}

// initialize each account with it's state; includes
// - it's public and private key
// - it's NAM balance
// - check if it's PK has been revealed and if not, reveal it, otherwise reveal them
// - returns a list of futures with potential revelations that need to be run first and update the account structure - this should only happen on the very first run
fn gen_accounts(wallet: &mut Wallet<SdkWalletUtils>, size: usize) -> Vec<Account> {
    let mnemonic = Mnemonic::from_phrase(MNEMONIC_CODE, namada::bip39::Language::English).unwrap();
    let seed = Seed::new(&mnemonic, "");
    let mut accounts: Vec<Account> = vec![];

    for i in 0..size {
        let derivation_path = format!("m/44'/877'/0'/0'/{}'", i);
        let alias = format!("default_{}", i);
        let (key_alias, sk) = wallet
            .gen_and_store_key(
                SchemeType::Ed25519,
                Some(alias),
                false,
                Some((
                    seed.clone(),
                    DerivationPath::from_path_str(SchemeType::Ed25519, &derivation_path).unwrap(),
                )),
                None,
            )
            .unwrap();
        let account = Account {
            key_alias: key_alias,
            public_key: sk.to_public(),
            private_key: sk,
            balance: Amount::from(0),
            revealed: false,
        };
        accounts.push(account);
    }
    wallet::save(wallet.store(), wallet.store_dir()).unwrap();
    accounts
}

async fn update_token_balances(client: &HttpClient, accounts: &mut Vec<Account>) {
    for account in accounts {
        let amount = rpc::get_token_balance(
            client,
            &Address::from_str(NATIVE_TOKEN).unwrap(),
            &Address::from(&account.public_key),
        )
        .await;
        if amount.is_none() {
            account.balance = Amount::from(0);
        } else {
            account.balance = amount.unwrap();
        }
    }
}

/*
   - check if need to reveal and if not, then don't reveal
*/
async fn reveal_pks(
    client: &HttpClient,
    accounts: &mut Vec<Account>,
    wallet: &mut Wallet<SdkWalletUtils>,
) {
    let native_token = Address::from_str(NATIVE_TOKEN).unwrap();
    let chain_id = ChainId::from_str(CHAIN_ID).unwrap();

    for mut account in accounts {
        let reveal_tx = args::RevealPk {
            tx: args::Tx {
                dry_run: false,
                dump_tx: false,
                force: false,
                broadcast_only: false,
                ledger_address: (),
                initialized_account_alias: None,
                wallet_alias_force: false,
                fee_amount: 0.into(),
                fee_token: native_token.clone(),
                gas_limit: 0.into(),
                expiration: None,
                chain_id: Some(chain_id.clone()),
                signing_key: Some(account.private_key.clone()),
                signer: None,
                tx_reveal_code_path: PathBuf::from("tx_reveal_pk.wasm"),
                password: None,
            },
            public_key: account.public_key.clone(),
        };
        let res = tx::submit_reveal_pk(client, wallet, reveal_tx).await;
        if res.is_ok() {
            account.revealed = true;
        }
    }
}

// impl StdFuture<Output = std::result::Result<(), namada::ledger::tx::Error>>
fn get_funds_from_faucet<'a>(
    client: &'a HttpClient,
    account: &'a Account,
) -> impl StdFuture<Output = std::result::Result<(), namada::ledger::tx::Error>> + 'a {
    let faucet = Address::from_str(FAUCET).unwrap();
    let native_token = Address::from_str(NATIVE_TOKEN).unwrap();
    let chain_id = ChainId::from_str(CHAIN_ID).unwrap();

    let wallet = gen_or_load_wallet(PathBuf::from("wallet.toml"));
    let shielded_ctx = SdkShieldedUtils::new(Path::new("masp/").to_path_buf());

    let amount = Amount::from(1_000_000_000);

    let transfer_tx = args::TxTransfer {
        tx: args::Tx {
            dry_run: false,
            dump_tx: false,
            force: false,
            broadcast_only: false,
            ledger_address: (),
            initialized_account_alias: None,
            wallet_alias_force: false,
            fee_amount: 0.into(),
            fee_token: native_token.clone(),
            gas_limit: 0.into(),
            expiration: None,
            chain_id: Some(chain_id.clone()),
            signing_key: Some(account.private_key.clone()),
            signer: None,
            tx_reveal_code_path: PathBuf::from("tx_reveal_pk.wasm"),
            password: None,
        },
        source: TransferSource::Address(faucet.clone()),
        target: TransferTarget::Address(Address::from(&account.public_key)),
        token: native_token.clone(),
        sub_prefix: None,
        amount: amount,
        native_token: native_token.clone(),
        tx_code_path: PathBuf::from("tx_transfer.wasm"),
    };

    tx::submit_transfer(client, wallet, shielded_ctx, transfer_tx)
}

fn gen_transfer<'a>(
    client: &'a HttpClient,
    source: &'a Account,
    destination: &'a Account,
    amount: Amount,
) -> impl StdFuture<Output = std::result::Result<(), namada::ledger::tx::Error>> + 'a {
    let native_token = Address::from_str(NATIVE_TOKEN).unwrap();
    let chain_id = ChainId::from_str(CHAIN_ID).unwrap();

    let wallet = gen_or_load_wallet(PathBuf::from("wallet.toml"));
    let shielded_ctx = SdkShieldedUtils::new(Path::new("masp/").to_path_buf());

    let transfer_tx = args::TxTransfer {
        tx: args::Tx {
            dry_run: false,
            dump_tx: false,
            force: false,
            broadcast_only: false,
            ledger_address: (),
            initialized_account_alias: None,
            wallet_alias_force: false,
            fee_amount: 500_000.into(),
            fee_token: native_token.clone(),
            gas_limit: 1.into(),
            expiration: None,
            chain_id: Some(chain_id.clone()),
            signing_key: Some(source.private_key.clone()),
            signer: None,
            tx_reveal_code_path: PathBuf::from("tx_reveal_pk.wasm"),
            password: None,
        },
        source: TransferSource::Address(Address::from(&source.public_key)),
        target: TransferTarget::Address(Address::from(&destination.public_key)),
        token: native_token.clone(),
        sub_prefix: None,
        amount: amount,
        native_token: native_token.clone(),
        tx_code_path: PathBuf::from("tx_transfer.wasm"),
    };

    tx::submit_transfer(client, wallet, shielded_ctx, transfer_tx)
}

async fn gen_actions(client: &HttpClient, accounts: &Vec<Account>, repeats: usize) {
    let mut rand_gen = rand::thread_rng();

    let mut txs = vec![];

    for i in 0..repeats {
        let rand_one = rand_gen.gen_range(0..accounts.len());
        let rand_two = rand_gen.gen_range(0..accounts.len());

        if accounts[rand_one].balance < Amount::from(1_000_000) {
            txs.push(Box::pin(get_funds_from_faucet(client, &accounts[rand_one])) as Pin<Box<dyn StdFuture<Output = std::result::Result<(), namada::ledger::tx::Error>>>>);
            continue;
        }

        let amount = Amount::from(rand_gen.gen_range(0..accounts[rand_one].balance.micro));
        txs.push(Box::pin(gen_transfer(client, &accounts[rand_one], &accounts[rand_two], amount)));
    }

    let outputs = futures::future::join_all(txs).await;

    for o in outputs {
        println!("Tx Result: {:?}", o);
    }
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let tendermint_addr =
        TendermintAddress::from_str("127.0.0.1:26757").expect("Unable to connect to RPC");
    let http_client = HttpClient::new(tendermint_addr).unwrap();

    fs::remove_file("wallet.toml").await;
    let mut shielded_ctx = SdkShieldedUtils::new(Path::new("masp/").to_path_buf());
    let mut wallet = gen_or_load_wallet(PathBuf::from("wallet.toml"));
    let mut accounts = gen_accounts(&mut wallet, 100);
    update_token_balances(&http_client, &mut accounts).await;
    for account in &accounts {
        println!(
            "Address: {:?} - Balance: {:?} - Revealed: {:?}",
            Address::from(&account.public_key),
            account.balance,
            account.revealed
        );
    }
    reveal_pks(&http_client, &mut accounts, &mut wallet).await;
    let initial_accounts = accounts.clone();

    let mut counter = 0;

    loop {
        println!("+++++ Starting the loop +++++");
        update_token_balances(&http_client, &mut accounts).await;
        let initial_accounts = accounts.clone();
        for account in &initial_accounts {
            println!("Address: {:?} - Balance: {:?} - Revealed: {:?}", Address::from(&account.public_key), account.balance, account.revealed);
        }

        gen_actions(&http_client, &accounts, 15).await;

        let sleep = time::Duration::from_secs(1);
        println!("Sleeping");
        thread::sleep(sleep);

        update_token_balances(&http_client, &mut accounts).await;
        for i in 0..accounts.len() {
            println!("Address: {:?} - Old Balance: {:?} - New Balance: {:?} - Difference: {:?}", Address::from(&accounts[i].public_key), initial_accounts[i].balance, accounts[i].balance, initial_accounts[i].balance.checked_sub(accounts[i].balance));
        }

        let sleep = time::Duration::from_secs(15);
        println!("Sleeping");
        thread::sleep(sleep);

        counter += 1;

        println!("Counter: {:?}", counter);
        // if counter == 3 {
        //     break
        // }
    }

    /*
       - create a configurable number of accounts
       - send a configurable number of transactions between these accounts without PoW challenge
       - after each set of transactions, update the balance on the account structure
    */

    // println!("alive");
    // fs::remove_file("wallet.toml").await;
    // println!("alive");
    //
    // println!("alive");
    //
    // loop {

    //     println!("alive");
    //     let accounts = gen_accounts(&mut wallet, 10);
    //     println!("alive");
    //     let actions = gen_actions(accounts, 25);
    //     println!("alive");
    //     // let futures: Vec<_> = actions.into_iter().map(|action| {
    //     //     tx::submit_transfer(&http_client, &mut wallet, &mut shielded_ctx, action)
    //     // }).collect();
    //
    //     let mut futures = vec![];
    //     for a in actions {
    //         let wallet = gen_or_load_wallet(PathBuf::from("wallet.toml"));
    //         let shielded_ctx = SdkShieldedUtils::new(Path::new("masp/").to_path_buf());
    //         let tx = tx::submit_transfer(&http_client, wallet, shielded_ctx, a);
    //         futures.push(tx);
    //     }
    //     println!("alive");
    //
    //     let outputs = join_all(futures).await;
    //
    //     for o in outputs {
    //         println!("Tx Result: {:?}", o);
    //     }
    //
    //     // break;
    //     let sleep = time::Duration::from_secs(15);
    //     println!("Sleeping");
    //     thread::sleep(sleep);
    //
    //     fs::remove_file("wallet.toml").await;
    //     println!("Next Iteration");
    // }

    // let key_alias_0 = "default0".to_owned();
    // let key_alias_1 = "default1".to_owned();
    // let key_alias_2 = "default2".to_owned();
    //
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
    //
    // let native_token = Address::from_str(
    //     "atest1v4ehgw36x3prswzxggunzv6pxqmnvdj9xvcyzvpsggeyvs3cg9qnywf589qnwvfsg5erg3fkl09rg5",
    // )
    // .expect("Unable to construct native token");
    // let faucet = Address::from_str(
    //     "atest1v4ehgw36gc6yxvpjxccyzvphxycrxw2xxsuyydesxgcnjs3cg9znwv3cxgmnj32yxy6rssf5tcqjm3",
    // )
    // .expect("Should work");
    // let chain_id = ChainId::from_str("public-testnet-10.3718993c3648").unwrap();
    //
    // let tendermint_addr =
    //     TendermintAddress::from_str("127.0.0.1:26757").expect("Unable to connect to RPC");
    // let http_client = HttpClient::new(tendermint_addr).unwrap();
    // let block_res = rpc::query_block(&http_client).await;
    // println!("Query Block: {:?}", block_res);
    //
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
    //
    // let init_acc_res = tx::submit_init_account(&http_client, &mut wallet, init_tx).await;
    // println!("Tx Result: {:?}", init_acc_res);
    //
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
    //
    // let transfer_tx_res = tx::submit_transfer(&http_client, &mut wallet, &mut shielded_ctx, transfer_tx).await;
    // println!("Tx Result: {:?}", transfer_tx_res);
    //
    // let balance_res = rpc::get_token_balance(
    //     &http_client,
    //     &native_token,
    //     wallet.find_address(&key_alias_1).unwrap(),
    // )
    //     .await;
    // println!("Balance {:?}", balance_res);

    Ok(())
}

mod wallet {
    use std::io::prelude::*;
    use std::{fs, path::PathBuf};

    use file_lock::{FileLock, FileOptions};
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

    /// Save the wallet store to a file.
    pub fn save(store: &Store, store_dir: &PathBuf) -> std::io::Result<()> {
        let data = store.encode();
        // let wallet_path = wallet_file(store_dir);
        // Make sure the dir exists
        let wallet_dir = store_dir.parent().unwrap();
        fs::create_dir_all(wallet_dir)?;
        // Write the file
        let options = FileOptions::new().create(true).write(true).truncate(true);
        let mut filelock = FileLock::lock(store_dir, true, options)?;
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
        match FileLock::lock(store_dir, true, FileOptions::new().read(true).write(false)) {
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
