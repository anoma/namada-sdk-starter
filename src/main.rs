use async_std::fs;
use futures::future::join_all;
use namada_sdk::key::RefTo;
use std::future::Future;
use std::path::Path;
use std::path::PathBuf;
use std::pin::Pin;
use std::str::FromStr;
use std::{thread, time, vec};

use rand::Rng;
use tendermint_config::net::Address as TendermintAddress;
use tendermint_rpc::HttpClient;

use namada_sdk::args::InputAmount;
use namada_sdk::args::TxBuilder;
use namada_sdk::bip39::Mnemonic;
use namada_sdk::address::Address;
use namada_sdk::chain::ChainId;
use namada_sdk::key::common::SecretKey;
use namada_sdk::key::{common, SchemeType};
use namada_sdk::masp::TransferSource;
use namada_sdk::masp::TransferTarget;
use namada_sdk::token::Amount;
use namada_sdk::uint::Uint;
use namada_sdk::io::NullIo;
use namada_sdk::masp::fs::FsShieldedUtils;
use namada_sdk::rpc;
use namada_sdk::signing::default_sign;
use namada_sdk::tx::ProcessTxResponse;
use namada_sdk::wallet::DerivationPath;
use namada_sdk::wallet::fs::FsWalletUtils;
use namada_sdk::Namada;
use namada_sdk::NamadaImpl;
use namada_sdk::zeroize::Zeroizing;

use namada_sdk::proof_of_stake;

const MNEMONIC_CODE: &str = "cruise ball fame lucky fabric govern \
                            length fruit permit tonight fame pear \
                            horse park key chimney furnace lobster \
                            foot example shoot dry fuel lawn";

const CHAIN_ID: &str = "e2e-test.a4f327974f92303b6b2cc";
const FAUCET: &str =
    "atest1v4ehgw36xq6ngs3ng5crvdpngg6yvsecx4znjdfegyurgwzzx4pyywfexuuyys69gc6rzdfnryrntx";
const FAUCET_KEY: &str = "00447ffcd1ffd641e7fcf09f8991ec398081dcc1f14af46e78d406fae3c6223ac0";
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

#[derive(Clone)]
struct Account {
    pub public_key: common::PublicKey,
    pub private_key: common::SecretKey,
    pub balance: Amount,
    pub revealed: bool,
}


// Generate the given number of accounts and load each up with a preset number
// of native tokens from the faucet
async fn gen_accounts(namada: &mut impl Namada, size: usize) -> Vec<Account> {
    let signing_key = SecretKey::from_str(FAUCET_KEY).unwrap();
    let mut accounts: Vec<Account> = vec![];
    let mnemonic = Mnemonic::from_phrase(MNEMONIC_CODE, namada_sdk::bip39::Language::English)
        .expect("unable to construct mnemonic");
    let mut txs: Vec<Pin<Box<dyn Future<Output = _>>>> = vec![];

    // Create the given number of accounts
    for i in 0..size {
        let derivation_path = DerivationPath::from_str(&format!("m/44'/877'/0'/0'/{}'", i))
            .expect("unable to parse derivation path");
        let alias = format!("default_{}", i);
        let (_key_alias, sk) = namada
            .wallet_mut()
            .await
            .derive_store_key_from_mnemonic_code(
                SchemeType::Ed25519,
                Some(alias),
                false,
                derivation_path,
                Some((mnemonic.clone(), Zeroizing::new("".to_owned()))),
                false,
                None,
            )
            .expect("unable to derive key from mnemonic code");
        let account = Account {
            public_key: sk.to_public(),
            private_key: sk,
            balance: Amount::from(0),
            revealed: false,
        };
        accounts.push(account);
    }
    // Preload them with a preset number of tokens
    for account in &accounts {
        txs.push(Box::pin(get_funds_from_faucet(namada, account)));
    }

    // Wait for all the accounts to finish being loaded and display results
    for output in join_all(txs).await {
        println!("Tx Result: {:?}", output);
    }
    // Save the new accounts in the wallet
    namada.wallet().await.save().expect("unable to save wallet");
    accounts
}

// Query the current account balances from the network
async fn update_token_balances(namada: &impl Namada, accounts: &mut Vec<Account>) {
    for account in accounts {
        account.balance = rpc::get_token_balance(
            namada.client(),
            &namada.native_token(),
            &Address::from(&account.public_key),
        )
        .await
        .expect("unable to query account balance");
    }
}


// Submit transactions to reveal the public key of each account
async fn reveal_pks(namada: &mut impl Namada, accounts: &mut [Account]) {
    let mut reveal_builders = Vec::new();
    let mut txs: Vec<Pin<Box<dyn Future<Output = _>>>> = vec![];
    // Construct and sign all the reveal PK transactions
    for account in accounts.iter() {
        let reveal_tx_builder = namada
            .new_reveal_pk(account.public_key.clone())
            .signing_keys(vec![account.public_key.clone()]);
        let (mut reveal_tx, signing_data) = reveal_tx_builder
            .build(namada)
            .await
            .expect("unable to build reveal pk tx");
        namada
            .sign(&mut reveal_tx, &reveal_tx_builder.tx, signing_data, default_sign, ())
            .await
            .expect("unable to sign reveal pk tx");
        reveal_builders.push((reveal_tx, reveal_tx_builder.tx));
    }
    // Submit all of the reveal PK transactions
    for (reveal_tx, reveal_tx_builder) in reveal_builders.iter() {
        txs.push(namada.submit(reveal_tx.clone(), reveal_tx_builder));
    }
    // Wait for all the public keys to be revealed and display results
    for (account, res) in accounts.iter_mut().zip(join_all(txs).await.iter()) {
        account.revealed |= res.is_ok();
        println!("Tx Result: {:?}", res);
    }
}

// Load a preset amount of tokens from the faucet into the given account
async fn get_funds_from_faucet(
    namada: &impl Namada,
    account: &Account,
) -> std::result::Result<ProcessTxResponse, namada_sdk::error::Error> {
    let faucet_sk = common::SecretKey::from_str(FAUCET_KEY).unwrap();
    let faucet_pk = faucet_sk.to_public();
    let faucet = Address::from_str(FAUCET).unwrap();

    let mut transfer_tx_builder = namada
        .new_transfer(
            TransferSource::Address(faucet.clone()),
            TransferTarget::Address(Address::from(&account.public_key)),
            namada.native_token(),
            InputAmount::from_str("1000").unwrap(),
        )
        .signing_keys(vec![faucet_pk]);
    let (mut transfer_tx, signing_data, _epoch) = transfer_tx_builder
        .build(namada)
        .await
        .expect("unable to build transfer");
    namada
        .sign(&mut transfer_tx, &transfer_tx_builder.tx, signing_data, default_sign, ())
        .await
        .expect("unable to sign reveal pk tx");
    namada.submit(transfer_tx, &transfer_tx_builder.tx).await
}

// Transfer the given amount of native tokens from the source account to the
// destination account.
async fn gen_transfer(
    namada: &impl Namada,
    source: &Account,
    destination: &Account,
    amount: InputAmount,
) -> std::result::Result<ProcessTxResponse, namada_sdk::error::Error> {
    let mut transfer_tx_builder = namada
        .new_transfer(
            TransferSource::Address(Address::from(&source.public_key)),
            TransferTarget::Address(Address::from(&destination.public_key)),
            namada.native_token(),
            amount,
        )
        .signing_keys(vec![source.public_key.clone()]);
    let (mut transfer_tx, signing_data, _epoch) = transfer_tx_builder
        .build(namada)
        .await
        .expect("unable to build transfer");
    namada
        .sign(&mut transfer_tx, &transfer_tx_builder.tx, signing_data, default_sign, ())
        .await
        .expect("unable to sign reveal pk tx");
    namada.submit(transfer_tx, &transfer_tx_builder.tx).await
}

// Rnadomly select pairs of accounts and transfer a random amount of native
// tokens from the first to the second in those cases where the source balance
// exceeds 1 NAM. Otherwise reload a preset amount of native tokens into the
// source account from the faucet.
async fn gen_actions(namada: &impl Namada, accounts: &Vec<Account>, repeats: usize) {
    let mut rand_gen = rand::thread_rng();

    let mut txs: Vec<Pin<Box<dyn Future<Output = _>>>> = vec![];

    for _ in 0..repeats {
        let rand_one = rand_gen.gen_range(0..accounts.len());
        let rand_two = rand_gen.gen_range(0..accounts.len());

        if accounts[rand_one].balance < Amount::from(1_000_000) {
            // Initiate a fund reload from the faucet
            txs.push(Box::pin(get_funds_from_faucet(namada, &accounts[rand_one])));
        } else {
            // Generate a random amount that is less than the source balance
            let balance = u128::try_from(accounts[rand_one].balance).unwrap();
            let amount = namada.denominate_amount(
                &namada.native_token(),
                Amount::from_uint(Uint::from(rand_gen.gen_range(0..balance)), 0).unwrap(),
            )
            .await
            .into();
            // Initiate the transfer from the source to the destination
            txs.push(Box::pin(gen_transfer(
                namada,
                &accounts[rand_one],
                &accounts[rand_two],
                amount,
            )));
        }
    }

    // Wait until all the transactions have completed
    for output in join_all(txs).await {
        println!("Tx Result: {:?}", output);
    }
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    // Setup client
    let tendermint_addr =
        TendermintAddress::from_str("127.0.0.1:27657").expect("Unable to connect to RPC");
    let http_client = HttpClient::new(tendermint_addr).unwrap();
    let _ = fs::remove_file("wallet.toml").await;
    // Setup wallet storage
    let wallet: namada_sdk::wallet::Wallet<FsWalletUtils> = FsWalletUtils::new(PathBuf::from("wallet.toml"));
    // Setup shielded context storage
    let shielded_ctx = FsShieldedUtils::new(Path::new("masp/").to_path_buf());
    // Setup the Namada context
    let mut namada = NamadaImpl::new(http_client, wallet, shielded_ctx, NullIo)
        .await
        .expect("unable to construct Namada object")
        .chain_id(ChainId::from_str(CHAIN_ID).unwrap());
    // Note the native token address
    let nam = namada.native_token();
    // Generate 500 accounts
    let mut accounts = gen_accounts(&mut namada, 500).await;
    // Record their balances and display
    update_token_balances(&namada, &mut accounts).await;
    for account in &accounts {
        println!(
            "Address: {:?} - Balance: {} - Revealed: {:?}",
            Address::from(&account.public_key),
            namada.format_amount(&nam, account.balance).await,
            account.revealed
        );
    }
    // Reveal all the account public keys
    reveal_pks(&mut namada, &mut accounts).await;

    for counter in 0.. {
        println!("+++++ Starting loop {} +++++", counter);
        // Record and display all the account balances
        update_token_balances(&namada, &mut accounts).await;
        let initial_accounts = accounts.clone();
        for account in &initial_accounts {
            println!(
                "Address: {:?} - Balance: {} - Revealed: {:?}",
                Address::from(&account.public_key),
                namada.format_amount(&nam, account.balance).await,
                account.revealed,
            );
        }

        // Execute some random actions involving the accounts
        gen_actions(&namada, &accounts, 15).await;

        let sleep = time::Duration::from_secs(1);
        println!("Sleeping");
        thread::sleep(sleep);

        // Record and display all the account balance changes
        update_token_balances(&namada, &mut accounts).await;
        for i in 0..accounts.len() {
            let (sign, diff) = if initial_accounts[i].balance > accounts[i].balance {
                ('-', initial_accounts[i].balance - accounts[i].balance)
            } else {
                ('+', accounts[i].balance - initial_accounts[i].balance)
            };
            println!(
                "Address: {:?} - Old Balance: {} - New Balance: {} - Difference: {}{}",
                Address::from(&accounts[i].public_key),
                namada.format_amount(&nam, initial_accounts[i].balance).await,
                namada.format_amount(&nam, accounts[i].balance).await,
                sign,
                namada.format_amount(&nam, diff).await,
            );
        }

        let sleep = time::Duration::from_secs(15);
        println!("Sleeping");
        thread::sleep(sleep);
    }
    Ok(())
}
