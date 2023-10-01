use async_std::fs;
use std::path::Path;
use std::path::PathBuf;
use std::str::FromStr;
use std::{thread, time, vec};
use std::future::Future;
use futures::future::join_all;
use std::pin::Pin;

use rand::Rng;
use tendermint_config::net::Address as TendermintAddress;
use tendermint_rpc::HttpClient;
use zeroize::Zeroizing;

use namada::bip39::Mnemonic;
use namada::ledger::wallet::fs::FsWalletUtils;
use namada::ledger::rpc;
use namada::ledger::masp::fs::FsShieldedUtils;
use namada::types::address::Address;
use namada::types::chain::ChainId;
use namada::types::key::{common, SchemeType};
use namada::types::masp::TransferSource;
use namada::types::masp::TransferTarget;
use namada::types::token::Amount;
use namada::ledger::NamadaImpl;
use namada::ledger::Namada;
use namada::ledger::args::TxBuilder;
use namada::ledger::tx::ProcessTxResponse;
use namada::ledger::args::InputAmount;
use namada::types::uint::Uint;
use namada::ledger::rpc::denominate_amount;

const MNEMONIC_CODE: &str = "cruise ball fame lucky fabric govern \
                            length fruit permit tonight fame pear \
                            horse park key chimney furnace lobster \
                            foot example shoot dry fuel lawn";

const CHAIN_ID: &str = "public-testnet-10.3718993c3648";
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
async fn gen_accounts<'a>(namada: &mut impl Namada<'a>, size: usize) -> Vec<Account> {
    let mut accounts: Vec<Account> = vec![];
    let mnemonic = Mnemonic::from_phrase(MNEMONIC_CODE, namada::bip39::Language::English)
        .expect("unable to construct mnemonic");

    for i in 0..size {
        let derivation_path = format!("m/44'/877'/0'/0'/{}'", i);
        let alias = format!("default_{}", i);
        let (key_alias, sk) = namada
            .wallet_mut()
            .await
            .derive_key_from_user_mnemonic_code(
                SchemeType::Ed25519,
                Some(alias),
                false,
                Some(derivation_path),
                Some((mnemonic.clone(), Zeroizing::new("".to_owned()))),
                None,
            )
            .expect("unable to derive key from mnemonic code")
            .unwrap();
        let account = Account {
            key_alias,
            public_key: sk.to_public(),
            private_key: sk,
            balance: Amount::from(0),
            revealed: false,
        };
        accounts.push(account);
    }
    namada.wallet().await.save().expect("unable to save wallet");
    accounts
}

async fn update_token_balances<'a>(
    namada: &impl Namada<'a>,
    accounts: &mut Vec<Account>,
) {
    for account in accounts {
        account.balance = rpc::get_token_balance(
            namada.client(),
            &namada.native_token().await,
            &Address::from(&account.public_key),
        )
        .await.expect("unable to query account balance");
    }
}

/*
   - check if need to reveal and if not, then don't reveal
*/
async fn reveal_pks<'a>(
    namada: &mut impl Namada<'a>,
    accounts: &mut Vec<Account>,
) {
    for mut account in accounts {
        let reveal_tx_builder = namada
            .new_reveal_pk(account.public_key.clone())
            .await
            .signing_keys(vec![account.private_key.clone()]);
        let (mut reveal_tx, signing_data, _) = reveal_tx_builder
            .build(namada)
            .await
            .expect("unable to build reveal pk tx");
        namada.sign(&mut reveal_tx, &reveal_tx_builder.tx, signing_data)
            .await
            .expect("unable to sign reveal pk tx");
        let res = namada.submit(reveal_tx, &reveal_tx_builder.tx).await;
        account.revealed |= res.is_ok();
    }
}

async fn get_funds_from_faucet<'a>(
    namada: &impl Namada<'a>,
    account: &Account,
) -> std::result::Result<ProcessTxResponse, namada::types::error::Error> {
    let faucet = Address::from_str(FAUCET).unwrap();
    let native_token = namada.native_token().await;

    let mut transfer_tx_builder = namada.new_transfer(
        TransferSource::Address(faucet.clone()),
        TransferTarget::Address(Address::from(&account.public_key)),
        native_token,
        InputAmount::from_str("1000").unwrap(),
    )
        .await
        .signing_keys(vec![account.private_key.clone()]);
    let (mut transfer_tx, signing_data, _epoch) = transfer_tx_builder
        .build(namada)
        .await
        .expect("unable to build transfer");
    namada.sign(&mut transfer_tx, &transfer_tx_builder.tx, signing_data)
        .await
        .expect("unable to sign reveal pk tx");
    namada.submit(transfer_tx, &transfer_tx_builder.tx).await
}

async fn gen_transfer<'a>(
    namada: &impl Namada<'a>,
    source: &Account,
    destination: &Account,
    amount: InputAmount,
) -> std::result::Result<ProcessTxResponse, namada::types::error::Error> {
    let native_token = namada.native_token().await;
    
    let mut transfer_tx_builder = namada.new_transfer(
        TransferSource::Address(Address::from(&source.public_key)),
        TransferTarget::Address(Address::from(&destination.public_key)),
        native_token,
        amount,
    )
        .await
        .signing_keys(vec![source.private_key.clone()])
        .fee_amount(InputAmount::from_str("0.5").unwrap())
        .gas_limit(1.into());
    let (mut transfer_tx, signing_data, _epoch) = transfer_tx_builder
        .build(namada)
        .await
        .expect("unable to build transfer");
    namada.sign(&mut transfer_tx, &transfer_tx_builder.tx, signing_data)
        .await
        .expect("unable to sign reveal pk tx");
    namada.submit(transfer_tx, &transfer_tx_builder.tx).await
}

async fn gen_actions<'a>(
    namada: &impl Namada<'a>,
    accounts: &Vec<Account>,
    repeats: usize,
) {
    let mut rand_gen = rand::thread_rng();

    let mut txs: Vec<Pin<Box<dyn Future<Output = _>>>> = vec![];

    for _ in 0..repeats {
        let rand_one = rand_gen.gen_range(0..accounts.len());
        let rand_two = rand_gen.gen_range(0..accounts.len());

        if accounts[rand_one].balance < Amount::from(1_000_000) {
            txs.push(Box::pin(get_funds_from_faucet(namada, &accounts[rand_one])));
        } else {
            let balance = u128::try_from(accounts[rand_one].balance).unwrap();
            let native_token = namada.native_token().await;
            let amount = denominate_amount(
                namada.client(),
                &native_token,
                Amount::from_uint(Uint::from(rand_gen.gen_range(0..balance)),0).unwrap(),
            ).await.into();
            txs.push(Box::pin(gen_transfer(namada, &accounts[rand_one], &accounts[rand_two], amount)));
        }
    }

    for o in join_all(txs).await {
        println!("Tx Result: {:?}", o);
    }
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let tendermint_addr =
        TendermintAddress::from_str("127.0.0.1:26757").expect("Unable to connect to RPC");
    let http_client = HttpClient::new(tendermint_addr).unwrap();

    let _ = fs::remove_file("wallet.toml").await;
    let mut shielded_ctx = FsShieldedUtils::new(Path::new("masp/").to_path_buf());
    let mut wallet = FsWalletUtils::new(PathBuf::from("wallet.toml"));
    let mut namada = NamadaImpl::new(&http_client, &mut wallet, &mut shielded_ctx)
        .chain_id(ChainId::from_str(CHAIN_ID).unwrap());
    let mut accounts = gen_accounts(&mut namada, 100).await;
    update_token_balances(&namada, &mut accounts).await;
    for account in &accounts {
        println!(
            "Address: {:?} - Balance: {:?} - Revealed: {:?}",
            Address::from(&account.public_key),
            account.balance,
            account.revealed
        );
    }
    reveal_pks(&mut namada, &mut accounts).await;

    let mut counter = 0;

    loop {
        println!("+++++ Starting the loop +++++");
        update_token_balances(&mut namada, &mut accounts).await;
        let initial_accounts = accounts.clone();
        for account in &initial_accounts {
            println!("Address: {:?} - Balance: {:?} - Revealed: {:?}", Address::from(&account.public_key), account.balance, account.revealed);
        }

        gen_actions(&mut namada, &accounts, 15).await;

        let sleep = time::Duration::from_secs(1);
        println!("Sleeping");
        thread::sleep(sleep);

        update_token_balances(&mut namada, &mut accounts).await;
        for i in 0..accounts.len() {
            println!("Address: {:?} - Old Balance: {:?} - New Balance: {:?} - Difference: {:?}", Address::from(&accounts[i].public_key), initial_accounts[i].balance, accounts[i].balance, initial_accounts[i].balance.checked_sub(accounts[i].balance));
        }

        let sleep = time::Duration::from_secs(15);
        println!("Sleeping");
        thread::sleep(sleep);

        counter += 1;

        println!("Counter: {:?}", counter);
    }
}
