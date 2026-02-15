//! Prints three bs58-encoded transactions for testing the gobble CLI
//! against programs deployed on mainnet-beta.
//!
//! Run with:
//!   cargo run --example txn -p gobble-lib
//!
//! Then test each with:
//!   cargo run -p gobble -- <bs58_txn> -f 8-16
//!
//! Transactions:
//! 1. Router -> Gobble:        TRUE POSITIVE  (reads forbidden bytes 8-16 from sysvar)
//! 2. Router -> AMM:            TRUE NEGATIVE  (reads bytes 0-8 from CPI data, no sysvar)
//! 3. Router -> GobbleSolana:   FALSE POSITIVE (load_instruction_at_checked deserializes all)

use {
    solana_instruction::{AccountMeta, Instruction},
    solana_message::Message,
    solana_pubkey::Pubkey,
    solana_signature::Signature,
    solana_message::VersionedMessage,
    solana_transaction::versioned::VersionedTransaction,
};

fn main() {
    // Deployed program IDs on mainnet-beta
    let router: Pubkey = "routerzmjRpidSb1pbhyAViZSfDTPpX7PNk41NC97v1".parse().unwrap();
    let gobble: Pubkey = "GoBBLEtFoGJkKGRMe2dtTsEK2DmdDoAJWT1LmQ3sGd5V".parse().unwrap();
    let amm: Pubkey = "AMMMMM9H5dFuQjpZJPcQ6ZY8eSqjmj1bJMvkAryTDHbM".parse().unwrap();
    let gobble_solana: Pubkey = "GoBBLswskSgbtEUDoboHaSxdHfmUpEa2YQCUW1SmMfcg".parse().unwrap();
    let instructions_sysvar = solana_sdk_ids::sysvar::instructions::id();

    // Dummy fee payer (won't actually sign; CLI only needs the message structure)
    let fee_payer: Pubkey = "11111111111111111111111111111112".parse().unwrap();

    let min_amount_out: u64 = 1000;

    // Helper: build a router instruction
    let make_router_ix = |discriminator: u64, target_program: Pubkey| -> Instruction {
        let mut data = Vec::with_capacity(16);
        data.extend_from_slice(&discriminator.to_le_bytes());
        data.extend_from_slice(&min_amount_out.to_le_bytes());

        Instruction {
            program_id: router,
            accounts: vec![
                AccountMeta::new_readonly(target_program, false),
                AccountMeta::new_readonly(instructions_sysvar, false),
            ],
            data,
        }
    };

    // Helper: message -> bs58 versioned transaction
    let encode_txn = |ix: Instruction| -> String {
        let message = Message::new_with_blockhash(
            &[ix],
            Some(&fee_payer),
            &solana_hash::Hash::default(),
        );
        let txn = VersionedTransaction {
            signatures: vec![Signature::default()],
            message: VersionedMessage::Legacy(message),
        };
        let bytes = bincode::serialize(&txn).expect("serialize");
        bs58::encode(&bytes).into_string()
    };

    // 1. Router -> Gobble (TRUE POSITIVE: gobble reads forbidden bytes 8-16 via sysvar)
    let txn1 = encode_txn(make_router_ix(1, gobble));

    // 2. Router -> AMM (TRUE NEGATIVE: amm reads only bytes 0-8 from CPI data)
    let txn2 = encode_txn(make_router_ix(2, amm));

    // 3. Router -> GobbleSolana (FALSE POSITIVE: load_instruction_at_checked reads all bytes)
    let txn3 = encode_txn(make_router_ix(1, gobble_solana));

    println!("=== Test Transactions for gobble CLI ===\n");

    println!("1) Router -> Gobble (TRUE POSITIVE)");
    println!("   Expected: forbidden access DETECTED");
    println!("   cargo run -p gobble -- \\\n     '{txn1}' \\\n     -f 8-16\n");

    println!("2) Router -> AMM (TRUE NEGATIVE)");
    println!("   Expected: forbidden access NOT detected");
    println!("   cargo run -p gobble -- \\\n     '{txn2}' \\\n     -f 8-16\n");

    println!("3) Router -> GobbleSolana (FALSE POSITIVE)");
    println!("   Expected: forbidden access DETECTED (false positive from deserialization)");
    println!("   cargo run -p gobble -- \\\n     '{txn3}' \\\n     -f 8-16\n");
}
