use {
    agave_syscalls::create_program_runtime_environment_v1,
    anyhow::{Context, Result},
    base64::{engine::general_purpose::STANDARD as BASE64, Engine},
    clap::Parser,
    gobble_lib::{DetectionConfig, GobbleDetector, InstructionInfo},
    solana_account::{Account, AccountSharedData, ReadableAccount},
    solana_builtins::BUILTINS,
    solana_compute_budget::compute_budget::ComputeBudget,
    solana_instruction::{BorrowedAccountMeta, BorrowedInstruction},
    solana_instructions_sysvar::construct_instructions_data,
    solana_message::{
        v0::LoadedAddresses, LegacyMessage, SanitizedMessage, SimpleAddressLoader, VersionedMessage,
    },
    solana_program_runtime::{
        invoke_context::{EnvironmentConfig, InvokeContext},
        loaded_programs::{
            LoadProgramMetrics, ProgramCacheEntry, ProgramCacheForTxBatch,
            ProgramRuntimeEnvironments,
        },
        sysvar_cache::SysvarCache,
    },
    solana_pubkey::Pubkey,
    solana_svm_callback::InvokeContextCallback,
    solana_svm_feature_set::SVMFeatureSet,
    solana_svm_log_collector::LogCollector,
    solana_svm_timings::ExecuteTimings,
    solana_svm_transaction::{instruction::SVMInstruction, svm_message::SVMStaticMessage},
    solana_transaction::versioned::VersionedTransaction,
    solana_transaction_context::transaction::TransactionContext,
    std::{collections::HashSet, rc::Rc, sync::Arc},
};

#[derive(Parser)]
#[command(name = "gobble")]
#[command(about = "Detect forbidden instruction data reads in Solana transactions")]
struct Cli {
    /// Base58-encoded transaction
    transaction: String,

    /// RPC URL
    #[arg(short, long, default_value = "https://api.mainnet-beta.solana.com")]
    rpc_url: String,

    /// Instruction index to watch (0-based)
    #[arg(short, long, default_value_t = 0)]
    instruction_index: usize,

    /// Forbidden byte ranges (comma-separated, e.g. "8-16,20-24")
    #[arg(short, long, default_value = "8-16")]
    forbidden_ranges: String,
}

struct NoopCallback;
impl InvokeContextCallback for NoopCallback {}

fn parse_ranges(s: &str) -> Result<Vec<std::ops::Range<usize>>> {
    s.split(',')
        .map(|r| {
            let parts: Vec<&str> = r.trim().split('-').collect();
            if parts.len() != 2 {
                anyhow::bail!("Invalid range format: '{r}'. Expected 'start-end'.");
            }
            let start: usize = parts[0]
                .parse()
                .with_context(|| format!("Invalid range start: '{}'", parts[0]))?;
            let end: usize = parts[1]
                .parse()
                .with_context(|| format!("Invalid range end: '{}'", parts[1]))?;
            Ok(start..end)
        })
        .collect()
}

/// Fetch multiple accounts from RPC in a single atomic call.
fn fetch_accounts(
    client: &reqwest::blocking::Client,
    rpc_url: &str,
    keys: &[Pubkey],
) -> Result<Vec<Option<AccountSharedData>>> {
    let params: Vec<String> = keys.iter().map(|k| k.to_string()).collect();
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "getMultipleAccounts",
        "params": [
            params,
            { "encoding": "base64" }
        ]
    });

    let resp: serde_json::Value = client
        .post(rpc_url)
        .json(&body)
        .send()
        .with_context(|| "RPC request failed")?
        .json()
        .with_context(|| "Failed to parse RPC response")?;

    if let Some(error) = resp.get("error") {
        anyhow::bail!("RPC error: {error}");
    }

    let accounts = resp["result"]["value"]
        .as_array()
        .with_context(|| "Invalid RPC response format")?;

    accounts
        .iter()
        .map(|account_value| {
            if account_value.is_null() {
                return Ok(None);
            }

            let lamports = account_value["lamports"].as_u64().unwrap_or(0);
            let owner: Pubkey = account_value["owner"]
                .as_str()
                .unwrap_or("")
                .parse()
                .unwrap_or_default();
            let executable = account_value["executable"].as_bool().unwrap_or(false);
            let rent_epoch = account_value["rentEpoch"].as_u64().unwrap_or(0);

            let data_arr = account_value["data"]
                .as_array()
                .with_context(|| "Missing account data array")?;
            let data = BASE64
                .decode(data_arr[0].as_str().unwrap_or(""))
                .with_context(|| "Failed to decode account data")?;

            Ok(Some(AccountSharedData::from(Account {
                lamports,
                data,
                owner,
                executable,
                rent_epoch,
            })))
        })
        .collect()
}

/// Parse an address lookup table account's data to extract the stored addresses.
/// ALT format: 56 bytes metadata, then packed 32-byte pubkeys.
fn parse_alt_addresses(data: &[u8]) -> Vec<Pubkey> {
    const META_SIZE: usize = 56;
    if data.len() < META_SIZE {
        return Vec::new();
    }
    let addresses_data = &data[META_SIZE..];
    addresses_data
        .chunks_exact(32)
        .map(|chunk| Pubkey::new_from_array(chunk.try_into().unwrap()))
        .collect()
}

/// Resolve V0 message address lookup tables by fetching ALT accounts from RPC.
fn resolve_address_lookups(
    client: &reqwest::blocking::Client,
    rpc_url: &str,
    message: &solana_message::v0::Message,
) -> Result<LoadedAddresses> {
    if message.address_table_lookups.is_empty() {
        return Ok(LoadedAddresses::default());
    }

    let alt_keys: Vec<Pubkey> = message
        .address_table_lookups
        .iter()
        .map(|lookup| lookup.account_key)
        .collect();

    let alt_accounts = fetch_accounts(client, rpc_url, &alt_keys)?;

    let mut writable = Vec::new();
    let mut readonly = Vec::new();

    for (lookup, maybe_account) in message
        .address_table_lookups
        .iter()
        .zip(alt_accounts.iter())
    {
        let account = maybe_account
            .as_ref()
            .with_context(|| format!("Address lookup table {} not found", lookup.account_key))?;

        let addresses = parse_alt_addresses(account.data());

        for &idx in &lookup.writable_indexes {
            let addr = addresses.get(idx as usize).with_context(|| {
                format!(
                    "ALT {} writable index {} out of bounds (table has {} addresses)",
                    lookup.account_key,
                    idx,
                    addresses.len()
                )
            })?;
            writable.push(*addr);
        }

        for &idx in &lookup.readonly_indexes {
            let addr = addresses.get(idx as usize).with_context(|| {
                format!(
                    "ALT {} readonly index {} out of bounds (table has {} addresses)",
                    lookup.account_key,
                    idx,
                    addresses.len()
                )
            })?;
            readonly.push(*addr);
        }
    }

    Ok(LoadedAddresses { writable, readonly })
}

/// Construct the instructions sysvar account data from a sanitized message.
fn construct_instructions_account(sanitized_message: &SanitizedMessage) -> AccountSharedData {
    let account_keys = sanitized_message.account_keys();
    let mut decompiled_instructions = Vec::with_capacity(sanitized_message.instructions().len());

    for instruction in sanitized_message.instructions() {
        let program_id_index = instruction.program_id_index as usize;
        let program_id = account_keys.get(program_id_index).unwrap();

        let accounts: Vec<BorrowedAccountMeta> = instruction
            .accounts
            .iter()
            .map(|&account_index| {
                let account_index = account_index as usize;
                BorrowedAccountMeta {
                    is_signer: sanitized_message.is_signer(account_index),
                    is_writable: sanitized_message.is_writable(account_index),
                    pubkey: account_keys.get(account_index).unwrap(),
                }
            })
            .collect();

        decompiled_instructions.push(BorrowedInstruction {
            accounts,
            data: &instruction.data,
            program_id,
        });
    }

    AccountSharedData::from(Account {
        data: construct_instructions_data(&decompiled_instructions),
        owner: solana_sdk_ids::sysvar::id(),
        ..Account::default()
    })
}

/// Build a program cache with builtins and any executable accounts loaded as BPF programs.
fn build_program_cache(
    feature_set: &SVMFeatureSet,
    compute_budget: &ComputeBudget,
    executable_accounts: &[(Pubkey, AccountSharedData)],
) -> Result<ProgramCacheForTxBatch> {
    let mut cache = ProgramCacheForTxBatch::default();
    cache.set_slot_for_tests(1);

    // Register builtins
    for builtin in BUILTINS {
        cache.replenish(
            builtin.program_id,
            Arc::new(ProgramCacheEntry::new_builtin(
                0,
                builtin.name.len(),
                builtin.entrypoint,
            )),
        );
    }

    let env = Arc::new(
        create_program_runtime_environment_v1(
            feature_set,
            &compute_budget.to_budget(),
            false,
            false,
        )
        .map_err(|e| anyhow::anyhow!("Failed to create program runtime environment: {e}"))?,
    );

    // Load BPF programs from executable accounts
    for (program_id, account) in executable_accounts {
        // Skip builtins (already registered)
        if BUILTINS.iter().any(|b| b.program_id == *program_id) {
            continue;
        }

        let owner = account.owner();
        let data = account.data();

        // Check if this is a BPF Loader account with ELF data directly
        if *owner == solana_sdk_ids::bpf_loader::id()
            || *owner == solana_sdk_ids::bpf_loader_deprecated::id()
        {
            match ProgramCacheEntry::new(
                owner,
                env.clone(),
                0,
                0,
                data,
                data.len(),
                &mut LoadProgramMetrics::default(),
            ) {
                Ok(entry) => {
                    cache.replenish(*program_id, Arc::new(entry));
                }
                Err(e) => {
                    eprintln!("  Warning: Failed to load BPF program {program_id}: {e}");
                }
            }
        }
        // For upgradeable loader (BPF Loader Upgradeable), the ELF lives in a
        // separate programdata account. We handle this below.
    }

    Ok(cache)
}

/// Fetch programdata accounts for upgradeable BPF programs and load them into the cache.
fn load_upgradeable_programs(
    client: &reqwest::blocking::Client,
    rpc_url: &str,
    feature_set: &SVMFeatureSet,
    compute_budget: &ComputeBudget,
    cache: &mut ProgramCacheForTxBatch,
    accounts: &[(Pubkey, Option<AccountSharedData>)],
) -> Result<()> {
    let env = Arc::new(
        create_program_runtime_environment_v1(
            feature_set,
            &compute_budget.to_budget(),
            false,
            false,
        )
        .map_err(|e| anyhow::anyhow!("Failed to create program runtime environment: {e}"))?,
    );

    let bpf_loader_upgradeable = solana_sdk_ids::bpf_loader_upgradeable::id();

    // Collect program IDs that use the upgradeable loader
    let mut programdata_keys = Vec::new();
    let mut program_ids = Vec::new();

    for (key, maybe_account) in accounts {
        if let Some(account) = maybe_account {
            if account.executable() && *account.owner() == bpf_loader_upgradeable {
                // The account data starts with a 4-byte enum discriminant (UpgradeableLoaderState),
                // followed by the programdata address for the Program variant.
                // Program variant = discriminant 2, then 32 bytes of programdata address
                let data = account.data();
                if data.len() >= 36 {
                    let discriminant = u32::from_le_bytes(data[0..4].try_into().unwrap());
                    if discriminant == 2 {
                        // Program variant
                        let programdata_key =
                            Pubkey::new_from_array(data[4..36].try_into().unwrap());
                        programdata_keys.push(programdata_key);
                        program_ids.push(*key);
                    }
                }
            }
        }
    }

    if programdata_keys.is_empty() {
        return Ok(());
    }

    eprintln!(
        "  Fetching {} programdata account(s) for upgradeable programs...",
        programdata_keys.len()
    );

    let programdata_accounts = fetch_accounts(client, rpc_url, &programdata_keys)?;

    for (program_id, maybe_programdata) in program_ids.iter().zip(programdata_accounts.iter()) {
        if let Some(programdata) = maybe_programdata {
            let data = programdata.data();
            // ProgramData variant: 4 bytes discriminant (3), 8 bytes slot, 1 byte option,
            // 32 bytes authority (if present), then ELF data
            // Offset to ELF: 4 + 8 + 1 + 32 = 45
            const PROGRAMDATA_HEADER: usize = 45;
            if data.len() > PROGRAMDATA_HEADER {
                let elf = &data[PROGRAMDATA_HEADER..];
                match ProgramCacheEntry::new(
                    &bpf_loader_upgradeable,
                    env.clone(),
                    0,
                    0,
                    elf,
                    elf.len(),
                    &mut LoadProgramMetrics::default(),
                ) {
                    Ok(entry) => {
                        cache.replenish(*program_id, Arc::new(entry));
                    }
                    Err(e) => {
                        eprintln!(
                            "  Warning: Failed to load upgradeable program {program_id}: {e}"
                        );
                    }
                }
            }
        }
    }

    Ok(())
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let forbidden_ranges = parse_ranges(&cli.forbidden_ranges)?;

    eprintln!("=== Gobble ===\n");
    eprintln!("  Instruction index: {}", cli.instruction_index);
    eprintln!("  Forbidden ranges: {:?}", forbidden_ranges);
    eprintln!("  RPC URL: {}\n", cli.rpc_url);

    // 1. Decode the transaction
    let tx_bytes = bs58::decode(&cli.transaction)
        .into_vec()
        .with_context(|| "Failed to decode base58 transaction")?;

    let versioned_tx: VersionedTransaction =
        bincode::deserialize(&tx_bytes).with_context(|| "Failed to deserialize transaction")?;

    let num_signatures = versioned_tx.signatures.len();
    eprintln!("  Transaction decoded: {num_signatures} signature(s)");

    // 2. Resolve account keys (handle V0 ALT lookups)
    let client = reqwest::blocking::Client::new();

    let (sanitized_message, all_account_keys) = match versioned_tx.message {
        VersionedMessage::Legacy(ref message) => {
            let sanitized =
                SanitizedMessage::Legacy(LegacyMessage::new(message.clone(), &HashSet::new()));
            let keys: Vec<Pubkey> = message.account_keys.clone();
            (sanitized, keys)
        }
        VersionedMessage::V0(ref message) => {
            eprintln!("  V0 message detected, resolving address lookup tables...");
            let loaded_addresses = resolve_address_lookups(&client, &cli.rpc_url, message)?;

            let sanitized = SanitizedMessage::try_new(
                solana_message::SanitizedVersionedMessage {
                    message: versioned_tx.message.clone(),
                },
                SimpleAddressLoader::Enabled(loaded_addresses),
                &HashSet::new(),
            )
            .with_context(|| "Failed to create sanitized message")?;

            let keys: Vec<Pubkey> = sanitized.account_keys().iter().cloned().collect();
            (sanitized, keys)
        }
    };

    eprintln!(
        "  Total accounts: {} ({} instructions)",
        all_account_keys.len(),
        sanitized_message.instructions().len()
    );

    // 3. Fetch all accounts from RPC
    eprintln!("\n  Fetching accounts from RPC...");
    let fetched_accounts = fetch_accounts(&client, &cli.rpc_url, &all_account_keys)?;

    let accounts_found = fetched_accounts.iter().filter(|a| a.is_some()).count();
    eprintln!(
        "  Fetched {accounts_found}/{} accounts",
        all_account_keys.len()
    );

    // 4. Construct the instructions sysvar account
    let instructions_sysvar_id = solana_sdk_ids::sysvar::instructions::id();
    let instructions_account = construct_instructions_account(&sanitized_message);

    // 5. Build transaction accounts list
    let transaction_accounts: Vec<(Pubkey, AccountSharedData)> = all_account_keys
        .iter()
        .zip(fetched_accounts.iter())
        .map(|(key, maybe_account)| {
            let account = if *key == instructions_sysvar_id {
                instructions_account.clone()
            } else if let Some(account) = maybe_account {
                account.clone()
            } else {
                // Account not found on-chain — create a default
                AccountSharedData::default()
            };
            (*key, account)
        })
        .collect();

    // 6. Calculate forbidden sysvar offsets
    let instructions: Vec<InstructionInfo> = sanitized_message
        .instructions()
        .iter()
        .map(|ix| InstructionInfo::new(ix.accounts.len(), ix.data.len()))
        .collect();

    let config = DetectionConfig::with_ranges(cli.instruction_index, forbidden_ranges);
    let detector = GobbleDetector::new(config);
    let forbidden_sysvar_offsets = detector
        .calculate_forbidden_sysvar_offsets(&instructions)
        .with_context(|| "Failed to calculate forbidden sysvar offsets")?;

    eprintln!(
        "  Forbidden sysvar byte offsets: {:?}",
        forbidden_sysvar_offsets
    );

    // 7. Build program cache
    eprintln!("\n  Building program cache...");
    let feature_set = SVMFeatureSet::all_enabled();
    let compute_budget = ComputeBudget::new_with_defaults(false, false);

    let executable_accounts: Vec<(Pubkey, AccountSharedData)> = transaction_accounts
        .iter()
        .filter(|(_, acct)| acct.executable())
        .cloned()
        .collect();

    let mut program_cache =
        build_program_cache(&feature_set, &compute_budget, &executable_accounts)?;

    // Load upgradeable programs (fetch programdata accounts)
    let keyed_accounts: Vec<(Pubkey, Option<AccountSharedData>)> = all_account_keys
        .iter()
        .zip(fetched_accounts.iter())
        .map(|(k, a)| (*k, a.clone()))
        .collect();
    load_upgradeable_programs(
        &client,
        &cli.rpc_url,
        &feature_set,
        &compute_budget,
        &mut program_cache,
        &keyed_accounts,
    )?;

    let builtins_count = BUILTINS.len();
    let loaded_programs = executable_accounts.len();
    eprintln!("  Program cache: {builtins_count} builtins + {loaded_programs} loaded programs");

    // 8. Populate sysvar cache from RPC
    eprintln!("  Populating sysvar cache...");
    let sysvar_ids = [
        solana_sdk_ids::sysvar::clock::id(),
        solana_sdk_ids::sysvar::epoch_schedule::id(),
        solana_sdk_ids::sysvar::rent::id(),
        solana_sdk_ids::sysvar::slot_hashes::id(),
        solana_sdk_ids::sysvar::stake_history::id(),
        solana_sdk_ids::sysvar::epoch_rewards::id(),
        solana_sdk_ids::sysvar::last_restart_slot::id(),
        solana_sdk_ids::sysvar::fees::id(),
        solana_sdk_ids::sysvar::recent_blockhashes::id(),
    ];
    let sysvar_accounts = fetch_accounts(&client, &cli.rpc_url, &sysvar_ids)?;
    let sysvar_map: std::collections::HashMap<Pubkey, Vec<u8>> = sysvar_ids
        .iter()
        .zip(sysvar_accounts.iter())
        .filter_map(|(id, maybe_acct)| maybe_acct.as_ref().map(|acct| (*id, acct.data().to_vec())))
        .collect();

    let mut sysvar_cache = SysvarCache::default();
    sysvar_cache.fill_missing_entries(|sysvar_id: &Pubkey, callback: &mut dyn FnMut(&[u8])| {
        if let Some(data) = sysvar_map.get(sysvar_id) {
            callback(data);
        }
    });
    eprintln!("  Sysvar cache populated with {} entries", sysvar_map.len());

    let rent = solana_rent::Rent::default();

    let mut transaction_context = TransactionContext::new(
        transaction_accounts,
        rent,
        compute_budget.max_instruction_stack_depth,
        compute_budget.max_instruction_trace_length,
        sanitized_message.num_instructions(),
    );

    let environments = ProgramRuntimeEnvironments {
        program_runtime_v1: Arc::new(
            create_program_runtime_environment_v1(
                &feature_set,
                &compute_budget.to_budget(),
                false,
                false,
            )
            .map_err(|e| anyhow::anyhow!("Failed to create runtime environment: {e}"))?,
        ),
        ..ProgramRuntimeEnvironments::default()
    };

    let log_collector = LogCollector::new_ref();

    // 9. Execute with forbidden range tracking
    eprintln!("\n  Executing transaction...\n");

    let result = {
        let mut invoke_context = InvokeContext::new(
            &mut transaction_context,
            &mut program_cache,
            EnvironmentConfig::new(
                solana_hash::Hash::default(),
                0,
                &NoopCallback,
                &feature_set,
                &environments,
                &environments,
                &sysvar_cache,
            ),
            Some(log_collector.clone()),
            compute_budget.to_budget(),
            compute_budget.to_cost(),
        );

        // Set forbidden ranges on the invoke context
        invoke_context.set_forbidden_sysvar_data_ranges(forbidden_sysvar_offsets);

        let compiled_ix = sanitized_message
            .instructions()
            .get(cli.instruction_index)
            .with_context(|| {
                format!(
                    "Instruction index {} out of bounds (have {} instructions)",
                    cli.instruction_index,
                    sanitized_message.instructions().len()
                )
            })?;
        let svm_instruction = SVMInstruction::from(compiled_ix);
        let program_account_index = compiled_ix.program_id_index as u16;

        invoke_context
            .prepare_next_top_level_instruction(
                &sanitized_message,
                &svm_instruction,
                program_account_index,
                svm_instruction.data,
            )
            .with_context(|| "prepare_next_top_level_instruction failed")?;

        let mut cu = 0u64;
        let mut timings = ExecuteTimings::default();
        let exec_result = invoke_context.process_instruction(&mut cu, &mut timings);

        let forbidden_accesses = invoke_context.get_forbidden_memory_accesses().to_vec();
        (exec_result, forbidden_accesses)
    };

    let (exec_result, forbidden_accesses) = result;

    // 10. Collect and display results
    let logs = Rc::try_unwrap(log_collector)
        .ok()
        .map(|cell| cell.into_inner().into_messages())
        .unwrap_or_default();

    let success = exec_result.is_ok();
    let forbidden_detected = !forbidden_accesses.is_empty();

    println!("=== Results ===\n");
    println!(
        "  Execution: {}",
        if success { "SUCCESS" } else { "FAILED" }
    );
    if let Err(ref e) = exec_result {
        println!("  Error: {e}");
    }
    println!();

    println!("  Forbidden access detected: {forbidden_detected}");
    if forbidden_detected {
        println!("  Forbidden accesses:");
        for (addr, size) in &forbidden_accesses {
            println!("    VM addr: {addr:#x}, size: {size}");
        }
    }
    println!();

    println!("  Logs:");
    for log in &logs {
        println!("    {log}");
    }

    if forbidden_detected {
        std::process::exit(1);
    }
    Ok(())
}
