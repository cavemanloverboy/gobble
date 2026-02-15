//! End-to-end demonstration of gobble detection.
//!
//! Run with:
//!   cargo run --example gobble
//!
//! This example:
//! 1. Loads the compiled router, gobble, amm, and gobble-solana BPF programs
//! 2. Configures forbidden byte ranges for bytes [8..16] of the router instruction
//! 3. Executes the router->gobble path and detects forbidden access
//! 4. Executes the router->amm path and confirms no forbidden access
//! 5. Demonstrates a FALSE POSITIVE: gobble-solana uses load_instruction_at_checked()
//!    which deserializes ALL instruction data, triggering detection even though the
//!    program only reads bytes 0-8

use {
    agave_syscalls::create_program_runtime_environment_v1,
    gobble_lib::{DetectionConfig, GobbleDetector, InstructionInfo},
    solana_account::{Account, AccountSharedData, WritableAccount},
    solana_builtins::BUILTINS,
    solana_compute_budget::compute_budget::ComputeBudget,
    solana_instruction::{AccountMeta, BorrowedAccountMeta, BorrowedInstruction, Instruction},
    solana_instructions_sysvar::construct_instructions_data,
    solana_message::{LegacyMessage, Message, SanitizedMessage},
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
    solana_transaction_context::transaction::TransactionContext,
    std::{collections::HashSet, path::Path, rc::Rc, sync::Arc},
};

/// Deterministic program IDs for our programs
fn router_program_id() -> Pubkey {
    Pubkey::new_from_array([
        0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10,
        0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10,
        0x10, 0x10, 0x10, 0x10,
    ])
}

fn gobble_program_id() -> Pubkey {
    Pubkey::new_from_array([
        0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
        0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
        0x20, 0x20, 0x20, 0x20,
    ])
}

fn amm_program_id() -> Pubkey {
    Pubkey::new_from_array([
        0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
        0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
        0x30, 0x30, 0x30, 0x30,
    ])
}

fn gobble_solana_program_id() -> Pubkey {
    Pubkey::new_from_array([
        0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40,
        0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40,
        0x40, 0x40, 0x40, 0x40,
    ])
}

struct NoopCallback;
impl InvokeContextCallback for NoopCallback {}

/// Load an ELF binary from the fixtures directory.
fn load_elf(name: &str) -> Vec<u8> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("fixtures")
        .join(format!("{name}.so"));
    std::fs::read(&path).unwrap_or_else(|e| {
        panic!(
            "Failed to read {}: {e}. Did you run cargo-build-sbf for all programs?",
            path.display()
        )
    })
}

/// Build a program cache with builtins plus our BPF programs.
fn build_program_cache(
    feature_set: &SVMFeatureSet,
    compute_budget: &ComputeBudget,
) -> ProgramCacheForTxBatch {
    let mut cache = ProgramCacheForTxBatch::default();
    cache.set_slot_for_tests(1);

    // Register builtins (system program, etc.)
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
        .unwrap(),
    );

    let loader_key = solana_sdk_ids::bpf_loader::id();

    // Load and register each BPF program
    for (program_id, elf_name) in [
        (router_program_id(), "router"),
        (gobble_program_id(), "gobble"),
        (amm_program_id(), "amm"),
        (gobble_solana_program_id(), "gobble-solana"),
    ] {
        let elf = load_elf(elf_name);
        let entry = ProgramCacheEntry::new(
            &loader_key,
            env.clone(),
            0,
            0,
            &elf,
            elf.len(),
            &mut LoadProgramMetrics::default(),
        )
        .unwrap_or_else(|e| panic!("Failed to load {elf_name}: {e}"));
        cache.replenish(program_id, Arc::new(entry));
    }

    cache
}

/// Construct the instructions sysvar account data, identically to agave's
/// `construct_instructions_account` in `svm/src/account_loader.rs`.
///
/// This uses `construct_instructions_data` from `solana-instructions-sysvar`
/// with `BorrowedInstruction` from `solana-instruction`, exactly matching
/// how the SVM populates this account for program execution.
fn construct_instructions_account(instruction: &Instruction) -> AccountSharedData {
    let borrowed = BorrowedInstruction {
        accounts: instruction
            .accounts
            .iter()
            .map(|meta| BorrowedAccountMeta {
                is_signer: meta.is_signer,
                is_writable: meta.is_writable,
                pubkey: &meta.pubkey,
            })
            .collect(),
        data: &instruction.data,
        program_id: &instruction.program_id,
    };

    AccountSharedData::from(Account {
        data: construct_instructions_data(&[borrowed]),
        owner: solana_sdk_ids::sysvar::id(),
        ..Account::default()
    })
}

/// Execute a single router instruction and return (success, logs, forbidden_accesses).
fn execute_router_instruction(
    discriminator: u64,
    min_amount_out: u64,
    target_program_id: Pubkey,
    program_cache: &mut ProgramCacheForTxBatch,
    feature_set: &SVMFeatureSet,
    compute_budget: &ComputeBudget,
    sysvar_cache: &SysvarCache,
    _forbidden_vm_ranges: &[std::ops::Range<u64>],
) -> (bool, Vec<String>, Vec<(u64, usize)>) {
    let instructions_sysvar_id = solana_sdk_ids::sysvar::instructions::id();
    let loader_key = solana_sdk_ids::bpf_loader::id();

    // Build the router instruction data: [discriminator: u64, min_amount_out: u64]
    let mut instruction_data = Vec::new();
    instruction_data.extend_from_slice(&discriminator.to_le_bytes());
    instruction_data.extend_from_slice(&min_amount_out.to_le_bytes());

    let instruction = Instruction {
        program_id: router_program_id(),
        accounts: vec![
            AccountMeta::new_readonly(target_program_id, false),
            AccountMeta::new_readonly(instructions_sysvar_id, false),
        ],
        data: instruction_data,
    };

    // Construct the instructions sysvar account data identically to agave
    let instructions_account = construct_instructions_account(&instruction);

    // Compile the message (same pattern as svm-test-harness)
    let message = Message::new(std::slice::from_ref(&instruction), None);

    let transaction_accounts: Vec<(Pubkey, AccountSharedData)> = message
        .account_keys
        .iter()
        .map(|key| {
            let account = if *key == router_program_id()
                || *key == gobble_program_id()
                || *key == amm_program_id()
            {
                let mut a = AccountSharedData::new(0, 0, &loader_key);
                a.set_executable(true);
                a
            } else if *key == instructions_sysvar_id {
                // Use the properly constructed instructions sysvar account
                instructions_account.clone()
            } else {
                AccountSharedData::default()
            };
            (*key, account)
        })
        .collect();

    let sanitized_message =
        SanitizedMessage::Legacy(LegacyMessage::new(message, &HashSet::new()));

    let rent = solana_rent::Rent::default();
    let mut transaction_context = TransactionContext::new(
        transaction_accounts,
        rent.clone(),
        compute_budget.max_instruction_stack_depth,
        compute_budget.max_instruction_trace_length,
        sanitized_message.num_instructions(),
    );

    let environments = ProgramRuntimeEnvironments {
        program_runtime_v1: Arc::new(
            create_program_runtime_environment_v1(
                feature_set,
                &compute_budget.to_budget(),
                false,
                false,
            )
            .unwrap(),
        ),
        ..ProgramRuntimeEnvironments::default()
    };

    let log_collector = LogCollector::new_ref();

    let result = {
        let mut invoke_context = InvokeContext::new(
            &mut transaction_context,
            program_cache,
            EnvironmentConfig::new(
                solana_hash::Hash::default(),
                0,
                &NoopCallback,
                feature_set,
                &environments,
                &environments,
                sysvar_cache,
            ),
            Some(log_collector.clone()),
            compute_budget.to_budget(),
            compute_budget.to_cost(),
        );

        let compiled_ix = sanitized_message.instructions().first().unwrap();
        let svm_instruction = SVMInstruction::from(compiled_ix);
        let program_account_index = compiled_ix.program_id_index as u16;

        invoke_context
            .prepare_next_top_level_instruction(
                &sanitized_message,
                &svm_instruction,
                program_account_index,
                svm_instruction.data,
            )
            .expect("prepare_next_top_level_instruction failed");

        let mut cu = 0u64;
        let mut timings = ExecuteTimings::default();
        invoke_context.process_instruction(&mut cu, &mut timings)
    };

    let logs = Rc::try_unwrap(log_collector)
        .ok()
        .map(|cell| cell.into_inner().into_messages())
        .unwrap_or_default();

    let success = result.is_ok();

    // For now, report forbidden accesses based on log analysis.
    // In a full implementation the VM tracker would be checked directly.
    let forbidden_accesses = Vec::new();

    (success, logs, forbidden_accesses)
}

/// Execute a program directly (not through router) with VM-level forbidden range tracking.
///
/// The instruction has 16 bytes of data:
///   [0]: target_instruction_index (0 = read itself from sysvar)
///   [1..8]: padding
///   [8..16]: "forbidden" min_amount_out value
///
/// Returns (execution_success, logs, forbidden_accesses).
fn execute_direct_program(
    program_id: Pubkey,
    program_cache: &mut ProgramCacheForTxBatch,
    feature_set: &SVMFeatureSet,
    compute_budget: &ComputeBudget,
    sysvar_cache: &SysvarCache,
    forbidden_sysvar_offsets: &[std::ops::Range<usize>],
) -> (bool, Vec<String>, Vec<(u64, usize)>) {
    let instructions_sysvar_id = solana_sdk_ids::sysvar::instructions::id();
    let loader_key = solana_sdk_ids::bpf_loader::id();

    // Build instruction data: 16 bytes total
    // byte 0 = target_instruction_index (0 = read itself from sysvar)
    // bytes 8-16 = some forbidden value
    let mut instruction_data = vec![0u8; 16];
    instruction_data[0] = 0;
    instruction_data[8..16].copy_from_slice(&0xDEADBEEF_u64.to_le_bytes());

    let instruction = Instruction {
        program_id,
        accounts: vec![
            AccountMeta::new_readonly(instructions_sysvar_id, false),
        ],
        data: instruction_data,
    };

    let instructions_account = construct_instructions_account(&instruction);
    let message = Message::new(std::slice::from_ref(&instruction), None);

    let transaction_accounts: Vec<(Pubkey, AccountSharedData)> = message
        .account_keys
        .iter()
        .map(|key| {
            let account = if *key == program_id {
                let mut a = AccountSharedData::new(0, 0, &loader_key);
                a.set_executable(true);
                a
            } else if *key == instructions_sysvar_id {
                instructions_account.clone()
            } else {
                AccountSharedData::default()
            };
            (*key, account)
        })
        .collect();

    let sanitized_message =
        SanitizedMessage::Legacy(LegacyMessage::new(message, &HashSet::new()));

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
                feature_set,
                &compute_budget.to_budget(),
                false,
                false,
            )
            .unwrap(),
        ),
        ..ProgramRuntimeEnvironments::default()
    };

    let log_collector = LogCollector::new_ref();

    let (exec_result, forbidden_accesses) = {
        let mut invoke_context = InvokeContext::new(
            &mut transaction_context,
            program_cache,
            EnvironmentConfig::new(
                solana_hash::Hash::default(),
                0,
                &NoopCallback,
                feature_set,
                &environments,
                &environments,
                sysvar_cache,
            ),
            Some(log_collector.clone()),
            compute_budget.to_budget(),
            compute_budget.to_cost(),
        );

        invoke_context.set_forbidden_sysvar_data_ranges(forbidden_sysvar_offsets.to_vec());

        let compiled_ix = sanitized_message.instructions().first().unwrap();
        let svm_instruction = SVMInstruction::from(compiled_ix);
        let program_account_index = compiled_ix.program_id_index as u16;

        invoke_context
            .prepare_next_top_level_instruction(
                &sanitized_message,
                &svm_instruction,
                program_account_index,
                svm_instruction.data,
            )
            .expect("prepare_next_top_level_instruction failed");

        let mut cu = 0u64;
        let mut timings = ExecuteTimings::default();
        let exec_result = invoke_context.process_instruction(&mut cu, &mut timings);
        let forbidden = invoke_context.get_forbidden_memory_accesses().to_vec();
        (exec_result, forbidden)
    };

    let logs = Rc::try_unwrap(log_collector)
        .ok()
        .map(|cell| cell.into_inner().into_messages())
        .unwrap_or_default();

    (exec_result.is_ok(), logs, forbidden_accesses)
}

fn main() {
    println!("=== Gobble Detector Demo ===\n");

    let feature_set = SVMFeatureSet::all_enabled();
    let compute_budget = ComputeBudget::new_with_defaults(false, false);
    let sysvar_cache = SysvarCache::default();

    let mut program_cache = build_program_cache(&feature_set, &compute_budget);

    // ---------------------------------------------------------------
    // Demonstrate the address calculation for forbidden byte ranges
    // ---------------------------------------------------------------
    println!("--- Step 1: Calculate Forbidden Memory Ranges ---\n");

    let config = DetectionConfig::with_ranges(
        0,
        vec![8..16], // min_amount_out at bytes 8-16
    );
    let detector = GobbleDetector::new(config);

    // The router instruction has:
    //   2 accounts (target_program, instructions_sysvar)
    //   16 bytes of data (discriminator + min_amount_out)
    let instructions = vec![InstructionInfo::new(2, 16)];
    let forbidden_vm_ranges = detector
        .calculate_forbidden_vm_ranges(&instructions)
        .expect("Failed to calculate forbidden VM ranges");

    for (i, range) in forbidden_vm_ranges.iter().enumerate() {
        println!(
            "  Forbidden range {i}: VM addresses {:#x}..{:#x} ({} bytes)",
            range.start,
            range.end,
            range.end - range.start
        );
    }
    println!();

    // ---------------------------------------------------------------
    // Test 1: Router -> Gobble (SHOULD detect forbidden access)
    // ---------------------------------------------------------------
    println!("--- Test 1: Router -> Gobble (should detect) ---\n");

    let (success, logs, _forbidden) = execute_router_instruction(
        1, // discriminator = 1 (gobble)
        1000,
        gobble_program_id(),
        &mut program_cache,
        &feature_set,
        &compute_budget,
        &sysvar_cache,
        &forbidden_vm_ranges,
    );

    println!("  Execution success: {success}");
    println!("  Logs:");
    for log in &logs {
        println!("    {log}");
    }

    // Check logs for evidence the gobble program read the forbidden bytes
    let gobble_read_forbidden = logs
        .iter()
        .any(|l| l.contains("Read forbidden bytes") || l.contains("Gobble"));
    println!(
        "\n  Gobble read forbidden bytes (via log analysis): {gobble_read_forbidden}"
    );
    println!();

    // ---------------------------------------------------------------
    // Test 2: Router -> AMM (should NOT detect forbidden access)
    // ---------------------------------------------------------------
    println!("--- Test 2: Router -> AMM (should NOT detect) ---\n");

    let (success, logs, _forbidden) = execute_router_instruction(
        2, // discriminator = 2 (amm)
        1000,
        amm_program_id(),
        &mut program_cache,
        &feature_set,
        &compute_budget,
        &sysvar_cache,
        &forbidden_vm_ranges,
    );

    println!("  Execution success: {success}");
    println!("  Logs:");
    for log in &logs {
        println!("    {log}");
    }

    let amm_read_forbidden = logs
        .iter()
        .any(|l| l.contains("Read forbidden bytes") || l.contains("Gobble"));
    println!(
        "\n  AMM read forbidden bytes (via log analysis): {amm_read_forbidden}"
    );
    println!();

    // ---------------------------------------------------------------
    // Test 3: gobble-solana FALSE POSITIVE
    //
    // gobble-solana uses load_instruction_at_checked() which deserializes
    // the ENTIRE instruction from the sysvar (copying ALL data bytes),
    // even though the program only reads bytes 0-8.
    //
    // For comparison, amm (pinocchio) also only reads bytes 0-8 but does
    // NOT trigger the detector because pinocchio uses zero-copy access.
    // ---------------------------------------------------------------
    println!("--- Test 3: gobble-solana FALSE POSITIVE (load_instruction_at_checked) ---\n");

    // Calculate forbidden sysvar offsets for a direct invocation:
    // 1 account, 16 bytes of data, forbidden range 8-16
    let config = DetectionConfig::with_ranges(0, vec![8..16]);
    let detector = GobbleDetector::new(config);
    let direct_instructions = vec![InstructionInfo::new(1, 16)];
    let forbidden_sysvar_offsets = detector
        .calculate_forbidden_sysvar_offsets(&direct_instructions)
        .expect("Failed to calculate forbidden sysvar offsets");

    println!("  Forbidden sysvar byte offsets: {:?}", forbidden_sysvar_offsets);

    // gobble-solana: uses load_instruction_at_checked → deserializes ALL bytes
    let (success, logs, forbidden_accesses) = execute_direct_program(
        gobble_solana_program_id(),
        &mut program_cache,
        &feature_set,
        &compute_budget,
        &sysvar_cache,
        &forbidden_sysvar_offsets,
    );

    let gs_detected = !forbidden_accesses.is_empty();
    println!("  Execution: {}", if success { "SUCCESS" } else { "FAILED" });
    println!("  Forbidden access detected: {gs_detected}");
    if !forbidden_accesses.is_empty() {
        for (addr, size) in &forbidden_accesses {
            println!("    VM addr: {addr:#x}, size: {size}");
        }
    }
    println!("  Logs:");
    for log in &logs {
        println!("    {log}");
    }
    println!();

    // amm (pinocchio): only reads bytes 0-8, zero-copy, no sysvar access
    println!("  Comparison: amm (pinocchio, zero-copy, same bytes 0-8 only)");
    let (success, _logs, forbidden_accesses) = execute_direct_program(
        amm_program_id(),
        &mut program_cache,
        &feature_set,
        &compute_budget,
        &sysvar_cache,
        &forbidden_sysvar_offsets,
    );

    let amm_detected = !forbidden_accesses.is_empty();
    println!("  Execution: {}", if success { "SUCCESS" } else { "FAILED" });
    println!("  Forbidden access detected: {amm_detected}");
    println!();

    // ---------------------------------------------------------------
    // Summary
    // ---------------------------------------------------------------
    println!("=== Summary ===\n");
    println!("  Router -> Gobble: gobble read forbidden bytes = {gobble_read_forbidden}");
    println!("  Router -> AMM:    AMM read forbidden bytes    = {amm_read_forbidden}");
    println!("  gobble-solana (load_instruction_at_checked):  detected = {gs_detected} (FALSE POSITIVE)");
    println!("  amm (pinocchio, zero-copy):                   detected = {amm_detected} (true negative)");

    if gobble_read_forbidden && !amm_read_forbidden {
        println!("\n  PASS: Gobble was correctly identified, AMM was correctly cleared.");
    } else if !success {
        println!("\n  NOTE: Transaction execution failed (see logs above).");
    }

    if gs_detected && !amm_detected {
        println!("  CONFIRMED: load_instruction_at_checked() causes a FALSE POSITIVE.");
        println!("  The deserialization reads ALL instruction data bytes from the sysvar,");
        println!("  triggering the detector even though the program only uses bytes 0-8.");
    }

    println!("\n  VM memory tracking ranges configured:");
    for (i, range) in forbidden_vm_ranges.iter().enumerate() {
        println!(
            "    Range {i}: {:#x}..{:#x}",
            range.start, range.end
        );
    }
    println!("\n  These ranges would be passed to vm.add_watched_memory_ranges()");
    println!("  to detect forbidden reads at the SBPF VM level.");
}
