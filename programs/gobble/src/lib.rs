//! Gobble program - reads FORBIDDEN bytes (8-16) from top-level instruction via instruction sysvar
//!
//! This program demonstrates a malicious pattern where a program reads sensitive parameters
//! (like min_amount_out slippage) from the caller's instruction data to exploit the user.

use pinocchio::{
    entrypoint,
    sysvars::instructions::Instructions,
    AccountView, Address, ProgramResult,
};
use solana_msg::msg;

entrypoint!(process_instruction);

/// Process instruction
///
/// Instruction data format:
/// - byte 0: target_instruction_index (which instruction in the transaction to read from)
///
/// This program reads bytes 8-16 from the specified instruction, which should be FORBIDDEN
/// if that instruction is the router instruction containing min_amount_out.
fn process_instruction(
    _program_id: &Address,
    accounts: &[AccountView],
    instruction_data: &[u8],
) -> ProgramResult {
    msg!("Gobble: Starting");

    if instruction_data.is_empty() {
        msg!("Gobble: No instruction data provided");
        return Err(pinocchio::error::ProgramError::InvalidInstructionData);
    }

    let target_instruction_index = instruction_data[0] as usize;
    msg!("Gobble: Target instruction index: {}", target_instruction_index);

    // Last account should be the instructions sysvar
    let instructions_account = accounts
        .last()
        .ok_or(pinocchio::error::ProgramError::NotEnoughAccountKeys)?;

    let instructions = Instructions::try_from(instructions_account)?;

    // Load the target instruction from the sysvar
    let instruction = instructions.load_instruction_at(target_instruction_index)?;

    msg!("Gobble: Loaded instruction from sysvar");
    let data = instruction.get_instruction_data();
    msg!("  Data length: {}", data.len());

    // Read bytes 8-16 (the FORBIDDEN bytes if this is the router instruction)
    if data.len() < 16 {
        msg!("Gobble: Instruction data too short");
        return Err(pinocchio::error::ProgramError::InvalidInstructionData);
    }

    // THIS IS THE FORBIDDEN READ - accessing bytes 8-16
    let forbidden_bytes = &data[8..16];
    let min_amount_out = u64::from_le_bytes(
        forbidden_bytes.try_into().map_err(|_| pinocchio::error::ProgramError::InvalidInstructionData)?
    );

    msg!("Gobble: Read forbidden bytes as u64: {}", min_amount_out);
    msg!("Gobble: Successfully gobbled forbidden bytes! (This should be detected)");

    Ok(())
}
