//! gobble-solana: Uses standard solana-program-entrypoint crate to read instruction data
//! via `load_instruction_at_checked`.
//!
//! This program ONLY reads bytes 0-8 (the NON-forbidden range), but because
//! `load_instruction_at_checked` deserializes the ENTIRE instruction (including
//! bytes 8-16), it triggers the memory access tracker — a FALSE POSITIVE.

use {
    solana_account_info::AccountInfo,
    solana_instructions_sysvar as instructions,
    solana_msg::msg,
    solana_program_error::{ProgramError, ProgramResult},
    solana_pubkey::Pubkey,
};

solana_program_entrypoint::entrypoint_no_alloc!(process_instruction);

fn process_instruction(
    _program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    msg!("GobbleSolana: Starting");

    if instruction_data.is_empty() {
        msg!("GobbleSolana: No instruction data provided");
        return Err(ProgramError::InvalidInstructionData);
    }

    let target_instruction_index = instruction_data[0] as usize;
    msg!("GobbleSolana: Target instruction index: {}", target_instruction_index);

    // Last account should be the instructions sysvar
    let instructions_account = accounts
        .last()
        .ok_or(ProgramError::NotEnoughAccountKeys)?;

    // This call deserializes the ENTIRE instruction from the sysvar, reading ALL bytes
    // of instruction data (including the forbidden 8-16 range) even though we only
    // need bytes 0-8.
    let instruction = instructions::load_instruction_at_checked(
        target_instruction_index,
        instructions_account,
    )?;

    msg!("GobbleSolana: Loaded instruction from sysvar");
    msg!("  Data length: {}", instruction.data.len());

    if instruction.data.len() < 8 {
        msg!("GobbleSolana: Instruction data too short");
        return Err(ProgramError::InvalidInstructionData);
    }

    // ONLY read bytes 0-8 (the ALLOWED range — this is NOT the forbidden range)
    let allowed_bytes = &instruction.data[0..8];
    let discriminator = u64::from_le_bytes(
        allowed_bytes.try_into().map_err(|_| ProgramError::InvalidInstructionData)?
    );

    msg!("GobbleSolana: Read discriminator (bytes 0-8): {}", discriminator);
    msg!("GobbleSolana: Did NOT explicitly read bytes 8-16, but deserialization did");

    Ok(())
}
