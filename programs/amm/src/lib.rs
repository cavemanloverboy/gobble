//! AMM program - reads NON-FORBIDDEN bytes from instruction data
//!
//! This program demonstrates a legitimate pattern where a program only reads
//! its own instruction data passed via CPI, not the caller's sensitive parameters.

use pinocchio::{entrypoint, AccountView, Address, ProgramResult};
use solana_msg::msg;

entrypoint!(process_instruction);

/// Process instruction
///
/// Instruction data format:
/// - bytes 0-8: amount (u64) - this is passed directly by the router via CPI
///
/// This program reads only bytes 0-8, which are NON-FORBIDDEN bytes because
/// they are part of this program's own CPI instruction, not the router's instruction.
fn process_instruction(
    _program_id: &Address,
    _accounts: &[AccountView],
    instruction_data: &[u8],
) -> ProgramResult {
    msg!("AMM: Starting");

    if instruction_data.len() < 8 {
        msg!("AMM: Insufficient instruction data");
        return Err(pinocchio::error::ProgramError::InvalidInstructionData);
    }

    // Read bytes 0-8 (NON-FORBIDDEN - this is data specifically for this CPI)
    let amount = u64::from_le_bytes(
        instruction_data[0..8]
            .try_into()
            .map_err(|_| pinocchio::error::ProgramError::InvalidInstructionData)?,
    );

    msg!("AMM: Processing swap with amount: {}", amount);
    msg!("AMM: Successfully processed NON-FORBIDDEN bytes (This should NOT be detected)");

    Ok(())
}
