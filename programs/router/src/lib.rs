//! Router program - invokes either gobble or amm based on discriminator
//! The router instruction contains min_amount_out in bytes 8-16 (FORBIDDEN)

use pinocchio::{
    cpi::invoke,
    entrypoint,
    instruction::{InstructionAccount, InstructionView},
    sysvars::instructions::{Instructions, INSTRUCTIONS_ID},
    AccountView, Address, ProgramResult,
};
use solana_msg::msg;

entrypoint!(process_instruction);

const DISCRIMINATOR_GOBBLE: u64 = 1;
const DISCRIMINATOR_AMM: u64 = 2;

/// Process instruction
///
/// Instruction data format:
/// - bytes 0-7: discriminator (u64) - 1 for gobble, 2 for amm
/// - bytes 8-15: min_amount_out (u64) - FORBIDDEN bytes
fn process_instruction(
    _program_id: &Address,
    accounts: &[AccountView],
    instruction_data: &[u8],
) -> ProgramResult {
    msg!("Router: Starting");

    if instruction_data.len() < 16 {
        msg!("Router: Insufficient instruction data");
        return Err(pinocchio::error::ProgramError::InvalidInstructionData);
    }

    let discriminator = u64::from_le_bytes(
        instruction_data[0..8]
            .try_into()
            .map_err(|_| pinocchio::error::ProgramError::InvalidInstructionData)?,
    );

    let min_amount_out = u64::from_le_bytes(
        instruction_data[8..16]
            .try_into()
            .map_err(|_| pinocchio::error::ProgramError::InvalidInstructionData)?,
    );

    msg!("Router: discriminator={}, min_amount_out={}", discriminator, min_amount_out);

    if accounts.len() < 2 {
        return Err(pinocchio::error::ProgramError::NotEnoughAccountKeys);
    }

    let target_program = &accounts[0];
    let instructions_sysvar = &accounts[1];

    // Verify instructions sysvar
    if instructions_sysvar.address() != &INSTRUCTIONS_ID {
        msg!("Router: Instructions sysvar not provided");
        return Err(pinocchio::error::ProgramError::InvalidAccountData);
    }

    // Get current instruction index
    let instructions = Instructions::try_from(instructions_sysvar)?;
    let current_index = instructions.load_current_index();
    msg!("Router: Current instruction index: {}", current_index);

    match discriminator {
        DISCRIMINATOR_GOBBLE => {
            msg!("Router: Invoking gobble (will read FORBIDDEN bytes)");

            // Pass the current instruction index so gobble can read THIS instruction's data
            let instruction_accounts = [
                InstructionAccount::readonly(&INSTRUCTIONS_ID),
            ];

            let data = [current_index as u8];

            let instruction = InstructionView {
                program_id: target_program.address(),
                accounts: &instruction_accounts,
                data: &data,
            };

            invoke(&instruction, &[instructions_sysvar])?;
        }
        DISCRIMINATOR_AMM => {
            msg!("Router: Invoking AMM (will read NON-FORBIDDEN bytes)");

            // Pass only the min_amount_out value to AMM
            let data = min_amount_out.to_le_bytes();

            let instruction = InstructionView {
                program_id: target_program.address(),
                accounts: &[],
                data: &data,
            };

            invoke(&instruction, &[])?;
        }
        _ => {
            msg!("Router: Invalid discriminator");
            return Err(pinocchio::error::ProgramError::InvalidInstructionData);
        }
    }

    msg!("Router: Complete");
    Ok(())
}
