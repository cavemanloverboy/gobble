//! Gobble - Transaction simulation harness that detects forbidden byte reads
//!
//! This crate provides functionality to detect when Solana programs read forbidden bytes
//! from instruction data via memory tracking in the SBPF VM.

use {
    anyhow::Result,
    std::ops::Range,
};

/// Configuration for forbidden byte detection
#[derive(Debug, Clone)]
pub struct DetectionConfig {
    /// Instruction index to watch (typically 0 for the top-level router instruction)
    pub instruction_index: usize,
    /// Forbidden byte ranges within the instruction data (can specify multiple ranges)
    pub forbidden_ranges: Vec<Range<usize>>,
}

impl Default for DetectionConfig {
    fn default() -> Self {
        Self {
            instruction_index: 0,
            forbidden_ranges: vec![8..16], // Default: bytes 8-16 (min_amount_out)
        }
    }
}

impl DetectionConfig {
    /// Create a new detection config for a single forbidden range
    pub fn new(instruction_index: usize, forbidden_start: usize, forbidden_end: usize) -> Self {
        Self {
            instruction_index,
            forbidden_ranges: vec![forbidden_start..forbidden_end],
        }
    }

    /// Create a new detection config with multiple forbidden ranges
    pub fn with_ranges(instruction_index: usize, ranges: Vec<Range<usize>>) -> Self {
        Self {
            instruction_index,
            forbidden_ranges: ranges,
        }
    }
}

/// Result of transaction simulation with forbidden access detection
#[derive(Debug)]
pub struct DetectionResult {
    /// Whether the transaction executed successfully
    pub execution_success: bool,
    /// Whether any forbidden accesses were detected
    pub forbidden_access_detected: bool,
    /// List of (vm_address, size) tuples for each forbidden access
    pub forbidden_accesses: Vec<(u64, usize)>,
    /// Execution logs
    pub logs: Vec<String>,
}

/// Main harness for detecting forbidden byte reads
pub struct GobbleDetector {
    config: DetectionConfig,
}

impl GobbleDetector {
    /// Create a new detector with the given configuration
    pub fn new(config: DetectionConfig) -> Self {
        Self { config }
    }

    /// Create a detector with default configuration (watching bytes 8-16 of instruction 0)
    pub fn with_default_config() -> Self {
        Self::new(DetectionConfig::default())
    }

    /// Calculate VM memory address ranges for forbidden bytes in the instruction sysvar
    ///
    /// The instruction sysvar is serialized into VM memory at MM_INPUT_START.
    /// This function calculates where specific instruction data bytes will be located.
    ///
    /// # Instruction Sysvar Format
    ///
    /// ```text
    /// [0..2]: num_instructions (u16)
    /// [2..2+2*n]: instruction offset table (u16[n])
    /// [variable]: serialized instructions
    ///
    /// Each instruction:
    ///   [0..2]: num_accounts (u16)
    ///   [accounts]: (1 byte meta + 32 bytes pubkey) * num_accounts
    ///   [+N..+N+32]: program_id (32 bytes)
    ///   [+32..+34]: data_len (u16)
    ///   [+34..]: instruction data
    /// ```
    /// Calculate byte offset ranges within the instruction sysvar account data
    /// that correspond to the forbidden instruction data bytes.
    ///
    /// Returns offsets relative to the start of the instruction sysvar data.
    /// These offsets can be combined with the sysvar account's `vm_data_addr`
    /// at runtime to get actual VM addresses.
    pub fn calculate_forbidden_sysvar_offsets(
        &self,
        instructions: &[InstructionInfo],
    ) -> Result<Vec<Range<usize>>> {
        if self.config.instruction_index >= instructions.len() {
            anyhow::bail!(
                "Invalid instruction index: {} (have {} instructions)",
                self.config.instruction_index,
                instructions.len()
            );
        }

        let target_instruction = &instructions[self.config.instruction_index];

        // Calculate offset in instruction sysvar data
        let mut offset = 2; // num_instructions (u16)
        offset += 2 * instructions.len(); // instruction offset table

        // Add size of all instructions before target
        for (idx, instr) in instructions.iter().enumerate() {
            if idx == self.config.instruction_index {
                break;
            }
            offset += 2; // num_accounts
            offset += instr.num_accounts * 33; // (1 meta + 32 pubkey) per account
            offset += 32; // program_id
            offset += 2; // data_len
            offset += instr.data_len; // instruction data
        }

        // Now at target instruction start
        offset += 2; // num_accounts
        offset += target_instruction.num_accounts * 33; // accounts
        offset += 32; // program_id
        offset += 2; // data_len
        // offset now points to start of instruction data

        let mut sysvar_offsets = Vec::new();
        for forbidden_range in &self.config.forbidden_ranges {
            if forbidden_range.end > target_instruction.data_len {
                anyhow::bail!(
                    "Forbidden range {:?} exceeds instruction data length {}",
                    forbidden_range,
                    target_instruction.data_len
                );
            }

            sysvar_offsets.push(
                (offset + forbidden_range.start)..(offset + forbidden_range.end),
            );
        }

        Ok(sysvar_offsets)
    }

    /// Calculate VM memory address ranges for forbidden bytes in the instruction sysvar.
    ///
    /// This assumes the sysvar data starts at MM_INPUT_START (useful for the
    /// standalone example). For actual VM-level detection, use
    /// `calculate_forbidden_sysvar_offsets()` combined with the runtime's
    /// `vm_data_addr` for the instructions sysvar account.
    pub fn calculate_forbidden_vm_ranges(
        &self,
        instructions: &[InstructionInfo],
    ) -> Result<Vec<Range<u64>>> {
        use solana_sbpf::ebpf::MM_INPUT_START;

        let sysvar_offsets = self.calculate_forbidden_sysvar_offsets(instructions)?;
        Ok(sysvar_offsets
            .into_iter()
            .map(|r| {
                (MM_INPUT_START + r.start as u64)..(MM_INPUT_START + r.end as u64)
            })
            .collect())
    }
}

/// Simplified instruction info for address calculation
#[derive(Debug, Clone)]
pub struct InstructionInfo {
    /// Number of accounts in this instruction
    pub num_accounts: usize,
    /// Length of instruction data in bytes
    pub data_len: usize,
}

impl InstructionInfo {
    pub fn new(num_accounts: usize, data_len: usize) -> Self {
        Self {
            num_accounts,
            data_len,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use solana_sbpf::ebpf::MM_INPUT_START;

    #[test]
    fn test_detection_config_default() {
        let config = DetectionConfig::default();
        assert_eq!(config.instruction_index, 0);
        assert_eq!(config.forbidden_ranges, vec![8..16]);
    }

    #[test]
    fn test_detection_config_new() {
        let config = DetectionConfig::new(1, 4, 12);
        assert_eq!(config.instruction_index, 1);
        assert_eq!(config.forbidden_ranges, vec![4..12]);
    }

    #[test]
    fn test_detection_config_with_ranges() {
        let ranges = vec![0..4, 8..16, 20..24];
        let config = DetectionConfig::with_ranges(0, ranges.clone());
        assert_eq!(config.instruction_index, 0);
        assert_eq!(config.forbidden_ranges, ranges);
    }

    #[test]
    fn test_calculate_forbidden_vm_ranges_simple() {
        // Single instruction with no accounts, 16 bytes of data
        let instructions = vec![InstructionInfo::new(0, 16)];

        let detector = GobbleDetector::new(DetectionConfig::new(0, 8, 16));
        let ranges = detector.calculate_forbidden_vm_ranges(&instructions).unwrap();

        assert_eq!(ranges.len(), 1);

        // Calculate expected offset:
        // 2 (num_instructions) + 2*1 (offset table) = 4
        // Instruction 0:
        //   2 (num_accounts) + 0*33 (accounts) + 32 (program_id) + 2 (data_len) = 36
        // Total offset to data start = 4 + 36 = 40
        // Forbidden bytes [8..16] → VM addresses [48..56]

        let expected_start = MM_INPUT_START + 48;
        let expected_end = MM_INPUT_START + 56;
        assert_eq!(ranges[0], expected_start..expected_end);
    }

    #[test]
    fn test_calculate_forbidden_vm_ranges_with_accounts() {
        // Instruction with 2 accounts
        let instructions = vec![InstructionInfo::new(2, 16)];

        let detector = GobbleDetector::new(DetectionConfig::new(0, 0, 8));
        let ranges = detector.calculate_forbidden_vm_ranges(&instructions).unwrap();

        // Offset: 4 (header) + 2 (num_accounts) + 2*33 (accounts) + 32 (program_id) + 2 (data_len)
        //       = 4 + 2 + 66 + 32 + 2 = 106
        // Bytes [0..8] → VM [106..114]

        let expected_start = MM_INPUT_START + 106;
        let expected_end = MM_INPUT_START + 114;
        assert_eq!(ranges[0], expected_start..expected_end);
    }

    #[test]
    fn test_calculate_forbidden_vm_ranges_multiple() {
        let instructions = vec![InstructionInfo::new(0, 32)];
        let ranges = vec![0..4, 8..16, 20..24];
        let detector = GobbleDetector::new(DetectionConfig::with_ranges(0, ranges));
        let vm_ranges = detector.calculate_forbidden_vm_ranges(&instructions).unwrap();

        assert_eq!(vm_ranges.len(), 3);

        // Base offset = 40 (as calculated above)
        let base = MM_INPUT_START + 40;
        assert_eq!(vm_ranges[0], base..(base + 4));
        assert_eq!(vm_ranges[1], (base + 8)..(base + 16));
        assert_eq!(vm_ranges[2], (base + 20)..(base + 24));
    }

    #[test]
    fn test_calculate_forbidden_vm_ranges_second_instruction() {
        // Two instructions: first has 1 account and 10 bytes, second has 0 accounts and 20 bytes
        let instructions = vec![
            InstructionInfo::new(1, 10),
            InstructionInfo::new(0, 20),
        ];

        let detector = GobbleDetector::new(DetectionConfig::new(1, 8, 16));
        let ranges = detector.calculate_forbidden_vm_ranges(&instructions).unwrap();

        // Header: 2 + 2*2 = 6
        // Instruction 0: 2 + 1*33 + 32 + 2 + 10 = 79
        // Instruction 1 start: 6 + 79 = 85
        // Instruction 1 data start: 85 + 2 + 0 + 32 + 2 = 121
        // Bytes [8..16] → VM [129..137]

        let expected_start = MM_INPUT_START + 129;
        let expected_end = MM_INPUT_START + 137;
        assert_eq!(ranges[0], expected_start..expected_end);
    }
}
