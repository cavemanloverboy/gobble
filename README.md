# Gobble

Transaction simulation harness that detects when Solana programs read forbidden bytes from instruction data via the instructions sysvar. This identifies malicious AMMs that snoop on slippage parameters (e.g. `min_amount_out` at bytes 8-16) to provide worse fills during CPI.

## Deployed programs (mainnet-beta)

| Program | Address |
|---------|---------|
| Router | `routerzmjRpidSb1pbhyAViZSfDTPpX7PNk41NC97v1` |
| Gobble | `GoBBLEtFoGJkKGRMe2dtTsEK2DmdDoAJWT1LmQ3sGd5V` |
| AMM | `AMMMMM9H5dFuQjpZJPcQ6ZY8eSqjmj1bJMvkAryTDHbM` |
| GobbleSolana | `GoBBLswskSgbtEUDoboHaSxdHfmUpEa2YQCUW1SmMfcg` |

## Architecture

### `sbpf/` — Modified SBPF VM

Fork of [solana-labs/rbpf](https://github.com/solana-labs/rbpf) with a `MemoryAccessTracker` that records VM memory reads overlapping watched address ranges. Instrumented in both `load<T>()` (individual reads) and `map()` (bulk operations like memcpy/memmove/memcmp).

### `agave/` — Modified Agave runtime

Fork of [anza-xyz/agave](https://github.com/anza-xyz/agave) with forbidden range tracking in `InvokeContext`. Key changes:
- `InvokeContext` accepts forbidden sysvar data offset ranges and translates them to VM addresses using the instructions sysvar account's `vm_data_addr`
- `vm.rs` wires the translated ranges into the SBPF VM's `MemoryAccessTracker`

### `gobble-lib/` — Detection library

Offset calculation logic and detection API. Given instruction metadata (account counts, data lengths), calculates which byte offsets in the serialized instructions sysvar correspond to forbidden instruction data ranges.

### `gobble/` — CLI binary

Takes a bs58-encoded transaction, fetches accounts from RPC, simulates execution, and reports whether any program read the forbidden byte ranges. See [gobble/README.md](gobble/README.md) for CLI usage.

### `programs/` — Test programs (pinocchio + solana-program)

Four programs deployed on mainnet-beta for testing:
- **router** — Routes CPI to a target program, passing instruction data with a discriminator (bytes 0-8) and `min_amount_out` (bytes 8-16)
- **gobble** — Malicious pattern: reads bytes 8-16 from the router's instruction via the instructions sysvar (pinocchio, zero-copy)
- **amm** — Legitimate pattern: only reads bytes 0-8 from its own CPI data, ignores the sysvar
- **gobble-solana** — Uses standard `solana-program-entrypoint` crate; triggers a false positive (see below)

## How detection works

### Instruction sysvar layout

The instructions sysvar serializes all transaction instructions into a binary format:

```
[0..2]:       num_instructions (u16)
[2..2+2*n]:   instruction offset table (u16 per instruction)

Each instruction:
  [0..2]:       num_accounts (u16)
  [2..]:        accounts — (1 byte meta + 32 bytes pubkey) * num_accounts
  [+N..+N+32]:  program_id (32 bytes)
  [+32..+34]:   data_len (u16)
  [+34..]:      instruction data bytes
```

### Detection pipeline

```
1. Parse transaction, identify the target instruction (e.g. index 0)
   |
2. Calculate byte offsets in the sysvar data for forbidden instruction data ranges
   (e.g. bytes 8-16 of instruction 0 -> sysvar offsets [48..56])
   |
3. At runtime, translate sysvar data offsets to VM addresses using the
   instructions sysvar account's vm_data_addr
   |
4. Configure the SBPF VM's MemoryAccessTracker with these VM address ranges
   |
5. Execute the transaction — any program reading the forbidden VM addresses
   gets flagged
   |
6. After execution, check for forbidden memory accesses
```

### Example offset calculation

For a single instruction with 0 accounts and 16 bytes of data, watching bytes [8..16]:

```
Header:
  2 (num_instructions) + 2*1 (offset table) = 4 bytes

Instruction 0:
  2 (num_accounts)
  + 0*33 (no accounts)
  + 32 (program_id)
  + 2 (data_len)
  = 36 bytes

Total offset to data start: 4 + 36 = 40
Forbidden bytes [8..16] -> sysvar offsets [48..56]
```

## Known limitation: false positives

Programs using `load_instruction_at_checked` from the standard `solana-instructions-sysvar` crate trigger false positives. The underlying `deserialize_instruction()` calls `read_slice()` which copies ALL instruction data bytes from the sysvar into a `Vec<u8>`, even if the program only uses bytes 0-8 afterward.

Pinocchio programs don't have this issue — `load_instruction_at()` returns an `IntrospectedInstruction` wrapping a raw pointer (zero-copy), so only bytes actually accessed by the program trigger detection.

The `gobble-solana` test program demonstrates this false positive.

## Building

### Prerequisites

- Rust (stable)
- Solana CLI tools (`cargo-build-sbf`) — only needed to rebuild the test programs

### Build the CLI

```bash
cargo build -p gobble
```

### Build the test programs

```bash
cd programs/gobble && cargo build-sbf
cd ../amm && cargo build-sbf
cd ../router && cargo build-sbf
cd ../gobble-solana && cargo build-sbf
```

Pre-compiled `.so` files are in `gobble-lib/fixtures/`.

## Usage

```bash
# Simulate a transaction and check for forbidden reads of bytes 8-16
./target/debug/gobble '<bs58-encoded-transaction>' -f 8-16

# Custom RPC endpoint
./target/debug/gobble '<bs58-transaction>' --rpc-url https://your-rpc.example.com
```

See [gobble/example.sh](gobble/example.sh) for a complete test run with three pre-built transactions.

## Testing

```bash
# Unit tests (7 tests for offset calculation)
cargo test -p gobble-lib

# End-to-end example with VM-level tracking (no RPC needed)
cargo run --example gobble -p gobble-lib
```

The `gobble` example loads all four programs from fixtures and demonstrates:
1. Router -> Gobble: forbidden access **detected** (true positive)
2. Router -> AMM: forbidden access **not detected** (true negative)
3. Router -> GobbleSolana: forbidden access **detected** (false positive from deserialization)

## License

This project modifies Agave (Apache 2.0) and SBPF (Apache 2.0). See individual LICENSE files.
