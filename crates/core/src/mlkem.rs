// Copyright 2026 RISC Zero, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! ML-KEM-768 EVM precompile (FIPS 203).
//!
//! Provides deterministic encapsulation and decapsulation at address `0x20`.

use alloy_primitives::{Address, address};
use ml_kem::{EncodedSizeUser, KemCore, MlKem768, kem::Decapsulate};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use reth_evm::revm::precompile::{PrecompileError, PrecompileOutput, PrecompileResult};

/// Precompile address for ML-KEM-768.
pub(crate) const MLKEM_ADDRESS: Address =
    address!("0x0000000000000000000000000000000000000020");

// ABI sizes (FIPS 203, ML-KEM-768)
const EK_SIZE: usize = 1184;
const DK_SIZE: usize = 2400;
const CT_SIZE: usize = 1088;
const SS_SIZE: usize = 32;
const SEED_SIZE: usize = 32;

// Gas costs (placeholder — calibrate via zkVM benchmarks)
const GAS_ENCAPSULATE: u64 = 100_000;
const GAS_DECAPSULATE: u64 = 50_000;

const OP_ENCAPSULATE: u8 = 0x00;
const OP_DECAPSULATE: u8 = 0x01;

/// ML-KEM-768 precompile entry point.
///
/// # ABI
///
/// - **Encapsulate** (`0x00`): `input[0]=0x00 | input[1..1185]=ek | input[1185..1217]=seed`
///   → `output[0..1088]=ct | output[1088..1120]=ss`
/// - **Decapsulate** (`0x01`): `input[0]=0x01 | input[1..2401]=dk | input[2401..3489]=ct`
///   → `output[0..32]=ss`
pub(crate) fn mlkem768(input: &[u8], gas_limit: u64) -> PrecompileResult {
    if input.is_empty() {
        return Err(PrecompileError::other("empty input"));
    }
    match input[0] {
        OP_ENCAPSULATE => encapsulate(&input[1..], gas_limit),
        OP_DECAPSULATE => decapsulate(&input[1..], gas_limit),
        _ => Err(PrecompileError::other("invalid ML-KEM operation")),
    }
}

fn encapsulate(data: &[u8], gas_limit: u64) -> PrecompileResult {
    if gas_limit < GAS_ENCAPSULATE {
        return Err(PrecompileError::OutOfGas);
    }
    if data.len() != EK_SIZE + SEED_SIZE {
        return Err(PrecompileError::other("invalid encapsulate input length"));
    }

    let ek = <MlKem768 as KemCore>::EncapsulationKey::from_bytes(
        data[..EK_SIZE].try_into().expect("EK_SIZE slice"),
    );
    let seed: [u8; SEED_SIZE] = data[EK_SIZE..].try_into().unwrap();
    let mut rng = ChaCha20Rng::from_seed(seed);

    use ml_kem::kem::Encapsulate;
    let (ct, ss) = ek.encapsulate(&mut rng).map_err(|_| PrecompileError::other("encapsulate"))?;

    let mut output = Vec::with_capacity(CT_SIZE + SS_SIZE);
    output.extend_from_slice(ct.as_ref());
    output.extend_from_slice(ss.as_ref());
    Ok(PrecompileOutput::new(GAS_ENCAPSULATE, output.into()))
}

fn decapsulate(data: &[u8], gas_limit: u64) -> PrecompileResult {
    if gas_limit < GAS_DECAPSULATE {
        return Err(PrecompileError::OutOfGas);
    }
    if data.len() != DK_SIZE + CT_SIZE {
        return Err(PrecompileError::other("invalid decapsulate input length"));
    }

    let dk = <MlKem768 as KemCore>::DecapsulationKey::from_bytes(
        data[..DK_SIZE].try_into().expect("DK_SIZE slice"),
    );
    let ct_bytes: &[u8; CT_SIZE] = data[DK_SIZE..].try_into().unwrap();
    let ss = dk.decapsulate(ct_bytes.into()).map_err(|_| PrecompileError::other("decapsulate"))?;
    let ss_bytes: &[u8] = ss.as_ref();

    Ok(PrecompileOutput::new(GAS_DECAPSULATE, ss_bytes.to_vec().into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ml_kem::MlKem768;

    #[test]
    fn roundtrip() {
        let (dk, ek) = MlKem768::generate(&mut rand_core::OsRng);
        let ek_bytes = ek.as_bytes();
        let seed = [0x42u8; SEED_SIZE];

        // Encapsulate
        let mut enc_input = vec![OP_ENCAPSULATE];
        enc_input.extend_from_slice(ek_bytes.as_ref());
        enc_input.extend_from_slice(&seed);

        let enc_out = mlkem768(&enc_input, GAS_ENCAPSULATE).expect("encapsulate");
        assert_eq!(enc_out.bytes.len(), CT_SIZE + SS_SIZE);
        let ct = &enc_out.bytes[..CT_SIZE];
        let ss_enc = &enc_out.bytes[CT_SIZE..];

        // Decapsulate
        let mut dec_input = vec![OP_DECAPSULATE];
        dec_input.extend_from_slice(dk.as_bytes().as_ref());
        dec_input.extend_from_slice(ct);

        let dec_out = mlkem768(&dec_input, GAS_DECAPSULATE).expect("decapsulate");
        assert_eq!(dec_out.bytes.len(), SS_SIZE);
        assert_eq!(&dec_out.bytes[..], ss_enc, "shared secrets must match");
    }

    #[test]
    fn deterministic_encapsulate() {
        let (_dk, ek) = MlKem768::generate(&mut rand_core::OsRng);
        let ek_bytes = ek.as_bytes();
        let seed = [0xABu8; SEED_SIZE];

        let mut input = vec![OP_ENCAPSULATE];
        input.extend_from_slice(ek_bytes.as_ref());
        input.extend_from_slice(&seed);

        let out1 = mlkem768(&input, GAS_ENCAPSULATE).unwrap();
        let out2 = mlkem768(&input, GAS_ENCAPSULATE).unwrap();
        assert_eq!(out1.bytes, out2.bytes, "same seed must produce same output");
    }

    #[test]
    fn invalid_length() {
        let result = mlkem768(&[OP_ENCAPSULATE, 0x00], GAS_ENCAPSULATE);
        assert!(result.is_err());
    }

    #[test]
    fn empty_input() {
        let result = mlkem768(&[], GAS_ENCAPSULATE);
        assert!(result.is_err());
    }

    #[test]
    fn out_of_gas() {
        let (_dk, ek) = MlKem768::generate(&mut rand_core::OsRng);
        let mut input = vec![OP_ENCAPSULATE];
        input.extend_from_slice(ek.as_bytes().as_ref());
        input.extend_from_slice(&[0u8; SEED_SIZE]);

        let result = mlkem768(&input, GAS_ENCAPSULATE - 1);
        assert!(matches!(result, Err(PrecompileError::OutOfGas)));
    }
}
