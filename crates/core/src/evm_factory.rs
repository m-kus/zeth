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

//! Custom EVM factory that extends the standard Ethereum precompiles with ML-KEM-768.

use crate::mlkem::{MLKEM_ADDRESS, mlkem768};
use reth_evm::{
    Database, EthEvm, EvmEnv, EvmFactory,
    eth::EthEvmBuilder,
    precompiles::{DynPrecompile, PrecompilesMap},
    revm::{
        context::{BlockEnv, CfgEnv, TxEnv},
        context_interface::result::{EVMError, HaltReason},
        inspector::{Inspector, NoOpInspector},
        precompile::{PrecompileId, PrecompileSpecId, Precompiles},
        primitives::hardfork::SpecId,
    },
};

type EthEvmContext<DB> = reth_evm::revm::context::Context<BlockEnv, TxEnv, CfgEnv, DB>;

/// EVM factory that extends standard Ethereum precompiles with the ML-KEM-768 precompile.
#[derive(Debug, Clone, Copy, Default)]
#[non_exhaustive]
pub struct ZethEvmFactory;

impl EvmFactory for ZethEvmFactory {
    type Evm<DB: Database, I: Inspector<EthEvmContext<DB>>> = EthEvm<DB, I, Self::Precompiles>;
    type Context<DB: Database> = EthEvmContext<DB>;
    type Tx = TxEnv;
    type Error<DBError: core::error::Error + Send + Sync + 'static> = EVMError<DBError>;
    type HaltReason = HaltReason;
    type Spec = SpecId;
    type BlockEnv = BlockEnv;
    type Precompiles = PrecompilesMap;

    fn create_evm<DB: Database>(&self, db: DB, input: EvmEnv) -> Self::Evm<DB, NoOpInspector> {
        let spec = input.cfg_env.spec;
        let mut precompiles = PrecompilesMap::from_static(Precompiles::new(
            PrecompileSpecId::from_spec_id(spec),
        ));
        precompiles.extend_precompiles([(
            MLKEM_ADDRESS,
            DynPrecompile::new(PrecompileId::custom("mlkem768"), |input| {
                mlkem768(input.data, input.gas)
            }),
        )]);
        EthEvmBuilder::new(db, input).precompiles(precompiles).build()
    }

    fn create_evm_with_inspector<DB: Database, I: Inspector<Self::Context<DB>>>(
        &self,
        db: DB,
        input: EvmEnv,
        inspector: I,
    ) -> Self::Evm<DB, I> {
        EthEvm::new(self.create_evm(db, input).into_inner().with_inspector(inspector), true)
    }
}
