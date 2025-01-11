// Copyright 2024 Aleo Network Foundation
// This file is part of the snarkOS library.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at:

// http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use crate::{LedgerService, fmt_id, spawn_blocking};
use snarkvm::{
    ledger::{
        Ledger,
        authority::Authority,
        block::{Block, Transaction},
        committee::Committee,
        narwhal::{BatchCertificate, Data, Subdag, Transmission, TransmissionID},
        puzzle::{Solution, SolutionID},
        store::ConsensusStorage,
    },
    prelude::{Address, Field, FromBytes, Network, Result, bail},
    synthesizer::program::FinalizeGlobalState,
};

use anyhow::anyhow;
use indexmap::IndexMap;
use lru::LruCache;
use parking_lot::{Mutex, RwLock};
use rand::{CryptoRng, Rng};
use std::{
    fmt,
    io::Read,
    ops::Range,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

/// The capacity of the LRU holding the recently queried committees.
const COMMITTEE_CACHE_SIZE: usize = 16;

/// A core ledger service.
#[allow(clippy::type_complexity)]
pub struct CoreLedgerService<N: Network, C: ConsensusStorage<N>> {
    ledger: Ledger<N, C>,
    committee_cache: Arc<Mutex<LruCache<u64, Committee<N>>>>,
    latest_leader: Arc<RwLock<Option<(u64, Address<N>)>>>,
    shutdown: Arc<AtomicBool>,
}

impl<N: Network, C: ConsensusStorage<N>> CoreLedgerService<N, C> {
    /// Initializes a new core ledger service.
    pub fn new(ledger: Ledger<N, C>, shutdown: Arc<AtomicBool>) -> Self {
        let committee_cache = Arc::new(Mutex::new(LruCache::new(COMMITTEE_CACHE_SIZE.try_into().unwrap())));
        Self { ledger, committee_cache, latest_leader: Default::default(), shutdown }
    }
}

impl<N: Network, C: ConsensusStorage<N>> fmt::Debug for CoreLedgerService<N, C> {
    /// Implements a custom `fmt::Debug` for `CoreLedgerService`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CoreLedgerService").field("current_committee", &self.current_committee()).finish()
    }
}

#[async_trait]
impl<N: Network, C: ConsensusStorage<N>> LedgerService<N> for CoreLedgerService<N, C> {
    /// Returns the latest round in the ledger.
    fn latest_round(&self) -> u64 {
        self.ledger.latest_round()
    }

    /// Returns the latest block height in the ledger.
    fn latest_block_height(&self) -> u32 {
        self.ledger.latest_height()
    }

    /// Returns the latest block in the ledger.
    fn latest_block(&self) -> Block<N> {
        self.ledger.latest_block()
    }

    /// Returns the latest restrictions ID in the ledger.
    fn latest_restrictions_id(&self) -> Field<N> {
        self.ledger.vm().restrictions().restrictions_id()
    }

    /// Returns the latest cached leader and its associated round.
    fn latest_leader(&self) -> Option<(u64, Address<N>)> {
        *self.latest_leader.read()
    }

    /// Updates the latest cached leader and its associated round.
    fn update_latest_leader(&self, round: u64, leader: Address<N>) {
        *self.latest_leader.write() = Some((round, leader));
    }

    /// Returns `true` if the given block height exists in the ledger.
    fn contains_block_height(&self, height: u32) -> bool {
        self.ledger.contains_block_height(height).unwrap_or(false)
    }

    /// Returns the block height for the given block hash, if it exists.
    fn get_block_height(&self, hash: &N::BlockHash) -> Result<u32> {
        self.ledger.get_height(hash)
    }

    /// Returns the block hash for the given block height, if it exists.
    fn get_block_hash(&self, height: u32) -> Result<N::BlockHash> {
        self.ledger.get_hash(height)
    }

    /// Returns the block round for the given block height, if it exists.
    fn get_block_round(&self, height: u32) -> Result<u64> {
        self.ledger.get_block(height).map(|block| block.round())
    }

    /// Returns the block for the given block height.
    fn get_block(&self, height: u32) -> Result<Block<N>> {
        self.ledger.get_block(height)
    }

    /// Returns the blocks in the given block range.
    /// The range is inclusive of the start and exclusive of the end.
    fn get_blocks(&self, heights: Range<u32>) -> Result<Vec<Block<N>>> {
        self.ledger.get_blocks(heights)
    }

    /// Returns the solution for the given solution ID.
    fn get_solution(&self, solution_id: &SolutionID<N>) -> Result<Solution<N>> {
        self.ledger.get_solution(solution_id)
    }

    /// Returns the unconfirmed transaction for the given transaction ID.
    fn get_unconfirmed_transaction(&self, transaction_id: N::TransactionID) -> Result<Transaction<N>> {
        self.ledger.get_unconfirmed_transaction(&transaction_id)
    }

    /// Returns the batch certificate for the given batch certificate ID.
    fn get_batch_certificate(&self, certificate_id: &Field<N>) -> Result<BatchCertificate<N>> {
        match self.ledger.get_batch_certificate(certificate_id) {
            Ok(Some(certificate)) => Ok(certificate),
            Ok(None) => bail!("No batch certificate found for certificate ID {certificate_id} in the ledger"),
            Err(error) => Err(error),
        }
    }

    /// Returns the current committee.
    fn current_committee(&self) -> Result<Committee<N>> {
        self.ledger.latest_committee()
    }

    /// Returns the committee for the given round.
    fn get_committee_for_round(&self, round: u64) -> Result<Committee<N>> {
        // Check if the committee is already in the cache.
        if let Some(committee) = self.committee_cache.lock().get(&round) {
            return Ok(committee.clone());
        }

        match self.ledger.get_committee_for_round(round)? {
            // Return the committee if it exists.
            Some(committee) => {
                // Insert the committee into the cache.
                self.committee_cache.lock().push(round, committee.clone());
                // Return the committee.
                Ok(committee)
            }
            // Return the current committee if the round is equivalent.
            None => {
                // Retrieve the current committee.
                let current_committee = self.current_committee()?;
                // Return the current committee if the round is equivalent.
                match current_committee.starting_round() == round {
                    true => Ok(current_committee),
                    false => bail!("No committee found for round {round} in the ledger"),
                }
            }
        }
    }

    /// Returns the committee lookback for the given round.
    fn get_committee_lookback_for_round(&self, round: u64) -> Result<Committee<N>> {
        // Get the round number for the previous committee. Note, we subtract 2 from odd rounds,
        // because committees are updated in even rounds.
        let previous_round = match round % 2 == 0 {
            true => round.saturating_sub(1),
            false => round.saturating_sub(2),
        };

        // Get the committee lookback round.
        let committee_lookback_round = previous_round.saturating_sub(Committee::<N>::COMMITTEE_LOOKBACK_RANGE);

        // Retrieve the committee for the committee lookback round.
        self.get_committee_for_round(committee_lookback_round)
    }

    /// Returns `true` if the ledger contains the given certificate ID in block history.
    fn contains_certificate(&self, certificate_id: &Field<N>) -> Result<bool> {
        self.ledger.contains_certificate(certificate_id)
    }

    /// Returns `true` if the transmission exists in the ledger.
    fn contains_transmission(&self, transmission_id: &TransmissionID<N>) -> Result<bool> {
        match transmission_id {
            TransmissionID::Ratification => Ok(false),
            TransmissionID::Solution(solution_id, _) => self.ledger.contains_solution_id(solution_id),
            TransmissionID::Transaction(transaction_id, _) => self.ledger.contains_transaction_id(transaction_id),
        }
    }

    /// Ensures that the given transmission is not a fee and matches the given transmission ID.
    fn ensure_transmission_is_well_formed(
        &self,
        transmission_id: TransmissionID<N>,
        transmission: &mut Transmission<N>,
    ) -> Result<()> {
        match (transmission_id, transmission) {
            (TransmissionID::Ratification, Transmission::Ratification) => {}
            (
                TransmissionID::Transaction(expected_transaction_id, expected_checksum),
                Transmission::Transaction(transaction_data),
            ) => {
                // Deserialize the transaction. If the transaction exceeds the maximum size, then return an error.
                let transaction = match transaction_data.clone() {
                    Data::Object(transaction) => transaction,
                    Data::Buffer(bytes) => Transaction::<N>::read_le(&mut bytes.take(N::MAX_TRANSACTION_SIZE as u64))?,
                };
                // Ensure the transaction ID matches the expected transaction ID.
                if transaction.id() != expected_transaction_id {
                    bail!(
                        "Received mismatching transaction ID - expected {}, found {}",
                        fmt_id(expected_transaction_id),
                        fmt_id(transaction.id()),
                    );
                }

                // Ensure the transmission checksum matches the expected checksum.
                let checksum = transaction_data.to_checksum::<N>()?;
                if checksum != expected_checksum {
                    bail!(
                        "Received mismatching checksum for transaction {} - expected {expected_checksum} but found {checksum}",
                        fmt_id(expected_transaction_id)
                    );
                }

                // Ensure the transaction is not a fee transaction.
                if transaction.is_fee() {
                    bail!("Received a fee transaction in a transmission");
                }

                // Update the transmission with the deserialized transaction.
                *transaction_data = Data::Object(transaction);
            }
            (
                TransmissionID::Solution(expected_solution_id, expected_checksum),
                Transmission::Solution(solution_data),
            ) => {
                match solution_data.clone().deserialize_blocking() {
                    Ok(solution) => {
                        if solution.id() != expected_solution_id {
                            bail!(
                                "Received mismatching solution ID - expected {}, found {}",
                                fmt_id(expected_solution_id),
                                fmt_id(solution.id()),
                            );
                        }

                        // Ensure the transmission checksum matches the expected checksum.
                        let checksum = solution_data.to_checksum::<N>()?;
                        if checksum != expected_checksum {
                            bail!(
                                "Received mismatching checksum for solution {} - expected {expected_checksum} but found {checksum}",
                                fmt_id(expected_solution_id)
                            );
                        }

                        // Update the transmission with the deserialized solution.
                        *solution_data = Data::Object(solution);
                    }
                    Err(err) => {
                        bail!("Failed to deserialize solution: {err}");
                    }
                }
            }
            _ => {
                bail!("Mismatching `(transmission_id, transmission)` pair");
            }
        }

        Ok(())
    }

    /// Checks the given solution is well-formed.
    async fn check_solution_basic(&self, solution_id: SolutionID<N>, solution: Data<Solution<N>>) -> Result<()> {
        // Deserialize the solution.
        let solution = spawn_blocking!(solution.deserialize_blocking())?;
        // Ensure the solution ID matches in the solution.
        if solution_id != solution.id() {
            bail!("Invalid solution - expected {solution_id}, found {}", solution.id());
        }

        // Compute the current epoch hash.
        let epoch_hash = self.ledger.latest_epoch_hash()?;
        // Retrieve the current proof target.
        let proof_target = self.ledger.latest_proof_target();

        // Ensure that the solution is valid for the given epoch.
        let puzzle = self.ledger.puzzle().clone();
        match spawn_blocking!(puzzle.check_solution(&solution, epoch_hash, proof_target)) {
            Ok(()) => Ok(()),
            Err(e) => bail!("Invalid solution '{}' for the current epoch - {e}", fmt_id(solution_id)),
        }
    }

    /// Checks the given transaction is well-formed and unique.
    async fn check_transaction_basic(
        &self,
        transaction_id: N::TransactionID,
        transaction: Data<Transaction<N>>,
    ) -> Result<()> {
        // Deserialize the transaction. If the transaction exceeds the maximum size, then return an error.
        let transaction = spawn_blocking!({
            match transaction {
                Data::Object(transaction) => Ok(transaction),
                Data::Buffer(bytes) => Ok(Transaction::<N>::read_le(&mut bytes.take(N::MAX_TRANSACTION_SIZE as u64))?),
            }
        })?;
        // Ensure the transaction ID matches in the transaction.
        if transaction_id != transaction.id() {
            bail!("Invalid transaction - expected {transaction_id}, found {}", transaction.id());
        }
        // Check if the transmission is a fee transaction.
        if transaction.is_fee() {
            bail!("Invalid transaction - 'Transaction::fee' type is not valid at this stage ({})", transaction.id());
        }
        // Check the transaction is well-formed.
        let ledger = self.ledger.clone();
        spawn_blocking!(ledger.check_transaction_basic(&transaction, None, &mut rand::thread_rng()))
    }

    /// Checks the given block is valid next block.
    fn check_next_block(&self, block: &Block<N>) -> Result<()> {
        self.check_next_block_internal(block, &mut rand::thread_rng())
    }

    /// Returns a candidate for the next block in the ledger, using a committed subdag and its transmissions.
    #[cfg(feature = "ledger-write")]
    fn prepare_advance_to_next_quorum_block(
        &self,
        subdag: Subdag<N>,
        transmissions: IndexMap<TransmissionID<N>, Transmission<N>>,
    ) -> Result<Block<N>> {
        self.ledger.prepare_advance_to_next_quorum_block(subdag, transmissions, &mut rand::thread_rng())
    }

    /// Adds the given block as the next block in the ledger.
    #[cfg(feature = "ledger-write")]
    fn advance_to_next_block(&self, block: &Block<N>) -> Result<()> {
        // If the Ctrl-C handler registered the signal, then skip advancing to the next block.
        if self.shutdown.load(Ordering::Acquire) {
            bail!("Skipping advancing to block {} - The node is shutting down", block.height());
        }
        // Advance to the next block.
        self.ledger.advance_to_next_block(block)?;
        // Update BFT metrics.
        #[cfg(feature = "metrics")]
        {
            let num_sol = block.solutions().len();
            let num_tx = block.transactions().len();

            metrics::gauge(metrics::bft::HEIGHT, block.height() as f64);
            metrics::gauge(metrics::bft::LAST_COMMITTED_ROUND, block.round() as f64);
            metrics::increment_gauge(metrics::blocks::SOLUTIONS, num_sol as f64);
            metrics::increment_gauge(metrics::blocks::TRANSACTIONS, num_tx as f64);
            metrics::update_block_metrics(block);
        }

        tracing::info!("\n\nAdvanced to block {} at round {} - {}\n", block.height(), block.round(), block.hash());
        Ok(())
    }
}

// AlexZ: snarkvm::Ledger::check_next_block() fails due to our cheat that always sets the same leader.
// Here I am extracting some of the snarkvm code that allows me to disable this check rather than
// completely comment out the function.
//
// Relevant log dump:
// DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 2/7
// DEBUG snarkos_node_bft::primary: Inserted signature to signed_proposals 2/7
//  INFO snarkos_node_bft::bft: Checking if the leader is ready to be committed for round 6...
//  INFO snarkos_node_bft::bft: Proceeding to commit round 6 with leader 'aleo1rhgdu77hgyq..'
//
// ERROR snarkos_node_consensus: Unable to advance to the next block - Quorum block 1 is authored by an unexpected leader
//      (found: aleo1rhgdu77hgyqd3xjj8ucu3jj9r2krwz6mnzyd80gncr5fxcwlh5rsvzp9px,
//      expected: aleo12ux3gdauck0v60westgcpqj7v8rrcr3v346e4jtq04q7kkt22czsh808v2)
//
// ERROR snarkos_node_bft::bft: BFT failed to advance the subdag for round 2 - Quorum block 1 is authored by an unexpected
//      leader (found: aleo1rhgdu77hgyqd3xjj8ucu3jj9r2krwz6mnzyd80gncr5fxcwlh5rsvzp9px,
//      expected: aleo12ux3gdauck0v60westgcpqj7v8rrcr3v346e4jtq04q7kkt22czsh808v2)
//
impl<N: Network, C: ConsensusStorage<N>> CoreLedgerService<N, C> {
    /// Checks the given block is valid next block.
    fn check_next_block_internal<R: CryptoRng + Rng>(&self, block: &Block<N>, rng: &mut R) -> Result<()> {
        let height = block.height();

        // Ensure the block hash does not already exist.
        if self.ledger.contains_block_hash(&block.hash())? {
            bail!("Block hash '{}' already exists in the ledger", block.hash())
        }

        // Ensure the block height does not already exist.
        if self.ledger.contains_block_height(block.height())? {
            bail!("Block height '{height}' already exists in the ledger")
        }

        // Ensure the solutions do not already exist.
        for solution_id in block.solutions().solution_ids() {
            if self.ledger.contains_solution_id(solution_id)? {
                bail!("Solution ID {solution_id} already exists in the ledger");
            }
        }

        // Construct the finalize state.
        let state = FinalizeGlobalState::new::<N>(
            block.round(),
            block.height(),
            block.cumulative_weight(),
            block.cumulative_proof_target(),
            block.previous_hash(),
        )?;

        // Ensure speculation over the unconfirmed transactions is correct and ensure each transaction is well-formed and unique.
        let time_since_last_block = block.timestamp().saturating_sub(self.ledger.latest_timestamp());
        let ratified_finalize_operations = self.ledger.vm().check_speculate(
            state,
            time_since_last_block,
            block.ratifications(),
            block.solutions(),
            block.transactions(),
            rng,
        )?;

        // Retrieve the committee lookback.
        let committee_lookback = {
            // Determine the round number for the previous committee. Note, we subtract 2 from odd rounds,
            // because committees are updated in even rounds.
            let previous_round = match block.round() % 2 == 0 {
                true => block.round().saturating_sub(1),
                false => block.round().saturating_sub(2),
            };
            // Determine the committee lookback round.
            let committee_lookback_round = previous_round.saturating_sub(Committee::<N>::COMMITTEE_LOOKBACK_RANGE);
            // Output the committee lookback.
            self.ledger
                .get_committee_for_round(committee_lookback_round)?
                .ok_or(anyhow!("Failed to fetch committee for round {committee_lookback_round}"))?
        };

        // Retrieve the previous committee lookback.
        let previous_committee_lookback = {
            // Calculate the penultimate round, which is the round before the anchor round.
            let penultimate_round = block.round().saturating_sub(1);
            // Determine the round number for the previous committee. Note, we subtract 2 from odd rounds,
            // because committees are updated in even rounds.
            let previous_penultimate_round = match penultimate_round % 2 == 0 {
                true => penultimate_round.saturating_sub(1),
                false => penultimate_round.saturating_sub(2),
            };
            // Determine the previous committee lookback round.
            let penultimate_committee_lookback_round =
                previous_penultimate_round.saturating_sub(Committee::<N>::COMMITTEE_LOOKBACK_RANGE);
            // Output the previous committee lookback.
            self.ledger
                .get_committee_for_round(penultimate_committee_lookback_round)?
                .ok_or(anyhow!("Failed to fetch committee for round {penultimate_committee_lookback_round}"))?
        };

        // Ensure the block is correct.
        let (expected_existing_solution_ids, expected_existing_transaction_ids) = block.verify(
            &self.ledger.latest_block(),
            self.ledger.latest_state_root(),
            &previous_committee_lookback,
            &committee_lookback,
            self.ledger.puzzle(),
            self.ledger.latest_epoch_hash()?,
            time::OffsetDateTime::now_utc().unix_timestamp(),
            ratified_finalize_operations,
        )?;

        // Determine if the block subdag is correctly constructed and is not a combination of multiple subdags.
        self.check_block_subdag_atomicity(block)?;

        // Ensure that each existing solution ID from the block exists in the ledger.
        for existing_solution_id in expected_existing_solution_ids {
            if !self.ledger.contains_solution_id(&existing_solution_id)? {
                bail!("Solution ID '{existing_solution_id}' does not exist in the ledger");
            }
        }

        // Ensure that each existing transaction ID from the block exists in the ledger.
        for existing_transaction_id in expected_existing_transaction_ids {
            if !self.ledger.contains_transaction_id(&existing_transaction_id)? {
                bail!("Transaction ID '{existing_transaction_id}' does not exist in the ledger");
            }
        }

        Ok(())
    }

    /// Checks that the block subdag can not be split into multiple valid subdags.
    fn check_block_subdag_atomicity(&self, block: &Block<N>) -> Result<()> {
        // Returns `true` if there is a path from the previous certificate to the current certificate.
        fn is_linked<N: Network>(
            subdag: &Subdag<N>,
            previous_certificate: &BatchCertificate<N>,
            current_certificate: &BatchCertificate<N>,
        ) -> Result<bool> {
            // Initialize the list containing the traversal.
            let mut traversal = vec![current_certificate];
            // Iterate over the rounds from the current certificate to the previous certificate.
            for round in (previous_certificate.round()..current_certificate.round()).rev() {
                // Retrieve all of the certificates for this past round.
                let certificates = subdag.get(&round).ok_or(anyhow!("No certificates found for round {round}"))?;
                // Filter the certificates to only include those that are in the traversal.
                traversal = certificates
                    .into_iter()
                    .filter(|p| traversal.iter().any(|c| c.previous_certificate_ids().contains(&p.id())))
                    .collect();
            }
            Ok(traversal.contains(&previous_certificate))
        }

        // Check if the block has a subdag.
        let subdag = match block.authority() {
            Authority::Quorum(subdag) => subdag,
            _ => return Ok(()),
        };

        // Iterate over the rounds to find possible leader certificates.
        for round in
            (self.ledger.latest_round().saturating_add(2)..=subdag.anchor_round().saturating_sub(2)).rev().step_by(2)
        {
            // Retrieve the previous committee lookback.
            let previous_committee_lookback = self
                .ledger
                .get_committee_lookback_for_round(round)?
                .ok_or_else(|| anyhow!("No committee lookback found for round {round}"))?;

            // Compute the leader for the commit round.
            let computed_leader = previous_committee_lookback
                .get_leader(round)
                .map_err(|e| anyhow!("Failed to compute leader for round {round}: {e}"))?;

            // Retrieve the previous leader certificates.
            let previous_certificate = match subdag.get(&round).and_then(|certificates| {
                certificates.iter().find(|certificate| certificate.author() == computed_leader)
            }) {
                Some(cert) => cert,
                None => continue,
            };

            // Determine if there is a path between the previous certificate and the subdag's leader certificate.
            if is_linked(subdag, previous_certificate, subdag.leader_certificate())? {
                bail!(
                    "The previous certificate should not be linked to the current certificate in block {}",
                    block.height()
                );
            }
        }

        Ok(())
    }
}
