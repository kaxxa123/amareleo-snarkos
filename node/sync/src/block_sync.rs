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

use crate::{helpers::PeerPair, locators::BlockLocators};
use snarkos_node_bft_ledger_service::LedgerService;
use snarkos_node_sync_locators::{CHECKPOINT_INTERVAL, NUM_RECENT_BLOCKS};
use snarkvm::prelude::{Network, block::Block};

use anyhow::{Result, bail};
use indexmap::IndexMap;
use parking_lot::{Mutex, RwLock};
use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU32, Ordering},
    },
};

#[cfg(not(test))]
pub const REDUNDANCY_FACTOR: usize = 1;
#[cfg(test)]
pub const REDUNDANCY_FACTOR: usize = 3;

/// The maximum number of blocks tolerated before the primary is considered behind its peers.
pub const MAX_BLOCKS_BEHIND: u32 = 1; // blocks

/// This is a dummy IP address that is used to represent the local node.
/// Note: This here does not need to be a real IP address, but it must be unique/distinct from all other connections.
pub const DUMMY_SELF_IP: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 0);

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum BlockSyncMode {
    Router,
    Gateway,
}

impl BlockSyncMode {
    /// Returns `true` if the node is in router mode.
    pub const fn is_router(&self) -> bool {
        matches!(self, Self::Router)
    }

    /// Returns `true` if the node is in gateway mode.
    pub const fn is_gateway(&self) -> bool {
        matches!(self, Self::Gateway)
    }
}

/// A struct that keeps track of the current block sync state.
///
/// # State
/// - When a request is inserted, the `requests` map and `request_timestamps` map insert an entry for the request height.
/// - When a response is inserted, the `requests` map inserts the entry for the request height.
/// - When a request is completed, the `requests` map still has the entry, but its `sync_ips` is empty;
///   the `request_timestamps` map remains unchanged.
/// - When a response is removed/completed, the `requests` map and `request_timestamps` map also remove the entry for the request height.
/// - When a request is timed out, the `requests`, `request_timestamps`, and `responses` map remove the entry for the request height;
#[derive(Clone, Debug)]
pub struct BlockSync<N: Network> {
    /// The block sync mode.
    mode: BlockSyncMode,
    /// The canonical map of block height to block hash.
    /// This map is a linearly-increasing map of block heights to block hashes,
    /// updated solely from the ledger and candidate blocks (not from peers' block locators, to ensure there are no forks).
    canon: Arc<dyn LedgerService<N>>,
    /// The map of peer IP to their block locators.
    /// The block locators are consistent with the canonical map and every other peer's block locators.
    locators: Arc<RwLock<HashMap<SocketAddr, BlockLocators<N>>>>,
    /// The map of peer-to-peer to their common ancestor.
    /// This map is used to determine which peers to request blocks from.
    common_ancestors: Arc<RwLock<IndexMap<PeerPair, u32>>>,
    /// The boolean indicator of whether the node is synced up to the latest block (within the given tolerance).
    is_block_synced: Arc<AtomicBool>,
    /// The number of blocks the peer is behind the greatest peer height.
    num_blocks_behind: Arc<AtomicU32>,
    /// The lock to guarantee advance_with_sync_blocks() is called only once at a time.
    advance_with_sync_blocks_lock: Arc<Mutex<()>>,
}

impl<N: Network> BlockSync<N> {
    /// Initializes a new block sync module.
    pub fn new(mode: BlockSyncMode, ledger: Arc<dyn LedgerService<N>>) -> Self {
        Self {
            mode,
            canon: ledger,
            locators: Default::default(),
            common_ancestors: Default::default(),
            is_block_synced: Default::default(),
            num_blocks_behind: Default::default(),
            advance_with_sync_blocks_lock: Default::default(),
        }
    }

    /// Returns the block sync mode.
    #[inline]
    pub const fn mode(&self) -> BlockSyncMode {
        self.mode
    }

    /// Returns `true` if the node is synced up to the latest block (within the given tolerance).
    #[inline]
    pub fn is_block_synced(&self) -> bool {
        self.is_block_synced.load(Ordering::SeqCst)
    }

    /// Returns the number of blocks the node is behind the greatest peer height.
    #[inline]
    pub fn num_blocks_behind(&self) -> u32 {
        self.num_blocks_behind.load(Ordering::SeqCst)
    }
}

#[allow(dead_code)]
impl<N: Network> BlockSync<N> {
    /// Returns the latest block height of the given peer IP.
    fn get_peer_height(&self, peer_ip: &SocketAddr) -> Option<u32> {
        self.locators.read().get(peer_ip).map(|locators| locators.latest_locator_height())
    }

    /// Returns the common ancestor for the given peer pair, if it exists.
    fn get_common_ancestor(&self, peer_a: SocketAddr, peer_b: SocketAddr) -> Option<u32> {
        self.common_ancestors.read().get(&PeerPair(peer_a, peer_b)).copied()
    }
}

impl<N: Network> BlockSync<N> {
    /// Returns the block locators.
    #[inline]
    pub fn get_block_locators(&self) -> Result<BlockLocators<N>> {
        // Retrieve the latest block height.
        let latest_height = self.canon.latest_block_height();

        // Initialize the recents map.
        let mut recents = IndexMap::with_capacity(NUM_RECENT_BLOCKS);
        // Retrieve the recent block hashes.
        for height in latest_height.saturating_sub((NUM_RECENT_BLOCKS - 1) as u32)..=latest_height {
            recents.insert(height, self.canon.get_block_hash(height)?);
        }

        // Initialize the checkpoints map.
        let mut checkpoints = IndexMap::with_capacity((latest_height / CHECKPOINT_INTERVAL + 1).try_into()?);
        // Retrieve the checkpoint block hashes.
        for height in (0..=latest_height).step_by(CHECKPOINT_INTERVAL as usize) {
            checkpoints.insert(height, self.canon.get_block_hash(height)?);
        }

        // Construct the block locators.
        BlockLocators::new(recents, checkpoints)
    }

    /// Performs one iteration of the block sync.
    #[inline]
    pub async fn try_block_sync(&self) {
        // Update the state of `is_block_synced` for the sync module.
        self.update_is_block_synced(0, MAX_BLOCKS_BEHIND);
    }

    /// Processes the block response from the given peer IP.
    #[inline]
    pub fn process_block_response(&self, _peer_ip: SocketAddr, blocks: Vec<Block<N>>) -> Result<()> {
        // Insert the candidate blocks into the sync pool.
        if !blocks.is_empty() {
            bail!("The sync pool did not request any blocks")
        }

        Ok(())
    }

    /// Attempts to advance with blocks from the sync pool.
    #[inline]
    pub fn advance_with_sync_blocks(&self, peer_ip: SocketAddr, blocks: Vec<Block<N>>) -> Result<()> {
        // Process the block response from the given peer IP.
        self.process_block_response(peer_ip, blocks)?;

        // Acquire the lock to ensure this function is called only once at a time.
        // If the lock is already acquired, return early.
        let Some(_lock) = self.advance_with_sync_blocks_lock.try_lock() else {
            trace!("Skipping a call to advance_with_sync_blocks() as it is already in progress");
            return Ok(());
        };
        Ok(())
    }
}

impl<N: Network> BlockSync<N> {
    /// Updates the block locators and common ancestors for the given peer IP.
    /// This function checks that the given block locators are well-formed, however it does **not** check
    /// that the block locators are consistent the peer's previous block locators or other peers' block locators.
    pub fn update_peer_locators(&self, peer_ip: SocketAddr, locators: BlockLocators<N>) -> Result<()> {
        // If the locators match the existing locators for the peer, return early.
        if self.locators.read().get(&peer_ip) == Some(&locators) {
            return Ok(());
        }

        // Ensure the given block locators are well-formed.
        locators.ensure_is_valid()?;
        // Update the locators entry for the given peer IP.
        self.locators.write().insert(peer_ip, locators.clone());

        // Compute the common ancestor with this node.
        // Attention: Please do not optimize this loop, as it performs fork-detection. In addition,
        // by iterating upwards, it also early-terminates malicious block locators at the *first* point
        // of bifurcation in their ledger history, which is a critical safety guarantee provided here.
        let mut ancestor = 0;
        for (height, hash) in locators.clone().into_iter() {
            if let Ok(canon_hash) = self.canon.get_block_hash(height) {
                match canon_hash == hash {
                    true => ancestor = height,
                    false => break, // fork
                }
            }
        }
        // Update the common ancestor entry for this node.
        self.common_ancestors.write().insert(PeerPair(DUMMY_SELF_IP, peer_ip), ancestor);

        // Compute the common ancestor with every other peer.
        let mut common_ancestors = self.common_ancestors.write();
        for (other_ip, other_locators) in self.locators.read().iter() {
            // Skip if the other peer is the given peer.
            if other_ip == &peer_ip {
                continue;
            }
            // Compute the common ancestor with the other peer.
            let mut ancestor = 0;
            for (height, hash) in other_locators.clone().into_iter() {
                if let Some(expected_hash) = locators.get_hash(height) {
                    match expected_hash == hash {
                        true => ancestor = height,
                        false => break, // fork
                    }
                }
            }
            common_ancestors.insert(PeerPair(peer_ip, *other_ip), ancestor);
        }

        Ok(())
    }

    /// TODO (howardwu): Remove the `common_ancestor` entry. But check that this is safe
    ///  (that we don't rely upon it for safety when we re-connect with the same peer).
    /// Removes the peer from the sync pool, if they exist.
    pub fn remove_peer(&self, peer_ip: &SocketAddr) {
        // Remove the locators entry for the given peer IP.
        self.locators.write().remove(peer_ip);
    }
}

impl<N: Network> BlockSync<N> {
    /// Updates the state of `is_block_synced` for the sync module.
    fn update_is_block_synced(&self, greatest_peer_height: u32, max_blocks_behind: u32) {
        // Retrieve the latest block height.
        let canon_height = self.canon.latest_block_height();
        trace!(
            "Updating is_block_synced: greatest_peer_height = {greatest_peer_height}, canon_height = {canon_height}"
        );
        // Compute the number of blocks that we are behind by.
        let num_blocks_behind = greatest_peer_height.saturating_sub(canon_height);
        // Determine if the primary is synced.
        let is_synced = num_blocks_behind <= max_blocks_behind;
        // Update the num blocks behind.
        self.num_blocks_behind.store(num_blocks_behind, Ordering::SeqCst);
        // Update the sync status.
        self.is_block_synced.store(is_synced, Ordering::SeqCst);
        // Update the `IS_SYNCED` metric.
        #[cfg(feature = "metrics")]
        metrics::gauge(metrics::bft::IS_SYNCED, is_synced);
    }
}
