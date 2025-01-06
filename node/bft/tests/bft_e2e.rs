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

#[allow(dead_code)]
mod common;
#[allow(dead_code)]
mod components;

use crate::common::primary::{TestNetwork, TestNetworkConfig};
use deadline::deadline;
use itertools::Itertools;
use std::time::Duration;

#[tokio::test(flavor = "multi_thread")]
#[ignore = "long-running e2e test"]
async fn test_state_coherence() {
    const N: u16 = 4;
    const TRANSMISSION_INTERVAL_MS: u64 = 10;

    let mut network = TestNetwork::new(TestNetworkConfig {
        num_nodes: N,
        bft: true,
        fire_transmissions: Some(TRANSMISSION_INTERVAL_MS),
        // Set this to Some(0..=4) to see the logs.
        log_level: Some(0),
    });

    network.start().await;

    std::future::pending::<()>().await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "fails"]
async fn test_resync() {
    // Start N nodes, connect them and start the cannons for each.
    const N: u16 = 4;
    const TRANSMISSION_INTERVAL_MS: u64 = 10;
    let mut network = TestNetwork::new(TestNetworkConfig {
        num_nodes: N,
        bft: true,
        fire_transmissions: Some(TRANSMISSION_INTERVAL_MS),
        // Set this to Some(0..=4) to see the logs.
        log_level: Some(0),
    });
    network.start().await;

    // Let the nodes advance through the rounds.
    const BREAK_ROUND: u64 = 4;
    let network_clone = network.clone();
    deadline!(Duration::from_secs(20), move || { network_clone.is_round_reached(BREAK_ROUND) });

    let mut spare_network =
        TestNetwork::new(TestNetworkConfig { num_nodes: N, bft: true, fire_transmissions: None, log_level: None });
    spare_network.start().await;

    for i in 1..N {
        let spare_validator = spare_network.validators.get(&i).cloned().unwrap();
        network.validators.insert(i, spare_validator);
    }

    const RECOVERY_ROUND: u64 = 8;
    let network_clone = network.clone();
    deadline!(Duration::from_secs(20), move || { network_clone.is_round_reached(RECOVERY_ROUND) });
}

#[tokio::test(flavor = "multi_thread")]
async fn test_quorum_break() {
    // Start N nodes, connect them and start the cannons for each.
    const N: u16 = 4;
    const TRANSMISSION_INTERVAL_MS: u64 = 10;
    let mut network = TestNetwork::new(TestNetworkConfig {
        num_nodes: N,
        bft: true,
        fire_transmissions: Some(TRANSMISSION_INTERVAL_MS),
        // Set this to Some(0..=4) to see the logs.
        log_level: None,
    });
    network.start().await;

    // Check the nodes have started advancing through the rounds.
    const TARGET_ROUND: u64 = 4;
    // Note: cloning the network is fine because the primaries it wraps are `Arc`ed.
    let network_clone = network.clone();
    deadline!(Duration::from_secs(20), move || { network_clone.is_round_reached(TARGET_ROUND) });

    // Check the nodes have stopped advancing through the rounds.
    assert!(network.is_halted().await);
}

#[tokio::test(flavor = "multi_thread")]
async fn test_leader_election_consistency() {
    // The minimum and maximum rounds to check for leader consistency.
    // From manual experimentation, the minimum round that works is 4.
    // Starting at 0 or 2 causes assertion failures. Seems like the committee takes a few rounds to stabilize.
    const STARTING_ROUND: u64 = 4;
    const MAX_ROUND: u64 = 20;

    // Start N nodes, connect them and start the cannons for each.
    const N: u16 = 4;
    const CANNON_INTERVAL_MS: u64 = 10;
    let mut network = TestNetwork::new(TestNetworkConfig {
        num_nodes: N,
        bft: true,
        fire_transmissions: Some(CANNON_INTERVAL_MS),
        // Set this to Some(0..=4) to see the logs.
        log_level: None,
    });
    network.start().await;

    // Wait for starting round to be reached
    let cloned_network = network.clone();
    deadline!(Duration::from_secs(60), move || { cloned_network.is_round_reached(STARTING_ROUND) });

    // Check that validators agree about leaders in every even round
    for target_round in (STARTING_ROUND..=MAX_ROUND).step_by(2) {
        let cloned_network = network.clone();
        deadline!(Duration::from_secs(20), move || { cloned_network.is_round_reached(target_round) });

        // Get all validators in the network
        let validators = network.validators.values().collect_vec();

        // Get leaders of all validators in the current round
        let mut leaders = Vec::new();
        for validator in validators.iter() {
            if validator.primary.current_round() == target_round {
                let bft = validator.bft.get().unwrap();
                if let Some(leader) = bft.leader() {
                    // Validator is a live object - just because it's
                    // been on the current round above doesn't mean
                    // that's still the case
                    if validator.primary.current_round() == target_round {
                        leaders.push(leader);
                    }
                }
            }
        }

        println!("Found {} validators with a leader ({} out of sync)", leaders.len(), validators.len() - leaders.len());

        // Assert that all leaders are equal
        assert!(leaders.iter().all_equal());
    }
}
