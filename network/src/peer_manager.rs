// Copyright (C) 2019-2020 Aleo Systems Inc.
// This file is part of the snarkOS library.

// The snarkOS library is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// The snarkOS library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with the snarkOS library. If not, see <https://www.gnu.org/licenses/>.

use crate::{
    external::{
        message::MessageName,
        message_types::{Block, GetPeers, Transaction, Verack, Version},
        Channel,
    },
    peers::{PeerBook, PeerInfo},
    request::Request,
    Environment,
    NetworkError,
    ReceiveHandler,
    SendHandler,
};

// TODO (howardwu): Move these imports to SyncManager.
use snarkos_consensus::{
    memory_pool::{Entry, MemoryPool},
    ConsensusParameters,
    MerkleTreeLedger,
};
use snarkos_dpc::base_dpc::{
    instantiated::{Components, Tx},
    parameters::PublicParameters,
};
use snarkos_utilities::FromBytes;

use chrono::Utc;
use std::{collections::HashMap, net::SocketAddr, sync::Arc, time::Duration};
use tokio::{
    net::TcpListener,
    sync::{mpsc, oneshot, Mutex, RwLock},
    task,
    time::sleep,
};

pub(crate) type PeerSender = mpsc::Sender<(oneshot::Sender<Arc<Channel>>, MessageName, Vec<u8>, Arc<Channel>)>;
pub(crate) type PeerReceiver = mpsc::Receiver<(oneshot::Sender<Arc<Channel>>, MessageName, Vec<u8>, Arc<Channel>)>;

pub enum PeerMessage {
    /// Received a version message and preparing to send a verack message back.
    VersionToVerack(SocketAddr, Version),
    /// Receive handler has signaled to drop the connection with the specified peer.
    DisconnectFrom(SocketAddr),
}

/// A stateful component for managing the peer connections of this node.
#[derive(Clone)]
pub struct PeerManager {
    /// The parameters and settings of this node server.
    environment: Environment,
    /// The send handler of this node server.
    send_handler: SendHandler,
    /// The receive handler of this node server.
    receive_handler: ReceiveHandler,
    /// The list of connected and disconnected peers of this node server.
    peer_book: Arc<RwLock<PeerBook>>,
    /// The sender for the receive handler to send responses to this manager.
    peer_sender: Arc<RwLock<PeerSender>>,
    /// The receiver for this peer manager to receive responses from the receive handler.
    peer_receiver: Arc<PeerReceiver>,

    sender: Arc<mpsc::Sender<PeerMessage>>,
    receiver: Arc<RwLock<mpsc::Receiver<PeerMessage>>>,
}

impl PeerManager {
    ///
    /// Creates a new instance of `PeerManager`.
    ///
    /// Initializes the `PeerManager` with the following steps.
    /// 1. Attempt to connect to all default bootnodes on the network.
    /// 2. Attempt to connect to all disconnected peers from the stored peer book.
    ///
    #[inline]
    // pub async fn new(environment: Environment) -> Result<Self, NetworkError> {
    pub fn new(environment: &mut Environment) -> Result<Self, NetworkError> {
        trace!("Instantiating peer manager");

        // Create a send handler.
        let send_handler = SendHandler::new();
        // Create a receive handler.
        let mut receive_handler = ReceiveHandler::new(send_handler.clone());

        // Initialize the peer sender and peer receiver.
        let (sender, receiver) = mpsc::channel(1024);
        let (peer_sender, peer_receiver) = (Arc::new(RwLock::new(sender)), Arc::new(receiver));

        // Load the peer book from storage, or create a new peer book.
        let peer_book = PeerBook::new(*environment.local_address());
        // let peer_book = match PeerBook::load(&*environment.storage_read().await) {
        //     // Case 1 - The peer book was found in storage.
        //     Ok(peer_book) => peer_book,
        //     // Case 2 - Either the peer book does not exist in storage, or could not be deserialized.
        //     // Create a new instance of the peer book.
        //     _ => PeerBook::new(*environment.local_address()),
        // };

        // Initialize the sender and receiver.
        let (sender, receiver) = mpsc::channel(1024);
        let (sender, receiver) = (Arc::new(sender), Arc::new(RwLock::new(receiver)));

        // Initialize the peer sender with the receive handler.
        receive_handler.initialize(peer_sender.clone(), sender.clone())?;

        // Instantiate the peer manager.
        let peer_manager = Self {
            environment: environment.clone(),
            send_handler,
            receive_handler,
            peer_book: Arc::new(RwLock::new(peer_book)),
            peer_sender,
            peer_receiver,

            sender,
            receiver,
        };

        // Save the peer book to storage.
        // peer_manager.save_peer_book_to_storage().await?;

        trace!("Instantiated peer manager");
        Ok(peer_manager)
    }

    ///
    /// Broadcasts a connection request to each default bootnode of the network
    /// and each disconnected peer saved in the peer book.
    ///
    #[inline]
    pub async fn initialize(&self) -> Result<(), NetworkError> {
        debug!("Initializing peer manager");

        // Attempt to connect to the default bootnodes of the network.
        trace!("Broadcasting connection requests to the default bootnodes");
        self.connect_to_bootnodes().await?;

        // Check that this node is not a bootnode.
        if !self.environment.is_bootnode() {
            // Attempt to connect to each disconnected peer saved in the peer book.
            trace!("Broadcasting connection requests to disconnected peers");
            self.connect_to_disconnected_peers().await?;
        }

        {
            let environment = self.environment.clone();
            let receive_handler = self.receive_handler.clone();
            let peer_book = self.peer_book.clone();

            task::spawn(async move {
                loop {
                    info!("PEER_MANAGER: START NEXT RECEIVER LISTENER");
                    if let Err(error) = receive_handler
                        .clone()
                        .listen(environment.clone(), peer_book.clone())
                        .await
                    {
                        // TODO: Handle receiver error appropriately with tracing and server state updates.
                        error!("Receive handler errored with {}", error);
                        sleep(Duration::from_secs(10)).await;
                    }

                    info!("PEER_MANAGER: END LISTEN");
                }
            });

            let mut peer_manager = self.clone();
            task::spawn(async move {
                loop {
                    peer_manager.receive_handler().await;
                }
            });
        }

        debug!("Initialized peer manager");
        Ok(())
    }

    ///
    /// Updates the current peer connections and broadcasts new connection requests
    /// to maintain an acceptable number of peers.
    ///
    #[inline]
    pub async fn update(&self) -> Result<(), NetworkError> {
        debug!("Updating peer manager");

        // If this node is connected to less peers than the minimum required,
        // ask every peer this node is connected to for more peers.
        let number_of_connected_peers = self.number_of_connected_peers().await;
        if number_of_connected_peers < self.environment.minimum_number_of_connected_peers() {
            trace!("Connected to {} peers and requesting more", number_of_connected_peers);

            // Broadcast a `GetPeers` message to request for more peers.
            self.broadcast_getpeers_requests().await?;

            // Attempt a connection request with every disconnected peer.
            self.connect_to_disconnected_peers().await?;

            // Attempt a connection request with each bootnode peer again.
            // Reconnect with any bootnode peer this node may have failed to connect to.
            // Filters attempts to connect to itself and already-connected bootnode peers.
            self.connect_to_bootnodes().await?;
        }

        // TODO (howardwu): Unify `Ping` and `Version` requests.
        //  This is a remnant and these currently do not need to be distinct.

        // Broadcast a `Version` request to each connected peer.
        self.broadcast_version_requests().await?;

        // Store the internal state of the peer book.
        self.save_peer_book_to_storage().await?;

        debug!("Updated peer manager");
        Ok(())
    }

    #[inline]
    pub async fn receive_handler(&mut self) {
        warn!("PEER_MANAGER: START NEXT RECEIVER HANDLER");

        if let Some(message) = self.receiver.write().await.recv().await {
            match message {
                PeerMessage::VersionToVerack(remote_address, version) => {
                    debug!("Receiving version message from {}", remote_address);
                    // TODO (howardwu): Move to its own function.
                    /// Receives a handshake request from a connected peer.
                    /// Updates the handshake channel address, if needed.
                    /// Sends a handshake response back to the connected peer.
                    // ORIGINAL CODE

                    // match environment.handshakes().write().await.get_mut(&remote_address) {
                    //     Some(handshake) => {
                    //         handshake.update_address(remote_address);
                    //         handshake.receive(message).await.is_ok()
                    //     }
                    //     None => false,
                    // }
                    let number_of_connected_peers = self.number_of_connected_peers().await;
                    let maximum_number_of_connected_peers = self.environment.maximum_number_of_connected_peers();
                    if number_of_connected_peers < maximum_number_of_connected_peers {
                        /// Receives the version message from a connected peer,
                        /// and sends a verack message to acknowledge back.
                        // You are the new sender and your peer is the receiver.
                        let address_receiver = remote_address;
                        let address_sender = version.receiver;
                        self.send_handler
                            .broadcast(&Request::Verack(Verack::new(
                                version.nonce,
                                address_sender,
                                address_receiver,
                            )))
                            .await;
                    }
                    debug!("Received version message from {}", remote_address);
                }
                PeerMessage::DisconnectFrom(remote_address) => {
                    debug!("Disconnecting from {}", remote_address);
                    self.disconnect_from_peer(&remote_address).await.unwrap();
                    debug!("Disconnected from {}", remote_address);
                }
            }
        }

        warn!("PEER_MANAGER: END HANDLER");
    }

    ///
    /// Returns `true` if the given address is connecting with this node.
    ///
    #[inline]
    pub async fn is_connecting(&self, address: &SocketAddr) -> bool {
        // Acquire a peer book read lock.
        let peer_book = self.peer_book.read().await;
        // Fetch if the given address is connecting in the peer book.
        peer_book.is_connecting(address)
    }

    ///
    /// Returns `true` if the given address is connected with this node.
    ///
    #[inline]
    pub async fn is_connected(&self, address: &SocketAddr) -> bool {
        // Acquire a peer book read lock.
        let peer_book = self.peer_book.read().await;
        // Fetch if the given address is connected in the peer book.
        peer_book.is_connected(address)
    }

    ///
    /// Returns `true` if the given address is a disconnected peer of this node.
    ///
    #[inline]
    pub async fn is_disconnected(&self, address: &SocketAddr) -> bool {
        // Acquire a peer book read lock.
        let peer_book = self.peer_book.read().await;
        // Fetch if the given address is disconnected in the peer book.
        peer_book.is_disconnected(address)
    }

    ///
    /// Returns the number of peers connected to this node.
    ///
    #[inline]
    pub async fn number_of_connected_peers(&self) -> u16 {
        // Acquire a peer book read lock.
        let peer_book = self.peer_book.read().await;
        // Fetch the number of connected peers.
        peer_book.number_of_connected_peers()
    }

    ///
    /// Returns a map of all connected peers with their peer-specific information.
    ///
    #[inline]
    pub async fn connected_peers(&self) -> HashMap<SocketAddr, PeerInfo> {
        // Acquire a peer book read lock.
        let peer_book = self.peer_book.read().await;
        // Fetch the connected peers of this node.
        peer_book.connected_peers().clone()
    }

    ///
    /// Returns a map of all disconnected peers with their peer-specific information.
    ///
    #[inline]
    pub async fn disconnected_peers(&self) -> HashMap<SocketAddr, PeerInfo> {
        // Acquire a peer book read lock.
        let peer_book = self.peer_book.read().await;
        // Fetch the disconnected peers of this node.
        peer_book.disconnected_peers().clone()
    }

    /// Returns the local address of this node.
    #[inline]
    pub fn local_address(&self) -> SocketAddr {
        // TODO (howardwu): Check that env addr and peer book addr match.
        // // Acquire the peer book reader.
        // let peer_book = self.peer_book.read().await;
        // // Fetch the local address of this node.
        // peer_book.local_address()

        *self.environment.local_address()
    }

    /// Updates the local address stored in the `PeerBook`.
    #[inline]
    pub async fn set_local_address(&mut self, local_address: SocketAddr) {
        // Acquire the peer book write lock.
        let mut peer_book = self.peer_book.write().await;
        // Update the local address stored in the peer book.
        peer_book.set_local_address(local_address);
    }

    /// Returns the current handshake nonce for the given connected peer.
    #[inline]
    pub async fn handshake(&self, remote_address: &SocketAddr) -> Result<u64, NetworkError> {
        // Acquire a peer book read lock.
        let peer_book = self.peer_book.read().await;
        // Fetch the handshake of connected peer.
        peer_book.handshake(remote_address)
    }

    /// TODO (howardwu): Add logic to remove the active channels
    ///  and handshakes of the peer from this struct.
    /// Attempts to disconnect the given address from this node.
    #[inline]
    pub async fn disconnect_from_peer(&self, remote_address: &SocketAddr) -> Result<(), NetworkError> {
        // Acquire the peer book write lock.
        let mut peer_book = self.peer_book.write().await;
        // Set the peer as disconnected in the peer book.
        peer_book.set_disconnected(remote_address)
        // TODO (howardwu): Attempt to blindly send disconnect message to peer.
    }

    /// Adds the given address to the disconnected peers in this peer book.
    /// Returns `true` on success. Otherwise, returns `false`.
    #[inline]
    pub async fn found_peer(&self, address: &SocketAddr) -> Result<(), NetworkError> {
        // Acquire the peer book write lock.
        let mut peer_book = self.peer_book.write().await;
        // Add the given address to the peer book.
        peer_book.add_peer(address)
    }

    /// Broadcasts a connection request to all default bootnodes of the network.
    #[inline]
    async fn connect_to_bootnodes(&self) -> Result<(), NetworkError> {
        trace!("Connecting to bootnodes");

        // Fetch the local address of this node.
        let local_address = self.local_address();
        // Fetch the current connected peers of this node.
        let connected_peers = self.connected_peers().await;
        // Fetch the current block height of this node.
        let block_height = self.environment.current_block_height().await;

        // Iterate through each bootnode address and attempt a connection request.
        for bootnode_address in self.environment.bootnodes().iter() {
            // Check that this node does not try connecting to itself.
            let is_self = local_address == *bootnode_address;
            // Check that this node does not try reconnecting to a connected peer.
            let is_connected = connected_peers.contains_key(bootnode_address);

            if !is_self && !is_connected {
                // Initialize the `Version` request.
                // TODO (raychu86): Establish a formal node version.
                let version = Version::new_with_rng(1u64, block_height, local_address, *bootnode_address);
                let request = Request::Version(version.clone());

                // Set the bootnode as a connecting peer in the peer book.
                self.peer_book
                    .write()
                    .await
                    .set_connecting(bootnode_address, version.nonce);

                // Send a connection request with the send handler.
                self.send_handler.broadcast(&request).await?;
            }
        }

        Ok(())
    }

    /// Broadcasts a connection request to all disconnected peers.
    #[inline]
    async fn connect_to_disconnected_peers(&self) -> Result<(), NetworkError> {
        // Fetch the local address of this node.
        let local_address = self.local_address();
        // Fetch the current block height of this node.
        let block_height = self.environment.current_block_height().await;

        // Iterate through each connected peer and attempts a connection request.
        for (remote_address, _) in self.disconnected_peers().await {
            // Initialize the `Version` request.
            // TODO (raychu86): Establish a formal node version.
            let version = Version::new_with_rng(1u64, block_height, local_address, remote_address);
            let request = Request::Version(version.clone());

            // Set the disconnected peer as a connecting peer in the peer book.
            self.peer_book
                .write()
                .await
                .set_connecting(&remote_address, version.nonce);

            // Send a connection request with the send handler.
            self.send_handler.broadcast(&request).await?;
        }

        Ok(())
    }

    /// TODO (howardwu): Implement manual serializers and deserializers to prevent forward breakage
    ///  when the PeerBook or PeerInfo struct fields change.
    ///
    /// Stores the current peer book to the given storage object.
    ///
    /// This function checks that this node is not connected to itself,
    /// and proceeds to serialize the peer book into a byte vector for storage.
    ///
    #[inline]
    async fn save_peer_book_to_storage(&self) -> Result<(), NetworkError> {
        trace!("Peer manager is saving peer book to storage");

        // Acquire the peer book write lock.
        let mut peer_book = self.peer_book.write().await;
        // Check that the node does not maintain a connection to itself.
        peer_book.remove_peer(&self.local_address());
        // Serialize the peer book.
        let serialized_peer_book = bincode::serialize(&*peer_book)?;
        // Drop the peer book write lock.
        drop(peer_book);

        // Acquire the storage write lock.
        let storage = self.environment.storage_mut().await;
        // Save the serialized peer book to storage.
        storage.save_peer_book_to_storage(serialized_peer_book)?;

        trace!("Peer manager saved peer book to storage");
        Ok(())
    }

    /// Broadcasts a `Version` message to all connected peers.
    #[inline]
    async fn broadcast_version_requests(&self) -> Result<(), NetworkError> {
        // Get the local address of this node.
        let local_address = self.local_address();
        // Fetch the current block height of this node.
        let block_height = self.environment.current_block_height().await;

        // Broadcast a `Version` message to each connected peer for a periodic sync.
        if self.number_of_connected_peers().await > 0 {
            debug!("Sending out periodic version message to peers");

            // Send a `Version` message to every connected peer of this node.
            for (remote_address, _) in self.connected_peers().await {
                // Get the handshake nonce.
                match self.handshake(&remote_address).await {
                    // Case 1 - The remote address is of a connected peer and the nonce was retrieved.
                    Ok(nonce) => {
                        // TODO (raychu86): Establish a formal node version.
                        // Broadcast a `Version` message to the connected peer.
                        self.send_handler
                            .broadcast(&Request::Version(Version::new(
                                1u64,
                                block_height,
                                nonce,
                                local_address,
                                remote_address,
                            )))
                            .await?;
                    }
                    // Case 2 - The remote address is not of a connected peer, proceed to disconnect.
                    Err(error) => {
                        // Disconnect from the peer if there is no active connection channel
                        // TODO (howardwu): Inform SendHandler to also disconnect, by dropping any channels held with this peer.
                        self.disconnect_from_peer(&remote_address).await?;
                    }
                };
            }
        }

        Ok(())
    }

    /// Broadcasts a `GetPeers` message to all connected peers to request for more peers.
    #[inline]
    async fn broadcast_getpeers_requests(&self) -> Result<(), NetworkError> {
        for (remote_address, _) in self.connected_peers().await {
            // Broadcast a `GetPeers` message to the connected peer.
            self.send_handler
                .broadcast(&Request::GetPeers(remote_address, GetPeers))
                .await?;

            // // Fetch the connection channel.
            // if let Some(channel) = self.get_channel(&remote_address) {
            //     // Broadcast the message over the channel.
            //     if let Err(_) = channel.write(&GetPeers).await {
            //         // Disconnect from the peer if the message fails to send.
            //         self.disconnect_from_peer(&remote_address).await?;
            //     }
            // } else {
            //     // Disconnect from the peer if the channel is not active.
            //     self.disconnect_from_peer(&remote_address).await?;
            // }
        }

        Ok(())
    }

    /// TODO (howardwu): Move this to the SyncManager.
    /// Broadcast block to connected peers
    pub async fn propagate_block(&self, block_bytes: Vec<u8>, block_miner: SocketAddr) -> Result<(), NetworkError> {
        debug!("Propagating a block to peers");

        let local_address = self.local_address();
        for (remote_address, _) in self.connected_peers().await {
            if remote_address != block_miner && remote_address != local_address {
                // Broadcast a `Block` message to the connected peer.
                self.send_handler
                    .broadcast(&Request::Block(remote_address, Block::new(block_bytes.clone())))
                    .await?;

                // if let Some(channel) = peer_manager.get_channel(&remote_address) {
                //     match channel.write(&).await {
                //         Ok(_) => num_peers += 1,
                //         Err(error) => warn!(
                //             "Failed to propagate block to peer {}. (error message: {})",
                //             channel.address, error
                //         ),
                //     }
                // }
            }
        }

        Ok(())
    }

    /// TODO (howardwu): Move this to the SyncManager.
    /// Broadcast transaction to connected peers
    pub async fn propagate_transaction(
        &self,
        environment: &Environment,
        transaction_bytes: Vec<u8>,
        transaction_sender: SocketAddr,
    ) -> Result<(), NetworkError> {
        debug!("Propagating a transaction to peers");

        let local_address = self.local_address();

        for (remote_address, _) in self.connected_peers().await {
            if remote_address != transaction_sender && remote_address != local_address {
                // Broadcast a `Block` message to the connected peer.
                self.send_handler
                    .broadcast(&Request::Transaction(
                        remote_address,
                        Transaction::new(transaction_bytes.clone()),
                    ))
                    .await?;

                // if let Some(channel) = connections.get_channel(&socket) {
                //     match channel.write(&Transaction::new(transaction_bytes.clone())).await {
                //         Ok(_) => num_peers += 1,
                //         Err(error) => warn!(
                //             "Failed to propagate transaction to peer {}. (error message: {})",
                //             channel.address, error
                //         ),
                //     }
                // }
            }
        }

        Ok(())
    }

    /// TODO (howardwu): Move this to the SyncManager.
    /// Verify a transaction, add it to the memory pool, propagate it to peers.
    pub async fn process_transaction_internal(
        &self,
        environment: &Environment,
        consensus: &ConsensusParameters,
        parameters: &PublicParameters<Components>,
        storage: &Arc<RwLock<MerkleTreeLedger>>,
        memory_pool: &Arc<Mutex<MemoryPool<Tx>>>,
        transaction_bytes: Vec<u8>,
        transaction_sender: SocketAddr,
    ) -> Result<(), NetworkError> {
        if let Ok(transaction) = Tx::read(&transaction_bytes[..]) {
            let mut memory_pool = memory_pool.lock().await;

            if !consensus.verify_transaction(parameters, &transaction, &*storage.read().await)? {
                error!("Received a transaction that was invalid");
                return Ok(());
            }

            if transaction.value_balance.is_negative() {
                error!("Received a transaction that was a coinbase transaction");
                return Ok(());
            }

            let entry = Entry::<Tx> {
                size_in_bytes: transaction_bytes.len(),
                transaction,
            };

            if let Ok(inserted) = memory_pool.insert(&*storage.read().await, entry) {
                if inserted.is_some() {
                    info!("Transaction added to memory pool.");
                    self.propagate_transaction(environment, transaction_bytes, transaction_sender)
                        .await?;
                }
            }
        }

        Ok(())
    }
}
