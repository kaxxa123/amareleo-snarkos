```
alexubuntu22@WDEV-PC8:~$ snarkos start --nodisplay --dev 0 --validator --network 1



         ╦╬╬╬╬╬╦
        ╬╬╬╬╬╬╬╬╬                    ▄▄▄▄        ▄▄▄
       ╬╬╬╬╬╬╬╬╬╬╬                  ▐▓▓▓▓▌       ▓▓▓
      ╬╬╬╬╬╬╬╬╬╬╬╬╬                ▐▓▓▓▓▓▓▌      ▓▓▓     ▄▄▄▄▄▄       ▄▄▄▄▄▄
     ╬╬╬╬╬╬╬╬╬╬╬╬╬╬╬              ▐▓▓▓  ▓▓▓▌     ▓▓▓   ▄▓▓▀▀▀▀▓▓▄   ▐▓▓▓▓▓▓▓▓▌
    ╬╬╬╬╬╬╬╜ ╙╬╬╬╬╬╬╬            ▐▓▓▓▌  ▐▓▓▓▌    ▓▓▓  ▐▓▓▓▄▄▄▄▓▓▓▌ ▐▓▓▓    ▓▓▓▌
   ╬╬╬╬╬╬╣     ╠╬╬╬╬╬╬           ▓▓▓▓▓▓▓▓▓▓▓▓    ▓▓▓  ▐▓▓▀▀▀▀▀▀▀▀▘ ▐▓▓▓    ▓▓▓▌
  ╬╬╬╬╬╬╣       ╠╬╬╬╬╬╬         ▓▓▓▓▌    ▐▓▓▓▓   ▓▓▓   ▀▓▓▄▄▄▄▓▓▀   ▐▓▓▓▓▓▓▓▓▌
 ╬╬╬╬╬╬╣         ╠╬╬╬╬╬╬       ▝▀▀▀▀      ▀▀▀▀▘  ▀▀▀     ▀▀▀▀▀▀       ▀▀▀▀▀▀
╚╬╬╬╬╬╩           ╩╬╬╬╬╩


👋 Welcome to Aleo! We thank you for running a node and supporting privacy.

🔑 Your development private key for node 0 is APrivateKey1zkp8CZNn3yeCseEtxuVPbDCwSyhGW6yZKUYKfgXmcpoGPWH.

👛 Your Aleo address is aleo1rhgdu77hgyqd3xjj8ucu3jj9r2krwz6mnzyd80gncr5fxcwlh5rsvzp9px.

🧭 Starting a validator node on Aleo Testnet (v0) at 0.0.0.0:4130.

🌐 Starting the REST server at 0.0.0.0:3030.

🔑 Your one-time JWT token is eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhbGVvMXJoZ2R1NzdoZ3lxZDN4amo4dWN1M2pqOXIya3J3ejZtbnp5ZDgwZ25jcjVmeGN3bGg1cnN2enA5cHgiLCJpYXQiOjE3MzQzODI0NjUsImV4cCI6MjA0OTc0MjQ2NX0.F341pGgagY-apIwRqVtQALdqtxmjJbtpdMFlmC8a7J4

⚠️  The open files limit (1024) for this process is lower than recommended.
  • To ensure correct behavior of the node, please raise it to at least 2048.
  • See the `ulimit` command and `/etc/security/limits.conf` for more details.

⚠️  The number of cores (8 cores) on this machine is insufficient for a validator (minimum 64 cores)

⚠️  The amount of RAM (7 GiB) on this machine is insufficient for a validator (minimum 256 GiB)

2024-12-16T20:54:25.234768Z  INFO snarkvm_ledger: Loading the ledger from storage...
2024-12-16T20:54:25.349690Z  INFO snarkos_node_consensus: Starting the consensus instance...
2024-12-16T20:54:25.350656Z  INFO snarkos_node_bft::bft: Starting the BFT instance...
2024-12-16T20:54:25.352047Z  INFO snarkos_node_bft::primary: Starting the primary instance of the memory pool...
2024-12-16T20:54:25.352132Z  INFO snarkos_node_bft::worker: Starting worker instance 0 of the memory pool...
2024-12-16T20:54:25.352217Z  INFO snarkos_node_bft::sync: Syncing storage with the ledger...
2024-12-16T20:54:25.352349Z DEBUG snarkos_node_bft::sync: Syncing storage with the ledger from block 0 to 1...
2024-12-16T20:54:25.352464Z  INFO snarkos_node_bft::sync: Starting the sync module...
2024-12-16T20:54:25.352578Z DEBUG snarkos_node_bft::gateway: Starting the gateway for the memory pool...
2024-12-16T20:54:25.356102Z  INFO snarkos_node_bft::gateway: Started the gateway for the memory pool at '127.0.0.1:5000'
2024-12-16T20:54:25.358139Z DEBUG snarkos_node_rest: REST rate limit per IP - 10 RPS
2024-12-16T20:54:25.364793Z DEBUG snarkos_node_router::heartbeat: No connected peers
2024-12-16T20:54:26.357465Z  INFO snarkos_node_bft::gateway: Starting the heartbeat of the gateway...
2024-12-16T20:54:26.357596Z  INFO snarkos_node_bft::gateway: No connected validators
2024-12-16T20:54:26.357747Z DEBUG snarkos_node_bft::gateway: Connecting to validator 127.0.0.1:5001...
2024-12-16T20:54:26.358203Z  WARN snarkos_node_bft::gateway: Unable to connect to '127.0.0.1:5001' - Connection refused (os error 111)
2024-12-16T20:54:27.857252Z DEBUG snarkos_node_bft::primary: Skipping batch proposal (node is syncing)
2024-12-16T20:54:28.359012Z  INFO snarkos_node::validator: Starting transaction pool...
2024-12-16T20:54:30.358105Z DEBUG snarkos_node_bft::primary: Skipping batch proposal (node is syncing)
2024-12-16T20:54:32.859383Z DEBUG snarkos_node_bft::primary: Skipping batch proposal (node is syncing)
2024-12-16T20:54:35.365124Z  INFO snarkos_node_bft::primary: Proposing a batch with 0 transmissions for round 1...
2024-12-16T20:54:35.368008Z  INFO snarkos_node_bft::primary: Quorum threshold reached - Preparing to certify our batch for round 1...
2024-12-16T20:54:35.376499Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for round 1
2024-12-16T20:54:35.376677Z  INFO snarkos_node_bft::primary:

Our batch with 0 transmissions for round 1 was certified!

2024-12-16T20:54:35.376840Z  INFO snarkos_node_bft::helpers::storage: Starting round 2...
2024-12-16T20:54:35.390152Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 1/1
2024-12-16T20:54:35.398982Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 2/1
2024-12-16T20:54:35.410901Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 3/1
2024-12-16T20:54:37.915843Z  INFO snarkos_node_bft::primary: Proposing a batch with 0 transmissions for round 2...
2024-12-16T20:54:37.918363Z  INFO snarkos_node_bft::primary: Quorum threshold reached - Preparing to certify our batch for round 2...
2024-12-16T20:54:37.928127Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for round 2
2024-12-16T20:54:37.928255Z  INFO snarkos_node_bft::primary:

Our batch with 0 transmissions for round 2 was certified!

2024-12-16T20:54:37.928303Z  INFO snarkos_node_bft::helpers::storage: Starting round 3...
2024-12-16T20:54:37.945221Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 1/2
2024-12-16T20:54:37.956614Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 2/2
2024-12-16T20:54:37.982728Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 3/2
2024-12-16T20:54:40.487198Z  INFO snarkos_node_bft::primary: Proposing a batch with 0 transmissions for round 3...
2024-12-16T20:54:40.489703Z  INFO snarkos_node_bft::primary: Quorum threshold reached - Preparing to certify our batch for round 3...
2024-12-16T20:54:40.497935Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for round 3
2024-12-16T20:54:40.498942Z  INFO snarkos_node_bft::primary:

Our batch with 0 transmissions for round 3 was certified!

2024-12-16T20:54:40.499006Z  INFO snarkos_node_bft::helpers::storage: Starting round 4...
2024-12-16T20:54:40.509560Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 1/3
2024-12-16T20:54:40.521717Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 2/3
2024-12-16T20:54:40.536266Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 3/3
2024-12-16T20:54:41.359260Z  INFO snarkos_node_bft::gateway: No connected validators
2024-12-16T20:54:41.359443Z DEBUG snarkos_node_bft::gateway: Connecting to validator 127.0.0.1:5001...
2024-12-16T20:54:41.359788Z  WARN snarkos_node_bft::gateway: Unable to connect to '127.0.0.1:5001' - Connection refused (os error 111)
2024-12-16T20:54:43.020919Z  INFO snarkos_node::validator: Transaction pool broadcasted the transaction
2024-12-16T20:54:43.069423Z  INFO snarkos_node_bft::primary: Proposing a batch with 1 transmissions for round 4...
2024-12-16T20:54:43.071091Z  INFO snarkos_node_bft::primary: Quorum threshold reached - Preparing to certify our batch for round 4...
2024-12-16T20:54:43.077400Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for round 4
2024-12-16T20:54:43.077499Z  INFO snarkos_node_bft::primary:

Our batch with 1 transmissions for round 4 was certified!

2024-12-16T20:54:43.077535Z  INFO snarkos_node_bft::helpers::storage: Starting round 5...
2024-12-16T20:54:43.085450Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 1/4
2024-12-16T20:54:43.092818Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 2/4
2024-12-16T20:54:43.1s00570Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 3/4
2024-12-16T20:54:45.603146Z  INFO snarkos_node_bft::primary: Proposing a batch with 0 transmissions for round 5...
2024-12-16T20:54:45.604850Z  INFO snarkos_node_bft::primary: Quorum threshold reached - Preparing to certify our batch for round 5...
2024-12-16T20:54:45.611316Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for round 5
2024-12-16T20:54:45.612070Z  INFO snarkos_node_bft::primary:

Our batch with 0 transmissions for round 5 was certified!

2024-12-16T20:54:45.612093Z  INFO snarkos_node_bft::helpers::storage: Starting round 6...
2024-12-16T20:54:45.621546Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 1/5
2024-12-16T20:54:45.631036Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 2/5
2024-12-16T20:54:45.642442Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 3/5
2024-12-16T20:54:48.144742Z  INFO snarkos_node_bft::primary: Proposing a batch with 0 transmissions for round 6...
2024-12-16T20:54:48.146359Z  INFO snarkos_node_bft::primary: Quorum threshold reached - Preparing to certify our batch for round 6...
2024-12-16T20:54:48.153136Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for round 6
2024-12-16T20:54:48.153196Z  INFO snarkos_node_bft::primary:

Our batch with 0 transmissions for round 6 was certified!

2024-12-16T20:54:48.153209Z  INFO snarkos_node_bft::helpers::storage: Starting round 7...
2024-12-16T20:54:48.167330Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 1/6
2024-12-16T20:54:48.181273Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 2/6
2024-12-16T20:54:48.195577Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 3/6
2024-12-16T20:54:50.366329Z DEBUG snarkos_node_router::heartbeat: No connected peers
2024-12-16T20:54:50.456734Z  INFO snarkos_node::validator: Transaction pool broadcasted the transaction
2024-12-16T20:54:50.723932Z  INFO snarkos_node_bft::primary: Proposing a batch with 1 transmissions for round 7...
2024-12-16T20:54:50.725403Z  INFO snarkos_node_bft::primary: Quorum threshold reached - Preparing to certify our batch for round 7...
2024-12-16T20:54:50.731990Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for round 7
2024-12-16T20:54:50.732785Z  INFO snarkos_node_bft::primary:

Our batch with 1 transmissions for round 7 was certified!

2024-12-16T20:54:50.732813Z  INFO snarkos_node_bft::helpers::storage: Starting round 8...
2024-12-16T20:54:50.738750Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 1/7
2024-12-16T20:54:50.744624Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 2/7
2024-12-16T20:54:50.750698Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 3/7
2024-12-16T20:54:53.254033Z  INFO snarkos_node_bft::primary: Proposing a batch with 0 transmissions for round 8...
2024-12-16T20:54:53.255828Z  INFO snarkos_node_bft::primary: Quorum threshold reached - Preparing to certify our batch for round 8...
2024-12-16T20:54:53.263192Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for round 8
2024-12-16T20:54:53.263275Z  INFO snarkos_node_bft::primary:

Our batch with 0 transmissions for round 8 was certified!

2024-12-16T20:54:53.263289Z  INFO snarkos_node_bft::helpers::storage: Starting round 9...
2024-12-16T20:54:53.274224Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 1/8
2024-12-16T20:54:53.284784Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 2/8
2024-12-16T20:54:53.294232Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 3/8
2024-12-16T20:54:55.798011Z  INFO snarkos_node_bft::primary: Proposing a batch with 0 transmissions for round 9...
2024-12-16T20:54:55.799563Z  INFO snarkos_node_bft::primary: Quorum threshold reached - Preparing to certify our batch for round 9...
2024-12-16T20:54:55.809054Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for round 9
2024-12-16T20:54:55.810096Z  INFO snarkos_node_bft::primary:

Our batch with 0 transmissions for round 9 was certified!

2024-12-16T20:54:55.810131Z  INFO snarkos_node_bft::helpers::storage: Starting round 10...
2024-12-16T20:54:55.820454Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 1/9
2024-12-16T20:54:55.831912Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 2/9
2024-12-16T20:54:55.842073Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 3/9
2024-12-16T20:54:56.360774Z  INFO snarkos_node_bft::gateway: No connected validators
2024-12-16T20:54:56.360930Z DEBUG snarkos_node_bft::gateway: Connecting to validator 127.0.0.1:5001...
2024-12-16T20:54:56.361196Z  WARN snarkos_node_bft::gateway: Unable to connect to '127.0.0.1:5001' - Connection refused (os error 111)
2024-12-16T20:54:57.755534Z  INFO snarkos_node::validator: Transaction pool broadcasted the transaction
2024-12-16T20:54:58.369463Z  INFO snarkos_node_bft::primary: Proposing a batch with 1 transmissions for round 10...
2024-12-16T20:54:58.371031Z  INFO snarkos_node_bft::primary: Quorum threshold reached - Preparing to certify our batch for round 10...
2024-12-16T20:54:58.377540Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for round 10
2024-12-16T20:54:58.377672Z  INFO snarkos_node_bft::primary:

Our batch with 1 transmissions for round 10 was certified!

2024-12-16T20:54:58.377744Z  INFO snarkos_node_bft::helpers::storage: Starting round 11...
2024-12-16T20:54:58.383896Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 1/10
2024-12-16T20:54:58.390087Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 2/10
2024-12-16T20:54:58.396185Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 3/10
2024-12-16T20:55:00.900720Z  INFO snarkos_node_bft::primary: Proposing a batch with 0 transmissions for round 11...
2024-12-16T20:55:00.902565Z  INFO snarkos_node_bft::primary: Quorum threshold reached - Preparing to certify our batch for round 11...
2024-12-16T20:55:00.911325Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for round 11
2024-12-16T20:55:00.912696Z  INFO snarkos_node_bft::primary:

Our batch with 0 transmissions for round 11 was certified!

2024-12-16T20:55:00.912760Z  INFO snarkos_node_bft::helpers::storage: Starting round 12...
2024-12-16T20:55:00.924054Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 1/11
2024-12-16T20:55:00.934153Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 2/11
2024-12-16T20:55:00.945577Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 3/11
2024-12-16T20:55:03.448650Z  INFO snarkos_node_bft::primary: Proposing a batch with 0 transmissions for round 12...
2024-12-16T20:55:03.450398Z  INFO snarkos_node_bft::primary: Quorum threshold reached - Preparing to certify our batch for round 12...
2024-12-16T20:55:03.457809Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for round 12
2024-12-16T20:55:03.457890Z  INFO snarkos_node_bft::primary:

Our batch with 0 transmissions for round 12 was certified!

2024-12-16T20:55:03.457925Z  INFO snarkos_node_bft::helpers::storage: Starting round 13...
2024-12-16T20:55:03.468050Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 1/12
2024-12-16T20:55:03.479617Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 2/12
2024-12-16T20:55:03.491453Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 3/12
2024-12-16T20:55:04.487996Z  INFO snarkos_node::validator: Transaction pool broadcasted the transaction
2024-12-16T20:55:06.057897Z  INFO snarkos_node_bft::primary: Proposing a batch with 1 transmissions for round 13...
2024-12-16T20:55:06.060479Z  INFO snarkos_node_bft::primary: Quorum threshold reached - Preparing to certify our batch for round 13...
2024-12-16T20:55:06.080915Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for round 13
2024-12-16T20:55:06.081967Z  INFO snarkos_node_bft::primary:

Our batch with 1 transmissions for round 13 was certified!

2024-12-16T20:55:06.082022Z  INFO snarkos_node_bft::helpers::storage: Starting round 14...
2024-12-16T20:55:06.104793Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 1/13
2024-12-16T20:55:06.115365Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 2/13
2024-12-16T20:55:06.124970Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 3/13
2024-12-16T20:55:08.627633Z  INFO snarkos_node_bft::primary: Proposing a batch with 0 transmissions for round 14...
2024-12-16T20:55:08.629271Z  INFO snarkos_node_bft::primary: Quorum threshold reached - Preparing to certify our batch for round 14...
2024-12-16T20:55:08.635999Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for round 14
2024-12-16T20:55:08.636088Z  INFO snarkos_node_bft::primary:

Our batch with 0 transmissions for round 14 was certified!

2024-12-16T20:55:08.636126Z  INFO snarkos_node_bft::helpers::storage: Starting round 15...
2024-12-16T20:55:08.646245Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 1/14
2024-12-16T20:55:08.655553Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 2/14
2024-12-16T20:55:08.666364Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 3/14
2024-12-16T20:55:11.168877Z  INFO snarkos_node_bft::primary: Proposing a batch with 0 transmissions for round 15...
2024-12-16T20:55:11.170774Z  INFO snarkos_node_bft::primary: Quorum threshold reached - Preparing to certify our batch for round 15...
2024-12-16T20:55:11.180142Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for round 15
2024-12-16T20:55:11.181341Z  INFO snarkos_node_bft::primary:

Our batch with 0 transmissions for round 15 was certified!

2024-12-16T20:55:11.181380Z  INFO snarkos_node_bft::helpers::storage: Starting round 16...
2024-12-16T20:55:11.193732Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 1/15
2024-12-16T20:55:11.206761Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 2/15
2024-12-16T20:55:11.218367Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 3/15
2024-12-16T20:55:11.362006Z  INFO snarkos_node_bft::gateway: No connected validators
2024-12-16T20:55:11.362119Z DEBUG snarkos_node_bft::gateway: Connecting to validator 127.0.0.1:5001...
2024-12-16T20:55:11.362260Z  INFO snarkos_node::validator: Transaction pool broadcasted the transaction
2024-12-16T20:55:11.362323Z  WARN snarkos_node_bft::gateway: Unable to connect to '127.0.0.1:5001' - Connection refused (os error 111)
2024-12-16T20:55:13.749929Z  INFO snarkos_node_bft::primary: Proposing a batch with 1 transmissions for round 16...
2024-12-16T20:55:13.752112Z  INFO snarkos_node_bft::primary: Quorum threshold reached - Preparing to certify our batch for round 16...
2024-12-16T20:55:13.760625Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for round 16
2024-12-16T20:55:13.760752Z  INFO snarkos_node_bft::primary:

Our batch with 1 transmissions for round 16 was certified!

2024-12-16T20:55:13.760866Z  INFO snarkos_node_bft::helpers::storage: Starting round 17...
2024-12-16T20:55:13.770638Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 1/16
2024-12-16T20:55:13.782436Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 2/16
2024-12-16T20:55:13.795049Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 3/16
2024-12-16T20:55:15.367072Z DEBUG snarkos_node_router::heartbeat: No connected peers
2024-12-16T20:55:16.298785Z  INFO snarkos_node_bft::primary: Proposing a batch with 0 transmissions for round 17...
2024-12-16T20:55:16.300540Z  INFO snarkos_node_bft::primary: Quorum threshold reached - Preparing to certify our batch for round 17...
2024-12-16T20:55:16.310704Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for round 17
2024-12-16T20:55:16.311714Z  INFO snarkos_node_bft::primary:

Our batch with 0 transmissions for round 17 was certified!

2024-12-16T20:55:16.311752Z  INFO snarkos_node_bft::helpers::storage: Starting round 18...
2024-12-16T20:55:16.321806Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 1/17
2024-12-16T20:55:16.334295Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 2/17
2024-12-16T20:55:16.345438Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 3/17
2024-12-16T20:55:18.127135Z  INFO snarkos_node::validator: Transaction pool broadcasted the transaction
2024-12-16T20:55:18.868400Z  INFO snarkos_node_bft::primary: Proposing a batch with 1 transmissions for round 18...
2024-12-16T20:55:18.869938Z  INFO snarkos_node_bft::primary: Quorum threshold reached - Preparing to certify our batch for round 18...
2024-12-16T20:55:18.875177Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for round 18
2024-12-16T20:55:18.875236Z  INFO snarkos_node_bft::primary:

Our batch with 1 transmissions for round 18 was certified!

2024-12-16T20:55:18.875256Z  INFO snarkos_node_bft::helpers::storage: Starting round 19...
2024-12-16T20:55:18.881492Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 1/18
2024-12-16T20:55:18.887745Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 2/18
2024-12-16T20:55:18.894211Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 3/18
2024-12-16T20:55:21.398505Z  INFO snarkos_node_bft::primary: Proposing a batch with 0 transmissions for round 19...
2024-12-16T20:55:21.400980Z  INFO snarkos_node_bft::primary: Quorum threshold reached - Preparing to certify our batch for round 19...
2024-12-16T20:55:21.410141Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for round 19
2024-12-16T20:55:21.411110Z  INFO snarkos_node_bft::primary:

Our batch with 0 transmissions for round 19 was certified!

2024-12-16T20:55:21.411139Z  INFO snarkos_node_bft::helpers::storage: Starting round 20...
2024-12-16T20:55:21.422055Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 1/19
2024-12-16T20:55:21.435666Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 2/19
2024-12-16T20:55:21.449380Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 3/19
2024-12-16T20:55:23.952336Z  INFO snarkos_node_bft::primary: Proposing a batch with 0 transmissions for round 20...
2024-12-16T20:55:23.954090Z  INFO snarkos_node_bft::primary: Quorum threshold reached - Preparing to certify our batch for round 20...
2024-12-16T20:55:23.960005Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for round 20
2024-12-16T20:55:23.960077Z  INFO snarkos_node_bft::primary:

Our batch with 0 transmissions for round 20 was certified!

2024-12-16T20:55:23.960117Z  INFO snarkos_node_bft::helpers::storage: Starting round 21...
2024-12-16T20:55:23.968334Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 1/20
2024-12-16T20:55:23.977863Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 2/20
2024-12-16T20:55:23.989243Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 3/20
2024-12-16T20:55:25.688399Z  INFO snarkos_node::validator: Transaction pool broadcasted the transaction
2024-12-16T20:55:26.363721Z  INFO snarkos_node_bft::gateway: No connected validators
2024-12-16T20:55:26.363821Z DEBUG snarkos_node_bft::gateway: Connecting to validator 127.0.0.1:5001...
2024-12-16T20:55:26.364044Z  WARN snarkos_node_bft::gateway: Unable to connect to '127.0.0.1:5001' - Connection refused (os error 111)
2024-12-16T20:55:26.513561Z  INFO snarkos_node_bft::primary: Proposing a batch with 1 transmissions for round 21...
2024-12-16T20:55:26.515098Z  INFO snarkos_node_bft::primary: Quorum threshold reached - Preparing to certify our batch for round 21...
2024-12-16T20:55:26.521818Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for round 21
2024-12-16T20:55:26.522421Z  INFO snarkos_node_bft::primary:

Our batch with 1 transmissions for round 21 was certified!

2024-12-16T20:55:26.522451Z  INFO snarkos_node_bft::helpers::storage: Starting round 22...
2024-12-16T20:55:26.528612Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 1/21
2024-12-16T20:55:26.534853Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 2/21
2024-12-16T20:55:26.541755Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 3/21
2024-12-16T20:55:29.046671Z  INFO snarkos_node_bft::primary: Proposing a batch with 0 transmissions for round 22...
2024-12-16T20:55:29.048874Z  INFO snarkos_node_bft::primary: Quorum threshold reached - Preparing to certify our batch for round 22...
2024-12-16T20:55:29.057261Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for round 22
2024-12-16T20:55:29.057378Z  INFO snarkos_node_bft::primary:

Our batch with 0 transmissions for round 22 was certified!

2024-12-16T20:55:29.057420Z  INFO snarkos_node_bft::helpers::storage: Starting round 23...
2024-12-16T20:55:29.070280Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 1/22
2024-12-16T20:55:29.080723Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 2/22
2024-12-16T20:55:29.090956Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 3/22
2024-12-16T20:55:31.595034Z  INFO snarkos_node_bft::primary: Proposing a batch with 0 transmissions for round 23...
2024-12-16T20:55:31.596963Z  INFO snarkos_node_bft::primary: Quorum threshold reached - Preparing to certify our batch for round 23...
2024-12-16T20:55:31.604381Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for round 23
2024-12-16T20:55:31.605429Z  INFO snarkos_node_bft::primary:

Our batch with 0 transmissions for round 23 was certified!

2024-12-16T20:55:31.605479Z  INFO snarkos_node_bft::helpers::storage: Starting round 24...
2024-12-16T20:55:31.612842Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 1/23
2024-12-16T20:55:31.622547Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 2/23
2024-12-16T20:55:31.634846Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 3/23
2024-12-16T20:55:33.165863Z  INFO snarkos_node::validator: Transaction pool broadcasted the transaction
2024-12-16T20:55:34.169955Z  INFO snarkos_node_bft::primary: Proposing a batch with 1 transmissions for round 24...
2024-12-16T20:55:34.172001Z  INFO snarkos_node_bft::primary: Quorum threshold reached - Preparing to certify our batch for round 24...
2024-12-16T20:55:34.178831Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for round 24
2024-12-16T20:55:34.178904Z  INFO snarkos_node_bft::primary:

Our batch with 1 transmissions for round 24 was certified!

2024-12-16T20:55:34.178929Z  INFO snarkos_node_bft::helpers::storage: Starting round 25...
2024-12-16T20:55:34.185872Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 1/24
2024-12-16T20:55:34.192666Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 2/24
2024-12-16T20:55:34.199570Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 3/24
2024-12-16T20:55:36.702992Z  INFO snarkos_node_bft::primary: Proposing a batch with 0 transmissions for round 25...
2024-12-16T20:55:36.704771Z  INFO snarkos_node_bft::primary: Quorum threshold reached - Preparing to certify our batch for round 25...
2024-12-16T20:55:36.713655Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for round 25
2024-12-16T20:55:36.714717Z  INFO snarkos_node_bft::primary:

Our batch with 0 transmissions for round 25 was certified!

2024-12-16T20:55:36.714757Z  INFO snarkos_node_bft::helpers::storage: Starting round 26...
2024-12-16T20:55:36.725742Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 1/25
2024-12-16T20:55:36.737378Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 2/25
2024-12-16T20:55:36.745395Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 3/25
2024-12-16T20:55:39.248929Z  INFO snarkos_node_bft::primary: Proposing a batch with 0 transmissions for round 26...
2024-12-16T20:55:39.251225Z  INFO snarkos_node_bft::primary: Quorum threshold reached - Preparing to certify our batch for round 26...
2024-12-16T20:55:39.257591Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for round 26
2024-12-16T20:55:39.257661Z  INFO snarkos_node_bft::primary:

Our batch with 0 transmissions for round 26 was certified!

2024-12-16T20:55:39.257694Z  INFO snarkos_node_bft::helpers::storage: Starting round 27...
2024-12-16T20:55:39.266458Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 1/26
2024-12-16T20:55:39.277329Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 2/26
2024-12-16T20:55:39.288754Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 3/26
2024-12-16T20:55:40.368382Z DEBUG snarkos_node_router::heartbeat: No connected peers
2024-12-16T20:55:40.569746Z  INFO snarkos_node::validator: Transaction pool broadcasted the transaction
2024-12-16T20:55:41.365042Z  INFO snarkos_node_bft::gateway: No connected validators
2024-12-16T20:55:41.365159Z DEBUG snarkos_node_bft::gateway: Connecting to validator 127.0.0.1:5001...
2024-12-16T20:55:41.365365Z  WARN snarkos_node_bft::gateway: Unable to connect to '127.0.0.1:5001' - Connection refused (os error 111)
2024-12-16T20:55:41.829177Z  INFO snarkos_node_bft::primary: Proposing a batch with 1 transmissions for round 27...
2024-12-16T20:55:41.831200Z  INFO snarkos_node_bft::primary: Quorum threshold reached - Preparing to certify our batch for round 27...
2024-12-16T20:55:41.839812Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for round 27
2024-12-16T20:55:41.840485Z  INFO snarkos_node_bft::primary:

Our batch with 1 transmissions for round 27 was certified!

2024-12-16T20:55:41.840499Z  INFO snarkos_node_bft::helpers::storage: Starting round 28...
2024-12-16T20:55:41.850848Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 1/27
2024-12-16T20:55:41.859593Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 2/27
2024-12-16T20:55:41.869263Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 3/27
2024-12-16T20:55:44.371759Z  INFO snarkos_node_bft::primary: Proposing a batch with 0 transmissions for round 28...
2024-12-16T20:55:44.373209Z  INFO snarkos_node_bft::primary: Quorum threshold reached - Preparing to certify our batch for round 28...
2024-12-16T20:55:44.378730Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for round 28
2024-12-16T20:55:44.378783Z  INFO snarkos_node_bft::primary:

Our batch with 0 transmissions for round 28 was certified!

2024-12-16T20:55:44.378815Z  INFO snarkos_node_bft::helpers::storage: Starting round 29...
2024-12-16T20:55:44.385672Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 1/28
2024-12-16T20:55:44.393201Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 2/28
2024-12-16T20:55:44.399976Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 3/28
2024-12-16T20:55:46.903396Z  INFO snarkos_node_bft::primary: Proposing a batch with 0 transmissions for round 29...
2024-12-16T20:55:46.905743Z  INFO snarkos_node_bft::primary: Quorum threshold reached - Preparing to certify our batch for round 29...
2024-12-16T20:55:46.914057Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for round 29
2024-12-16T20:55:46.915033Z  INFO snarkos_node_bft::primary:

Our batch with 0 transmissions for round 29 was certified!

2024-12-16T20:55:46.915101Z  INFO snarkos_node_bft::helpers::storage: Starting round 30...
2024-12-16T20:55:46.926101Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 1/29
2024-12-16T20:55:46.936100Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 2/29
2024-12-16T20:55:46.947618Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 3/29
2024-12-16T20:55:47.487874Z  INFO snarkos_node::validator: Transaction pool broadcasted the transaction
2024-12-16T20:55:49.494070Z  INFO snarkos_node_bft::primary: Proposing a batch with 1 transmissions for round 30...
2024-12-16T20:55:49.496662Z  INFO snarkos_node_bft::primary: Quorum threshold reached - Preparing to certify our batch for round 30...
2024-12-16T20:55:49.506295Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for round 30
2024-12-16T20:55:49.506401Z  INFO snarkos_node_bft::primary:

Our batch with 1 transmissions for round 30 was certified!

2024-12-16T20:55:49.506441Z  INFO snarkos_node_bft::helpers::storage: Starting round 31...
2024-12-16T20:55:49.519120Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 1/30
2024-12-16T20:55:49.530643Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 2/30
2024-12-16T20:55:49.540694Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 3/30
2024-12-16T20:55:52.044553Z  INFO snarkos_node_bft::primary: Proposing a batch with 0 transmissions for round 31...
2024-12-16T20:55:52.047026Z  INFO snarkos_node_bft::primary: Quorum threshold reached - Preparing to certify our batch for round 31...
2024-12-16T20:55:52.055633Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for round 31
2024-12-16T20:55:52.056708Z  INFO snarkos_node_bft::primary:

Our batch with 0 transmissions for round 31 was certified!

2024-12-16T20:55:52.056765Z  INFO snarkos_node_bft::helpers::storage: Starting round 32...
2024-12-16T20:55:52.069626Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 1/31
2024-12-16T20:55:52.080685Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 2/31
2024-12-16T20:55:52.089600Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 3/31
2024-12-16T20:55:54.592757Z  INFO snarkos_node_bft::primary: Proposing a batch with 0 transmissions for round 32...
2024-12-16T20:55:54.594572Z  INFO snarkos_node_bft::primary: Quorum threshold reached - Preparing to certify our batch for round 32...
2024-12-16T20:55:54.601892Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for round 32
2024-12-16T20:55:54.601988Z  INFO snarkos_node_bft::primary:

Our batch with 0 transmissions for round 32 was certified!

2024-12-16T20:55:54.602001Z  INFO snarkos_node_bft::helpers::storage: Starting round 33...
2024-12-16T20:55:54.612262Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 1/32
2024-12-16T20:55:54.625434Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 2/32
2024-12-16T20:55:54.636071Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 3/32
2024-12-16T20:55:54.926107Z  INFO snarkos_node::validator: Transaction pool broadcasted the transaction
2024-12-16T20:55:56.366404Z  INFO snarkos_node_bft::gateway: No connected validators
2024-12-16T20:55:56.366529Z DEBUG snarkos_node_bft::gateway: Connecting to validator 127.0.0.1:5001...
2024-12-16T20:55:56.366772Z  WARN snarkos_node_bft::gateway: Unable to connect to '127.0.0.1:5001' - Connection refused (os error 111)
2024-12-16T20:55:57.166613Z  INFO snarkos_node_bft::primary: Proposing a batch with 1 transmissions for round 33...
2024-12-16T20:55:57.169216Z  INFO snarkos_node_bft::primary: Quorum threshold reached - Preparing to certify our batch for round 33...
2024-12-16T20:55:57.178653Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for round 33
2024-12-16T20:55:57.179434Z  INFO snarkos_node_bft::primary:

Our batch with 1 transmissions for round 33 was certified!

2024-12-16T20:55:57.179474Z  INFO snarkos_node_bft::helpers::storage: Starting round 34...
2024-12-16T20:55:57.189446Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 1/33
2024-12-16T20:55:57.201348Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 2/33
2024-12-16T20:55:57.211752Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 3/33
2024-12-16T20:55:59.715635Z  INFO snarkos_node_bft::primary: Proposing a batch with 0 transmissions for round 34...
2024-12-16T20:55:59.717826Z  INFO snarkos_node_bft::primary: Quorum threshold reached - Preparing to certify our batch for round 34...
2024-12-16T20:55:59.726889Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for round 34
2024-12-16T20:55:59.726978Z  INFO snarkos_node_bft::primary:

Our batch with 0 transmissions for round 34 was certified!

2024-12-16T20:55:59.727017Z  INFO snarkos_node_bft::helpers::storage: Starting round 35...
2024-12-16T20:55:59.737270Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 1/34
2024-12-16T20:55:59.745166Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 2/34
2024-12-16T20:55:59.756816Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 3/34
2024-12-16T20:56:01.771985Z  INFO snarkos_node::validator: Transaction pool broadcasted the transaction
2024-12-16T20:56:02.284296Z  INFO snarkos_node_bft::primary: Proposing a batch with 1 transmissions for round 35...
2024-12-16T20:56:02.286664Z  INFO snarkos_node_bft::primary: Quorum threshold reached - Preparing to certify our batch for round 35...
2024-12-16T20:56:02.292747Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for round 35
2024-12-16T20:56:02.293329Z  INFO snarkos_node_bft::primary:

Our batch with 1 transmissions for round 35 was certified!

2024-12-16T20:56:02.293365Z  INFO snarkos_node_bft::helpers::storage: Starting round 36...
2024-12-16T20:56:02.299845Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 1/35
2024-12-16T20:56:02.306617Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 2/35
2024-12-16T20:56:02.312973Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 3/35
2024-12-16T20:56:04.816256Z  INFO snarkos_node_bft::primary: Proposing a batch with 0 transmissions for round 36...
2024-12-16T20:56:04.818873Z  INFO snarkos_node_bft::primary: Quorum threshold reached - Preparing to certify our batch for round 36...
2024-12-16T20:56:04.827825Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for round 36
2024-12-16T20:56:04.827926Z  INFO snarkos_node_bft::primary:

Our batch with 0 transmissions for round 36 was certified!

2024-12-16T20:56:04.827963Z  INFO snarkos_node_bft::helpers::storage: Starting round 37...
2024-12-16T20:56:04.839177Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 1/36
2024-12-16T20:56:04.850576Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 2/36
2024-12-16T20:56:04.862627Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 3/36
2024-12-16T20:56:05.369509Z DEBUG snarkos_node_router::heartbeat: No connected peers
^C2024-12-16T20:56:07.231655Z  WARN snarkos_node::traits: ==========================================================================================
2024-12-16T20:56:07.231738Z  WARN snarkos_node::traits: ⚠️  Attention - Starting the graceful shutdown procedure (ETA: 30 seconds)...
2024-12-16T20:56:07.231783Z  WARN snarkos_node::traits: ⚠️  Attention - To avoid DATA CORRUPTION, do NOT interrupt snarkOS (or press Ctrl+C again)
2024-12-16T20:56:07.231791Z  WARN snarkos_node::traits: ⚠️  Attention - Please wait until the shutdown gracefully completes (ETA: 30 seconds)
2024-12-16T20:56:07.231820Z  WARN snarkos_node::traits: ==========================================================================================
2024-12-16T20:56:07.231835Z  INFO snarkos_node::validator: Shutting down...
2024-12-16T20:56:07.231865Z  INFO snarkos_node_router: Shutting down the router...
2024-12-16T20:56:07.231961Z  INFO snarkos_node_consensus: Shutting down consensus...
2024-12-16T20:56:07.231975Z  INFO snarkos_node_bft::bft: Shutting down the BFT...
2024-12-16T20:56:07.231983Z  INFO snarkos_node_bft::primary: Shutting down the primary...
2024-12-16T20:56:07.232785Z  INFO snarkos_node_bft::helpers::proposal_cache: Storing the proposal cache to /home/alexubuntu22/.current-proposal-cache-1-0...
2024-12-16T20:56:07.237724Z  INFO snarkos_node_bft::gateway: Shutting down the gateway...
2024-12-16T20:56:07.237789Z  INFO snarkos_node::validator: Node has shut down.
alexubuntu22@WDEV-PC8:~$
```