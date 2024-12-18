```
snarkos start --nodisplay --dev 0 --validator --network 1



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

🔑 Your one-time JWT token is eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhbGVvMXJoZ2R1NzdoZ3lxZDN4amo4dWN1M2pqOXIya3J3ejZtbnp5ZDgwZ25jcjVmeGN3bGg1cnN2enA5cHgiLCJpYXQiOjE3MzQ1NTAwNjMsImV4cCI6MjA0OTkxMDA2M30.1zBaeEOrQ99oaQftqMTv61WOljyT98LcUmiLA0Huoec

⚠️  The open files limit (1024) for this process is lower than recommended.
  • To ensure correct behavior of the node, please raise it to at least 2048.
  • See the `ulimit` command and `/etc/security/limits.conf` for more details.

⚠️  The number of cores (8 cores) on this machine is insufficient for a validator (minimum 64 cores)

⚠️  The amount of RAM (7 GiB) on this machine is insufficient for a validator (minimum 256 GiB)

2024-12-18T19:27:43.156032Z  INFO snarkvm_ledger: Loading the ledger from storage...
2024-12-18T19:27:43.327744Z  INFO snarkos_node_consensus: Starting the consensus instance...
2024-12-18T19:27:43.327883Z  INFO snarkos_node_bft::bft: Starting the BFT instance...
2024-12-18T19:27:43.328739Z  INFO snarkos_node_bft::primary: Starting the primary instance of the memory pool...
2024-12-18T19:27:43.329072Z  INFO snarkos_node_bft::worker: Starting worker instance 0 of the memory pool...
2024-12-18T19:27:43.329795Z  INFO snarkos_node_bft::sync: Syncing storage with the ledger...
2024-12-18T19:27:43.330000Z DEBUG snarkos_node_bft::sync: Syncing storage with the ledger from block 0 to 1...
2024-12-18T19:27:43.330746Z  INFO snarkos_node_bft::sync: Starting the sync module...
2024-12-18T19:27:43.330834Z DEBUG snarkos_node_bft::gateway: Starting the gateway for the memory pool...
2024-12-18T19:27:43.333189Z  INFO snarkos_node_bft::gateway: Started the gateway for the memory pool at '127.0.0.1:5000'
2024-12-18T19:27:43.336559Z DEBUG snarkos_node_rest: REST rate limit per IP - 10 RPS
2024-12-18T19:27:43.344734Z DEBUG snarkos_node_router::heartbeat: No connected peers
2024-12-18T19:27:44.335458Z  INFO snarkos_node_bft::gateway: Starting the heartbeat of the gateway...
2024-12-18T19:27:44.335536Z  INFO snarkos_node_bft::gateway: No connected validators
2024-12-18T19:27:44.336712Z DEBUG snarkos_node_bft::gateway: Connecting to validator 127.0.0.1:5001...
2024-12-18T19:27:44.337368Z  WARN snarkos_node_bft::gateway: Unable to connect to '127.0.0.1:5001' - Connection refused (os error 111)
2024-12-18T19:27:45.834804Z DEBUG snarkos_node_bft::primary: Skipping batch proposal (node is syncing)
2024-12-18T19:27:46.336608Z  INFO snarkos_node::validator: Starting transaction pool...
2024-12-18T19:27:48.335582Z DEBUG snarkos_node_bft::primary: Skipping batch proposal (node is syncing)
2024-12-18T19:27:50.836332Z DEBUG snarkos_node_bft::primary: Skipping batch proposal (node is syncing)
2024-12-18T19:27:53.343161Z  INFO snarkos_node_bft::primary: Proposing a batch with 0 transmissions for round 1...
2024-12-18T19:27:53.346466Z  INFO snarkos_node_bft::primary: Quorum threshold reached - Preparing to certify our batch for round 1...
2024-12-18T19:27:53.361072Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for round 1
2024-12-18T19:27:53.362141Z  INFO snarkos_node_bft::primary:

Our batch with 0 transmissions for round 1 was certified!

2024-12-18T19:27:53.363090Z DEBUG snarkos_node_bft::primary: Primary is not ready to propose the next round
2024-12-18T19:27:53.391723Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 1/1
2024-12-18T19:27:53.407134Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 2/1
2024-12-18T19:27:53.420833Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 3/1
2024-12-18T19:27:55.924633Z  INFO snarkos_node_bft::helpers::storage: Starting round 2...
2024-12-18T19:27:55.924719Z DEBUG snarkos_node_bft::primary: Primary is safely skipping (round 1 was already certified)
2024-12-18T19:27:58.428125Z  INFO snarkos_node_bft::primary: Proposing a batch with 0 transmissions for round 2...
2024-12-18T19:27:58.430437Z  INFO snarkos_node_bft::primary: Quorum threshold reached - Preparing to certify our batch for round 2...
2024-12-18T19:27:58.439507Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for round 2
2024-12-18T19:27:58.439613Z  INFO snarkos_node_bft::primary:

Our batch with 0 transmissions for round 2 was certified!

2024-12-18T19:27:58.439690Z  INFO snarkos_node_bft::bft:

Round 2 elected a leader - aleo1rhgdu77hgyqd3xjj8ucu3jj9r2krwz6mnzyd80gncr5fxcwlh5rsvzp9px

2024-12-18T19:27:58.439853Z DEBUG snarkos_node_bft::primary: Primary is not ready to propose the next round
2024-12-18T19:27:58.449895Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 1/2
2024-12-18T19:27:58.458642Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 2/2
2024-12-18T19:27:58.470877Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 3/2
2024-12-18T19:27:59.337123Z  INFO snarkos_node_bft::gateway: No connected validators
2024-12-18T19:27:59.337248Z DEBUG snarkos_node_bft::gateway: Connecting to validator 127.0.0.1:5001...
2024-12-18T19:27:59.337463Z  WARN snarkos_node_bft::gateway: Unable to connect to '127.0.0.1:5001' - Connection refused (os error 111)
2024-12-18T19:28:00.974538Z  INFO snarkos_node_bft::bft:

Round 2 elected a leader - aleo1rhgdu77hgyqd3xjj8ucu3jj9r2krwz6mnzyd80gncr5fxcwlh5rsvzp9px

2024-12-18T19:28:00.974651Z  INFO snarkos_node_bft::helpers::storage: Starting round 3...
2024-12-18T19:28:00.974697Z DEBUG snarkos_node_bft::primary: Primary is safely skipping (round 2 was already certified)
2024-12-18T19:28:03.478315Z  INFO snarkos_node_bft::primary: Proposing a batch with 0 transmissions for round 3...
2024-12-18T19:28:03.480498Z  INFO snarkos_node_bft::primary: Quorum threshold reached - Preparing to certify our batch for round 3...
2024-12-18T19:28:03.489038Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for round 3
2024-12-18T19:28:03.489099Z  INFO snarkos_node_bft::bft: Checking if the leader is ready to be committed for round 2...
2024-12-18T19:28:03.489157Z  INFO snarkos_node_bft::primary:

Our batch with 0 transmissions for round 3 was certified!

2024-12-18T19:28:03.489234Z DEBUG snarkos_node_bft::primary: Primary is not ready to propose the next round
2024-12-18T19:28:03.498470Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 1/3
2024-12-18T19:28:03.498570Z  INFO snarkos_node_bft::bft: Checking if the leader is ready to be committed for round 2...
2024-12-18T19:28:03.498671Z  INFO snarkos_node_bft::bft: Proceeding to commit round 2 with leader 'aleo1rhgdu77hgyq..'
2024-12-18T19:28:03.547509Z  INFO snarkos_node_bft_ledger_service::ledger:

Advanced to block 1 at round 2 - ab1pcflnte2jhufc6jgm3mxrj62hm8czwgln2thyz94f99u0ereyu8qc6hvh0

2024-12-18T19:28:03.547727Z  INFO snarkos_node_bft::bft:

Committing a subdag from round 2 with 0 transmissions: [(1, 4), (2, 1)]

2024-12-18T19:28:03.563197Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 2/3
2024-12-18T19:28:03.580680Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 3/3
2024-12-18T19:28:04.023926Z  INFO snarkos_node::validator: Transaction pool broadcasted the transaction
2024-12-18T19:28:06.083122Z  INFO snarkos_node_bft::helpers::storage: Starting round 4...
2024-12-18T19:28:06.083194Z DEBUG snarkos_node_bft::primary: Primary is safely skipping (round 3 was already certified)
2024-12-18T19:28:08.345643Z DEBUG snarkos_node_router::heartbeat: No connected peers
2024-12-18T19:28:08.625033Z  INFO snarkos_node_bft::primary: Proposing a batch with 1 transmissions for round 4...
2024-12-18T19:28:08.627064Z  INFO snarkos_node_bft::primary: Quorum threshold reached - Preparing to certify our batch for round 4...
2024-12-18T19:28:08.636561Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for round 4
2024-12-18T19:28:08.636658Z  INFO snarkos_node_bft::primary:

Our batch with 1 transmissions for round 4 was certified!

2024-12-18T19:28:08.636702Z  INFO snarkos_node_bft::bft:

Round 4 elected a leader - aleo1rhgdu77hgyqd3xjj8ucu3jj9r2krwz6mnzyd80gncr5fxcwlh5rsvzp9px

2024-12-18T19:28:08.636731Z DEBUG snarkos_node_bft::primary: Primary is not ready to propose the next round
2024-12-18T19:28:08.649438Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 1/4
2024-12-18T19:28:08.661273Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 2/4
2024-12-18T19:28:08.671962Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 3/4
2024-12-18T19:28:11.174636Z  INFO snarkos_node_bft::bft:

Round 4 elected a leader - aleo1rhgdu77hgyqd3xjj8ucu3jj9r2krwz6mnzyd80gncr5fxcwlh5rsvzp9px

2024-12-18T19:28:11.174701Z  INFO snarkos_node_bft::helpers::storage: Starting round 5...
2024-12-18T19:28:11.174710Z DEBUG snarkos_node_bft::primary: Primary is safely skipping (round 4 was already certified)
2024-12-18T19:28:11.301649Z  INFO snarkos_node::validator: Transaction pool broadcasted the transaction
2024-12-18T19:28:13.707552Z  INFO snarkos_node_bft::primary: Proposing a batch with 1 transmissions for round 5...
2024-12-18T19:28:13.710146Z  INFO snarkos_node_bft::primary: Quorum threshold reached - Preparing to certify our batch for round 5...
2024-12-18T19:28:13.719763Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for round 5
2024-12-18T19:28:13.719814Z  INFO snarkos_node_bft::bft: Checking if the leader is ready to be committed for round 4...
2024-12-18T19:28:13.719849Z  INFO snarkos_node_bft::primary:

Our batch with 1 transmissions for round 5 was certified!

2024-12-18T19:28:13.719885Z DEBUG snarkos_node_bft::primary: Primary is not ready to propose the next round
2024-12-18T19:28:13.732734Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 1/5
2024-12-18T19:28:13.732806Z  INFO snarkos_node_bft::bft: Checking if the leader is ready to be committed for round 4...
2024-12-18T19:28:13.732854Z  INFO snarkos_node_bft::bft: Proceeding to commit round 4 with leader 'aleo1rhgdu77hgyq..'
2024-12-18T19:28:13.848605Z  INFO snarkos_node_bft_ledger_service::ledger:

Advanced to block 2 at round 4 - ab16g3eums866ql6nadsm7lhzyvzehslqpr44se8ss6n3s3225jzuzsanmec6

2024-12-18T19:28:13.848958Z  INFO snarkos_node_bft::bft:

Committing a subdag from round 4 with 1 transmissions: [(2, 3), (3, 4), (4, 1)]

2024-12-18T19:28:13.863013Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 2/5
2024-12-18T19:28:13.876822Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 3/5
2024-12-18T19:28:14.338647Z  INFO snarkos_node_bft::gateway: No connected validators
2024-12-18T19:28:14.338762Z DEBUG snarkos_node_bft::gateway: Connecting to validator 127.0.0.1:5001...
2024-12-18T19:28:14.338962Z  WARN snarkos_node_bft::gateway: Unable to connect to '127.0.0.1:5001' - Connection refused (os error 111)
2024-12-18T19:28:16.380569Z  INFO snarkos_node_bft::helpers::storage: Starting round 6...
2024-12-18T19:28:16.380651Z DEBUG snarkos_node_bft::primary: Primary is safely skipping (round 5 was already certified)
2024-12-18T19:28:18.885357Z  INFO snarkos_node_bft::primary: Proposing a batch with 0 transmissions for round 6...
2024-12-18T19:28:18.887757Z  INFO snarkos_node_bft::primary: Quorum threshold reached - Preparing to certify our batch for round 6...
2024-12-18T19:28:18.896887Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for round 6
2024-12-18T19:28:18.897003Z  INFO snarkos_node_bft::primary:

Our batch with 0 transmissions for round 6 was certified!

2024-12-18T19:28:18.897076Z  INFO snarkos_node_bft::bft:

Round 6 elected a leader - aleo1rhgdu77hgyqd3xjj8ucu3jj9r2krwz6mnzyd80gncr5fxcwlh5rsvzp9px

2024-12-18T19:28:18.897149Z DEBUG snarkos_node_bft::primary: Primary is not ready to propose the next round
2024-12-18T19:28:18.909043Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 1/6
2024-12-18T19:28:18.922141Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 2/6
2024-12-18T19:28:18.933670Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 3/6
2024-12-18T19:28:19.119873Z  INFO snarkos_node::validator: Transaction pool broadcasted the transaction
2024-12-18T19:28:21.437212Z  INFO snarkos_node_bft::bft:

Round 6 elected a leader - aleo1rhgdu77hgyqd3xjj8ucu3jj9r2krwz6mnzyd80gncr5fxcwlh5rsvzp9px

2024-12-18T19:28:21.437329Z  INFO snarkos_node_bft::helpers::storage: Starting round 7...
2024-12-18T19:28:21.437349Z DEBUG snarkos_node_bft::primary: Primary is safely skipping (round 6 was already certified)
2024-12-18T19:28:23.976177Z  INFO snarkos_node_bft::primary: Proposing a batch with 1 transmissions for round 7...
2024-12-18T19:28:23.978761Z  INFO snarkos_node_bft::primary: Quorum threshold reached - Preparing to certify our batch for round 7...
2024-12-18T19:28:23.988372Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for round 7
2024-12-18T19:28:23.988529Z  INFO snarkos_node_bft::bft: Checking if the leader is ready to be committed for round 6...
2024-12-18T19:28:23.988641Z  INFO snarkos_node_bft::primary:

Our batch with 1 transmissions for round 7 was certified!

2024-12-18T19:28:23.988711Z DEBUG snarkos_node_bft::primary: Primary is not ready to propose the next round
2024-12-18T19:28:23.999922Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 1/7
2024-12-18T19:28:24.000012Z  INFO snarkos_node_bft::bft: Checking if the leader is ready to be committed for round 6...
2024-12-18T19:28:24.000092Z  INFO snarkos_node_bft::bft: Proceeding to commit round 6 with leader 'aleo1rhgdu77hgyq..'
2024-12-18T19:28:24.102003Z  INFO snarkos_node_bft_ledger_service::ledger:

Advanced to block 3 at round 6 - ab1je7u6xavyh2jckxj8cthu2kn6k7yxw494upsepeqtmshem0kn5ys7ell0m

2024-12-18T19:28:24.102336Z  INFO snarkos_node_bft::bft:

Committing a subdag from round 6 with 1 transmissions: [(4, 3), (5, 4), (6, 1)]

2024-12-18T19:28:24.115914Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 2/7
2024-12-18T19:28:24.128117Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 3/7
^C2024-12-18T19:28:24.851343Z  WARN snarkos_node::traits: ==========================================================================================
2024-12-18T19:28:24.851400Z  WARN snarkos_node::traits: ⚠️  Attention - Starting the graceful shutdown procedure (ETA: 30 seconds)...
2024-12-18T19:28:24.851406Z  WARN snarkos_node::traits: ⚠️  Attention - To avoid DATA CORRUPTION, do NOT interrupt snarkOS (or press Ctrl+C again)
2024-12-18T19:28:24.851411Z  WARN snarkos_node::traits: ⚠️  Attention - Please wait until the shutdown gracefully completes (ETA: 30 seconds)
2024-12-18T19:28:24.851415Z  WARN snarkos_node::traits: ==========================================================================================
2024-12-18T19:28:24.851447Z  INFO snarkos_node::validator: Shutting down...
2024-12-18T19:28:24.851494Z  INFO snarkos_node_router: Shutting down the router...
2024-12-18T19:28:24.851593Z  INFO snarkos_node_consensus: Shutting down consensus...
2024-12-18T19:28:24.851628Z  INFO snarkos_node_bft::bft: Shutting down the BFT...
2024-12-18T19:28:24.851659Z  INFO snarkos_node_bft::primary: Shutting down the primary...
2024-12-18T19:28:24.851864Z  INFO snarkos_node_bft::helpers::proposal_cache: Storing the proposal cache to /home/alexubuntu22/.current-proposal-cache-1-0...
2024-12-18T19:28:24.852538Z  INFO snarkos_node_bft::gateway: Shutting down the gateway...
2024-12-18T19:28:24.852594Z  INFO snarkos_node::validator: Node has shut down.
```