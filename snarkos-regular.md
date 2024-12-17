```
snarkos start --nodisplay --dev 0 --validator --network 1 --no-dev-txs



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

🔑 Your one-time JWT token is eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhbGVvMXJoZ2R1NzdoZ3lxZDN4amo4dWN1M2pqOXIya3J3ejZtbnp5ZDgwZ25jcjVmeGN3bGg1cnN2enA5cHgiLCJpYXQiOjE3MzQ0MjUyNTQsImV4cCI6MjA0OTc4NTI1NH0.J-AVy4zQNu6Y-Y7VNDT4T29vfq4-9U9bF9qUwsNN534

⚠️  The open files limit (1024) for this process is lower than recommended.
  • To ensure correct behavior of the node, please raise it to at least 2048.
  • See the `ulimit` command and `/etc/security/limits.conf` for more details.

⚠️  The number of cores (8 cores) on this machine is insufficient for a validator (minimum 64 cores)

⚠️  The amount of RAM (7 GiB) on this machine is insufficient for a validator (minimum 256 GiB)

2024-12-17T08:47:34.053948Z  INFO snarkvm_ledger: Loading the ledger from storage...
2024-12-17T08:47:34.138426Z  INFO snarkos_node_consensus: Starting the consensus instance...
2024-12-17T08:47:34.139751Z  INFO snarkos_node_bft::bft: Starting the BFT instance...
2024-12-17T08:47:34.141023Z  INFO snarkos_node_bft::primary: Starting the primary instance of the memory pool...
2024-12-17T08:47:34.141090Z  INFO snarkos_node_bft::worker: Starting worker instance 0 of the memory pool...
2024-12-17T08:47:34.141142Z  INFO snarkos_node_bft::sync: Syncing storage with the ledger...
2024-12-17T08:47:34.141253Z DEBUG snarkos_node_bft::sync: Syncing storage with the ledger from block 0 to 1...
2024-12-17T08:47:34.142066Z  INFO snarkos_node_bft::sync: Starting the sync module...
2024-12-17T08:47:34.142537Z DEBUG snarkos_node_bft::gateway: Starting the gateway for the memory pool...
2024-12-17T08:47:34.146204Z  INFO snarkos_node_bft::gateway: Started the gateway for the memory pool at '127.0.0.1:5000'
2024-12-17T08:47:34.164568Z DEBUG snarkos_node_rest: REST rate limit per IP - 10 RPS
2024-12-17T08:47:34.173729Z DEBUG snarkos_node_router::heartbeat: No connected peers
2024-12-17T08:47:35.146803Z  INFO snarkos_node_bft::gateway: Starting the heartbeat of the gateway...
2024-12-17T08:47:35.147156Z  INFO snarkos_node_bft::gateway: No connected validators
2024-12-17T08:47:35.147541Z DEBUG snarkos_node_bft::gateway: Connecting to validator 127.0.0.1:5001...
2024-12-17T08:47:35.148091Z  WARN snarkos_node_bft::gateway: Unable to connect to '127.0.0.1:5001' - Connection refused (os error 111)
2024-12-17T08:47:36.647869Z DEBUG snarkos_node_bft::primary: Skipping batch proposal (node is syncing)
2024-12-17T08:47:39.148980Z DEBUG snarkos_node_bft::primary: Skipping batch proposal (node is syncing)
2024-12-17T08:47:41.650390Z DEBUG snarkos_node_bft::primary: Skipping batch proposal (node is syncing)
2024-12-17T08:47:44.152875Z DEBUG snarkos_node_bft::primary: Skipping batch proposal (node is syncing)
2024-12-17T08:47:46.654177Z DEBUG snarkos_node_bft::primary: Skipping batch proposal (node is syncing)
2024-12-17T08:47:49.154766Z DEBUG snarkos_node_bft::primary: Skipping batch proposal (node is syncing)
2024-12-17T08:47:50.148323Z  INFO snarkos_node_bft::gateway: No connected validators
2024-12-17T08:47:50.148535Z DEBUG snarkos_node_bft::gateway: Connecting to validator 127.0.0.1:5001...
2024-12-17T08:47:50.148911Z  WARN snarkos_node_bft::gateway: Unable to connect to '127.0.0.1:5001' - Connection refused (os error 111)
2024-12-17T08:47:51.656433Z DEBUG snarkos_node_bft::primary: Skipping batch proposal (node is syncing)
2024-12-17T08:47:54.158641Z DEBUG snarkos_node_bft::primary: Skipping batch proposal (node is syncing)
2024-12-17T08:47:56.660596Z DEBUG snarkos_node_bft::primary: Skipping batch proposal (node is syncing)
2024-12-17T08:47:59.161853Z DEBUG snarkos_node_bft::primary: Skipping batch proposal (node is syncing)
2024-12-17T08:47:59.175126Z DEBUG snarkos_node_router::heartbeat: No connected peers
2024-12-17T08:48:01.663956Z DEBUG snarkos_node_bft::primary: Skipping batch proposal (node is syncing)
2024-12-17T08:48:04.165339Z DEBUG snarkos_node_bft::primary: Skipping batch proposal (node is syncing)
2024-12-17T08:48:05.150169Z  INFO snarkos_node_bft::gateway: No connected validators
2024-12-17T08:48:05.150396Z DEBUG snarkos_node_bft::gateway: Connecting to validator 127.0.0.1:5001...
2024-12-17T08:48:05.150871Z  WARN snarkos_node_bft::gateway: Unable to connect to '127.0.0.1:5001' - Connection refused (os error 111)
2024-12-17T08:48:06.665904Z DEBUG snarkos_node_bft::primary: Skipping batch proposal (node is syncing)
2024-12-17T08:48:09.167393Z DEBUG snarkos_node_bft::primary: Skipping batch proposal (node is syncing)
2024-12-17T08:48:11.337765Z DEBUG snarkos_node_router::handshake: Received a connection request from '127.0.0.1:55775'
2024-12-17T08:48:11.669296Z DEBUG snarkos_node_bft::primary: Skipping batch proposal (node is syncing)
2024-12-17T08:48:12.335180Z DEBUG snarkos_node_bft::gateway: [MemoryPool] Gateway received a connection request from '127.0.0.1:49279'
2024-12-17T08:48:12.342516Z  INFO snarkos_node_bft::gateway: [MemoryPool] Gateway is connected to '127.0.0.1:5001'
2024-12-17T08:48:14.173681Z DEBUG snarkos_node_bft::primary: Primary is safely skipping a batch proposal (please connect to more validators)
2024-12-17T08:48:16.675714Z DEBUG snarkos_node_bft::primary: Primary is safely skipping a batch proposal (please connect to more validators)
2024-12-17T08:48:19.177262Z DEBUG snarkos_node_bft::primary: Primary is safely skipping a batch proposal (please connect to more validators)
2024-12-17T08:48:20.150986Z  INFO snarkos_node_bft::gateway: Connected to 1 validators (of 3 bonded validators)
2024-12-17T08:48:20.151143Z DEBUG snarkos_node_bft::gateway:   127.0.0.1:5001 - aleo1s3ws5tra87fjycnjrwsjcrnw2qxr8jfqqdugnf0xzqqw29q9m5pqem2u4t
2024-12-17T08:48:21.678094Z DEBUG snarkos_node_bft::primary: Primary is safely skipping a batch proposal (please connect to more validators)
2024-12-17T08:48:24.175700Z DEBUG snarkos_node_router::heartbeat: No connected peers
2024-12-17T08:48:24.179107Z DEBUG snarkos_node_bft::primary: Primary is safely skipping a batch proposal (please connect to more validators)
2024-12-17T08:48:26.680700Z DEBUG snarkos_node_bft::primary: Primary is safely skipping a batch proposal (please connect to more validators)
2024-12-17T08:48:29.183007Z DEBUG snarkos_node_bft::primary: Primary is safely skipping a batch proposal (please connect to more validators)
2024-12-17T08:48:31.684649Z DEBUG snarkos_node_bft::primary: Primary is safely skipping a batch proposal (please connect to more validators)
2024-12-17T08:48:34.186960Z DEBUG snarkos_node_bft::primary: Primary is safely skipping a batch proposal (please connect to more validators)
2024-12-17T08:48:35.152273Z  INFO snarkos_node_bft::gateway: Connected to 1 validators (of 3 bonded validators)
2024-12-17T08:48:35.152343Z DEBUG snarkos_node_bft::gateway:   127.0.0.1:5001 - aleo1s3ws5tra87fjycnjrwsjcrnw2qxr8jfqqdugnf0xzqqw29q9m5pqem2u4t
2024-12-17T08:48:36.338731Z DEBUG snarkos_node_router::handshake: Received a connection request from '127.0.0.1:53067'
2024-12-17T08:48:36.687572Z DEBUG snarkos_node_bft::primary: Primary is safely skipping a batch proposal (please connect to more validators)
2024-12-17T08:48:39.189745Z DEBUG snarkos_node_bft::primary: Primary is safely skipping a batch proposal (please connect to more validators)
2024-12-17T08:48:41.691738Z DEBUG snarkos_node_bft::primary: Primary is safely skipping a batch proposal (please connect to more validators)
2024-12-17T08:48:44.192895Z DEBUG snarkos_node_bft::primary: Primary is safely skipping a batch proposal (please connect to more validators)
2024-12-17T08:48:45.507793Z DEBUG snarkos_node_router::handshake: Received a connection request from '127.0.0.1:46615'
2024-12-17T08:48:46.505070Z DEBUG snarkos_node_bft::gateway: [MemoryPool] Gateway received a connection request from '127.0.0.1:50231'
2024-12-17T08:48:46.513599Z  INFO snarkos_node_bft::gateway: [MemoryPool] Gateway is connected to '127.0.0.1:5002'
2024-12-17T08:48:46.694046Z  INFO snarkos_node_bft::primary: Proposing a batch with 0 transmissions for round 1...
2024-12-17T08:48:46.709535Z  INFO snarkos_node_bft::primary: Received a batch signature for round 1 from '127.0.0.1:5001'
2024-12-17T08:48:48.864706Z DEBUG snarkos_node_bft::primary: Signed a batch for round 1 from '127.0.0.1:5001'
2024-12-17T08:48:49.176988Z DEBUG snarkos_node_router::heartbeat: No connected peers
2024-12-17T08:48:49.201352Z DEBUG snarkos_node_bft::primary: Proposed batch for round 1 is still valid
2024-12-17T08:48:49.201478Z DEBUG snarkos_node_bft::primary: Resending batch proposal for round 1 to peer '127.0.0.1:5002'
2024-12-17T08:48:50.153465Z  INFO snarkos_node_bft::gateway: Connected to 2 validators (of 3 bonded validators)
2024-12-17T08:48:50.153627Z DEBUG snarkos_node_bft::gateway:   127.0.0.1:5001 - aleo1s3ws5tra87fjycnjrwsjcrnw2qxr8jfqqdugnf0xzqqw29q9m5pqem2u4t
2024-12-17T08:48:50.153649Z DEBUG snarkos_node_bft::gateway:   127.0.0.1:5002 - aleo1ashyu96tjwe63u0gtnnv8z5lhapdu4l5pjsl2kha7fv7hvz2eqxs5dz0rg
2024-12-17T08:48:51.704112Z DEBUG snarkos_node_bft::primary: Proposed batch for round 1 is still valid
2024-12-17T08:48:51.704302Z DEBUG snarkos_node_bft::primary: Resending batch proposal for round 1 to peer '127.0.0.1:5002'
2024-12-17T08:48:54.205196Z DEBUG snarkos_node_bft::primary: Proposed batch for round 1 is still valid
2024-12-17T08:48:54.205335Z DEBUG snarkos_node_bft::primary: Resending batch proposal for round 1 to peer '127.0.0.1:5002'
2024-12-17T08:48:55.512163Z DEBUG snarkos_node_bft::primary: Signed a batch for round 1 from '127.0.0.1:5002'
2024-12-17T08:48:55.521280Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for round 1 from '127.0.0.1:5002'
2024-12-17T08:48:56.382084Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for round 1 from '127.0.0.1:5001'
2024-12-17T08:48:56.706997Z DEBUG snarkos_node_bft::primary: Proposed batch for round 1 is still valid
2024-12-17T08:48:56.707124Z DEBUG snarkos_node_bft::primary: Resending batch proposal for round 1 to peer '127.0.0.1:5002'
2024-12-17T08:48:56.716963Z  INFO snarkos_node_bft::primary: Received a batch signature for round 1 from '127.0.0.1:5002'
2024-12-17T08:48:56.717462Z  INFO snarkos_node_bft::primary: Quorum threshold reached - Preparing to certify our batch for round 1...
2024-12-17T08:48:56.719999Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for round 1
2024-12-17T08:48:56.720085Z  INFO snarkos_node_bft::primary:

Our batch with 0 transmissions for round 1 was certified!

2024-12-17T08:48:56.720177Z  INFO snarkos_node_bft::helpers::storage: Starting round 2...
2024-12-17T08:48:56.720210Z DEBUG snarkos_node_bft::primary: Primary is ready to propose the next round
2024-12-17T08:48:56.721421Z  INFO snarkos_node_bft::primary: Proposing a batch with 0 transmissions for round 2...
2024-12-17T08:48:56.727822Z  INFO snarkos_node_bft::primary: Received a batch signature for round 2 from '127.0.0.1:5001'
2024-12-17T08:48:56.729885Z DEBUG snarkos_node_bft::primary: Signed a batch for round 2 from '127.0.0.1:5002'
2024-12-17T08:48:56.730544Z DEBUG snarkos_node_bft::primary: Signed a batch for round 2 from '127.0.0.1:5001'
2024-12-17T08:48:56.731190Z  INFO snarkos_node_bft::primary: Received a batch signature for round 2 from '127.0.0.1:5002'
2024-12-17T08:48:56.731545Z  INFO snarkos_node_bft::primary: Quorum threshold reached - Preparing to certify our batch for round 2...
2024-12-17T08:48:56.732988Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for round 2
2024-12-17T08:48:56.733080Z  INFO snarkos_node_bft::primary:

Our batch with 0 transmissions for round 2 was certified!

2024-12-17T08:48:56.733747Z  INFO snarkos_node_bft::bft:

Round 2 did not elect a leader

2024-12-17T08:48:56.733789Z DEBUG snarkos_node_bft::primary: Primary is not ready to propose the next round
2024-12-17T08:48:56.740137Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for round 2 from '127.0.0.1:5001'
2024-12-17T08:48:56.740182Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for round 2 from '127.0.0.1:5002'
2024-12-17T08:48:56.740213Z  INFO snarkos_node_bft::bft:

Round 2 did not elect a leader

2024-12-17T08:48:56.740234Z  INFO snarkos_node_bft::bft:

Round 2 did not elect a leader

2024-12-17T08:48:56.740244Z DEBUG snarkos_node_bft::primary: Primary is not ready to propose the next round
2024-12-17T08:48:56.740260Z DEBUG snarkos_node_bft::primary: Primary is not ready to propose the next round
2024-12-17T08:48:59.208210Z  INFO snarkos_node_bft::bft:

Round 2 did not elect a leader

2024-12-17T08:49:01.340523Z DEBUG snarkos_node_router::handshake: Received a connection request from '127.0.0.1:40893'
2024-12-17T08:49:01.709260Z DEBUG snarkos_node_bft::bft: BFT (timer expired) - Advancing from round 2 to the next round (without the leader)
2024-12-17T08:49:01.709323Z  INFO snarkos_node_bft::bft:

Round 2 reached quorum without a leader

2024-12-17T08:49:01.709330Z  INFO snarkos_node_bft::helpers::storage: Starting round 3...
2024-12-17T08:49:01.709339Z DEBUG snarkos_node_bft::primary: Primary is safely skipping (round 2 was already certified)
2024-12-17T08:49:03.874656Z DEBUG snarkos_node_bft::primary: Signed a batch for round 3 from '127.0.0.1:5001'
2024-12-17T08:49:03.882768Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for round 3 from '127.0.0.1:5001'
2024-12-17T08:49:04.209651Z  INFO snarkos_node_bft::primary: Proposing a batch with 0 transmissions for round 3...
2024-12-17T08:49:04.214891Z  INFO snarkos_node_bft::primary: Received a batch signature for round 3 from '127.0.0.1:5002'
2024-12-17T08:49:04.228170Z  INFO snarkos_node_bft::primary: Received a batch signature for round 3 from '127.0.0.1:5001'
2024-12-17T08:49:04.228504Z  INFO snarkos_node_bft::primary: Quorum threshold reached - Preparing to certify our batch for round 3...
2024-12-17T08:49:04.229717Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for round 3
2024-12-17T08:49:04.229779Z  INFO snarkos_node_bft::primary:

Our batch with 0 transmissions for round 3 was certified!

2024-12-17T08:49:04.229883Z DEBUG snarkos_node_bft::primary: Primary is not ready to propose the next round
2024-12-17T08:49:05.155366Z  INFO snarkos_node_bft::gateway: Connected to 2 validators (of 3 bonded validators)
2024-12-17T08:49:05.155518Z DEBUG snarkos_node_bft::gateway:   127.0.0.1:5001 - aleo1s3ws5tra87fjycnjrwsjcrnw2qxr8jfqqdugnf0xzqqw29q9m5pqem2u4t
2024-12-17T08:49:05.155542Z DEBUG snarkos_node_bft::gateway:   127.0.0.1:5002 - aleo1ashyu96tjwe63u0gtnnv8z5lhapdu4l5pjsl2kha7fv7hvz2eqxs5dz0rg
2024-12-17T08:49:05.519311Z DEBUG snarkos_node_bft::primary: Signed a batch for round 3 from '127.0.0.1:5002'
2024-12-17T08:49:05.570000Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for round 3 from '127.0.0.1:5002'
2024-12-17T08:49:05.570118Z  INFO snarkos_node_bft::helpers::storage: Starting round 4...
2024-12-17T08:49:05.570148Z DEBUG snarkos_node_bft::primary: Primary is ready to propose the next round
2024-12-17T08:49:05.570195Z  INFO snarkos_node_bft::primary: Proposing a batch with 0 transmissions for round 4...
2024-12-17T08:49:05.574175Z DEBUG snarkos_node_bft::primary: Signed a batch for round 4 from '127.0.0.1:5001'
2024-12-17T08:49:05.575560Z  INFO snarkos_node_bft::primary: Received a batch signature for round 4 from '127.0.0.1:5001'
2024-12-17T08:49:05.576253Z  INFO snarkos_node_bft::primary: Received a batch signature for round 4 from '127.0.0.1:5002'
2024-12-17T08:49:05.576533Z  INFO snarkos_node_bft::primary: Quorum threshold reached - Preparing to certify our batch for round 4...
2024-12-17T08:49:05.577826Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for round 4
2024-12-17T08:49:05.577868Z  INFO snarkos_node_bft::primary:

Our batch with 0 transmissions for round 4 was certified!

2024-12-17T08:49:05.578508Z  INFO snarkos_node_bft::bft:

Round 4 did not elect a leader

2024-12-17T08:49:05.578550Z DEBUG snarkos_node_bft::primary: Primary is not ready to propose the next round
2024-12-17T08:49:05.582292Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for round 4 from '127.0.0.1:5001'
2024-12-17T08:49:06.712837Z  INFO snarkos_node_bft::bft:

Round 4 did not elect a leader

2024-12-17T08:49:08.028857Z DEBUG snarkos_node_bft::primary: Signed a batch for round 4 from '127.0.0.1:5002'
2024-12-17T08:49:08.037351Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for round 4 from '127.0.0.1:5002'
2024-12-17T08:49:08.037438Z  INFO snarkos_node_bft::bft:

Round 4 elected a leader - aleo1ashyu96tjwe63u0gtnnv8z5lhapdu4l5pjsl2kha7fv7hvz2eqxs5dz0rg

2024-12-17T08:49:08.037467Z  INFO snarkos_node_bft::helpers::storage: Starting round 5...
2024-12-17T08:49:08.037484Z DEBUG snarkos_node_bft::primary: Primary is ready to propose the next round
2024-12-17T08:49:08.037521Z  INFO snarkos_node_bft::primary: Proposing a batch with 0 transmissions for round 5...
2024-12-17T08:49:08.040572Z DEBUG snarkos_node_bft::primary: Signed a batch for round 5 from '127.0.0.1:5001'
2024-12-17T08:49:08.042214Z  INFO snarkos_node_bft::primary: Received a batch signature for round 5 from '127.0.0.1:5002'
2024-12-17T08:49:08.042880Z  INFO snarkos_node_bft::primary: Received a batch signature for round 5 from '127.0.0.1:5001'
2024-12-17T08:49:08.043132Z  INFO snarkos_node_bft::primary: Quorum threshold reached - Preparing to certify our batch for round 5...
2024-12-17T08:49:08.044476Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for round 5
2024-12-17T08:49:08.044602Z  INFO snarkos_node_bft::primary:

Our batch with 0 transmissions for round 5 was certified!

2024-12-17T08:49:08.044690Z DEBUG snarkos_node_bft::primary: Primary is not ready to propose the next round
2024-12-17T08:49:08.048393Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for round 5 from '127.0.0.1:5001'
2024-12-17T08:49:08.048504Z  INFO snarkos_node_bft::bft: Proceeding to commit round 4 with leader 'aleo1ashyu96tjwe..'
2024-12-17T08:49:08.101787Z  INFO snarkos_node_bft_ledger_service::ledger:

Advanced to block 1 at round 4 - ab139xdx98at6x2lw0yryagnkdtyjgpcvk30dqd7qdgjgkzj6ehfvpq4e2640

2024-12-17T08:49:08.101913Z  INFO snarkos_node_bft::bft:

Committing a subdag from round 4 with 0 transmissions: [(1, 3), (2, 3), (3, 3), (4, 1)]

2024-12-17T08:49:10.508843Z DEBUG snarkos_node_router::handshake: Received a connection request from '127.0.0.1:35813'
2024-12-17T08:49:10.559829Z DEBUG snarkos_node_bft::primary: Signed a batch for round 5 from '127.0.0.1:5002'
2024-12-17T08:49:10.569292Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for round 5 from '127.0.0.1:5002'
2024-12-17T08:49:10.569389Z  INFO snarkos_node_bft::helpers::storage: Starting round 6...
2024-12-17T08:49:10.569422Z DEBUG snarkos_node_bft::primary: Primary is ready to propose the next round
2024-12-17T08:49:10.569468Z  INFO snarkos_node_bft::primary: Proposing a batch with 0 transmissions for round 6...
2024-12-17T08:49:10.573245Z DEBUG snarkos_node_bft::primary: Signed a batch for round 6 from '127.0.0.1:5001'
2024-12-17T08:49:10.573991Z  INFO snarkos_node_bft::primary: Received a batch signature for round 6 from '127.0.0.1:5001'
2024-12-17T08:49:10.574929Z  INFO snarkos_node_bft::primary: Received a batch signature for round 6 from '127.0.0.1:5002'
2024-12-17T08:49:10.575170Z  INFO snarkos_node_bft::primary: Quorum threshold reached - Preparing to certify our batch for round 6...
2024-12-17T08:49:10.576412Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for round 6
2024-12-17T08:49:10.576500Z  INFO snarkos_node_bft::primary:

Our batch with 0 transmissions for round 6 was certified!

2024-12-17T08:49:10.577202Z  INFO snarkos_node_bft::bft:

Round 6 did not elect a leader

2024-12-17T08:49:10.577243Z DEBUG snarkos_node_bft::primary: Primary is not ready to propose the next round
2024-12-17T08:49:10.582931Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for round 6 from '127.0.0.1:5001'
2024-12-17T08:49:11.715255Z  INFO snarkos_node_bft::bft:

Round 6 did not elect a leader

2024-12-17T08:49:13.035050Z DEBUG snarkos_node_bft::primary: Signed a batch for round 6 from '127.0.0.1:5002'
2024-12-17T08:49:13.042798Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for round 6 from '127.0.0.1:5002'
2024-12-17T08:49:13.042881Z  INFO snarkos_node_bft::bft:

Round 6 did not elect a leader

2024-12-17T08:49:13.042922Z DEBUG snarkos_node_bft::primary: Primary is not ready to propose the next round
2024-12-17T08:49:14.178016Z DEBUG snarkos_node_router::heartbeat: No connected peers
2024-12-17T08:49:14.216627Z  INFO snarkos_node_bft::bft:

Round 6 did not elect a leader

2024-12-17T08:49:16.718306Z DEBUG snarkos_node_bft::bft: BFT (timer expired) - Advancing from round 6 to the next round (without the leader)
2024-12-17T08:49:16.718375Z  INFO snarkos_node_bft::bft:

Round 6 reached quorum without a leader

2024-12-17T08:49:16.718396Z  INFO snarkos_node_bft::helpers::storage: Starting round 7...
2024-12-17T08:49:16.718434Z DEBUG snarkos_node_bft::primary: Primary is safely skipping (round 6 was already certified)
2024-12-17T08:49:18.041083Z DEBUG snarkos_node_bft::primary: Signed a batch for round 7 from '127.0.0.1:5002'
2024-12-17T08:49:18.048573Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for round 7 from '127.0.0.1:5002'
2024-12-17T08:49:18.887143Z DEBUG snarkos_node_bft::primary: Signed a batch for round 7 from '127.0.0.1:5001'
2024-12-17T08:49:18.897045Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for round 7 from '127.0.0.1:5001'
2024-12-17T08:49:19.220520Z  INFO snarkos_node_bft::primary: Proposing a batch with 0 transmissions for round 7...
2024-12-17T08:49:19.242882Z  INFO snarkos_node_bft::primary: Received a batch signature for round 7 from '127.0.0.1:5001'
2024-12-17T08:49:19.244056Z  INFO snarkos_node_bft::primary: Received a batch signature for round 7 from '127.0.0.1:5002'
2024-12-17T08:49:19.244516Z  INFO snarkos_node_bft::primary: Quorum threshold reached - Preparing to certify our batch for round 7...
2024-12-17T08:49:19.246455Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for round 7
2024-12-17T08:49:19.246556Z  INFO snarkos_node_bft::primary:

Our batch with 0 transmissions for round 7 was certified!

2024-12-17T08:49:19.246640Z  INFO snarkos_node_bft::helpers::storage: Starting round 8...
2024-12-17T08:49:19.246720Z DEBUG snarkos_node_bft::primary: Primary is ready to propose the next round
2024-12-17T08:49:19.246778Z DEBUG snarkos_node_bft::primary: Primary is safely skipping a batch proposal - Timestamp is too soon after the previous certificate at round 7
2024-12-17T08:49:19.254857Z DEBUG snarkos_node_bft::primary: Signed a batch for round 8 from '127.0.0.1:5002'
2024-12-17T08:49:19.254889Z DEBUG snarkos_node_bft::primary: Signed a batch for round 8 from '127.0.0.1:5001'
2024-12-17T08:49:19.262626Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for round 8 from '127.0.0.1:5001'
2024-12-17T08:49:19.262732Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for round 8 from '127.0.0.1:5002'
2024-12-17T08:49:20.157698Z  INFO snarkos_node_bft::gateway: Connected to 2 validators (of 3 bonded validators)
2024-12-17T08:49:20.157836Z DEBUG snarkos_node_bft::gateway:   127.0.0.1:5001 - aleo1s3ws5tra87fjycnjrwsjcrnw2qxr8jfqqdugnf0xzqqw29q9m5pqem2u4t
2024-12-17T08:49:20.157859Z DEBUG snarkos_node_bft::gateway:   127.0.0.1:5002 - aleo1ashyu96tjwe63u0gtnnv8z5lhapdu4l5pjsl2kha7fv7hvz2eqxs5dz0rg
2024-12-17T08:49:21.725135Z  INFO snarkos_node_bft::primary: Proposing a batch with 0 transmissions for round 8...
2024-12-17T08:49:21.737800Z  INFO snarkos_node_bft::primary: Received a batch signature for round 8 from '127.0.0.1:5001'
2024-12-17T08:49:21.739046Z  INFO snarkos_node_bft::primary: Received a batch signature for round 8 from '127.0.0.1:5002'
2024-12-17T08:49:21.739450Z  INFO snarkos_node_bft::primary: Quorum threshold reached - Preparing to certify our batch for round 8...
2024-12-17T08:49:21.741174Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for round 8
2024-12-17T08:49:21.741238Z  INFO snarkos_node_bft::primary:

Our batch with 0 transmissions for round 8 was certified!

2024-12-17T08:49:21.741756Z  INFO snarkos_node_bft::bft:

Round 8 elected a leader - aleo1ashyu96tjwe63u0gtnnv8z5lhapdu4l5pjsl2kha7fv7hvz2eqxs5dz0rg

2024-12-17T08:49:21.741788Z  INFO snarkos_node_bft::helpers::storage: Starting round 9...
2024-12-17T08:49:21.741822Z DEBUG snarkos_node_bft::primary: Primary is ready to propose the next round
2024-12-17T08:49:21.741836Z DEBUG snarkos_node_bft::primary: Primary is safely skipping a batch proposal - Timestamp is too soon after the previous certificate at round 8
2024-12-17T08:49:21.750007Z DEBUG snarkos_node_bft::primary: Signed a batch for round 9 from '127.0.0.1:5001'
2024-12-17T08:49:21.750579Z DEBUG snarkos_node_bft::primary: Signed a batch for round 9 from '127.0.0.1:5002'
2024-12-17T08:49:21.758072Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for round 9 from '127.0.0.1:5002'
2024-12-17T08:49:21.758120Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for round 9 from '127.0.0.1:5001'
2024-12-17T08:49:21.758164Z  INFO snarkos_node_bft::bft: Proceeding to commit round 8 with leader 'aleo1ashyu96tjwe..'
2024-12-17T08:49:21.807166Z  INFO snarkos_node_bft_ledger_service::ledger:

Advanced to block 2 at round 8 - ab1mmdjt4wpv9cw23wks9t9q70q5eq9zlvt9npgvppnpy5ld20qjsqsz5n9rg

2024-12-17T08:49:21.807290Z  INFO snarkos_node_bft::bft:

Committing a subdag from round 8 with 0 transmissions: [(4, 2), (5, 3), (6, 3), (7, 3), (8, 1)]

2024-12-17T08:49:24.230376Z  INFO snarkos_node_bft::primary: Proposing a batch with 0 transmissions for round 9...
2024-12-17T08:49:24.252064Z  INFO snarkos_node_bft::primary: Received a batch signature for round 9 from '127.0.0.1:5001'
2024-12-17T08:49:24.253057Z  INFO snarkos_node_bft::primary: Received a batch signature for round 9 from '127.0.0.1:5002'
2024-12-17T08:49:24.253376Z  INFO snarkos_node_bft::primary: Quorum threshold reached - Preparing to certify our batch for round 9...
2024-12-17T08:49:24.254951Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for round 9
2024-12-17T08:49:24.255021Z  INFO snarkos_node_bft::primary:

Our batch with 0 transmissions for round 9 was certified!

2024-12-17T08:49:24.255108Z  INFO snarkos_node_bft::helpers::storage: Starting round 10...
2024-12-17T08:49:24.255134Z DEBUG snarkos_node_bft::primary: Primary is ready to propose the next round
2024-12-17T08:49:24.255163Z DEBUG snarkos_node_bft::primary: Primary is safely skipping a batch proposal - Timestamp is too soon after the previous certificate at round 9
2024-12-17T08:49:24.262795Z DEBUG snarkos_node_bft::primary: Signed a batch for round 10 from '127.0.0.1:5001'
2024-12-17T08:49:24.262888Z DEBUG snarkos_node_bft::primary: Signed a batch for round 10 from '127.0.0.1:5002'
2024-12-17T08:49:24.270139Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for round 10 from '127.0.0.1:5002'
2024-12-17T08:49:24.271590Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for round 10 from '127.0.0.1:5001'
2024-12-17T08:49:26.341391Z DEBUG snarkos_node_router::handshake: Received a connection request from '127.0.0.1:48663'
2024-12-17T08:49:26.734713Z  INFO snarkos_node_bft::primary: Proposing a batch with 0 transmissions for round 10...
2024-12-17T08:49:26.744788Z  INFO snarkos_node_bft::primary: Received a batch signature for round 10 from '127.0.0.1:5001'
2024-12-17T08:49:26.745533Z  INFO snarkos_node_bft::primary: Received a batch signature for round 10 from '127.0.0.1:5002'
2024-12-17T08:49:26.746044Z  INFO snarkos_node_bft::primary: Quorum threshold reached - Preparing to certify our batch for round 10...
2024-12-17T08:49:26.747833Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for round 10
2024-12-17T08:49:26.747901Z  INFO snarkos_node_bft::primary:

Our batch with 0 transmissions for round 10 was certified!

2024-12-17T08:49:26.748580Z  INFO snarkos_node_bft::bft:

Round 10 did not elect a leader

2024-12-17T08:49:26.748613Z DEBUG snarkos_node_bft::primary: Primary is not ready to propose the next round
2024-12-17T08:49:29.239369Z DEBUG snarkos_node_bft::bft: BFT (timer expired) - Advancing from round 10 to the next round (without the leader)
2024-12-17T08:49:29.239429Z  INFO snarkos_node_bft::bft:

Round 10 reached quorum without a leader

2024-12-17T08:49:29.239435Z  INFO snarkos_node_bft::helpers::storage: Starting round 11...
2024-12-17T08:49:29.239442Z DEBUG snarkos_node_bft::primary: Primary is safely skipping (round 10 was already certified)
^C2024-12-17T08:49:29.261187Z  WARN snarkos_node::traits: ==========================================================================================
2024-12-17T08:49:29.261237Z  WARN snarkos_node::traits: ⚠️  Attention - Starting the graceful shutdown procedure (ETA: 30 seconds)...
2024-12-17T08:49:29.261242Z  WARN snarkos_node::traits: ⚠️  Attention - To avoid DATA CORRUPTION, do NOT interrupt snarkOS (or press Ctrl+C again)
2024-12-17T08:49:29.261245Z  WARN snarkos_node::traits: ⚠️  Attention - Please wait until the shutdown gracefully completes (ETA: 30 seconds)
2024-12-17T08:49:29.261248Z  WARN snarkos_node::traits: ==========================================================================================
2024-12-17T08:49:29.261284Z  INFO snarkos_node::validator: Shutting down...
2024-12-17T08:49:29.261306Z  INFO snarkos_node_router: Shutting down the router...
2024-12-17T08:49:29.261360Z  INFO snarkos_node_consensus: Shutting down consensus...
2024-12-17T08:49:29.261369Z  INFO snarkos_node_bft::bft: Shutting down the BFT...
2024-12-17T08:49:29.261390Z  INFO snarkos_node_bft::primary: Shutting down the primary...
2024-12-17T08:49:29.261504Z  INFO snarkos_node_bft::helpers::proposal_cache: Storing the proposal cache to /home/alexubuntu22/.current-proposal-cache-1-0...
2024-12-17T08:49:29.261669Z  INFO snarkos_node_bft::gateway: Shutting down the gateway...
2024-12-17T08:49:29.262563Z  INFO snarkos_node::validator: Node has shut down.
```