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

🔑 Your one-time JWT token is eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhbGVvMXJoZ2R1NzdoZ3lxZDN4amo4dWN1M2pqOXIya3J3ejZtbnp5ZDgwZ25jcjVmeGN3bGg1cnN2enA5cHgiLCJpYXQiOjE3MzQ0NDExOTEsImV4cCI6MjA0OTgwMTE5MX0.6IUkm_Mxt9jt55yFcY6YzZxmuNyramHDh7zU0uwId1Y

⚠️  The open files limit (1024) for this process is lower than recommended.
  • To ensure correct behavior of the node, please raise it to at least 2048.
  • See the `ulimit` command and `/etc/security/limits.conf` for more details.

⚠️  The number of cores (8 cores) on this machine is insufficient for a validator (minimum 64 cores)

⚠️  The amount of RAM (7 GiB) on this machine is insufficient for a validator (minimum 256 GiB)

2024-12-17T13:13:11.023007Z  INFO snarkvm_ledger: Loading the ledger from storage...
2024-12-17T13:13:11.123642Z  INFO snarkos_node_consensus: Starting the consensus instance...
2024-12-17T13:13:11.123736Z  INFO snarkos_node_bft::bft: Starting the BFT instance...
2024-12-17T13:13:11.123820Z  INFO snarkos_node_bft::primary: Starting the primary instance of the memory pool...
2024-12-17T13:13:11.123845Z  INFO snarkos_node_bft::worker: Starting worker instance 0 of the memory pool...
2024-12-17T13:13:11.123889Z  INFO snarkos_node_bft::sync: Syncing storage with the ledger...
2024-12-17T13:13:11.123932Z DEBUG snarkos_node_bft::sync: Syncing storage with the ledger from block 0 to 1...
2024-12-17T13:13:11.124025Z  INFO snarkos_node_bft::sync: Starting the sync module...
2024-12-17T13:13:11.124053Z DEBUG snarkos_node_bft::gateway: Starting the gateway for the memory pool...
2024-12-17T13:13:11.125098Z  INFO snarkos_node_bft::gateway: Started the gateway for the memory pool at '127.0.0.1:5000'
2024-12-17T13:13:11.127616Z DEBUG snarkos_node_rest: REST rate limit per IP - 10 RPS
2024-12-17T13:13:11.131480Z DEBUG snarkos_node_router::heartbeat: No connected peers
2024-12-17T13:13:12.128757Z  INFO snarkos_node_bft::gateway: Starting the heartbeat of the gateway...
2024-12-17T13:13:12.128927Z  INFO snarkos_node_bft::gateway: No connected validators
2024-12-17T13:13:12.129056Z DEBUG snarkos_node_bft::gateway: Connecting to validator 127.0.0.1:5001...
2024-12-17T13:13:12.131641Z  WARN snarkos_node_bft::gateway: Unable to connect to '127.0.0.1:5001' - Connection refused (os error 111)
2024-12-17T13:13:13.627084Z DEBUG snarkos_node_bft::primary: Skipping batch proposal (node is syncing)
2024-12-17T13:13:16.129049Z DEBUG snarkos_node_bft::primary: Skipping batch proposal (node is syncing)
2024-12-17T13:13:18.631098Z DEBUG snarkos_node_bft::primary: Skipping batch proposal (node is syncing)
2024-12-17T13:13:21.137063Z  INFO snarkos_node_bft::primary: Proposing a batch with 0 transmissions for round 1...
2024-12-17T13:13:21.138014Z  INFO snarkos_node_bft::primary: Quorum threshold reached - Preparing to certify our batch for round 1...
2024-12-17T13:13:21.143312Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for round 1
2024-12-17T13:13:21.143390Z  INFO snarkos_node_bft::primary:

Our batch with 0 transmissions for round 1 was certified!

2024-12-17T13:13:21.143455Z DEBUG snarkos_node_bft::primary: Primary is not ready to propose the next round
2024-12-17T13:13:21.149525Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 1/1
2024-12-17T13:13:21.154452Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 2/1
2024-12-17T13:13:21.159248Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 3/1
2024-12-17T13:13:23.664882Z  INFO snarkos_node_bft::helpers::storage: Starting round 2...
2024-12-17T13:13:23.664994Z DEBUG snarkos_node_bft::primary: Primary is safely skipping (round 1 was already certified)
2024-12-17T13:13:26.169922Z  INFO snarkos_node_bft::primary: Proposing a batch with 0 transmissions for round 2...
2024-12-17T13:13:26.171792Z  INFO snarkos_node_bft::primary: Quorum threshold reached - Preparing to certify our batch for round 2...
2024-12-17T13:13:26.176446Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for round 2
2024-12-17T13:13:26.176532Z  INFO snarkos_node_bft::primary:

Our batch with 0 transmissions for round 2 was certified!

2024-12-17T13:13:26.177387Z  INFO snarkos_node_bft::bft:

Round 2 did not elect a leader

2024-12-17T13:13:26.177464Z DEBUG snarkos_node_bft::primary: Primary is not ready to propose the next round
2024-12-17T13:13:26.183801Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 1/2
2024-12-17T13:13:26.189852Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 2/2
2024-12-17T13:13:26.200008Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 3/2
2024-12-17T13:13:27.130449Z  INFO snarkos_node_bft::gateway: No connected validators
2024-12-17T13:13:27.130690Z DEBUG snarkos_node_bft::gateway: Connecting to validator 127.0.0.1:5001...
2024-12-17T13:13:27.145064Z  WARN snarkos_node_bft::gateway: Unable to connect to '127.0.0.1:5001' - Connection refused (os error 111)
2024-12-17T13:13:28.704537Z  INFO snarkos_node_bft::bft:

Round 2 elected a leader - aleo12ux3gdauck0v60westgcpqj7v8rrcr3v346e4jtq04q7kkt22czsh808v2

2024-12-17T13:13:28.704607Z  INFO snarkos_node_bft::helpers::storage: Starting round 3...
2024-12-17T13:13:28.704615Z DEBUG snarkos_node_bft::primary: Primary is safely skipping (round 2 was already certified)
2024-12-17T13:13:31.209603Z  INFO snarkos_node_bft::primary: Proposing a batch with 0 transmissions for round 3...
2024-12-17T13:13:31.212799Z  INFO snarkos_node_bft::primary: Quorum threshold reached - Preparing to certify our batch for round 3...
2024-12-17T13:13:31.223105Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for round 3
2024-12-17T13:13:31.223243Z  INFO snarkos_node_bft::primary:

Our batch with 0 transmissions for round 3 was certified!

2024-12-17T13:13:31.223331Z DEBUG snarkos_node_bft::primary: Primary is not ready to propose the next round
2024-12-17T13:13:31.229064Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 1/3
2024-12-17T13:13:31.234191Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 2/3
2024-12-17T13:13:31.239135Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 3/3
2024-12-17T13:13:33.744238Z  INFO snarkos_node_bft::helpers::storage: Starting round 4...
2024-12-17T13:13:33.744364Z DEBUG snarkos_node_bft::primary: Primary is safely skipping (round 3 was already certified)
2024-12-17T13:13:36.132744Z DEBUG snarkos_node_router::heartbeat: No connected peers
2024-12-17T13:13:36.249583Z  INFO snarkos_node_bft::primary: Proposing a batch with 0 transmissions for round 4...
2024-12-17T13:13:36.251303Z  INFO snarkos_node_bft::primary: Quorum threshold reached - Preparing to certify our batch for round 4...
2024-12-17T13:13:36.261117Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for round 4
2024-12-17T13:13:36.261201Z  INFO snarkos_node_bft::primary:

Our batch with 0 transmissions for round 4 was certified!

2024-12-17T13:13:36.261858Z  INFO snarkos_node_bft::bft:

Round 4 did not elect a leader

2024-12-17T13:13:36.261904Z DEBUG snarkos_node_bft::primary: Primary is not ready to propose the next round
2024-12-17T13:13:36.269839Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 1/4
2024-12-17T13:13:36.276266Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 2/4
2024-12-17T13:13:36.281311Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 3/4
2024-12-17T13:13:38.785388Z  INFO snarkos_node_bft::bft:

Round 4 elected a leader - aleo1ashyu96tjwe63u0gtnnv8z5lhapdu4l5pjsl2kha7fv7hvz2eqxs5dz0rg

2024-12-17T13:13:38.785520Z  INFO snarkos_node_bft::helpers::storage: Starting round 5...
2024-12-17T13:13:38.785538Z DEBUG snarkos_node_bft::primary: Primary is safely skipping (round 4 was already certified)
2024-12-17T13:13:41.289812Z  INFO snarkos_node_bft::primary: Proposing a batch with 0 transmissions for round 5...
2024-12-17T13:13:41.290895Z  INFO snarkos_node_bft::primary: Quorum threshold reached - Preparing to certify our batch for round 5...
2024-12-17T13:13:41.295654Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for round 5
2024-12-17T13:13:41.295708Z  INFO snarkos_node_bft::primary:

Our batch with 0 transmissions for round 5 was certified!

2024-12-17T13:13:41.295763Z DEBUG snarkos_node_bft::primary: Primary is not ready to propose the next round
2024-12-17T13:13:41.301297Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 1/5
2024-12-17T13:13:41.306718Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 2/5
2024-12-17T13:13:41.311579Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 3/5
2024-12-17T13:13:42.131850Z  INFO snarkos_node_bft::gateway: No connected validators
2024-12-17T13:13:42.132047Z DEBUG snarkos_node_bft::gateway: Connecting to validator 127.0.0.1:5001...
2024-12-17T13:13:42.132567Z  WARN snarkos_node_bft::gateway: Unable to connect to '127.0.0.1:5001' - Connection refused (os error 111)
2024-12-17T13:13:43.816350Z  INFO snarkos_node_bft::helpers::storage: Starting round 6...
2024-12-17T13:13:43.816457Z DEBUG snarkos_node_bft::primary: Primary is safely skipping (round 5 was already certified)
2024-12-17T13:13:46.321659Z  INFO snarkos_node_bft::primary: Proposing a batch with 0 transmissions for round 6...
2024-12-17T13:13:46.323489Z  INFO snarkos_node_bft::primary: Quorum threshold reached - Preparing to certify our batch for round 6...
2024-12-17T13:13:46.328435Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for round 6
2024-12-17T13:13:46.328499Z  INFO snarkos_node_bft::primary:

Our batch with 0 transmissions for round 6 was certified!

2024-12-17T13:13:46.329130Z  INFO snarkos_node_bft::bft:

Round 6 did not elect a leader

2024-12-17T13:13:46.329183Z DEBUG snarkos_node_bft::primary: Primary is not ready to propose the next round
2024-12-17T13:13:46.335934Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 1/6
2024-12-17T13:13:46.341674Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 2/6
2024-12-17T13:13:46.347025Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 3/6
2024-12-17T13:13:48.850377Z  INFO snarkos_node_bft::bft:

Round 6 elected a leader - aleo12ux3gdauck0v60westgcpqj7v8rrcr3v346e4jtq04q7kkt22czsh808v2

2024-12-17T13:13:48.850467Z  INFO snarkos_node_bft::helpers::storage: Starting round 7...
2024-12-17T13:13:48.850479Z DEBUG snarkos_node_bft::primary: Primary is safely skipping (round 6 was already certified)
2024-12-17T13:13:51.355367Z  INFO snarkos_node_bft::primary: Proposing a batch with 0 transmissions for round 7...
2024-12-17T13:13:51.358194Z  INFO snarkos_node_bft::primary: Quorum threshold reached - Preparing to certify our batch for round 7...
2024-12-17T13:13:51.366747Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for round 7
2024-12-17T13:13:51.366835Z  INFO snarkos_node_bft::primary:

Our batch with 0 transmissions for round 7 was certified!

2024-12-17T13:13:51.366887Z DEBUG snarkos_node_bft::primary: Primary is not ready to propose the next round
2024-12-17T13:13:51.373356Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 1/7
2024-12-17T13:13:51.378441Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 2/7
2024-12-17T13:13:51.383525Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 3/7
2024-12-17T13:13:53.887580Z  INFO snarkos_node_bft::helpers::storage: Starting round 8...
2024-12-17T13:13:53.887679Z DEBUG snarkos_node_bft::primary: Primary is safely skipping (round 7 was already certified)
2024-12-17T13:13:56.389913Z  INFO snarkos_node_bft::primary: Proposing a batch with 0 transmissions for round 8...
2024-12-17T13:13:56.391590Z  INFO snarkos_node_bft::primary: Quorum threshold reached - Preparing to certify our batch for round 8...
2024-12-17T13:13:56.396113Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for round 8
2024-12-17T13:13:56.396206Z  INFO snarkos_node_bft::primary:

Our batch with 0 transmissions for round 8 was certified!

2024-12-17T13:13:56.396619Z  INFO snarkos_node_bft::bft:

Round 8 did not elect a leader

2024-12-17T13:13:56.397427Z DEBUG snarkos_node_bft::primary: Primary is not ready to propose the next round
2024-12-17T13:13:56.403043Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 1/8
2024-12-17T13:13:56.408206Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 2/8
2024-12-17T13:13:56.413564Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 3/8
2024-12-17T13:13:57.133566Z  INFO snarkos_node_bft::gateway: No connected validators
2024-12-17T13:13:57.133653Z DEBUG snarkos_node_bft::gateway: Connecting to validator 127.0.0.1:5001...
2024-12-17T13:13:57.133875Z  WARN snarkos_node_bft::gateway: Unable to connect to '127.0.0.1:5001' - Connection refused (os error 111)
2024-12-17T13:13:58.917934Z  INFO snarkos_node_bft::bft:

Round 8 elected a leader - aleo1ashyu96tjwe63u0gtnnv8z5lhapdu4l5pjsl2kha7fv7hvz2eqxs5dz0rg

2024-12-17T13:13:58.918066Z  INFO snarkos_node_bft::helpers::storage: Starting round 9...
2024-12-17T13:13:58.918087Z DEBUG snarkos_node_bft::primary: Primary is safely skipping (round 8 was already certified)
2024-12-17T13:14:01.134178Z DEBUG snarkos_node_router::heartbeat: No connected peers
2024-12-17T13:14:01.423394Z  INFO snarkos_node_bft::primary: Proposing a batch with 0 transmissions for round 9...
2024-12-17T13:14:01.426442Z  INFO snarkos_node_bft::primary: Quorum threshold reached - Preparing to certify our batch for round 9...
2024-12-17T13:14:01.433890Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for round 9
2024-12-17T13:14:01.433952Z  INFO snarkos_node_bft::primary:

Our batch with 0 transmissions for round 9 was certified!

2024-12-17T13:14:01.433996Z DEBUG snarkos_node_bft::primary: Primary is not ready to propose the next round
2024-12-17T13:14:01.439914Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 1/9
2024-12-17T13:14:01.445079Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 2/9
2024-12-17T13:14:01.450150Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 3/9
2024-12-17T13:14:03.953152Z  INFO snarkos_node_bft::helpers::storage: Starting round 10...
2024-12-17T13:14:03.953244Z DEBUG snarkos_node_bft::primary: Primary is safely skipping (round 9 was already certified)
2024-12-17T13:14:06.458093Z  INFO snarkos_node_bft::primary: Proposing a batch with 0 transmissions for round 10...
2024-12-17T13:14:06.461186Z  INFO snarkos_node_bft::primary: Quorum threshold reached - Preparing to certify our batch for round 10...
2024-12-17T13:14:06.472119Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for round 10
2024-12-17T13:14:06.472198Z  INFO snarkos_node_bft::primary:

Our batch with 0 transmissions for round 10 was certified!

2024-12-17T13:14:06.473029Z  INFO snarkos_node_bft::bft:

Round 10 did not elect a leader

2024-12-17T13:14:06.473094Z DEBUG snarkos_node_bft::primary: Primary is not ready to propose the next round
2024-12-17T13:14:06.481086Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 1/10
2024-12-17T13:14:06.488292Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 2/10
2024-12-17T13:14:06.494519Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 3/10
2024-12-17T13:14:08.996348Z  INFO snarkos_node_bft::bft:

Round 10 elected a leader - aleo12ux3gdauck0v60westgcpqj7v8rrcr3v346e4jtq04q7kkt22czsh808v2

2024-12-17T13:14:08.996400Z  INFO snarkos_node_bft::helpers::storage: Starting round 11...
2024-12-17T13:14:08.996408Z DEBUG snarkos_node_bft::primary: Primary is safely skipping (round 10 was already certified)
2024-12-17T13:14:11.499102Z  INFO snarkos_node_bft::primary: Proposing a batch with 0 transmissions for round 11...
2024-12-17T13:14:11.500308Z  INFO snarkos_node_bft::primary: Quorum threshold reached - Preparing to certify our batch for round 11...
2024-12-17T13:14:11.504547Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for round 11
2024-12-17T13:14:11.504601Z  INFO snarkos_node_bft::primary:

Our batch with 0 transmissions for round 11 was certified!

2024-12-17T13:14:11.504691Z DEBUG snarkos_node_bft::primary: Primary is not ready to propose the next round
2024-12-17T13:14:11.509795Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 1/11
2024-12-17T13:14:11.514777Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 2/11
2024-12-17T13:14:11.520290Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 3/11
2024-12-17T13:14:12.134238Z  INFO snarkos_node_bft::gateway: No connected validators
2024-12-17T13:14:12.134365Z DEBUG snarkos_node_bft::gateway: Connecting to validator 127.0.0.1:5001...
2024-12-17T13:14:12.134672Z  WARN snarkos_node_bft::gateway: Unable to connect to '127.0.0.1:5001' - Connection refused (os error 111)
2024-12-17T13:14:14.025702Z  INFO snarkos_node_bft::helpers::storage: Starting round 12...
2024-12-17T13:14:14.025844Z DEBUG snarkos_node_bft::primary: Primary is safely skipping (round 11 was already certified)
2024-12-17T13:14:16.530514Z  INFO snarkos_node_bft::primary: Proposing a batch with 0 transmissions for round 12...
2024-12-17T13:14:16.533982Z  INFO snarkos_node_bft::primary: Quorum threshold reached - Preparing to certify our batch for round 12...
2024-12-17T13:14:16.540319Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for round 12
2024-12-17T13:14:16.540381Z  INFO snarkos_node_bft::primary:

Our batch with 0 transmissions for round 12 was certified!

2024-12-17T13:14:16.540862Z  INFO snarkos_node_bft::bft:

Round 12 elected a leader - aleo1rhgdu77hgyqd3xjj8ucu3jj9r2krwz6mnzyd80gncr5fxcwlh5rsvzp9px

2024-12-17T13:14:16.540908Z DEBUG snarkos_node_bft::primary: Primary is not ready to propose the next round
2024-12-17T13:14:16.546229Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 1/12
2024-12-17T13:14:16.551497Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 2/12
2024-12-17T13:14:16.556727Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 3/12
2024-12-17T13:14:19.061815Z  INFO snarkos_node_bft::bft:

Round 12 elected a leader - aleo1rhgdu77hgyqd3xjj8ucu3jj9r2krwz6mnzyd80gncr5fxcwlh5rsvzp9px

2024-12-17T13:14:19.062042Z  INFO snarkos_node_bft::helpers::storage: Starting round 13...
2024-12-17T13:14:19.062110Z DEBUG snarkos_node_bft::primary: Primary is safely skipping (round 12 was already certified)
2024-12-17T13:14:21.566969Z  INFO snarkos_node_bft::primary: Proposing a batch with 0 transmissions for round 13...
2024-12-17T13:14:21.570278Z  INFO snarkos_node_bft::primary: Quorum threshold reached - Preparing to certify our batch for round 13...
2024-12-17T13:14:21.580575Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for round 13
2024-12-17T13:14:21.580649Z  INFO snarkos_node_bft::primary:

Our batch with 0 transmissions for round 13 was certified!

2024-12-17T13:14:21.580709Z DEBUG snarkos_node_bft::primary: Primary is not ready to propose the next round
2024-12-17T13:14:21.586704Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 1/13
2024-12-17T13:14:21.591852Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 2/13
2024-12-17T13:14:21.597265Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 3/13
2024-12-17T13:14:24.102204Z  INFO snarkos_node_bft::helpers::storage: Starting round 14...
2024-12-17T13:14:24.102334Z DEBUG snarkos_node_bft::primary: Primary is safely skipping (round 13 was already certified)
2024-12-17T13:14:26.135592Z DEBUG snarkos_node_router::heartbeat: No connected peers
2024-12-17T13:14:26.607499Z  INFO snarkos_node_bft::primary: Proposing a batch with 0 transmissions for round 14...
2024-12-17T13:14:26.610659Z  INFO snarkos_node_bft::primary: Quorum threshold reached - Preparing to certify our batch for round 14...
2024-12-17T13:14:26.619809Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for round 14
2024-12-17T13:14:26.619881Z  INFO snarkos_node_bft::primary:

Our batch with 0 transmissions for round 14 was certified!

2024-12-17T13:14:26.620534Z  INFO snarkos_node_bft::bft:

Round 14 did not elect a leader

2024-12-17T13:14:26.620586Z DEBUG snarkos_node_bft::primary: Primary is not ready to propose the next round
2024-12-17T13:14:26.627138Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 1/14
2024-12-17T13:14:26.632693Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 2/14
2024-12-17T13:14:26.637791Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 3/14
2024-12-17T13:14:27.135948Z  INFO snarkos_node_bft::gateway: No connected validators
2024-12-17T13:14:27.136148Z DEBUG snarkos_node_bft::gateway: Connecting to validator 127.0.0.1:5001...
2024-12-17T13:14:27.136506Z  WARN snarkos_node_bft::gateway: Unable to connect to '127.0.0.1:5001' - Connection refused (os error 111)
2024-12-17T13:14:29.143052Z  INFO snarkos_node_bft::bft:

Round 14 elected a leader - aleo1s3ws5tra87fjycnjrwsjcrnw2qxr8jfqqdugnf0xzqqw29q9m5pqem2u4t

2024-12-17T13:14:29.143211Z  INFO snarkos_node_bft::helpers::storage: Starting round 15...
2024-12-17T13:14:29.143235Z DEBUG snarkos_node_bft::primary: Primary is safely skipping (round 14 was already certified)
2024-12-17T13:14:31.646638Z  INFO snarkos_node_bft::primary: Proposing a batch with 0 transmissions for round 15...
2024-12-17T13:14:31.648846Z  INFO snarkos_node_bft::primary: Quorum threshold reached - Preparing to certify our batch for round 15...
2024-12-17T13:14:31.657984Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for round 15
2024-12-17T13:14:31.658097Z  INFO snarkos_node_bft::primary:

Our batch with 0 transmissions for round 15 was certified!

2024-12-17T13:14:31.658199Z DEBUG snarkos_node_bft::primary: Primary is not ready to propose the next round
2024-12-17T13:14:31.669552Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 1/15
2024-12-17T13:14:31.680387Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 2/15
2024-12-17T13:14:31.690422Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 3/15
2024-12-17T13:14:34.192955Z  INFO snarkos_node_bft::helpers::storage: Starting round 16...
2024-12-17T13:14:34.193016Z DEBUG snarkos_node_bft::primary: Primary is safely skipping (round 15 was already certified)
2024-12-17T13:14:36.698749Z  INFO snarkos_node_bft::primary: Proposing a batch with 0 transmissions for round 16...
2024-12-17T13:14:36.703122Z  INFO snarkos_node_bft::primary: Quorum threshold reached - Preparing to certify our batch for round 16...
2024-12-17T13:14:36.712637Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for round 16
2024-12-17T13:14:36.712719Z  INFO snarkos_node_bft::primary:

Our batch with 0 transmissions for round 16 was certified!

2024-12-17T13:14:36.713458Z  INFO snarkos_node_bft::bft:

Round 16 did not elect a leader

2024-12-17T13:14:36.713517Z DEBUG snarkos_node_bft::primary: Primary is not ready to propose the next round
2024-12-17T13:14:36.722135Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 1/16
2024-12-17T13:14:36.728021Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 2/16
2024-12-17T13:14:36.733817Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 3/16
2024-12-17T13:14:39.238498Z  INFO snarkos_node_bft::bft:

Round 16 elected a leader - aleo1ashyu96tjwe63u0gtnnv8z5lhapdu4l5pjsl2kha7fv7hvz2eqxs5dz0rg

2024-12-17T13:14:39.238637Z  INFO snarkos_node_bft::helpers::storage: Starting round 17...
2024-12-17T13:14:39.238658Z DEBUG snarkos_node_bft::primary: Primary is safely skipping (round 16 was already certified)
2024-12-17T13:14:41.743933Z  INFO snarkos_node_bft::primary: Proposing a batch with 0 transmissions for round 17...
2024-12-17T13:14:41.747086Z  INFO snarkos_node_bft::primary: Quorum threshold reached - Preparing to certify our batch for round 17...
2024-12-17T13:14:41.756116Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for round 17
2024-12-17T13:14:41.756183Z  INFO snarkos_node_bft::primary:

Our batch with 0 transmissions for round 17 was certified!

2024-12-17T13:14:41.756252Z DEBUG snarkos_node_bft::primary: Primary is not ready to propose the next round
2024-12-17T13:14:41.763438Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 1/17
2024-12-17T13:14:41.769256Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 2/17
2024-12-17T13:14:41.774520Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 3/17
2024-12-17T13:14:42.137429Z  INFO snarkos_node_bft::gateway: No connected validators
2024-12-17T13:14:42.137679Z DEBUG snarkos_node_bft::gateway: Connecting to validator 127.0.0.1:5001...
2024-12-17T13:14:42.138287Z  WARN snarkos_node_bft::gateway: Unable to connect to '127.0.0.1:5001' - Connection refused (os error 111)
2024-12-17T13:14:44.279743Z  INFO snarkos_node_bft::helpers::storage: Starting round 18...
2024-12-17T13:14:44.279900Z DEBUG snarkos_node_bft::primary: Primary is safely skipping (round 17 was already certified)
2024-12-17T13:14:46.785970Z  INFO snarkos_node_bft::primary: Proposing a batch with 0 transmissions for round 18...
2024-12-17T13:14:46.789206Z  INFO snarkos_node_bft::primary: Quorum threshold reached - Preparing to certify our batch for round 18...
2024-12-17T13:14:46.797865Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for round 18
2024-12-17T13:14:46.797921Z  INFO snarkos_node_bft::primary:

Our batch with 0 transmissions for round 18 was certified!

2024-12-17T13:14:46.798446Z  INFO snarkos_node_bft::bft:

Round 18 did not elect a leader

2024-12-17T13:14:46.798489Z DEBUG snarkos_node_bft::primary: Primary is not ready to propose the next round
2024-12-17T13:14:46.805384Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 1/18
2024-12-17T13:14:46.810731Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 2/18
2024-12-17T13:14:46.815987Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 3/18
2024-12-17T13:14:49.321174Z  INFO snarkos_node_bft::bft:

Round 18 elected a leader - aleo1s3ws5tra87fjycnjrwsjcrnw2qxr8jfqqdugnf0xzqqw29q9m5pqem2u4t

2024-12-17T13:14:49.321351Z  INFO snarkos_node_bft::helpers::storage: Starting round 19...
2024-12-17T13:14:49.321377Z DEBUG snarkos_node_bft::primary: Primary is safely skipping (round 18 was already certified)
2024-12-17T13:14:51.136826Z DEBUG snarkos_node_router::heartbeat: No connected peers
2024-12-17T13:14:51.826837Z  INFO snarkos_node_bft::primary: Proposing a batch with 0 transmissions for round 19...
2024-12-17T13:14:51.830117Z  INFO snarkos_node_bft::primary: Quorum threshold reached - Preparing to certify our batch for round 19...
2024-12-17T13:14:51.839855Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for round 19
2024-12-17T13:14:51.839936Z  INFO snarkos_node_bft::primary:

Our batch with 0 transmissions for round 19 was certified!

2024-12-17T13:14:51.839984Z DEBUG snarkos_node_bft::primary: Primary is not ready to propose the next round
2024-12-17T13:14:51.847583Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 1/19
2024-12-17T13:14:51.854154Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 2/19
2024-12-17T13:14:51.859012Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 3/19
2024-12-17T13:14:54.364271Z  INFO snarkos_node_bft::helpers::storage: Starting round 20...
2024-12-17T13:14:54.364348Z DEBUG snarkos_node_bft::primary: Primary is safely skipping (round 19 was already certified)
2024-12-17T13:14:56.869527Z  INFO snarkos_node_bft::primary: Proposing a batch with 0 transmissions for round 20...
2024-12-17T13:14:56.870597Z  INFO snarkos_node_bft::primary: Quorum threshold reached - Preparing to certify our batch for round 20...
2024-12-17T13:14:56.876355Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for round 20
2024-12-17T13:14:56.876412Z  INFO snarkos_node_bft::primary:

Our batch with 0 transmissions for round 20 was certified!

2024-12-17T13:14:56.876958Z  INFO snarkos_node_bft::bft:

Round 20 did not elect a leader

2024-12-17T13:14:56.877002Z DEBUG snarkos_node_bft::primary: Primary is not ready to propose the next round
2024-12-17T13:14:56.883082Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 1/20
2024-12-17T13:14:56.888220Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 2/20
2024-12-17T13:14:56.893541Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 3/20
2024-12-17T13:14:57.138340Z  INFO snarkos_node_bft::gateway: No connected validators
2024-12-17T13:14:57.138553Z DEBUG snarkos_node_bft::gateway: Connecting to validator 127.0.0.1:5001...
2024-12-17T13:14:57.139151Z  WARN snarkos_node_bft::gateway: Unable to connect to '127.0.0.1:5001' - Connection refused (os error 111)
2024-12-17T13:14:59.398322Z  INFO snarkos_node_bft::bft:

Round 20 elected a leader - aleo1s3ws5tra87fjycnjrwsjcrnw2qxr8jfqqdugnf0xzqqw29q9m5pqem2u4t

2024-12-17T13:14:59.398395Z  INFO snarkos_node_bft::helpers::storage: Starting round 21...
2024-12-17T13:14:59.398406Z DEBUG snarkos_node_bft::primary: Primary is safely skipping (round 20 was already certified)
2024-12-17T13:15:01.903870Z  INFO snarkos_node_bft::primary: Proposing a batch with 0 transmissions for round 21...
2024-12-17T13:15:01.907343Z  INFO snarkos_node_bft::primary: Quorum threshold reached - Preparing to certify our batch for round 21...
2024-12-17T13:15:01.918408Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for round 21
2024-12-17T13:15:01.918480Z  INFO snarkos_node_bft::primary:

Our batch with 0 transmissions for round 21 was certified!

2024-12-17T13:15:01.918534Z DEBUG snarkos_node_bft::primary: Primary is not ready to propose the next round
2024-12-17T13:15:01.929353Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 1/21
2024-12-17T13:15:01.935426Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 2/21
2024-12-17T13:15:01.940725Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 3/21
2024-12-17T13:15:04.443851Z  INFO snarkos_node_bft::helpers::storage: Starting round 22...
2024-12-17T13:15:04.443933Z DEBUG snarkos_node_bft::primary: Primary is safely skipping (round 21 was already certified)
2024-12-17T13:15:06.949038Z  INFO snarkos_node_bft::primary: Proposing a batch with 0 transmissions for round 22...
2024-12-17T13:15:06.950264Z  INFO snarkos_node_bft::primary: Quorum threshold reached - Preparing to certify our batch for round 22...
2024-12-17T13:15:06.955773Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for round 22
2024-12-17T13:15:06.955838Z  INFO snarkos_node_bft::primary:

Our batch with 0 transmissions for round 22 was certified!

2024-12-17T13:15:06.956495Z  INFO snarkos_node_bft::bft:

Round 22 did not elect a leader

2024-12-17T13:15:06.956548Z DEBUG snarkos_node_bft::primary: Primary is not ready to propose the next round
2024-12-17T13:15:06.962649Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 1/22
2024-12-17T13:15:06.968042Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 2/22
2024-12-17T13:15:06.972861Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 3/22
2024-12-17T13:15:09.478764Z  INFO snarkos_node_bft::bft:

Round 22 elected a leader - aleo1ashyu96tjwe63u0gtnnv8z5lhapdu4l5pjsl2kha7fv7hvz2eqxs5dz0rg

2024-12-17T13:15:09.478899Z  INFO snarkos_node_bft::helpers::storage: Starting round 23...
2024-12-17T13:15:09.478964Z DEBUG snarkos_node_bft::primary: Primary is safely skipping (round 22 was already certified)
2024-12-17T13:15:11.984516Z  INFO snarkos_node_bft::primary: Proposing a batch with 0 transmissions for round 23...
2024-12-17T13:15:11.988031Z  INFO snarkos_node_bft::primary: Quorum threshold reached - Preparing to certify our batch for round 23...
2024-12-17T13:15:11.999083Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for round 23
2024-12-17T13:15:11.999153Z  INFO snarkos_node_bft::primary:

Our batch with 0 transmissions for round 23 was certified!

2024-12-17T13:15:11.999209Z DEBUG snarkos_node_bft::primary: Primary is not ready to propose the next round
2024-12-17T13:15:12.007259Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 1/23
2024-12-17T13:15:12.012816Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 2/23
2024-12-17T13:15:12.018473Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 3/23
2024-12-17T13:15:12.140165Z  INFO snarkos_node_bft::gateway: No connected validators
2024-12-17T13:15:12.140384Z DEBUG snarkos_node_bft::gateway: Connecting to validator 127.0.0.1:5001...
2024-12-17T13:15:12.140859Z  WARN snarkos_node_bft::gateway: Unable to connect to '127.0.0.1:5001' - Connection refused (os error 111)
2024-12-17T13:15:14.523195Z  INFO snarkos_node_bft::helpers::storage: Starting round 24...
2024-12-17T13:15:14.523255Z DEBUG snarkos_node_bft::primary: Primary is safely skipping (round 23 was already certified)
2024-12-17T13:15:16.138308Z DEBUG snarkos_node_router::heartbeat: No connected peers
2024-12-17T13:15:17.026049Z  INFO snarkos_node_bft::primary: Proposing a batch with 0 transmissions for round 24...
2024-12-17T13:15:17.027229Z  INFO snarkos_node_bft::primary: Quorum threshold reached - Preparing to certify our batch for round 24...
2024-12-17T13:15:17.031884Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for round 24
2024-12-17T13:15:17.031926Z  INFO snarkos_node_bft::primary:

Our batch with 0 transmissions for round 24 was certified!

2024-12-17T13:15:17.032343Z  INFO snarkos_node_bft::bft:

Round 24 did not elect a leader

2024-12-17T13:15:17.032378Z DEBUG snarkos_node_bft::primary: Primary is not ready to propose the next round
2024-12-17T13:15:17.037455Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 1/24
2024-12-17T13:15:17.042380Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 2/24
2024-12-17T13:15:17.047255Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 3/24
2024-12-17T13:15:19.552209Z  INFO snarkos_node_bft::bft:

Round 24 elected a leader - aleo1s3ws5tra87fjycnjrwsjcrnw2qxr8jfqqdugnf0xzqqw29q9m5pqem2u4t

2024-12-17T13:15:19.552278Z  INFO snarkos_node_bft::helpers::storage: Starting round 25...
2024-12-17T13:15:19.552285Z DEBUG snarkos_node_bft::primary: Primary is safely skipping (round 24 was already certified)
2024-12-17T13:15:22.056780Z  INFO snarkos_node_bft::primary: Proposing a batch with 0 transmissions for round 25...
2024-12-17T13:15:22.058011Z  INFO snarkos_node_bft::primary: Quorum threshold reached - Preparing to certify our batch for round 25...
2024-12-17T13:15:22.067615Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for round 25
2024-12-17T13:15:22.067728Z  INFO snarkos_node_bft::primary:

Our batch with 0 transmissions for round 25 was certified!

2024-12-17T13:15:22.067822Z DEBUG snarkos_node_bft::primary: Primary is not ready to propose the next round
2024-12-17T13:15:22.075918Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 1/25
2024-12-17T13:15:22.081220Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 2/25
2024-12-17T13:15:22.086315Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 3/25
2024-12-17T13:15:24.591925Z  INFO snarkos_node_bft::helpers::storage: Starting round 26...
2024-12-17T13:15:24.592050Z DEBUG snarkos_node_bft::primary: Primary is safely skipping (round 25 was already certified)
2024-12-17T13:15:27.098061Z  INFO snarkos_node_bft::primary: Proposing a batch with 0 transmissions for round 26...
2024-12-17T13:15:27.101108Z  INFO snarkos_node_bft::primary: Quorum threshold reached - Preparing to certify our batch for round 26...
2024-12-17T13:15:27.110524Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for round 26
2024-12-17T13:15:27.110595Z  INFO snarkos_node_bft::primary:

Our batch with 0 transmissions for round 26 was certified!

2024-12-17T13:15:27.111300Z  INFO snarkos_node_bft::bft:

Round 26 did not elect a leader

2024-12-17T13:15:27.111357Z DEBUG snarkos_node_bft::primary: Primary is not ready to propose the next round
2024-12-17T13:15:27.118622Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 1/26
2024-12-17T13:15:27.124236Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 2/26
2024-12-17T13:15:27.129479Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 3/26
2024-12-17T13:15:27.141717Z  INFO snarkos_node_bft::gateway: No connected validators
2024-12-17T13:15:27.141817Z DEBUG snarkos_node_bft::gateway: Connecting to validator 127.0.0.1:5001...
2024-12-17T13:15:27.142058Z  WARN snarkos_node_bft::gateway: Unable to connect to '127.0.0.1:5001' - Connection refused (os error 111)
2024-12-17T13:15:29.634225Z  INFO snarkos_node_bft::bft:

Round 26 elected a leader - aleo12ux3gdauck0v60westgcpqj7v8rrcr3v346e4jtq04q7kkt22czsh808v2

2024-12-17T13:15:29.634382Z  INFO snarkos_node_bft::helpers::storage: Starting round 27...
2024-12-17T13:15:29.634403Z DEBUG snarkos_node_bft::primary: Primary is safely skipping (round 26 was already certified)
2024-12-17T13:15:32.139783Z  INFO snarkos_node_bft::primary: Proposing a batch with 0 transmissions for round 27...
2024-12-17T13:15:32.143024Z  INFO snarkos_node_bft::primary: Quorum threshold reached - Preparing to certify our batch for round 27...
2024-12-17T13:15:32.153579Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for round 27
2024-12-17T13:15:32.153660Z  INFO snarkos_node_bft::primary:

Our batch with 0 transmissions for round 27 was certified!

2024-12-17T13:15:32.153718Z DEBUG snarkos_node_bft::primary: Primary is not ready to propose the next round
2024-12-17T13:15:32.159778Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 1/27
2024-12-17T13:15:32.165030Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 2/27
2024-12-17T13:15:32.170259Z DEBUG snarkos_node_bft::primary: Stored a batch certificate for validator/round 3/27
^C2024-12-17T13:15:34.538524Z  WARN snarkos_node::traits: ==========================================================================================
2024-12-17T13:15:34.538641Z  WARN snarkos_node::traits: ⚠️  Attention - Starting the graceful shutdown procedure (ETA: 30 seconds)...
2024-12-17T13:15:34.538653Z  WARN snarkos_node::traits: ⚠️  Attention - To avoid DATA CORRUPTION, do NOT interrupt snarkOS (or press Ctrl+C again)
2024-12-17T13:15:34.538662Z  WARN snarkos_node::traits: ⚠️  Attention - Please wait until the shutdown gracefully completes (ETA: 30 seconds)
2024-12-17T13:15:34.538671Z  WARN snarkos_node::traits: ==========================================================================================
2024-12-17T13:15:34.538725Z  INFO snarkos_node::validator: Shutting down...
2024-12-17T13:15:34.538747Z  INFO snarkos_node_router: Shutting down the router...
2024-12-17T13:15:34.538934Z  INFO snarkos_node_consensus: Shutting down consensus...
2024-12-17T13:15:34.539019Z  INFO snarkos_node_bft::bft: Shutting down the BFT...
2024-12-17T13:15:34.539035Z  INFO snarkos_node_bft::primary: Shutting down the primary...
2024-12-17T13:15:34.539819Z  INFO snarkos_node_bft::helpers::proposal_cache: Storing the proposal cache to /home/alexubuntu22/.current-proposal-cache-1-0...
2024-12-17T13:15:34.543912Z  INFO snarkos_node_bft::gateway: Shutting down the gateway...
2024-12-17T13:15:34.543964Z  INFO snarkos_node::validator: Node has shut down.
```