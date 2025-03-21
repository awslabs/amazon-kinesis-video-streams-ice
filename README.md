## amazon-kinesis-video-streams-ice

The goal of the Interactive Connectivity Establishment ( ICE ) library is to
enable bi-directional peer-to-peer communication between two nodes.

## What is ICE?

[Interactive Connectivity Establishment ( ICE )](https://en.wikipedia.org/wiki/Interactive_Connectivity_Establishment),
as defined in [RFC 8445](https://datatracker.ietf.org/doc/html/rfc8445), is a
solution which utilizes STUN (Session Traversal Utilities for NAT) and TURN
(Traversal Using Relays Around NAT) to enable bi-directional peer-to-peer
communication between two nodes.

### ICE Agent
An ICE agent acts as a mediator between two endpoints, exchanging messages to
determine the best route for data transmission.

### ICE Candidate
An ICE candidate is essentially a transport address (IP + Port) of the ICE agent
at which the agent is reachable.

### ICE Candidate Pair
An ICE Candidate Pair is a pair containing a local candidate and a remote
candidate.


Each ICE agent performs the following steps to establish a connection between
two peers:

### Candidate Gathering

An ICE agent gathers all the possible addresses it is reachable at. These
addresses are known as local ICE candidates and include Host, Server Reflexive
and Relayed candidates. It includes the following steps:

* Read local interfaces to learn Host candidates.
* Send STUN Binding Request to each STUN server (obtained via signaling) from
  each Host candidate. STUN Binding Responses for these requests give us Server
  Reflexive candidates.
* Perform handshake with each TURN server (obtained via signaling) to obtain
  Relayed candidates.

### Connectivity Checks

The two ICE agents that want to talk to each other, exchange their local ICE
candidates (gathered in the previous step) with each other using Signaling. ICE
agent pairs each local candidate with each remote candidate and creates a
candidate pair list. It then performs a connectivity check on each ICE candidate
pair. Connectivity check on a candidate pair involves the exchange of the
following STUN messages:

```
        +-----------------+                                +------------------+
        |                 |                                |                  |
        | Local Candidate |                                | Remote Candidate |
        |                 |                                |                  |
        +-----------------+                                +------------------+
                |                                                   |
                |                                                   |
                |-------------------------------------------------->|
                |                   STUN Request                    |
                |<--------------------------------------------------|
                |                   STUN Response                   |
                |<--------------------------------------------------|
                |                   STUN Request                    |
                |-------------------------------------------------->|
                |                   STUN Response                   |
```
The candidate pairs for which the connectivity check succeeds, are promoted to
valid candidate pairs.

### Nominating Candidate Pair

An ICE agent is either Controlling or Controlled. The Controlling agent picks
one valid candidate pair and nominates it. The controlling agent sends a STUN
request on the nominated candidate pair with the USE-CANDIDATE attribute set
and if the connectivity check succeeds, the nominated candidate pair becomes
selected candidate pair. This candidate pair is then used for data transfer for
the rest of the session.

```
        +-----------------+                                +------------------+
        |                 |                                |                  |
        | Local Candidate |                                | Remote Candidate |
        |                 |                                |                  |
        +-----------------+                                +------------------+
                |                                                   |
                |                                                   |
                |-------------------------------------------------->|
                |          STUN Request with Attribute              |
                |<--------------------------------------------------|
                |                   STUN Response                   |

```


## Using the library

### Initialization
1. Call `Ice_Init()` to initialize the ICE Context.
1. Add local candidates.
    - Call `Ice_AddHostCandidate()` to add local host candidates.
    - Call `Ice_AddServerReflexiveCandidate()` to add local server reflexive candidates.
    - Call `Ice_AddRelayCandidate()` to add local relay candidates.
1. Call `Ice_AddRemoteCandidate()` to add remote candidates.

### Receive Side
1. Call `Ice_HandleTurnPacket()` to get TURN data and corresponding candidate pair if local
candidate type is relay.
1. Call `Ice_HandleStunPacket()` to address STUN message received from remote
   peer.
1. Based on the return values  `Ice_HandleStunPacket()`:
    - Call `Ice_CreateResponseForRequest()` to create STUN message for response
    to a STUN Binding Request.

### Send Side
1. Send candidate pair requests (like connectivity check/nomination request,
TURN create permission, and TURN channel binding request) to remote peer for every candidate pair.
    1. Call `Ice_GetCandidatePairCount` to get the number of existing candidate pairs.
    1. Loop through all candidate pairs, call `Ice_CreateNextPairRequest` to generate corresponding request.
    1. Send the generated message over network.
1. Send binding request for srflx candidates to query external IP or send allocation request for relay candidates.
    1. Call `Ice_GetLocalCandidateCount` to get the number of existing local candidate.
    1. Loop through all candidates, call `Ice_CreateNextCandidateRequest` to generate corresponding request.
    1. Send the generated message over network.
    
## Building Unit Tests

### Platform Prerequisites

- For running unit tests:
    - C99 compiler like gcc.
    - CMake 3.13.0 or later.
    - Ruby 2.0.0 or later (It is required for the CMock test framework that we
      use).
- For running the coverage target, gcov and lcov are required.


### Steps to Build Unit Tests

1. The following command in STEP 2 also ensures that the Submodules ( CMock and KVS Stun ) are added.
2. Run the following command to generate Makefiles:

    ```sh
    cmake -S test/unit-test -B build/ -G "Unix Makefiles" \
     -DCMAKE_BUILD_TYPE=Debug \
     -DBUILD_CLONE_SUBMODULES=ON \
     -DCMAKE_C_FLAGS='--coverage -Wall -Wextra -Werror -DNDEBUG'
    ```

### Steps to Generate Code Coverage Report and Run Unit Tests

1. Run Unit Tests in [Steps to Build Unit Tests](#steps-to-build-unit-tests).
2. Generate coverage report in the `build/coverage` folder:

    ```
    cd build && make coverage
    ```

### Script to Run Unit Test and Generate Code Coverage Report

```sh
cmake -S test/unit-test -B build/ -G "Unix Makefiles" -DCMAKE_BUILD_TYPE=Debug -DBUILD_CLONE_SUBMODULES=ON -DCMAKE_C_FLAGS='--coverage -Wall -Wextra -Werror -DNDEBUG -DLIBRARY_LOG_LEVEL=LOG_DEBUG'
cd build && make coverage
```

## Security

See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for more
information.

## License

This project is licensed under the Apache-2.0 License.
