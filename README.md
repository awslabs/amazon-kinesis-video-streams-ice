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

1. Call `Ice_Init()` to initialize the ICE Context.
2. Call `Ice_AddHostCandidate()` to add local host candidates .
3. Call `Ice_AddServerReflexiveCandidate()` to add local server reflexive
   candidates.
4. Call `Ice_AddRemoteCandidate()` to add remote candidates, received in SDP
   answer.
5. Call `Ice_HandleStunResponse()` to process STUN message received from remote
   peer.
6. Based on the return values  `Ice_HandleStunResponse()`:
    - Call `Ice_CreateRequestForConnectivityCheck()` to create STUN message to
    be sent to the remote candidate for connectivity check.
    - Call `Ice_CreateRequestForNominatingCandidatePair()` to create STUN
    message to be sent by the Controlling ICE agent for nomination of a valid
    candidate pair.
    - Call `Ice_CreateResponseForRequest()` to create STUN message for response
    to a STUN Binding Request.

## Security

See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for more
information.

## License

This project is licensed under the Apache-2.0 License.
