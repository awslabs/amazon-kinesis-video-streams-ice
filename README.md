## amazon-kinesis-video-streams-ice

The goal of the Interactive Connectivity Establishment ( ICE ) library is to establish a connection between two nodes which is as direct as possible.

## What is ICE?

[Interactive Connectivity Establishment ( ICE )](https://en.wikipedia.org/wiki/Interactive_Connectivity_Establishment),
as defined in [RFC 8445](https://datatracker.ietf.org/doc/html/rfc8445), is a 
Networking technique which makes use of STUN (Session Traversal Utilities for 
NAT) and TURN (Traversal Using Relays Around NAT) to establish a connection 
between two nodes which is as direct as possible.

One of the key components of Interactive Connectivity Establishment (ICE) is 
the ICE agent and candidate. An ICE agent acts as a mediator between two 
endpoints, exchanging messages to determine the best route for data 
transmission. On the other hand, an ICE candidate refers to a potential network 
address that an endpoint can use when establishing connectivity with another 
endpoint.

To establish a connection between two peers, each ICE agent performs the 
following steps:

- *Candidate Gathering*

    An ICE agent gathers all the possible addresses it is reachable at. These addresses are known as local ICE candidates and include Host, Server Reflexive and Relayed candidates. It includes the following steps:

    - Read local interfaces to learn Host candidates. 
    - Send STUN Binding Request to each STUN server (obtained via signaling) from each Host candidate. STUN Binding Responses for these requests give   us Server Reflexive candidates. 
    - Perform handshake with each TURN server (obtained via signaling) to obtain Relayed candidates.

- *Connectivity Checks*

    The two ICE agents that want to talk to each other, exchange their local ICE candidates (gathered in the previous step) with each other using Signaling.
    ICE agent pairs each local candidate with each remote candidate and creates a candidate pair list. It then performs a connectivity check on each ICE candidate pair. Connectivity check on a candidate pair involves the exchange of the following STUN messages:

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
The candidate pairs for which the connectivity check succeeds, are promoted to valid candidate pairs.


- *Nominating Candidate Pair*

    An ICE agent is either Controlling or Controlled. The Controlling agent picks one valid candidate pair and nominates it. The controlling agent sends a STUN request on the nominated candidate pair with the USE-CANDIDATE attribute set
and if the connectivity check succeeds, the nominated candidate pair becomes selected candidate pair. This candidate pair is then used for data transfer for the rest of the session.

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
3. Call `Ice_AddServerReflexiveCandidate()` to add local Srflx candidates.
4. Call `Ice_AddRemoteCandidate()` to add remote candidates, received over SDP 
answer.
5. Call `Ice_HandleStunResponse()` to process STUN packet received from remote 
peer.
6. Based on the return values after the STUN packets are processed:
    - Call `Ice_CreateRequestForConnectivityCheck()` to create STUN packet to 
    be sent to the remote candidate for connectivity check.
    - Call `Ice_CreateRequestForNominatingCandidatePair()` to create STUN 
    packet to be sent by the Controlling ICE agent for nomination of the valid
    candidiate pair.
    - Call `Ice_CreateResponseForRequest()` to create STUN packet for response
    to a STUN  Binding Request.

## Security

See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for more information.

## License

This project is licensed under the Apache-2.0 License.

