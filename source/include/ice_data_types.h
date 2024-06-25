#ifndef ICE_DATA_TYPES_H
#define ICE_DATA_TYPES_H

/* Standard includes. */
#include <stdint.h>
#include <stddef.h>

/* Stun includes. */
#include "stun_data_types.h"

/* Transaction ID Store includes. */
#include "transaction_id_store.h"

/*----------------------------------------------------------------------------*/

/* Macros used to track a candidate pair's connectivity check status. */
#define ICE_STUN_REQUEST_SENT_FLAG      ( 1 << 0 )
#define ICE_STUN_RESPONSE_RECEIVED_FLAG ( 1 << 1 )
#define ICE_STUN_REQUEST_RECEIVED_FLAG  ( 1 << 2 )
#define ICE_STUN_RESPONSE_SENT_FLAG     ( 1 << 3 )

#define ICE_STUN_CONNECTIVITY_CHECK_SUCCESSFUL( connectivityCheckFlags )    \
    ( ( connectivityCheckFlags ) == ( ICE_STUN_REQUEST_SENT_FLAG |          \
                                      ICE_STUN_RESPONSE_RECEIVED_FLAG |     \
                                      ICE_STUN_REQUEST_RECEIVED_FLAG |      \
                                      ICE_STUN_RESPONSE_SENT_FLAG ) )

/*----------------------------------------------------------------------------*/

typedef enum IceCandidateType
{
    ICE_CANDIDATE_TYPE_HOST,
    ICE_CANDIDATE_TYPE_PEER_REFLEXIVE,
    ICE_CANDIDATE_TYPE_SERVER_REFLEXIVE,
    ICE_CANDIDATE_TYPE_RELAYED,
} IceCandidateType_t;

typedef enum IceCandidateState
{
    ICE_CANDIDATE_STATE_INVALID,
    ICE_CANDIDATE_STATE_NEW,
    ICE_CANDIDATE_STATE_VALID
} IceCandidateState_t;

typedef enum IceCandidatePairState
{
    ICE_CANDIDATE_PAIR_STATE_INVALID,
    ICE_CANDIDATE_PAIR_STATE_FROZEN,
    ICE_CANDIDATE_PAIR_STATE_WAITING,
    ICE_CANDIDATE_PAIR_STATE_VALID,
    ICE_CANDIDATE_PAIR_STATE_NOMINATED,
    ICE_CANDIDATE_PAIR_STATE_SUCCEEDED
} IceCandidatePairState_t;

typedef enum IceSocketProtocol
{
    ICE_SOCKET_PROTOCOL_NONE,
    ICE_SOCKET_PROTOCOL_TCP,
    ICE_SOCKET_PROTOCOL_UDP
} IceSocketProtocol_t;

typedef enum IceResult
{
    ICE_RESULT_OK,
    ICE_RESULT_BAD_PARAM,
    ICE_RESULT_MAX_CANDIDATE_THRESHOLD,
    ICE_RESULT_MAX_CANDIDATE_PAIR_THRESHOLD,
    ICE_RESULT_STUN_ERROR,
    ICE_RESULT_RANDOM_GENERATION_ERROR,
    ICE_RESULT_CRC32_ERROR,
    ICE_RESULT_HMAC_ERROR,
    ICE_RESULT_TRANSACTION_ID_STORE_ERROR,
    ICE_RESULT_OUT_OF_MEMORY
} IceResult_t;

typedef enum IceHandleStunPacketResult
{
    /* Info codes. */
    ICE_HANDLE_STUN_PACKET_RESULT_OK,
    ICE_HANDLE_STUN_PACKET_RESULT_FOUND_PEER_REFLEXIVE_CANDIDATE,
    ICE_HANDLE_STUN_PACKET_RESULT_UPDATED_SERVER_REFLEXIVE_CANDIDATE_ADDRESS,
    ICE_HANDLE_STUN_PACKET_RESULT_VALID_CANDIDATE_PAIR,
    ICE_HANDLE_STUN_PACKET_RESULT_CANDIDATE_PAIR_READY,
    ICE_HANDLE_STUN_PACKET_RESULT_STUN_BINDING_INDICATION,

    /* Error codes. */
    ICE_HANDLE_STUN_PACKET_RESULT_BAD_PARAM,
    ICE_HANDLE_STUN_PACKET_RESULT_DESERIALIZE_ERROR,
    ICE_HANDLE_STUN_PACKET_RESULT_INTEGRITY_MISMATCH,
    ICE_HANDLE_STUN_PACKET_RESULT_FINGERPRINT_MISMATCH,
    ICE_HANDLE_STUN_PACKET_RESULT_INVALID_PACKET_TYPE,
    ICE_HANDLE_STUN_PACKET_RESULT_CANDIDATE_NOT_FOUND,
    ICE_HANDLE_STUN_PACKET_RESULT_CANDIDATE_PAIR_NOT_FOUND,
    ICE_HANDLE_STUN_PACKET_RESULT_ADDRESS_ATTRIBUTE_NOT_FOUND,
    ICE_HANDLE_STUN_PACKET_RESULT_MATCHING_TRANSACTION_ID_NOT_FOUND,

    /* Application needs to take action. */
    ICE_HANDLE_STUN_PACKET_RESULT_SEND_RESPONSE_FOR_REMOTE_REQUEST,
    ICE_HANDLE_STUN_PACKET_RESULT_SEND_TRIGGERED_CHECK,
    ICE_HANDLE_STUN_PACKET_RESULT_START_NOMINATION,
    ICE_HANDLE_STUN_PACKET_RESULT_SEND_RESPONSE_FOR_NOMINATION
} IceHandleStunPacketResult_t;

/*----------------------------------------------------------------------------*/

typedef IceResult_t ( * IceRandom_t ) ( uint8_t * pOutputBuffer,
                                        size_t outputBufferLength );
typedef IceResult_t ( * IceCrc32_t ) ( uint32_t initialResult,
                                       const uint8_t * pBuffer,
                                       size_t bufferLength,
                                       uint32_t * pCalculatedCrc32 );
typedef IceResult_t ( * IceHmac_t ) ( const uint8_t * pPassword,
                                      size_t passwordLength,
                                      const uint8_t * pBuffer,
                                      size_t bufferLength,
                                      uint8_t * pOutputBuffer,
                                      size_t * pOutputBufferLength );

/*----------------------------------------------------------------------------*/

typedef StunAttributeAddress_t IceTransportAddress_t;

typedef struct IceEndpoint
{
    IceTransportAddress_t transportAddress;
    uint8_t isPointToPoint;
} IceEndpoint_t;

typedef struct IceCandidate
{
    IceCandidateType_t candidateType;
    uint8_t isRemote;
    IceEndpoint_t endpoint;
    IceCandidateState_t state;
    uint32_t priority;
    IceSocketProtocol_t remoteProtocol;
} IceCandidate_t;

typedef struct IceCandidatePair
{
    IceCandidate_t * pLocalCandidate;
    IceCandidate_t * pRemoteCandidate;
    uint64_t priority;
    IceCandidatePairState_t state;
    uint32_t connectivityCheckFlags;
    uint8_t transactionId[ STUN_HEADER_TRANSACTION_ID_LENGTH ];
} IceCandidatePair_t;

typedef struct IceCryptoFunctions
{
    IceRandom_t randomFxn;
    IceCrc32_t crc32Fxn;
    IceHmac_t hmacFxn;
} IceCryptoFunctions_t;

typedef struct IceCredentials
{
    const char * pLocalUsername;
    size_t localUsernameLength;
    const char * pLocalPassword;
    size_t localPasswordLength;
    const char * pRemoteUsername;
    size_t remoteUsernameLength;
    const char * pRemotePassword;
    size_t remotePasswordLength;
    const char * pCombinedUsername;
    size_t combinedUsernameLength;
} IceCredentials_t;

typedef struct IceContext
{
    IceCredentials_t creds;
    IceCandidate_t * pLocalCandidates;
    size_t maxLocalCandidates;
    size_t numLocalCandidates;
    IceCandidate_t * pRemoteCandidates;
    size_t maxRemoteCandidates;
    size_t numRemoteCandidates;
    IceCandidatePair_t * pCandidatePairs;
    size_t maxCandidatePairs;
    size_t numCandidatePairs;
    uint64_t tieBreaker;
    uint8_t isControlling;
    TransactionIdStore_t * pStunBindingRequestTransactionIdStore;
    IceCryptoFunctions_t cryptoFunctions;
} IceContext_t;

typedef struct IceInitInfo
{
    IceCredentials_t creds;
    IceCandidate_t * pLocalCandidatesArray;
    size_t localCandidatesArrayLength;
    IceCandidate_t * pRemoteCandidatesArray;
    size_t remoteCandidatesArrayLength;
    IceCandidatePair_t * pCandidatePairsArray;
    size_t candidatePairsArrayLength;
    uint8_t isControlling;
    TransactionIdStore_t * pStunBindingRequestTransactionIdStore;
    IceCryptoFunctions_t cryptoFunctions;
} IceInitInfo_t;

typedef struct IceRemoteCandidateInfo
{
    IceCandidateType_t candidateType;
    IceSocketProtocol_t remoteProtocol;
    uint32_t priority;
    const IceEndpoint_t * pEndpoint;
} IceRemoteCandidateInfo_t;

typedef struct IceStunDeserializedPacketInfo
{
    uint8_t useCandidateFlag;
    uint16_t errorCode;
    uint32_t priority;
    IceTransportAddress_t transportAddress;
} IceStunDeserializedPacketInfo_t;

/*----------------------------------------------------------------------------*/

#endif /* ICE_DATA_TYPES_H */
