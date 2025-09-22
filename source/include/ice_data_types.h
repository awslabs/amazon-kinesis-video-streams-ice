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
#define ICE_STUN_REQUEST_SENT_FLAG          ( 1 << 0 )
#define ICE_STUN_RESPONSE_RECEIVED_FLAG     ( 1 << 1 )
#define ICE_STUN_REQUEST_RECEIVED_FLAG      ( 1 << 2 )
#define ICE_STUN_RESPONSE_SENT_FLAG         ( 1 << 3 )

#define ICE_STUN_CONNECTIVITY_CHECK_SUCCESSFUL( connectivityCheckFlags ) \
    ( ( connectivityCheckFlags ) == ( ICE_STUN_REQUEST_SENT_FLAG |       \
                                      ICE_STUN_RESPONSE_RECEIVED_FLAG |  \
                                      ICE_STUN_REQUEST_RECEIVED_FLAG |   \
                                      ICE_STUN_RESPONSE_SENT_FLAG ) )

/* https://tools.ietf.org/html/rfc5389#section-15.3. */
#define ICE_SERVER_CONFIG_MAX_USER_NAME_LENGTH  ( 512 )

/* https://docs.aws.amazon.com/kinesisvideostreams/latest/dg/API_AWSAcuitySignalingService_IceServer.html#KinesisVideo-Type-AWSAcuitySignalingService_IceServer-Password */
#define ICE_SERVER_CONFIG_MAX_PASSWORD_LENGTH   ( 256 )

/* https://tools.ietf.org/html/rfc5389#section-15.7. */
#define ICE_SERVER_CONFIG_MAX_REALM_LENGTH      ( 128 )

/* https://tools.ietf.org/html/rfc5389#section-15.8. */
#define ICE_SERVER_CONFIG_MAX_NONCE_LENGTH      ( 128 )

/* According to https://datatracker.ietf.org/doc/html/rfc5389#section-15.4,
 * long-term credentials are generated using MD5 hash, resulting in a fixed size
 * of 16 bytes. */
#define ICE_SERVER_CONFIG_LONG_TERM_PASSWORD_LENGTH         ( 16 )

/* Various TURN times. */
#define ICE_DEFAULT_TURN_ALLOCATION_LIFETIME_SECONDS        ( 600 )
#define ICE_TURN_ALLOCATION_REFRESH_GRACE_PERIOD_SECONDS    ( 30 )
#define ICE_DEFAULT_TURN_PERMISSION_LIFETIME_SECONDS        ( 300 )
#define ICE_TURN_PERMISSION_REFRESH_GRACE_PERIOD_SECONDS    ( 30 )

/*
 * According to https://datatracker.ietf.org/doc/html/rfc8656#section-12,
 * TURN channel numbers must be in range of 0x4000 ~ 0x4FFF.
 */
#define ICE_DEFAULT_TURN_CHANNEL_NUMBER_MIN ( 0x4000 )
#define ICE_DEFAULT_TURN_CHANNEL_NUMBER_MAX ( 0x4FFF )

/*
 * TURN ChannelData Message:

 * RFC: https://datatracker.ietf.org/doc/html/rfc8656#name-the-channeldata-message

 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |         Channel Number        |            Length             |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                                                               |
 * /                       Application Data                        /
 * /                                                               /
 * |                                                               |
 * |                               +-------------------------------+
 * |                               |
 * +-------------------------------+
 */
#define ICE_TURN_CHANNEL_DATA_MESSAGE_HEADER_LENGTH         ( 4 )
#define ICE_TURN_CHANNEL_DATA_MESSAGE_CHANNEL_NUMBER_OFFSET ( 0 )
#define ICE_TURN_CHANNEL_DATA_MESSAGE_LENGTH_OFFSET         ( 2 )

/*----------------------------------------------------------------------------*/

typedef enum IceCandidateType
{
    ICE_CANDIDATE_TYPE_HOST,
    ICE_CANDIDATE_TYPE_PEER_REFLEXIVE,
    ICE_CANDIDATE_TYPE_SERVER_REFLEXIVE,
    ICE_CANDIDATE_TYPE_RELAY
} IceCandidateType_t;

typedef enum IceCandidateState
{
    ICE_CANDIDATE_STATE_INVALID,
    ICE_CANDIDATE_STATE_NEW,
    ICE_CANDIDATE_STATE_ALLOCATING, /* Relay candidate to allocate resources on the TURN server. */
    ICE_CANDIDATE_STATE_VALID,
    ICE_CANDIDATE_STATE_RELEASING, /* Relay candidate to release resources on the TURN server. */
} IceCandidateState_t;

typedef enum IceCandidatePairState
{
    ICE_CANDIDATE_PAIR_STATE_INVALID,
    ICE_CANDIDATE_PAIR_STATE_FROZEN,
    ICE_CANDIDATE_PAIR_STATE_WAITING,
    ICE_CANDIDATE_PAIR_STATE_VALID,
    ICE_CANDIDATE_PAIR_STATE_NOMINATED,
    ICE_CANDIDATE_PAIR_STATE_SUCCEEDED,
    ICE_CANDIDATE_PAIR_STATE_CREATE_PERMISSION, /* Relay candidate to create permission for remote candidate. */
    ICE_CANDIDATE_PAIR_STATE_CHANNEL_BIND /* Relay candidate to associate channel number with remote candidate. */
} IceCandidatePairState_t;

typedef enum IceSocketProtocol
{
    ICE_SOCKET_PROTOCOL_NONE,
    ICE_SOCKET_PROTOCOL_TCP,
    ICE_SOCKET_PROTOCOL_UDP
} IceSocketProtocol_t;

typedef enum IceResult
{
    /* Info codes. */
    ICE_RESULT_OK,
    ICE_RESULT_NO_NEXT_ACTION,
    ICE_RESULT_TURN_CHANNEL_DATA_HEADER_NOT_REQUIRED,

    /* Error code. */
    ICE_RESULT_BAD_PARAM,
    ICE_RESULT_MAX_CANDIDATE_THRESHOLD,
    ICE_RESULT_MAX_CANDIDATE_PAIR_THRESHOLD,
    ICE_RESULT_MAX_TURN_SERVER_THRESHOLD,
    ICE_RESULT_MAX_CHANNEL_NUMBER_THRESHOLD,
    ICE_RESULT_STUN_ERROR,
    ICE_RESULT_STUN_ERROR_ADD_LIFETIME,
    ICE_RESULT_STUN_ERROR_ADD_REQUESTED_TRANSPORT,
    ICE_RESULT_STUN_ERROR_ADD_USERNAME,
    ICE_RESULT_STUN_ERROR_ADD_REALM,
    ICE_RESULT_STUN_ERROR_ADD_NONCE,
    ICE_RESULT_STUN_ERROR_ADD_XOR_PEER_ADDRESS,
    ICE_RESULT_STUN_ERROR_ADD_CHANNEL_NUMBER,
    ICE_RESULT_SNPRINTF_ERROR,
    ICE_RESULT_RANDOM_GENERATION_ERROR,
    ICE_RESULT_CRC32_ERROR,
    ICE_RESULT_HMAC_ERROR,
    ICE_RESULT_MD5_ERROR,
    ICE_RESULT_TRANSACTION_ID_STORE_ERROR,
    ICE_RESULT_OUT_OF_MEMORY,
    ICE_RESULT_INVALID_CANDIDATE_CREDENTIAL,
    ICE_RESULT_INVALID_CANDIDATE,
    ICE_RESULT_INVALID_CANDIDATE_PAIR,
    ICE_RESULT_TURN_CANDIDATE_PAIR_NOT_FOUND,
    ICE_RESULT_TURN_INVALID_MESSAGE,
    ICE_RESULT_TURN_UNEXPECTED_MESSAGE,
} IceResult_t;

typedef enum IceHandleStunPacketResult
{
    /* Info codes. */
    ICE_HANDLE_STUN_PACKET_RESULT_OK,
    ICE_HANDLE_STUN_PACKET_RESULT_FOUND_PEER_REFLEXIVE_CANDIDATE,
    ICE_HANDLE_STUN_PACKET_RESULT_UPDATED_SERVER_REFLEXIVE_CANDIDATE_ADDRESS,
    ICE_HANDLE_STUN_PACKET_RESULT_UPDATED_RELAY_CANDIDATE_ADDRESS,
    ICE_HANDLE_STUN_PACKET_RESULT_VALID_CANDIDATE_PAIR,
    ICE_HANDLE_STUN_PACKET_RESULT_CANDIDATE_PAIR_READY,
    ICE_HANDLE_STUN_PACKET_RESULT_STUN_BINDING_INDICATION,
    ICE_HANDLE_STUN_PACKET_RESULT_FRESH_COMPLETE,
    ICE_HANDLE_STUN_PACKET_RESULT_FRESH_CHANNEL_BIND_COMPLETE,
    ICE_HANDLE_STUN_PACKET_RESULT_TURN_SESSION_TERMINATED,
    ICE_HANDLE_STUN_PACKET_RESULT_DROP_PACKET,

    /* Error codes. */
    ICE_HANDLE_STUN_PACKET_RESULT_BAD_PARAM,
    ICE_HANDLE_STUN_PACKET_RESULT_DESERIALIZE_ERROR,
    ICE_HANDLE_STUN_PACKET_RESULT_INTEGRITY_MISMATCH,
    ICE_HANDLE_STUN_PACKET_RESULT_FINGERPRINT_MISMATCH,
    ICE_HANDLE_STUN_PACKET_RESULT_INVALID_PACKET_TYPE,
    ICE_HANDLE_STUN_PACKET_RESULT_INVALID_FAMILY_TYPE,
    ICE_HANDLE_STUN_PACKET_RESULT_INVALID_CANDIDATE_TYPE,
    ICE_HANDLE_STUN_PACKET_RESULT_CANDIDATE_NOT_FOUND,
    ICE_HANDLE_STUN_PACKET_RESULT_RELAY_CANDIDATE_NOT_REFRESHING,
    ICE_HANDLE_STUN_PACKET_RESULT_CANDIDATE_PAIR_NOT_FOUND,
    ICE_HANDLE_STUN_PACKET_RESULT_ADDRESS_ATTRIBUTE_NOT_FOUND,
    ICE_HANDLE_STUN_PACKET_RESULT_MATCHING_TRANSACTION_ID_NOT_FOUND,
    ICE_HANDLE_STUN_PACKET_RESULT_NON_ZERO_ERROR_CODE,
    ICE_HANDLE_STUN_PACKET_RESULT_INVALID_RESPONSE,
    ICE_HANDLE_STUN_PACKET_RESULT_ZERO_LIFETIME,
    ICE_HANDLE_STUN_PACKET_RESULT_RANDOM_ERROR_CODE,
    ICE_HANDLE_STUN_PACKET_RESULT_ALLOCATE_UNKNOWN_ERROR,
    ICE_HANDLE_STUN_PACKET_RESULT_REFRESH_UNKNOWN_ERROR,
    ICE_HANDLE_STUN_PACKET_RESULT_LONG_TERM_CREDENTIAL_CALCULATION_ERROR,
    ICE_HANDLE_STUN_PACKET_RESULT_ADD_REMOTE_CANDIDATE_FAILED,
    ICE_HANDLE_STUN_PACKET_RESULT_UNEXPECTED_RESPONSE,

    /* Application needs to take action. */
    ICE_HANDLE_STUN_PACKET_RESULT_NOT_STUN_PACKET,
    ICE_HANDLE_STUN_PACKET_RESULT_SEND_RESPONSE_FOR_REMOTE_REQUEST,
    ICE_HANDLE_STUN_PACKET_RESULT_SEND_TRIGGERED_CHECK,
    ICE_HANDLE_STUN_PACKET_RESULT_START_NOMINATION,
    ICE_HANDLE_STUN_PACKET_RESULT_SEND_RESPONSE_AND_START_NOMINATION,
    ICE_HANDLE_STUN_PACKET_RESULT_SEND_ALLOCATION_REQUEST,
    ICE_HANDLE_STUN_PACKET_RESULT_SEND_REFRESH_REQUEST,
    ICE_HANDLE_STUN_PACKET_RESULT_SEND_CHANNEL_BIND_REQUEST,
    ICE_HANDLE_STUN_PACKET_RESULT_SEND_CONNECTIVITY_CHECK_REQUEST,
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
                                      uint16_t * pOutputBufferLength );
typedef IceResult_t ( * IceMd5_t ) ( const uint8_t * pBuffer,
                                     size_t bufferLength,
                                     uint8_t * pOutputBuffer,
                                     uint16_t * pOutputBufferLength );

/*----------------------------------------------------------------------------*/

typedef StunAttributeAddress_t IceTransportAddress_t;

typedef struct IceEndpoint
{
    IceTransportAddress_t transportAddress;
    uint8_t isPointToPoint;
} IceEndpoint_t;

typedef struct IceTurnServer
{
    uint8_t userName[ ICE_SERVER_CONFIG_MAX_USER_NAME_LENGTH ];                 /* Username for the server. */
    size_t userNameLength;                                                      /* Length of the username. */
    uint8_t password[ ICE_SERVER_CONFIG_MAX_PASSWORD_LENGTH ];                  /* Password for the server. */
    size_t passwordLength;                                                      /* Length of the password. */
    uint8_t nonce[ ICE_SERVER_CONFIG_MAX_NONCE_LENGTH ];                        /* Nonce for the server. */
    size_t nonceLength;                                                         /* Length of the nonce. */
    uint8_t realm[ ICE_SERVER_CONFIG_MAX_REALM_LENGTH ];                        /* Realm for the server. */
    size_t realmLength;                                                         /* Length of the realm. */
    uint8_t longTermPassword[ ICE_SERVER_CONFIG_LONG_TERM_PASSWORD_LENGTH ];    /* Long term password for the server. */
    size_t longTermPasswordLength;                                              /* Length of the long term password. */
    uint64_t turnAllocationExpirationTimeSeconds;
    uint16_t nextAvailableTurnChannelNumber;
} IceTurnServer_t;

typedef struct IceCandidate
{
    IceCandidateType_t candidateType;
    uint8_t isRemote;
    IceEndpoint_t endpoint;
    IceCandidateState_t state;
    uint32_t priority;
    IceSocketProtocol_t remoteProtocol;
    uint8_t transactionId[ STUN_HEADER_TRANSACTION_ID_LENGTH ];
    uint16_t candidateId; /* Debugging aid only. */
    IceTurnServer_t * pTurnServer;
} IceCandidate_t;

typedef struct IceCandidatePair
{
    IceCandidate_t * pLocalCandidate;
    IceCandidate_t * pRemoteCandidate;
    uint64_t priority;
    IceCandidatePairState_t state;
    uint8_t succeeded;
    uint32_t connectivityCheckFlags;
    uint8_t transactionId[ STUN_HEADER_TRANSACTION_ID_LENGTH ];

    /* Below fields are for TURN. */
    uint16_t turnChannelNumber;
    uint64_t turnPermissionExpirationSeconds;
} IceCandidatePair_t;

typedef struct IceCryptoFunctions
{
    IceRandom_t randomFxn;
    IceCrc32_t crc32Fxn;
    IceHmac_t hmacFxn;
    IceMd5_t md5Fxn;
} IceCryptoFunctions_t;

typedef struct IceCredentials
{
    const uint8_t * pLocalUsername;
    size_t localUsernameLength;
    const uint8_t * pLocalPassword;
    size_t localPasswordLength;
    const uint8_t * pRemoteUsername;
    size_t remoteUsernameLength;
    const uint8_t * pRemotePassword;
    size_t remotePasswordLength;
    const uint8_t * pCombinedUsername;
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
    IceTurnServer_t * pTurnServers;
    size_t maxTurnServers;
    size_t numTurnServers;
    IceCandidatePair_t * pNominatedPair;
    uint64_t tieBreaker;
    uint8_t isControlling;
    TransactionIdStore_t * pStunBindingRequestTransactionIdStore;
    IceCryptoFunctions_t cryptoFunctions;
    StunReadWriteFunctions_t readWriteFunctions;
    uint16_t nextCandidateId;
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
    IceTurnServer_t * pTurnServerArray;
    size_t turnServerArrayLength;
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
    IceTransportAddress_t peerTransportAddress;
    IceTransportAddress_t relayTransportAddress;

    /* Below fields are for relay candidate. */
    uint8_t * pNonce;
    size_t nonceLength;
    uint8_t * pRealm;
    size_t realmLength;
    uint32_t lifetimeSeconds;
} IceStunDeserializedPacketInfo_t;

/*----------------------------------------------------------------------------*/

#endif /* ICE_DATA_TYPES_H */
