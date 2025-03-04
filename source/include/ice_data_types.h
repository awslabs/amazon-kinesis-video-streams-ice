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

#define ICE_STUN_CONNECTIVITY_CHECK_SUCCESSFUL( connectivityCheckFlags )    \
    ( ( connectivityCheckFlags ) == ( ICE_STUN_REQUEST_SENT_FLAG |          \
                                      ICE_STUN_RESPONSE_RECEIVED_FLAG |     \
                                      ICE_STUN_REQUEST_RECEIVED_FLAG |      \
                                      ICE_STUN_RESPONSE_SENT_FLAG ) )

#define ICE_SERVER_CONFIG_MAX_CONFIG_COUNT ( 5 )
#define ICE_SERVER_CONFIG_MAX_URIS_COUNT ( 3 )
#define ICE_SERVER_CONFIG_MAX_URI_LENGTH ( 256 )

// Max stun username attribute len: https://tools.ietf.org/html/rfc5389#section-15.3
#define ICE_SERVER_CONFIG_MAX_USER_NAME_LENGTH ( 512 )

/**
 * Maximum allowed ICE configuration password length
 * https://docs.aws.amazon.com/kinesisvideostreams/latest/dg/API_AWSAcuitySignalingService_IceServer.html#KinesisVideo-Type-AWSAcuitySignalingService_IceServer-Password
 */
#define ICE_SERVER_CONFIG_MAX_PASSWORD_LENGTH ( 256 )

/* https://tools.ietf.org/html/rfc5389#section-15.7 */
#define ICE_SERVER_CONFIG_MAX_REALM_LENGTH ( 128 )

/* https://tools.ietf.org/html/rfc5389#section-15.8 */
#define ICE_SERVER_CONFIG_MAX_NONCE_LENGTH ( 128 )

/*
 * According to https://datatracker.ietf.org/doc/html/rfc5389#section-15.4,
 * long-term credentials are generated using MD5 hash, resulting in a fixed size of 16 bytes.
 */
#define ICE_SERVER_CONFIG_MAX_LONG_TERM_PASSWORD_LENGTH ( 16 )

#define ICE_DEFAULT_TURN_ALLOCATION_LIFETIME_SECONDS ( 600 )
#define ICE_TURN_ALLOCATION_REFRESH_GRACE_PERIOD_SECONDS ( 30 )
#define ICE_DEFAULT_TURN_PERMISSION_LIFETIME_SECONDS ( 300 )
#define ICE_TURN_PERMISSION_REFRESH_GRACE_PERIOD_SECONDS ( 30 )

/*
 * According to https://datatracker.ietf.org/doc/html/rfc8656#section-12,
 * TURN channel numbers must be in range of 0x4000 ~ 0x4FFF.
 */
#define ICE_DEFAULT_TURN_CHANNEL_NUMBER_MIN ( 0x4000 )
#define ICE_DEFAULT_TURN_CHANNEL_NUMBER_MAX ( 0x4FFF )

/*
 * According to https://datatracker.ietf.org/doc/html/rfc8656#name-the-channeldata-message,
 * TURN channel header must be 4 bytes long.
 */
#define ICE_TURN_CHANNEL_DATA_HEADER_LENGTH ( 4 )

#define ICE_CANDIDATE_ID_START ( 0x7000 )

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
    ICE_CANDIDATE_STATE_ALLOCATING, /* Dedicate for relay candidate to allocate resource with TURN server. */
    ICE_CANDIDATE_STATE_VALID,
    ICE_CANDIDATE_STATE_RELEASING, /* Dedicate for relay candidate to refresh the lifetime to 0. */
    ICE_CANDIDATE_STATE_RELEASED /* Dedicate for relay candidate, means the TURN resource has been released. */
} IceCandidateState_t;

typedef enum IceCandidatePairState
{
    ICE_CANDIDATE_PAIR_STATE_INVALID,
    ICE_CANDIDATE_PAIR_STATE_FROZEN,
    ICE_CANDIDATE_PAIR_STATE_WAITING,
    ICE_CANDIDATE_PAIR_STATE_VALID,
    ICE_CANDIDATE_PAIR_STATE_NOMINATED,
    ICE_CANDIDATE_PAIR_STATE_SUCCEEDED,
    ICE_CANDIDATE_PAIR_STATE_CREATE_PERMISSION, /* Dedicate for relay candidate to create permission for remote candidate. */
    ICE_CANDIDATE_PAIR_STATE_CHANNEL_BIND /* Dedicate for relay candidate to associate channel number with remote candidate. */
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

    /* Error code. */
    ICE_RESULT_BAD_PARAM,
    ICE_RESULT_NO_NEXT_ACTION,
    ICE_RESULT_NEED_REFRESH_CANDIDATE,
    ICE_RESULT_NEED_REFRESH_PERMISSION,
    ICE_RESULT_MAX_CANDIDATE_THRESHOLD,
    ICE_RESULT_MAX_CANDIDATE_PAIR_THRESHOLD,
    ICE_RESULT_MAX_CHANNEL_NUMBER_ID,
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
    ICE_RESULT_INVALID_CANDIDATE_TYPE,
    ICE_RESULT_INVALID_CANDIDATE,
    ICE_RESULT_INVALID_CANDIDATE_PAIR,
    ICE_RESULT_TURN_CANDIDATE_PAIR_NOT_FOUND,
    ICE_RESULT_TURN_LENGTH_INVALID,
    ICE_RESULT_DATA_TOO_SMALL,

    /* User info. */
    ICE_RESULT_TURN_PREFIX_NOT_REQUIRED,
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
    ICE_HANDLE_STUN_PACKET_RESULT_ALLOCATION_UNEXPECTED_COMPLETE,
    ICE_HANDLE_STUN_PACKET_RESULT_FRESH_COMPLETE,
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
    ICE_HANDLE_STUN_PACKET_RESULT_RELAY_CANDIDATE_NOT_ALLOCATING,
    ICE_HANDLE_STUN_PACKET_RESULT_RELAY_CANDIDATE_NOT_REFRESHING,
    ICE_HANDLE_STUN_PACKET_RESULT_RELAY_CANDIDATE_PAIR_NOT_CREATING_PERMISSION,
    ICE_HANDLE_STUN_PACKET_RESULT_RELAY_CANDIDATE_PAIR_NOT_CHANNEL_BINDING,
    ICE_HANDLE_STUN_PACKET_RESULT_CANDIDATE_PAIR_NOT_FOUND,
    ICE_HANDLE_STUN_PACKET_RESULT_ADDRESS_ATTRIBUTE_NOT_FOUND,
    ICE_HANDLE_STUN_PACKET_RESULT_MATCHING_TRANSACTION_ID_NOT_FOUND,
    ICE_HANDLE_STUN_PACKET_RESULT_NON_ZERO_ERROR_CODE,
    ICE_HANDLE_STUN_PACKET_RESULT_ZERO_LIFETIME,
    ICE_HANDLE_STUN_PACKET_RESULT_RANDOM_ERROR_CODE,
    ICE_HANDLE_STUN_PACKET_RESULT_NONCE_LENGTH_EXCEEDED,
    ICE_HANDLE_STUN_PACKET_RESULT_REALM_LENGTH_EXCEEDED,
    ICE_HANDLE_STUN_PACKET_RESULT_ALLOCATE_UNKNOWN_ERROR,
    ICE_HANDLE_STUN_PACKET_RESULT_REFRESH_UNKNOWN_ERROR,
    ICE_HANDLE_STUN_PACKET_RESULT_LONG_TERM_CREDENTIAL_CALCULATION_ERROR,
    ICE_HANDLE_STUN_PACKET_RESULT_ADD_REMOTE_CANDIDATE_FAILED,

    /* Application needs to take action. */
    ICE_HANDLE_STUN_PACKET_RESULT_SEND_RESPONSE_FOR_REMOTE_REQUEST,
    ICE_HANDLE_STUN_PACKET_RESULT_SEND_TRIGGERED_CHECK,
    ICE_HANDLE_STUN_PACKET_RESULT_START_NOMINATION,
    ICE_HANDLE_STUN_PACKET_RESULT_SEND_RESPONSE_FOR_NOMINATION,
    ICE_HANDLE_STUN_PACKET_RESULT_SEND_ALLOCATION_REQUEST,
    ICE_HANDLE_STUN_PACKET_RESULT_SEND_REFRESH_REQUEST,
    ICE_HANDLE_STUN_PACKET_RESULT_SEND_CHANNEL_BIND_REQUEST,
    ICE_HANDLE_STUN_PACKET_RESULT_SEND_CONNECTIVITY_BINDING_REQUEST,
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
typedef uint64_t ( * IceGetCurrentTimeSeconds_t ) ( void );

/*----------------------------------------------------------------------------*/

typedef StunAttributeAddress_t IceTransportAddress_t;

typedef struct IceEndpoint
{
    IceTransportAddress_t transportAddress;
    uint8_t isPointToPoint;
} IceEndpoint_t;

typedef struct IceServerConfig
{
    uint8_t userName[ICE_SERVER_CONFIG_MAX_USER_NAME_LENGTH];                                        //!< Username for the server
    size_t userNameLength;                                                                                          //!< Length of username
    uint8_t password[ICE_SERVER_CONFIG_MAX_PASSWORD_LENGTH];                                         //!< Password for the server
    size_t passwordLength;                                                                                          //!< Length of password
    uint8_t nonce[ICE_SERVER_CONFIG_MAX_NONCE_LENGTH];                                         //!< Nonce for the server
    size_t nonceLength;                                                                                          //!< Length of Nonce
    uint8_t realm[ICE_SERVER_CONFIG_MAX_REALM_LENGTH];                                         //!< Realm for the server
    size_t realmLength;                                                                                          //!< Length of realm
    uint8_t longTermPassword[ICE_SERVER_CONFIG_MAX_LONG_TERM_PASSWORD_LENGTH];                                         //!< Long term password for the server
    size_t longTermPasswordLength;                                                                                          //!< Length of long term password
} IceServerInfo_t;

typedef struct IceCandidate
{
    IceCandidateType_t candidateType;
    uint8_t isRemote;
    IceEndpoint_t endpoint;
    IceCandidateState_t state;
    uint32_t priority;
    IceSocketProtocol_t remoteProtocol;
    uint8_t transactionId[ STUN_HEADER_TRANSACTION_ID_LENGTH ];
    uint16_t candidateId;

    /* Below fields are for relay candidate. */
    IceServerInfo_t iceServerInfo;
    uint16_t nextAvailableTurnChannelNumber;
    uint64_t turnAllocationExpirationSeconds;
} IceCandidate_t;

typedef struct IceCandidatePair
{
    IceCandidate_t * pLocalCandidate;
    IceCandidate_t * pRemoteCandidate;
    uint64_t priority;
    IceCandidatePairState_t state;
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
    IceCandidatePair_t * pNominatePairs;
    uint64_t tieBreaker;
    uint8_t isControlling;
    TransactionIdStore_t * pStunBindingRequestTransactionIdStore;
    IceCryptoFunctions_t cryptoFunctions;
    IceGetCurrentTimeSeconds_t getCurrentTimeSecondsFxn;
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
    uint8_t isControlling;
    TransactionIdStore_t * pStunBindingRequestTransactionIdStore;
    IceCryptoFunctions_t cryptoFunctions;
    IceGetCurrentTimeSeconds_t getCurrentTimeSecondsFxn;
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

typedef struct IceTurnChannelMessageHeader
{
    uint16_t channelNumber;
    uint16_t messageLength;
} IceTurnChannelMessageHeader_t;

/*----------------------------------------------------------------------------*/

#endif /* ICE_DATA_TYPES_H */
