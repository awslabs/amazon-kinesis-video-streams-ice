#ifndef ICE_DATA_TYPES_H
#define ICE_DATA_TYPES_H

/* Standard includes. */
#include <stdint.h>
#include <stddef.h>

/* Stun includes. */
#include "stun_data_types.h"

#define ICE_CONNECTIVITY_SUCCESS_FLAG                              15

#define ICE_DEFAULT_MAX_STORED_TRANSACTION_ID_COUNT                20
#define ICE_MAX_STORED_TRANSACTION_ID_COUNT                        100

#define ICE_MAX_LOCAL_CANDIDATE_COUNT                              100
#define ICE_MAX_REMOTE_CANDIDATE_COUNT                             100
#define ICE_MAX_CANDIDATE_PAIR_COUNT                               1024
#define MAX_ICE_SERVERS_COUNT                                      21

/* ICE candidate priorities */
#define ICE_PRIORITY_HOST_CANDIDATE_TYPE_PREFERENCE                126
#define ICE_PRIORITY_SERVER_REFLEXIVE_CANDIDATE_TYPE_PREFERENCE    100
#define ICE_PRIORITY_PEER_REFLEXIVE_CANDIDATE_TYPE_PREFERENCE      110
#define ICE_PRIORITY_RELAYED_CANDIDATE_TYPE_PREFERENCE             0
#define ICE_PRIORITY_LOCAL_PREFERENCE                              65535

/* ICE macros to define default values. */
#define ICE_RESULT_NO_VALID_CANDIDATE_PAIR                         ( -1 )
#define ICE_RESULT_NO_VALID_LOCAL_CANDIDATE                        ( -1 )
#define ICE_RESULT_NO_VALID_REMOTE_CANDIDATE                       ( -1 )

/**
 * Macros to define the bits set for connectivity checks in a candidate pair.
 * +-----+-----+-----+-----+-----+
 * |     | BIT3| BIT2| BIT1| BIT0|
 * +-----+-----+-----+-----+-----+
 *
 *   This depicts the connectivityChecks in a candidate pair, these 4 bits show which bit stands for which STUN request/ response.
 *
 *    1. BIT0 - STUN request from local candidate to remote candidate.
 *    2. BIT1 - STUN response from remote candidate to local candidate.
 *    3. BIT2 - STUN request from remote candidate to local candidate.
 *    4. BIT3 - STUN response from local candidate to remote candidate.
 *
 */
#define ICE_STUN_REQUEST_LOCAL_REMOTE_BIT0                         ( 0 )
#define ICE_STUN_RESPONSE_LOCAL_REMOTE_BIT1                        ( 1 )
#define ICE_STUN_REQUEST_REMOTE_LOCAL_BIT2                         ( 2 )
#define ICE_STUN_RESPONSE_REMOTE_LOCAL_BIT3                        ( 3 )

/**
 * Maximum allowed ICE configuration user name length
 * https://docs.aws.amazon.com/kinesisvideostreams/latest/dg/API_AWSAcuitySignalingService_GetIceServerConfig.html#API_AWSAcuitySignalingService_GetIceServerConfig_RequestSyntax
 */
#define ICE_MAX_CONFIG_USER_NAME_LEN                               256

/**
 * Maximum allowed ICE configuration password length
 * https://docs.aws.amazon.com/kinesisvideostreams/latest/dg/API_AWSAcuitySignalingService_IceServer.html#KinesisVideo-Type-AWSAcuitySignalingService_IceServer-Password
 */
#define ICE_MAX_CONFIG_CREDENTIAL_LEN                              256

/**
 * Maximum allowed ICE URI length
 */
#define ICE_MAX_CONFIG_URI_LEN                                     256


#define ICE_IS_IPV4_ADDR( pAddress )    ( ( pAddress ).family == STUN_ADDRESS_IPv4 )

#define ICE_STUN_MESSAGE_BUFFER_SIZE    1024
typedef uint32_t ( * Ice_ComputeCrc32 ) ( uint32_t initialResult,
                                          uint8_t * pBuffer,
                                          uint32_t bufferLength );
typedef void ( * Ice_ComputeHMAC ) ( uint8_t * pPassword,
                                     uint32_t passwordLength,
                                     uint8_t * pBuffer,
                                     uint32_t bufferLength,
                                     uint8_t * pOutput,
                                     uint32_t * pOutputLength );
typedef enum
{
    ICE_CANDIDATE_TYPE_HOST,
    ICE_CANDIDATE_TYPE_PEER_REFLEXIVE,
    ICE_CANDIDATE_TYPE_SERVER_REFLEXIVE,
    ICE_CANDIDATE_TYPE_RELAYED,
} IceCandidateType_t;

typedef enum
{
    ICE_CANDIDATE_STATE_INVALID,
    ICE_CANDIDATE_STATE_NEW,
    ICE_CANDIDATE_STATE_VALID
} IceCandidateState_t;

typedef enum
{
    ICE_CANDIDATE_PAIR_STATE_INVALID,
    ICE_CANDIDATE_PAIR_STATE_FROZEN,
    ICE_CANDIDATE_PAIR_STATE_WAITING,
    ICE_CANDIDATE_PAIR_STATE_VALID,
    ICE_CANDIDATE_PAIR_STATE_NOMINATED,
    ICE_CANDIDATE_PAIR_STATE_SUCCEEDED
} IceCandidatePairState_t;

typedef enum
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
    ICE_RESULT_OUT_OF_MEMORY
} IceResult_t;

typedef enum IceStunPacketHandleResult
{
    ICE_RESULT_STUN_DESERIALIZE_OK,
    ICE_RESULT_STUN_INTEGRITY_MISMATCH,
    ICE_RESULT_STUN_FINGERPRINT_MISMATCH,
    ICE_RESULT_STUN_INVALID_PACKET_TYPE,
    ICE_RESULT_FOUND_PEER_REFLEXIVE_CANDIDATE,
    ICE_RESULT_UPDATED_SRFLX_CANDIDATE_ADDRESS,
    ICE_RESULT_SEND_RESPONSE_FOR_REMOTE_REQUEST,
    ICE_RESULT_SEND_TRIGGERED_CHECK,
    ICE_RESULT_START_NOMINATION,
    ICE_RESULT_USE_CANDIDATE_FLAG,
    ICE_RESULT_SEND_RESPONSE_FOR_NOMINATION,
    ICE_RESULT_CANDIDATE_PAIR_READY,
    ICE_RESULT_NOT_FOUND_CANDIDATE,
    ICE_RESULT_NOT_FOUND_CANDIDATE_PAIR,
    ICE_RESULT_NOT_FOUND_ADDRESS_ATTRIBUTE,
    ICE_RESULT_NOT_FOUND_MATCHING_TRANSACTION_ID,
    ICE_RESULT_STUN_BINDING_INDICATION
} IceStunPacketHandleResult_t;

/* ICE component structures */

typedef struct IceIPAddress
{
    StunAttributeAddress_t ipAddress;
    uint32_t isPointToPoint;
} IceIPAddress_t;

typedef struct TransactionIdStore
{
    uint32_t maxTransactionIdsCount;
    uint32_t nextTransactionIdIndex;
    uint32_t earliestTransactionIdIndex;
    uint32_t transactionIdCount;
    uint8_t * pTransactionIds;
} TransactionIdStore_t;

typedef struct IceStunDeserializedPacketInfo
{
    uint8_t useCandidateFlag;
    uint16_t errorCode;
    uint32_t priority;
    StunAttributeAddress_t stunAttributeAddress;
} IceStunDeserializedPacketInfo_t;

typedef struct IceCandidate
{
    IceCandidateType_t iceCandidateType;
    uint32_t isRemote;
    IceIPAddress_t ipAddress;
    IceCandidateState_t state;
    uint32_t priority;
    IceSocketProtocol_t remoteProtocol;
} IceCandidate_t;

typedef struct IceCandidatePair
{
    IceCandidate_t * pLocal;
    IceCandidate_t * pRemote;
    uint64_t priority;
    IceCandidatePairState_t state;
    uint8_t connectivityChecks; /* checking for completion of 4-way handshake */
    uint8_t pTransactionIdStore[ STUN_HEADER_TRANSACTION_ID_LENGTH ];
} IceCandidatePair_t;

typedef struct IceAgent
{
    char localUsername[ ICE_MAX_CONFIG_USER_NAME_LEN + 1 ];
    char localPassword[ ICE_MAX_CONFIG_CREDENTIAL_LEN + 1 ];
    char remoteUsername[ ICE_MAX_CONFIG_USER_NAME_LEN + 1 ];
    char remotePassword[ ICE_MAX_CONFIG_CREDENTIAL_LEN + 1 ];
    char combinedUserName[ ( ICE_MAX_CONFIG_USER_NAME_LEN + 1 ) << 1 ];
    IceCandidate_t localCandidates[ ICE_MAX_LOCAL_CANDIDATE_COUNT ];
    IceCandidate_t remoteCandidates[ ICE_MAX_REMOTE_CANDIDATE_COUNT ];
    IceCandidatePair_t iceCandidatePairs[ ICE_MAX_CANDIDATE_PAIR_COUNT ];
    uint8_t stunMessageBuffer[ ICE_STUN_MESSAGE_BUFFER_SIZE ];
    uint32_t isControlling;
    uint64_t tieBreaker;
    TransactionIdStore_t * pStunBindingRequestTransactionIdStore;
    Ice_ComputeRandom computeRandom;
    Ice_ComputeCrc32 computeCRC32;
    Ice_ComputeHMAC computeHMAC;
} IceAgent_t;

#endif /* ICE_DATA_TYPES_H */
