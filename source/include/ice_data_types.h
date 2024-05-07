#ifndef ICE_DATA_TYPES_H
#define ICE_DATA_TYPES_H

/* Standard includes. */
#include <stdint.h>
#include <stddef.h>

/* Stun includes. */
#include "stun_data_types.h"

#define ICE_CONNECTIVITY_SUCCESS_FLAG                           15

#define ICE_DEFAULT_MAX_STORED_TRANSACTION_ID_COUNT                 20
#define ICE_MAX_STORED_TRANSACTION_ID_COUNT                         100

#define ICE_MAX_LOCAL_CANDIDATE_COUNT                       100
#define ICE_MAX_REMOTE_CANDIDATE_COUNT                      100
#define ICE_MAX_CANDIDATE_PAIR_COUNT                        1024
#define MAX_ICE_SERVERS_COUNT                               21

/* ICE candidate priorities */
#define ICE_PRIORITY_HOST_CANDIDATE_TYPE_PREFERENCE             126
#define ICE_PRIORITY_SERVER_REFLEXIVE_CANDIDATE_TYPE_PREFERENCE 100
#define ICE_PRIORITY_PEER_REFLEXIVE_CANDIDATE_TYPE_PREFERENCE   110
#define ICE_PRIORITY_RELAYED_CANDIDATE_TYPE_PREFERENCE          0
#define ICE_PRIORITY_LOCAL_PREFERENCE                           65535

/**
 * Maximum allowed ICE configuration user name length
 * https://docs.aws.amazon.com/kinesisvideostreams/latest/dg/API_AWSAcuitySignalingService_GetIceServerConfig.html#API_AWSAcuitySignalingService_GetIceServerConfig_RequestSyntax
 */
#define ICE_MAX_CONFIG_USER_NAME_LEN                            256

/**
 * Maximum allowed ICE configuration password length
 * https://docs.aws.amazon.com/kinesisvideostreams/latest/dg/API_AWSAcuitySignalingService_IceServer.html#KinesisVideo-Type-AWSAcuitySignalingService_IceServer-Password
 */
#define ICE_MAX_CONFIG_CREDENTIAL_LEN                           256

/**
 * Maximum allowed ICE URI length
 */
#define ICE_MAX_CONFIG_URI_LEN                                  256


#define ICE_IS_IPV4_ADDR(pAddress)                               ( ( pAddress ).family == STUN_ADDRESS_IPv4 )

#define ICE_STUN_MESSAGE_BUFFER_SIZE                            1024

typedef uint32_t ( * Ice_ComputeCrc32 ) ( uint32_t initialResult, uint8_t * pBuffer, uint32_t bufferLength );
typedef void ( * Ice_ComputeHMAC ) ( uint8_t * pPassword, uint32_t passwordLength, uint8_t * pBuffer, uint32_t bufferLength, uint8_t * pOutput, uint32_t * pOutputLength );
typedef enum {
    ICE_CANDIDATE_TYPE_HOST,
    ICE_CANDIDATE_TYPE_PEER_REFLEXIVE,
    ICE_CANDIDATE_TYPE_SERVER_REFLEXIVE,
    ICE_CANDIDATE_TYPE_RELAYED,
} IceCandidateType_t;

typedef enum {
    ICE_CANDIDATE_STATE_INVALID,
    ICE_CANDIDATE_STATE_NEW,
    ICE_CANDIDATE_STATE_VALID
} IceCandidateState_t;

typedef enum {
    ICE_CANDIDATE_PAIR_STATE_INVALID,
    ICE_CANDIDATE_PAIR_STATE_FROZEN,
    ICE_CANDIDATE_PAIR_STATE_WAITING,
    ICE_CANDIDATE_PAIR_STATE_VALID,
    ICE_CANDIDATE_PAIR_STATE_NOMINATED,
    ICE_CANDIDATE_PAIR_STATE_SUCCEEDED
} IceCandidatePairState_t;

typedef enum {
    ICE_SOCKET_PROTOCOL_NONE,
    ICE_SOCKET_PROTOCOL_TCP,
    ICE_SOCKET_PROTOCOL_UDP
} IceSocketProtocol_t;

typedef enum IceResult
{
    ICE_RESULT_OK = 0,
    ICE_RESULT_START_NOMINATION = 1,
    ICE_RESULT_UPDATE_SRFLX_CANDIDATE = 2,
    ICE_RESULT_USE_CANDIDATE_FLAG = 3,
    ICE_RESULT_SEND_STUN_LOCAL_REMOTE = 4,
    ICE_RESULT_SEND_STUN_REMOTE_LOCAL = 5,
    ICE_RESULT_SEND_STUN_REQUEST_RESPONSE = 6,
    ICE_RESULT_SEND_STUN_RESPONSE_FOR_NOMINATION = 7,
    ICE_RESULT_UPDATED_SRFLX_CANDIDATE_ADDRESS = 8,
    ICE_RESULT_CANDIDATE_PAIR_READY = 9,
    ICE_RESULT_BASE = 0x53000000,
    ICE_RESULT_BAD_PARAM,
    ICE_RESULT_MAX_CANDIDATE_THRESHOLD,
    ICE_RESULT_MAX_CANDIDATE_PAIR_THRESHOLD,
    ICE_RESULT_OUT_OF_MEMORY,
    ICE_RESULT_SPRINT_ERROR
} IceResult_t;

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
    uint8_t connectivityChecks; // checking for completion of 4-way handshake
} IceCandidatePair_t;

typedef struct IceAgent
{
    char localUsername[ICE_MAX_CONFIG_USER_NAME_LEN + 1];
    char localPassword[ICE_MAX_CONFIG_CREDENTIAL_LEN + 1];
    char remoteUsername[ICE_MAX_CONFIG_USER_NAME_LEN + 1];
    char remotePassword[ICE_MAX_CONFIG_CREDENTIAL_LEN + 1];
    char combinedUserName[(ICE_MAX_CONFIG_USER_NAME_LEN + 1) << 1];
    IceCandidate_t localCandidates[ ICE_MAX_LOCAL_CANDIDATE_COUNT ];
    IceCandidate_t remoteCandidates[ ICE_MAX_REMOTE_CANDIDATE_COUNT ];
    IceCandidatePair_t iceCandidatePairs[ ICE_MAX_CANDIDATE_PAIR_COUNT ];
    uint8_t stunMessageBuffers[ ICE_MAX_CANDIDATE_PAIR_COUNT ][ ICE_STUN_MESSAGE_BUFFER_SIZE ];
    uint16_t stunMessageBufferUsedCount;
    uint32_t isControlling;
    uint64_t tieBreaker;
    TransactionIdStore_t * pStunBindingRequestTransactionIdStore;
    Ice_ComputeCrc32 computeCRC32;
    Ice_ComputeHMAC computeHMAC;
} IceAgent_t;

#endif /* ICE_DATA_TYPES_H */
