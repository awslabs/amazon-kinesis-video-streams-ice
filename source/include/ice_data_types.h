#ifndef ICE_DATA_TYPES_H
#define ICE_DATA_TYPES_H

/* Standard includes. */
#include <stdint.h>
#include <stddef.h>

/* Stun includes. */
#include "stun_data_types.h"

#define ICE_CONNECTIVITY_SUCCESS_FLAG                           15

#define DEFAULT_MAX_STORED_TRANSACTION_ID_COUNT                 20
#define MAX_STORED_TRANSACTION_ID_COUNT                         100

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
#define MAX_ICE_CONFIG_USER_NAME_LEN                            256

/**
 * Maximum allowed ICE configuration password length
 * https://docs.aws.amazon.com/kinesisvideostreams/latest/dg/API_AWSAcuitySignalingService_IceServer.html#KinesisVideo-Type-AWSAcuitySignalingService_IceServer-Password
 */
#define MAX_ICE_CONFIG_CREDENTIAL_LEN                           256

/**
 * Maximum allowed ICE URI length
 */
#define MAX_ICE_CONFIG_URI_LEN                                  256


#define IS_IPV4_ADDR(pAddress)                               ( (pAddress).family == STUN_ADDRESS_IPv4 )

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
    ICE_RESULT_CANDIDATE_PAIR_READY = 7,
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
    uint8_t * transactionIds;
} TransactionIdStore_t;

typedef struct IceServer
{
    char url[MAX_ICE_CONFIG_URI_LEN + 1];
    char username[MAX_ICE_CONFIG_USER_NAME_LEN + 1];
    char credential[MAX_ICE_CONFIG_CREDENTIAL_LEN + 1];
    IceSocketProtocol_t transport;
    IceIPAddress_t ipAddress;
    uint8_t IceServerAttributeFlag;
} IceServer_t;

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
    IceCandidate_t* local;
    IceCandidate_t* remote;
    uint64_t priority;
    IceCandidatePairState_t state;
    uint8_t connectivityChecks; // checking for completion of 4-way handshake
} IceCandidatePair_t;

typedef struct IceAgent
{
    char localUsername[MAX_ICE_CONFIG_USER_NAME_LEN + 1];
    char localPassword[MAX_ICE_CONFIG_CREDENTIAL_LEN + 1];
    char remoteUsername[MAX_ICE_CONFIG_USER_NAME_LEN + 1];
    char remotePassword[MAX_ICE_CONFIG_CREDENTIAL_LEN + 1];
    char combinedUserName[(MAX_ICE_CONFIG_USER_NAME_LEN + 1) << 1];
    IceCandidate_t * localCandidates[ ICE_MAX_LOCAL_CANDIDATE_COUNT ];
    IceCandidate_t * remoteCandidates[ ICE_MAX_REMOTE_CANDIDATE_COUNT ];
    IceCandidatePair_t * iceCandidatePairs[ ICE_MAX_CANDIDATE_PAIR_COUNT ];
    uint8_t * stunMessageBuffers[ ICE_MAX_CANDIDATE_PAIR_COUNT ];
    uint16_t stunMessageBufferUsedCount;
    uint32_t isControlling;
    uint64_t tieBreaker;
    TransactionIdStore_t * pStunBindingRequestTransactionIdStore;
} IceAgent_t;

#endif /* ICE_DATA_TYPES_H */

