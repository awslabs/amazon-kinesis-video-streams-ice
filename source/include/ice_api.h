#ifndef ICE_API_H
#define ICE_API_H

/* *INDENT-OFF* */
#ifdef __cplusplus
extern "C" {
#endif
/* *INDENT-ON* */

/* Standard includes. */
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include "ice_data_types.h"

/************************************************************************************************************************************************/

IceResult_t Ice_CreateIceAgent( IceAgent_t * pIceAgent,
                                char * pLocalUsername,
                                char * pLocalPassword,
                                char * pRemoteUsername,
                                char * pRemotePassword,
                                char * pCombinedUsername,
                                TransactionIdStore_t * pBuffer,
                                Ice_ComputeCrc32 computeCrc32,
                                Ice_ComputeHMAC computeHMAC );

IceResult_t Ice_AddHostCandidate( const IceIPAddress_t ipAddr,
                                  IceAgent_t * pIceAgent,
                                  IceCandidate_t ** ppCandidate );

IceResult_t Ice_AddSrflxCandidate( const IceIPAddress_t ipAddr,
                                   IceAgent_t * pIceAgent,
                                   IceCandidate_t ** ppCandidate,
                                   uint8_t * pTransactionIdBuffer,
                                   uint8_t ** ppSendStunMessageBuffer,
                                   uint32_t * pSendStunMessageBufferLength );

IceResult_t Ice_AddRemoteCandidate( IceAgent_t * pIceAgent,
                                    IceCandidateType_t iceCandidateType,
                                    IceCandidate_t ** ppCandidate,
                                    const IceIPAddress_t ipAddr,
                                    IceSocketProtocol_t remoteProtocol,
                                    const uint32_t priority );

IceResult_t Ice_CheckPeerReflexiveCandidate( IceAgent_t * pIceAgent,
                                             IceIPAddress_t pIpAddr,
                                             uint32_t priority,
                                             IceCandidatePair_t * pIceCandidatePair );

IceResult_t Ice_CreateCandidatePair( IceAgent_t * pIceAgent,
                                     IceCandidate_t * pLocalCandidate,
                                     IceCandidate_t * pRemoteCandidate );

IceResult_t Ice_UpdateSrflxCandidateAddress( IceAgent_t * pIceAgent,
                                             IceCandidate_t * pCandidate,
                                             const IceIPAddress_t * pIpAddr );

IceResult_t Ice_InitializeStunPacket( StunContext_t * pStunCxt,
                                      uint8_t * pTransactionId,
                                      uint8_t * pStunMessageBuffer,
                                      StunHeader_t * pStunHeader,
                                      uint8_t isGenerateTransactionID,
                                      uint8_t isStunBindingRequest );

IceResult_t Ice_PackageStunPacket( IceAgent_t * pIceAgent,
                                   StunContext_t * pStunCxt,
                                   uint8_t * pPpassword,
                                   uint32_t passwordLen,
                                   uint32_t * pStunMessageBufferLength );

IceResult_t Ice_CreateRequestForSrflxCandidate( IceAgent_t * pIceAgent,
                                                uint8_t * pStunMessageBuffer,
                                                uint8_t * pTransactionIdBuffer,
                                                uint32_t * pSendStunMessageBufferLength );

IceResult_t Ice_CreateRequestForNominatingValidCandidatePair( IceAgent_t * pIceAgent,
                                                              uint8_t ** ppSendStunMessageBuffer,
                                                              uint32_t * pSendStunMessageBufferLength,
                                                              IceCandidatePair_t * pIceCandidatePair,
                                                              uint8_t * pTransactionIdBuffer );

IceResult_t Ice_CreateRequestForConnectivityCheck( IceAgent_t * pIceAgent,
                                                   uint8_t ** ppSendStunMessageBuffer,
                                                   uint32_t * pSendStunMessageBufferLength,
                                                   uint8_t * pTransactionIdBuffer,
                                                   IceCandidatePair_t * pIceCandidatePair );

IceResult_t Ice_CreateResponseForRequest( IceAgent_t * pIceAgent,
                                          uint8_t ** ppSendStunMessageBuffer,
                                          uint32_t * pSendStunMessageBufferLength,
                                          IceIPAddress_t * pSrcAddr,
                                          uint8_t * pTransactionIdBuffer );

IceResult_t Ice_DeserializeStunPacket( StunContext_t * pStunCxt,
                                       StunHeader_t * pStunHeader,
                                       StunAttribute_t * pStunAttribute,
                                       StunAttributeAddress_t * pStunAttributeAddress,
                                       uint32_t priority );

IceResult_t Ice_HandleStunPacket( IceAgent_t * pIceAgent,
                                  uint8_t * pReceivedStunMessageBuffer,
                                  uint32_t pReceivedStunMessageBufferLength,
                                  uint8_t * pTransactionIdBuffer,
                                  uint8_t ** ppSendStunMessageBuffer,
                                  uint32_t * pSendStunMessageBufferLength,
                                  IceCandidate_t * pLocalCandidate,
                                  IceIPAddress_t * pRemoteAddr,
                                  IceCandidatePair_t * pIceCandidatePair );

IceResult_t Ice_HandleServerReflexiveCandidateResponse( IceAgent_t * pIceAgent,
                                                        StunAttributeAddress_t * pStunMappedAddress,
                                                        IceCandidate_t * pLocalCandidate );

int Ice_GetValidCandidatePairCount( IceAgent_t * pIceAgent );

int Ice_GetValidRemoteCandidateCount( IceAgent_t * pIceAgent );

int Ice_GetValidLocalCandidateCount( IceAgent_t * pIceAgent );

/************************************************************************************************************************************************/

/* These APIs are intended for internal use by the ICE library. */

static bool Ice_IsSameIpAddress( StunAttributeAddress_t * pAddr1,
                                 StunAttributeAddress_t * pAddr2,
                                 bool checkPort );

static bool Ice_IsSameIpAddress( StunAttributeAddress_t * pAddr1,
                                 StunAttributeAddress_t * pAddr2,
                                 bool checkPort );

static IceCandidate_t Ice_FindCandidateFromIp( IceAgent_t * pIceAgent,
                                               IceIPAddress_t ipAddress,
                                               bool isRemote );

static void Ice_TransactionIdStoreRemove( TransactionIdStore_t * pTransactionIdStore,
                                          uint8_t * pTransactionId );

static bool Ice_TransactionIdStoreHasId( TransactionIdStore_t * pTransactionIdStore,
                                         uint8_t * pTransactionId );

static void Ice_TransactionIdStoreInsert( TransactionIdStore_t * pTransactionIdStore,
                                          uint8_t * pTransactionId );

static IceResult_t Ice_CreateTransactionIdStore( uint32_t maxIdCount,
                                                 TransactionIdStore_t * pTransactionIdStore );

static uint64_t Ice_ComputeCandidatePairPriority( IceCandidatePair_t * pIceCandidatePair,
                                                  uint32_t isLocalControlling );

static uint32_t Ice_ComputeCandidatePriority( IceCandidate_t * pIceCandidate );

static void Ice_InsertCandidatePair( IceAgent_t * pIceAgent,
                                     IceCandidatePair_t * pIceCandidatePair,
                                     int iceCandidatePairCount );

/************************************************************************************************************************************************/

#endif /* ICE_API_H */
