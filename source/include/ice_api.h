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
                                char * localUsername,
                                char * localPassword,
                                char * remoteUsername,
                                char * remotePassword,
                                char * combinedUsername,
                                TransactionIdStore_t * pBuffer );

IceResult_t Ice_AddHostCandidate( const IceIPAddress_t ipAddr,
                                  IceAgent_t * pIceAgent,
                                  IceCandidate_t ** ppCandidate );

IceResult_t Ice_AddSrflxCandidate( const IceIPAddress_t ipAddr,
                                   IceAgent_t * pIceAgent,
                                   IceCandidate_t ** ppCandidate,
                                   uint8_t * pStunMessageBuffer,
                                   uint8_t * pTransactionIdBuffer );

IceResult_t Ice_InsertLocalCandidate( IceAgent_t * pIceAgent,
                                      IceCandidate_t * pCandidate );

IceResult_t Ice_AddRemoteCandidate( IceAgent_t * pIceAgent,
                                    IceCandidateType_t iceCandidateType,
                                    IceCandidate_t ** ppCandidate,
                                    const IceIPAddress_t ipAddr,
                                    IceSocketProtocol_t remoteProtocol,
                                    const uint32_t priority );

IceResult_t Ice_InsertRemoteCandidate( IceAgent_t * pIceAgent,
                                       IceCandidate_t * pCandidate );

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
                                      uint8_t * transactionId,
                                      uint8_t * pStunMessageBuffer,
                                      StunHeader_t * pStunHeader,
                                      uint8_t isGenerateTransactionID,
                                      uint8_t isStunBindingRequest );

IceResult_t Ice_PackageStunPacket( StunContext_t * pStunCxt,
                                   uint8_t * password,
                                   uint32_t passwordLen );

IceResult_t Ice_CreateRequestForSrflxCandidate( IceAgent_t * pIceAgent,
                                                uint8_t * pStunMessageBuffer,
                                                uint8_t * pTransactionIdBuffer );

IceResult_t Ice_CreateRequestForNominatingValidCandidatePair( IceAgent_t * pIceAgent,
                                                              uint8_t * pStunMessageBuffer,
                                                              IceCandidatePair_t * pIceCandidatePair,
                                                              uint8_t * pTransactionIdBuffer );

IceResult_t Ice_CreateRequestForConnectivityCheck( IceAgent_t * pIceAgent,
                                                   uint8_t * pStunMessageBuffer,
                                                   uint8_t * pTransactionIdBuffer );

IceResult_t Ice_CreateResponseForRequest( IceAgent_t * pIceAgent,
                                          uint8_t * pStunMessageBuffer,
                                          IceIPAddress_t * pSrcAddr,
                                          uint8_t * pTransactionIdBuffer );

IceResult_t Ice_DeserializeStunPacket( StunContext_t * pStunCxt,
                                       StunHeader_t * pStunHeader,
                                       StunAttribute_t * pStunAttribute,
                                       StunAttributeAddress_t * pStunAttributeAddress,
                                       uint32_t priority );

IceResult_t Ice_HandleStunResponse( IceAgent_t * pIceAgent,
                                    uint8_t * pStunMessageBuffer,
                                    uint8_t pStunMessageBufferLength,
                                    uint8_t * pTransactionIdBuffer,
                                    IceCandidate_t * pLocalCandidate,
                                    IceIPAddress_t pSrcAddr,
                                    IceCandidatePair_t * pIceCandidatePair );

IceResult_t Ice_HandleServerReflexiveCandidateResponse( IceAgent_t * pIceAgent,
                                                        StunAttributeAddress_t * pStunMappedAddress,
                                                        IceCandidate_t * pLocalCandidate );

/************************************************************************************************************************************************/

/* These APIs are intended for internal use by the ICE library. */

bool Ice_IsSameIpAddress( StunAttributeAddress_t * pAddr1,
                          StunAttributeAddress_t * pAddr2,
                          bool checkPort );

bool Ice_IsSameIpAddress( StunAttributeAddress_t * pAddr1,
                          StunAttributeAddress_t * pAddr2,
                          bool checkPort );

IceCandidate_t * Ice_FindCandidateFromIp( IceAgent_t * pIceAgent,
                                          IceIPAddress_t pIpAddress,
                                          bool isRemote );

void Ice_TransactionIdStoreRemove( TransactionIdStore_t * pTransactionIdStore,
                                   uint8_t * transactionId );

bool Ice_TransactionIdStoreHasId( TransactionIdStore_t * pTransactionIdStore,
                                  uint8_t * transactionId );

void Ice_TransactionIdStoreInsert( TransactionIdStore_t * pTransactionIdStore,
                                   uint8_t * transactionId );

IceResult_t Ice_CreateTransactionIdStore( uint32_t maxIdCount,
                                          TransactionIdStore_t * pTransactionIdStore );

uint64_t Ice_ComputeCandidatePairPriority( IceCandidatePair_t * pIceCandidatePair,
                                           uint32_t isLocalControlling );

uint32_t Ice_ComputeCandidatePriority( IceCandidate_t * pIceCandidate );

int Ice_GetValidCandidatePairCount( IceAgent_t * pIceAgent );

int Ice_GetValidRemoteCandidateCount( IceAgent_t * pIceAgent );

int Ice_GetValidLocalCandidateCount( IceAgent_t * pIceAgent );

IceResult_t Ice_InsertRemoteCandidate( IceAgent_t * pIceAgent,
                                       IceCandidate_t * pCandidate );

IceResult_t Ice_InsertLocalCandidate( IceAgent_t * pIceAgent,
                                      IceCandidate_t * pCandidate );

void Ice_InsertCandidatePair( IceAgent_t * pIceAgent,
                              IceCandidatePair_t * pIceCandidatePair,
                              int iceCandidatePairCount );

/************************************************************************************************************************************************/

#endif /* ICE_API_H */
