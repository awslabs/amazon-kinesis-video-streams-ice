#ifndef ICE_API_PRIVATE_H
#define ICE_API_PRIVATE_H

#include "ice_data_types.h"

/*
 * Functions below are not part of the public API and are intended
 * for use by the library only.
 */
bool Ice_IsSameIpAddress( StunAttributeAddress_t * pAddr1,
                          StunAttributeAddress_t * pAddr2,
                          bool checkPort );

bool Ice_FindCandidateFromIP( IceAgent_t * pIceAgent,
                              IceCandidate_t ** ppCandidate,
                              IceIPAddress_t iceIpAddress,
                              bool isRemote );

bool Ice_FindCandidatePairWithLocalAndRemoteAddr( IceAgent_t * pIceAgent,
                                                  IceIPAddress_t * pSrcAddr,
                                                  IceIPAddress_t * pRemoteAddr,
                                                  IceCandidatePair_t ** ppCandidatePair );

IceResult_t Ice_CreateTransactionIdStore( uint32_t maxIdCount,
                                          TransactionIdStore_t * pTransactionIdStore );

void Ice_TransactionIdStoreInsert( TransactionIdStore_t * pTransactionIdStore,
                                   uint8_t * pTransactionId );

bool Ice_TransactionIdStoreHasId( TransactionIdStore_t * pTransactionIdStore,
                                  uint8_t * pTransactionId );

void Ice_TransactionIdStoreRemove( TransactionIdStore_t * pTransactionIdStore,
                                   uint8_t * pTransactionId );

IceResult_t Ice_CreateCandidatePair( IceAgent_t * pIceAgent,
                                     IceCandidate_t * pLocalCandidate,
                                     IceCandidate_t * pRemoteCandidate );

IceResult_t Ice_InsertCandidatePair( IceAgent_t * pIceAgent,
                                     IceCandidatePair_t * pIceCandidatePair,
                                     int iceCandidatePairCount );

IceResult_t Ice_CheckPeerReflexiveCandidate( IceAgent_t * pIceAgent,
                                             IceIPAddress_t * pIpAddr,
                                             IceCandidate_t * pLocalCandidate,
                                             uint32_t priority,
                                             bool isRemote );

uint32_t Ice_ComputeCandidatePriority( IceCandidate_t * pIceCandidate );

uint64_t Ice_ComputeCandidatePairPriority( IceCandidatePair_t * pIceCandidatePair,
                                           uint32_t isLocalControlling );

IceResult_t Ice_CreateRequestForSrflxCandidate( IceAgent_t * pIceAgent,
                                                uint8_t * pStunMessageBuffer,
                                                uint8_t * pTransactionIdBuffer,
                                                uint32_t * pSendStunMessageBufferLength );

IceResult_t Ice_UpdateSrflxCandidateAddress( IceAgent_t * pIceAgent,
                                             IceCandidate_t * pCandidate,
                                             const IceIPAddress_t * pIpAddr );

IceResult_t Ice_HandleServerReflexiveCandidateResponse( IceAgent_t * pIceAgent,
                                                        StunAttributeAddress_t * pStunMappedAddress,
                                                        IceCandidate_t * pLocalCandidate );

IceResult_t Ice_InitializeStunPacket( IceAgent_t * pIceAgent,
                                      StunContext_t * pStunCxt,
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

IceStunPacketHandleResult_t Ice_DeserializeStunPacket( IceAgent_t * pIceAgent,
                                                       StunContext_t * pStunCxt,
                                                       StunHeader_t * pStunHeader,
                                                       StunAttribute_t * pStunAttribute,
                                                       uint8_t * pPassword,
                                                       uint32_t passwordLen,
                                                       IceStunDeserializedPacketInfo_t * pDeserializedPacketInfo );

#endif /* ICE_API_PRIVATE_H */
