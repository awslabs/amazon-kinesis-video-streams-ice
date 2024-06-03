#ifndef ICE_API_PRIVATE_H
#define ICE_API_PRIVATE_H

#include "ice_data_types.h"


/* Static Functions. */
static bool Ice_IsSameIpAddress( StunAttributeAddress_t * pAddr1,
                                 StunAttributeAddress_t * pAddr2,
                                 bool checkPort );

static bool Ice_FindCandidateFromIP( IceAgent_t * pIceAgent,
                                     IceCandidate_t ** ppCandidate,
                                     IceIPAddress_t iceIpAddress,
                                     bool isRemote );

static bool Ice_FindCandidatePairWithLocalAndRemoteAddr( IceAgent_t * pIceAgent,
                                                         IceIPAddress_t * pSrcAddr,
                                                         IceIPAddress_t * pRemoteAddr,
                                                         IceCandidatePair_t ** ppCandidatePair );

static IceResult_t Ice_CreateTransactionIdStore( uint32_t maxIdCount,
                                                 TransactionIdStore_t * pTransactionIdStore );

static void Ice_TransactionIdStoreInsert( TransactionIdStore_t * pTransactionIdStore,
                                          uint8_t * pTransactionId );

static bool Ice_TransactionIdStoreHasId( TransactionIdStore_t * pTransactionIdStore,
                                         uint8_t * pTransactionId );

static void Ice_TransactionIdStoreRemove( TransactionIdStore_t * pTransactionIdStore,
                                          uint8_t * pTransactionId );

static IceResult_t Ice_CreateCandidatePair( IceAgent_t * pIceAgent,
                                            IceCandidate_t * pLocalCandidate,
                                            IceCandidate_t * pRemoteCandidate );

static IceResult_t Ice_InsertCandidatePair( IceAgent_t * pIceAgent,
                                            IceCandidatePair_t * pIceCandidatePair,
                                            int iceCandidatePairCount );

static IceResult_t Ice_CheckPeerReflexiveCandidate( IceAgent_t * pIceAgent,
                                                    IceIPAddress_t * pIpAddr,
                                                    IceCandidate_t * pLocalCandidate,
                                                    uint32_t priority,
                                                    bool isRemote );

static uint32_t Ice_ComputeCandidatePriority( IceCandidate_t * pIceCandidate );

static uint64_t Ice_ComputeCandidatePairPriority( IceCandidatePair_t * pIceCandidatePair,
                                                  uint32_t isLocalControlling );

static IceResult_t Ice_UpdateSrflxCandidateAddress( IceAgent_t * pIceAgent,
                                                    IceCandidate_t * pCandidate,
                                                    const IceIPAddress_t * pIpAddr );

static IceResult_t Ice_HandleServerReflexiveCandidateResponse( IceAgent_t * pIceAgent,
                                                               StunAttributeAddress_t * pStunMappedAddress,
                                                               IceCandidate_t * pLocalCandidate );

static IceResult_t Ice_InitializeStunPacket( IceAgent_t * pIceAgent,
                                             StunContext_t * pStunCxt,
                                             uint8_t * pTransactionId,
                                             uint8_t * pStunMessageBuffer,
                                             StunHeader_t * pStunHeader,
                                             uint8_t isGenerateTransactionID,
                                             uint8_t isStunBindingRequest );

static IceResult_t Ice_PackageStunPacket( IceAgent_t * pIceAgent,
                                          StunContext_t * pStunCxt,
                                          uint8_t * pPpassword,
                                          uint32_t passwordLen,
                                          uint32_t * pStunMessageBufferLength );

static IceStunPacketHandleResult_t Ice_DeserializeStunPacket( IceAgent_t * pIceAgent,
                                                              StunContext_t * pStunCxt,
                                                              StunHeader_t * pStunHeader,
                                                              StunAttribute_t * pStunAttribute,
                                                              uint8_t * pPassword,
                                                              uint32_t passwordLen,
                                                              IceStunDeserializedPacketInfo_t * pDeserializedPacketInfo );

#endif /* ICE_API_PRIVATE_H */
