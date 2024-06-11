#ifndef ICE_API_H
#define ICE_API_H

#include "ice_data_types.h"

IceResult_t Ice_CreateIceAgent( IceAgent_t * pIceAgent,
                                char * pLocalUsername,
                                char * pLocalPassword,
                                char * pRemoteUsername,
                                char * pRemotePassword,
                                char * pCombinedUsername,
                                TransactionIdStore_t * pBuffer,
                                Ice_ComputeRandom computeRandomFunction,
                                Ice_ComputeCrc32 computeCrc32Function,
                                Ice_ComputeHMAC computeHMACFunction );

IceResult_t Ice_AddHostCandidate( IceAgent_t * pIceAgent,
                                  const IceIPAddress_t ipAddr,
                                  IceCandidate_t ** ppCandidate );

IceResult_t Ice_AddSrflxCandidate( IceAgent_t * pIceAgent,
                                   const IceIPAddress_t ipAddr,
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
                                          IceCandidatePair_t * pIceCandidatePair,
                                          uint8_t * pTransactionIdBuffer );

IceStunPacketHandleResult_t Ice_HandleStunPacket( IceAgent_t * pIceAgent,
                                                  uint8_t * pReceivedStunMessageBuffer,
                                                  uint32_t receivedStunMessageBufferLength,
                                                  uint8_t ** ppSendTransactionIdBuffer,
                                                  IceIPAddress_t * pLocalCandidateAddress,
                                                  IceIPAddress_t * pRemoteCandidateAddress,
                                                  IceCandidatePair_t ** ppIceCandidatePair );

int Ice_GetValidCandidatePairCount( IceAgent_t * pIceAgent );

int Ice_GetValidRemoteCandidateCount( IceAgent_t * pIceAgent );

int Ice_GetValidLocalCandidateCount( IceAgent_t * pIceAgent );

#endif /* ICE_API_H */
