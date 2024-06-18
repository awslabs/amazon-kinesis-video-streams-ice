#ifndef ICE_API_H
#define ICE_API_H

#include "ice_data_types.h"

IceResult_t Ice_Init( IceContext_t * pContext,
                      IceInitInfo_t * pInitInfo );

IceResult_t Ice_AddHostCandidate( IceContext_t * pContext,
                                  IceEndpoint_t * pEndpoint );

IceResult_t Ice_AddServerReflexiveCandidate( IceContext_t * pContext,
                                             IceEndpoint_t * pEndpoint,
                                             uint8_t * pStunMessageBuffer,
                                             size_t * pStunMessageBufferLength );

IceResult_t Ice_AddRemoteCandidate( IceContext_t * pContext,
                                    IceRemoteCandidateInfo_t * pRemoteCandidateInfo );

IceResult_t Ice_CreateRequestForConnectivityCheck( IceContext_t * pContext,
                                                   IceCandidatePair_t * pIceCandidatePair,
                                                   uint8_t * pStunMessageBuffer,
                                                   size_t * pStunMessageBufferLength );

IceResult_t Ice_CreateRequestForNominatingCandidatePair( IceContext_t * pContext,
                                                         IceCandidatePair_t * pIceCandidatePair,
                                                         uint8_t * pStunMessageBuffer,
                                                         size_t * pStunMessageBufferLength );

IceResult_t Ice_CreateResponseForRequest( IceContext_t * pContext,
                                          IceCandidatePair_t * pIceCandidatePair,
                                          uint8_t * pTransactionId,
                                          uint8_t * pStunMessageBuffer,
                                          size_t * pStunMessageBufferLength );

IceHandleStunPacketResult_t Ice_HandleStunPacket( IceContext_t * pContext,
                                                  uint8_t * pReceivedStunMessage,
                                                  size_t receivedStunMessageLength,
                                                  IceEndpoint_t * pLocalCandidateEndpoint,
                                                  IceEndpoint_t * pRemoteCandidateEndpoint,
                                                  uint8_t ** ppTransactionId,
                                                  IceCandidatePair_t ** ppIceCandidatePair );

IceResult_t Ice_GetLocalCandidateCount( IceContext_t * pContext,
                                        size_t * pNumLocalCandidates );

IceResult_t Ice_GetRemoteCandidateCount( IceContext_t * pContext,
                                         size_t * pNumRemoteCandidates );

IceResult_t Ice_GetCandidatePairCount( IceContext_t * pContext,
                                       size_t * pNumCandidatePairs );

#endif /* ICE_API_H */
