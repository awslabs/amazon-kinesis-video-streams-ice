#ifndef ICE_API_H
#define ICE_API_H

#include "ice_data_types.h"

IceResult_t Ice_Init( IceContext_t * pContext,
                      const IceInitInfo_t * pInitInfo );

IceResult_t Ice_AddHostCandidate( IceContext_t * pContext,
                                  const IceEndpoint_t * pEndpoint );

IceResult_t Ice_AddServerReflexiveCandidate( IceContext_t * pContext,
                                             const IceEndpoint_t * pEndpoint,
                                             uint8_t * pStunMessageBuffer,
                                             size_t * pStunMessageBufferLength );

IceResult_t Ice_AddRelayCandidate( IceContext_t * pContext,
                                   const IceEndpoint_t * pEndpoint,
                                   char * pUsername,
                                   size_t usernameLength,
                                   char * pPassword,
                                   size_t passwordLength );

IceResult_t Ice_AddRemoteCandidate( IceContext_t * pContext,
                                    const IceRemoteCandidateInfo_t * pRemoteCandidateInfo );

IceResult_t Ice_CloseCandidate( IceContext_t * pContext,
                                IceCandidate_t * pLocalCandidate );

IceResult_t Ice_CloseCandidatePair( IceContext_t * pContext,
                                    IceCandidatePair_t * pIceCandidatePair );

IceResult_t Ice_CreateResponseForRequest( IceContext_t * pContext,
                                          const IceCandidatePair_t * pIceCandidatePair,
                                          uint8_t * pTransactionId,
                                          uint8_t * pStunMessageBuffer,
                                          size_t * pStunMessageBufferLength );

IceResult_t Ice_HandleTurnPacket( IceContext_t * pContext,
                                  IceCandidate_t * pIceLocalCandidate,
                                  const uint8_t * pReceivedBuffer,
                                  size_t receivedBufferLength,
                                  const uint8_t ** ppTurnPayloadBuffer,
                                  uint16_t * pTurnPayloadBufferLength,
                                  IceCandidatePair_t ** ppIceCandidatePair );

IceHandleStunPacketResult_t Ice_HandleStunPacket( IceContext_t * pContext,
                                                  uint8_t * pReceivedStunMessage,
                                                  size_t receivedStunMessageLength,
                                                  IceCandidate_t * pLocalCandidate,
                                                  const IceEndpoint_t * pRemoteCandidateEndpoint,
                                                  uint8_t ** ppTransactionId,
                                                  IceCandidatePair_t ** ppIceCandidatePair );

IceResult_t Ice_GetLocalCandidateCount( IceContext_t * pContext,
                                        size_t * pNumLocalCandidates );

IceResult_t Ice_GetRemoteCandidateCount( IceContext_t * pContext,
                                         size_t * pNumRemoteCandidates );

IceResult_t Ice_GetCandidatePairCount( IceContext_t * pContext,
                                       size_t * pNumCandidatePairs );

/**
 * Generates STUN/TURN requests for ICE candidate gathering:
 * - srflx candidate: STUN Binding request (query external IP/port)
 * - relay candidate: TURN Allocation request
 */
IceResult_t Ice_CreateNextCandidateRequest( IceContext_t * pContext,
                                            IceCandidate_t * pIceCandidate,
                                            uint8_t * pStunMessageBuffer,
                                            size_t * pStunMessageBufferLength );

/**
 * Generates STUN/TURN requests for ICE candidate pair:
 * - common candidate pair: STUN Binding request (connectivity check/nomination)
 * - relay candidate pair: TURN Create Permission/Channel Binding request
 */
IceResult_t Ice_CreateNextPairRequest( IceContext_t * pContext,
                                       IceCandidatePair_t * pIceCandidatePair,
                                       uint8_t * pStunMessageBuffer,
                                       size_t * pStunMessageBufferLength );

IceResult_t Ice_CreateTurnChannelDataMessage( IceContext_t * pContext,
                                              const IceCandidatePair_t * pIceCandidatePair,
                                              const uint8_t * pInputBuffer,
                                              size_t inputBufferLength,
                                              uint8_t * pOutputBuffer,
                                              size_t * pOutputBufferLength );

#endif /* ICE_API_H */
