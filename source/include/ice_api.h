#ifndef ICE_API_H
#define ICE_API_H

#include "ice_data_types.h"

IceResult_t Ice_Init( IceContext_t * pContext,
                      const IceInitInfo_t * pInitInfo );

IceResult_t Ice_AddHostCandidate( IceContext_t * pContext,
                                  const IceEndpoint_t * pEndpoint );

IceResult_t Ice_AddServerReflexiveCandidate( IceContext_t * pContext,
                                             const IceEndpoint_t * pEndpoint );

IceResult_t Ice_AddRelayCandidate( IceContext_t * pContext,
                                   const IceEndpoint_t * pEndpoint,
                                   const char * pTurnServerUsername,
                                   size_t turnServerUsernameLength,
                                   const char * pTurnServerPassword,
                                   size_t turnServerPasswordLength );

IceResult_t Ice_AddRemoteCandidate( IceContext_t * pContext,
                                    const IceRemoteCandidateInfo_t * pRemoteCandidateInfo );

IceResult_t Ice_CloseCandidate( IceContext_t * pContext,
                                IceCandidate_t * pLocalCandidate );

IceResult_t Ice_CloseCandidatePair( IceContext_t * pContext,
                                    IceCandidatePair_t * pIceCandidatePair );

IceResult_t Ice_CreateResponseForRequest( IceContext_t * pContext,
                                          const IceCandidatePair_t * pIceCandidatePair,
                                          uint8_t * pTransactionId,
                                          uint8_t * pMessageBuffer,
                                          size_t * pMessageBufferLength );

IceResult_t Ice_HandleTurnPacket( IceContext_t * pContext,
                                  const uint8_t * pReceivedTurnMessage,
                                  size_t receivedTurnMessageLength,
                                  IceCandidate_t * pLocalCandidate,
                                  const uint8_t ** ppTurnPayload,
                                  uint16_t * pTurnPayloadLength,
                                  IceCandidatePair_t ** ppIceCandidatePair );

IceHandleStunPacketResult_t Ice_HandleStunPacket( IceContext_t * pContext,
                                                  uint8_t * pReceivedStunMessage,
                                                  size_t receivedStunMessageLength,
                                                  IceCandidate_t * pLocalCandidate,
                                                  const IceEndpoint_t * pRemoteCandidateEndpoint,
                                                  uint64_t currentTimeSeconds,
                                                  uint8_t ** ppTransactionId,
                                                  IceCandidatePair_t ** ppIceCandidatePair );

IceResult_t Ice_GetLocalCandidateCount( IceContext_t * pContext,
                                        size_t * pNumLocalCandidates );

IceResult_t Ice_GetRemoteCandidateCount( IceContext_t * pContext,
                                         size_t * pNumRemoteCandidates );

IceResult_t Ice_GetCandidatePairCount( IceContext_t * pContext,
                                       size_t * pNumCandidatePairs );

/**
 * Generates STUN/TURN requests for ICE candidate:
 * - Server reflexive candidate: STUN Binding request (query external IP/port).
 * - Relay candidate: TURN Allocation request.
 */
IceResult_t Ice_CreateNextCandidateRequest( IceContext_t * pContext,
                                            IceCandidate_t * pIceCandidate,
                                            uint64_t currentTimeSeconds,
                                            uint8_t * pStunMessageBuffer,
                                            size_t * pStunMessageBufferLength );

/**
 * Generates STUN/TURN requests for ICE candidate pair:
 * - Non-Relay candidate pair: STUN Binding request (connectivity check/nomination).
 * - Relay candidate pair: TURN Create Permission/Channel Binding request.
 */
IceResult_t Ice_CreateNextPairRequest( IceContext_t * pContext,
                                       IceCandidatePair_t * pIceCandidatePair,
                                       uint64_t currentTimeSeconds,
                                       uint8_t * pStunMessageBuffer,
                                       size_t * pStunMessageBufferLength );

/* Writes 4 byte TURN channel data message header before the payload and the
 * required padding after the payload. It assumes that the caller has reserved
 * 4 (ICE_TURN_CHANNEL_DATA_MESSAGE_HEADER_LENGTH) bytes for the header.
 *
 * @param pTotalBufferLength [in, out]: On input, the total buffer length.
 *                                      On output, the turn message size
 *                                      including header and padding.
 *            pTurnPayload
 *            |
 *            V         turnPayloadLength
 *            <-------------------------------------->
 * +----------+--------------------------------------+----------+------------------+
 * |  Header  |           TURN Payload               |  Padding |                  |
 * +----------+--------------------------------------+----------+------------------+
 * <------------------------------------------------------------------------------->
 *                       *pTotalBufferLength (on input)
 * <------------------------------------------------------------>
 *                 *pTotalBufferLength (on output)
 */
IceResult_t Ice_CreateTurnChannelDataMessage( IceContext_t * pContext,
                                              const IceCandidatePair_t * pIceCandidatePair,
                                              uint8_t * pTurnPayload,
                                              size_t turnPayloadLength,
                                              size_t * pTotalBufferLength );

#endif /* ICE_API_H */
