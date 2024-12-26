#ifndef ICE_API_PRIVATE_H
#define ICE_API_PRIVATE_H

#include "ice_data_types.h"

/*----------------------------------------------------------------------------*/

/*
 * Functions below are not part of the public API and are intended
 * for use by the library only. We do not do parameter checking in these APIs
 * as those are done in public APIs
 */
uint8_t Ice_IsSameTransportAddress( const IceTransportAddress_t * pTransportAddress1,
                                    const IceTransportAddress_t * pTransportAddress2 );

uint8_t Ice_IsSameIpAddress( const IceTransportAddress_t * pTransportAddress1,
                             const IceTransportAddress_t * pTransportAddress2 );

IceResult_t Ice_AddCandidatePair( IceContext_t * pContext,
                                  IceCandidate_t * pLocalCandidate,
                                  IceCandidate_t * pRemoteCandidate,
                                  IceCandidatePair_t ** ppIceCandidatePair );

uint32_t Ice_ComputeCandidatePriority( IceCandidateType_t candidateType,
                                       uint8_t isPointToPoint );

uint64_t Ice_ComputeCandidatePairPriority( uint32_t localCandidatePriority,
                                           uint32_t remoteCandidatePriority,
                                           uint32_t isControlling );

IceResult_t Ice_FinalizeStunPacket( IceContext_t * pContext,
                                    StunContext_t * pStunCtx,
                                    const uint8_t * pPassword,
                                    size_t passwordLength,
                                    size_t * pStunMessageBufferLength );

IceHandleStunPacketResult_t Ice_DeserializeStunPacket( IceContext_t * pContext,
                                                       StunContext_t * pStunCtx,
                                                       const uint8_t * pPassword,
                                                       size_t passwordLength,
                                                       IceStunDeserializedPacketInfo_t * pDeserializedPacketInfo );

IceHandleStunPacketResult_t Ice_HandleStunBindingRequest( IceContext_t * pContext,
                                                          StunContext_t * pStunCtx,
                                                          const IceEndpoint_t * pLocalCandidateEndpoint,
                                                          const IceEndpoint_t * pRemoteCandidateEndpoint,
                                                          IceCandidatePair_t ** ppIceCandidatePair );

IceHandleStunPacketResult_t Ice_HandleServerReflexiveResponse( IceContext_t * pContext,
                                                               StunContext_t * pStunCtx,
                                                               const IceEndpoint_t * pLocalCandidateEndpoint );

IceHandleStunPacketResult_t Ice_HandleConnectivityCheckResponse( IceContext_t * pContext,
                                                                 StunContext_t * pStunCtx,
                                                                 const StunHeader_t * pStunHeader,
                                                                 const IceEndpoint_t * pLocalCandidateEndpoint,
                                                                 const IceEndpoint_t * pRemoteCandidateEndpoint,
                                                                 IceCandidatePair_t ** ppIceCandidatePair );

IceHandleStunPacketResult_t Ice_HandleTurnAllocateSuccessResponse( IceContext_t * pContext,
                                                                   StunContext_t * pStunCtx,
                                                                   const StunHeader_t * pStunHeader,
                                                                   const IceEndpoint_t * pLocalCandidateEndpoint );

IceHandleStunPacketResult_t Ice_HandleTurnAllocateErrorResponse( IceContext_t * pContext,
                                                                 StunContext_t * pStunCtx,
                                                                 const StunHeader_t * pStunHeader,
                                                                 const IceEndpoint_t * pLocalCandidateEndpoint );

IceHandleStunPacketResult_t Ice_HandleTurnCreatePermissionSuccessResponse( IceContext_t * pContext,
                                                                           StunContext_t * pStunCtx,
                                                                           const StunHeader_t * pStunHeader,
                                                                           const IceEndpoint_t * pLocalCandidateEndpoint,
                                                                           IceCandidatePair_t ** ppIceCandidatePair );

IceHandleStunPacketResult_t Ice_HandleTurnCreatePermissionErrorResponse( IceContext_t * pContext,
                                                                         StunContext_t * pStunCtx,
                                                                         const StunHeader_t * pStunHeader,
                                                                         const IceEndpoint_t * pLocalCandidateEndpoint,
                                                                         IceCandidatePair_t ** ppIceCandidatePair );

IceHandleStunPacketResult_t Ice_HandleTurnChannelBindSuccessResponse( IceContext_t * pContext,
                                                                      StunContext_t * pStunCtx,
                                                                      const StunHeader_t * pStunHeader,
                                                                      const IceEndpoint_t * pLocalCandidateEndpoint,
                                                                      IceCandidatePair_t ** ppIceCandidatePair );

IceHandleStunPacketResult_t Ice_HandleTurnChannelBindErrorResponse( IceContext_t * pContext,
                                                                    StunContext_t * pStunCtx,
                                                                    const StunHeader_t * pStunHeader,
                                                                    const IceEndpoint_t * pLocalCandidateEndpoint,
                                                                    IceCandidatePair_t ** ppIceCandidatePair );

/*----------------------------------------------------------------------------*/

#endif /* ICE_API_PRIVATE_H */
