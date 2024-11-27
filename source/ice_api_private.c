/* Standard includes. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* API includes. */
#include "ice_api.h"
#include "ice_api_private.h"

/* STUN API includes. */
#include "stun_data_types.h"
#include "stun_serializer.h"
#include "stun_deserializer.h"

/*----------------------------------------------------------------------------*/

/* Macros used to calculate ICE candidate priorities. */
#define ICE_PRIORITY_HOST_CANDIDATE_TYPE_PREFERENCE                126
#define ICE_PRIORITY_SERVER_REFLEXIVE_CANDIDATE_TYPE_PREFERENCE    100
#define ICE_PRIORITY_PEER_REFLEXIVE_CANDIDATE_TYPE_PREFERENCE      110
#define ICE_PRIORITY_RELAYED_CANDIDATE_TYPE_PREFERENCE             0
#define ICE_PRIORITY_LOCAL_PREFERENCE                              65535

/*----------------------------------------------------------------------------*/

uint8_t Ice_IsSameTransportAddress( const IceTransportAddress_t * pTransportAddress1,
                                    const IceTransportAddress_t * pTransportAddress2 )
{
    uint8_t isSameAddress = 0;
    size_t ipAddressLength = 0;

    if( ( pTransportAddress1 != NULL ) && ( pTransportAddress2 != NULL ) )
    {
        ipAddressLength = pTransportAddress1->family == STUN_ADDRESS_IPv4 ? STUN_IPV4_ADDRESS_SIZE :
                                                                            STUN_IPV6_ADDRESS_SIZE;

        if( ( pTransportAddress1->family == pTransportAddress2->family ) &&
            ( pTransportAddress1->port == pTransportAddress2->port ) &&
            ( memcmp( &( pTransportAddress1->address[ 0 ] ),
                      &( pTransportAddress2->address[ 0 ] ),
                      ipAddressLength ) == 0 ) )
        {
            isSameAddress = 1;
        }
    }

    return isSameAddress;
}

/*----------------------------------------------------------------------------*/

uint8_t Ice_IsSameIpAddress( const IceTransportAddress_t * pTransportAddress1,
                             const IceTransportAddress_t * pTransportAddress2 )
{
    uint8_t isSameIpAddress = 0;
    size_t ipAddressLength = 0;

    if( ( pTransportAddress1 != NULL ) && ( pTransportAddress2 != NULL ) )
    {
        ipAddressLength = pTransportAddress1->family == STUN_ADDRESS_IPv4 ? STUN_IPV4_ADDRESS_SIZE :
                                                                            STUN_IPV6_ADDRESS_SIZE;

        if( ( pTransportAddress1->family == pTransportAddress2->family ) &&
            ( memcmp( &( pTransportAddress1->address[ 0 ] ),
                      &( pTransportAddress2->address[ 0 ] ),
                      ipAddressLength ) == 0 ) )
        {
            isSameIpAddress = 1;
        }
    }

    return isSameIpAddress;
}

/*----------------------------------------------------------------------------*/

IceResult_t Ice_AddCandidatePair( IceContext_t * pContext,
                                  IceCandidate_t * pLocalCandidate,
                                  IceCandidate_t * pRemoteCandidate )
{
    IceResult_t result = ICE_RESULT_OK;
    uint64_t candidatePairPriority;
    size_t i, candidatePairIndex;
    uint8_t transactionId[ STUN_HEADER_TRANSACTION_ID_LENGTH ];

    if( ( pContext == NULL ) ||
        ( pLocalCandidate == NULL ) ||
        ( pRemoteCandidate == NULL ) )
    {
        result = ICE_RESULT_BAD_PARAM;
    }

    if( result == ICE_RESULT_OK )
    {
        if( pContext->numCandidatePairs == pContext->maxCandidatePairs )
        {
            result = ICE_RESULT_MAX_CANDIDATE_PAIR_THRESHOLD;
        }
    }

    if( result == ICE_RESULT_OK )
    {
        result = pContext->cryptoFunctions.randomFxn( &( transactionId[ 0 ] ),
                                                      STUN_HEADER_TRANSACTION_ID_LENGTH );
    }

    if( result == ICE_RESULT_OK )
    {
        candidatePairPriority = Ice_ComputeCandidatePairPriority( pLocalCandidate->priority,
                                                                  pRemoteCandidate->priority,
                                                                  pContext->isControlling );

        candidatePairIndex = pContext->numCandidatePairs;

        /* ICE Candidate pairs are sorted by priority. Find the correct location
         * of the new candidate pair in the candidate pair array. */
        for( i = 0; i < pContext->numCandidatePairs; i++ )
        {
            if( candidatePairPriority >= pContext->pCandidatePairs[ i ].priority )
            {
                candidatePairIndex = i;
                break;
            }
        }

        /* Move all the candidate pairs from candidatePairIndex by one to
         * make space for the new candidate pair. */
        for( i = pContext->numCandidatePairs; i > candidatePairIndex; i-- )
        {
            pContext->pCandidatePairs[ i ] = pContext->pCandidatePairs[ i - 1 ];
        }

        /* Insert the candidate pair at candidatePairIndex. */
        pContext->pCandidatePairs[ candidatePairIndex ].pLocalCandidate = pLocalCandidate;
        pContext->pCandidatePairs[ candidatePairIndex ].pRemoteCandidate = pRemoteCandidate;
        pContext->pCandidatePairs[ candidatePairIndex ].priority = candidatePairPriority;
        pContext->pCandidatePairs[ candidatePairIndex ].state = ICE_CANDIDATE_PAIR_STATE_WAITING;
        pContext->pCandidatePairs[ candidatePairIndex ].connectivityCheckFlags = 0;
        memcpy( &( pContext->pCandidatePairs[ candidatePairIndex ].transactionId[ 0 ] ),
                &( transactionId[ 0 ] ),
                STUN_HEADER_TRANSACTION_ID_LENGTH );
        pContext->numCandidatePairs += 1;
    }

    return result;
}

/*----------------------------------------------------------------------------*/

/* Ice_ComputeCandidatePriority - Compute the candidate priority.
 */
uint32_t Ice_ComputeCandidatePriority( IceCandidateType_t candidateType,
                                       uint8_t isPointToPoint )
{
    uint32_t typePreference = 0;
    uint32_t localPreference = 0;
    uint32_t candidatePriority = 0;

    switch( candidateType )
    {
        case ICE_CANDIDATE_TYPE_HOST:
            typePreference = ICE_PRIORITY_HOST_CANDIDATE_TYPE_PREFERENCE;
            break;

        case ICE_CANDIDATE_TYPE_SERVER_REFLEXIVE:
            typePreference = ICE_PRIORITY_SERVER_REFLEXIVE_CANDIDATE_TYPE_PREFERENCE;
            break;

        case ICE_CANDIDATE_TYPE_PEER_REFLEXIVE:
            typePreference = ICE_PRIORITY_PEER_REFLEXIVE_CANDIDATE_TYPE_PREFERENCE;
            break;

        case ICE_CANDIDATE_TYPE_RELAYED:
            typePreference = ICE_PRIORITY_RELAYED_CANDIDATE_TYPE_PREFERENCE;
            break;

        default:
            break;
    }

    if( isPointToPoint == 0 )
    {
        localPreference = ICE_PRIORITY_LOCAL_PREFERENCE;
    }

    /* Reference: https://tools.ietf.org/html/rfc5245#section-4.1.2.1
     * priority = (2^24)*(type preference) +
     *   (2^8)*(local preference) +
     *   (2^0)*(256 - component ID)
     *
     * Since type preference <= 126 and local preference <= 65535, the maximum possible
     * priority is (2^24) * (126) + (2^8) * (65535) + 255 = 2130706431. So, it's safe
     * to use UINT32 since 2130706431 < 2 ^ 32. */
    candidatePriority = ( ( 1 << 24 ) * ( typePreference ) + ( 1 << 8 ) * ( localPreference ) + 255 );

    return candidatePriority;
}

/*----------------------------------------------------------------------------*/

/* Ice_ComputeCandidatePairPriority - Compute the candidate pair priority. */

uint64_t Ice_ComputeCandidatePairPriority( uint32_t localCandidatePriority,
                                           uint32_t remoteCandidatePriority,
                                           uint32_t isControlling )
{
    uint64_t controllingAgentCandidatePriority;
    uint64_t controlledAgentCandidatePriority;
    uint64_t candidatePairPriority = 0;

    if( isControlling == 0 )
    {
        controllingAgentCandidatePriority = remoteCandidatePriority;
        controlledAgentCandidatePriority = localCandidatePriority;
    }
    else
    {
        controllingAgentCandidatePriority = localCandidatePriority;
        controlledAgentCandidatePriority = remoteCandidatePriority;
    }

    /* https://tools.ietf.org/html/rfc5245#appendix-B.5 */
    candidatePairPriority = ( ( ( uint64_t ) 1 << 32 ) *
                              ( controllingAgentCandidatePriority >= controlledAgentCandidatePriority ?
                                controlledAgentCandidatePriority : controllingAgentCandidatePriority ) +
                              ( 2 * ( controllingAgentCandidatePriority >= controlledAgentCandidatePriority ?
                                      controllingAgentCandidatePriority : controlledAgentCandidatePriority ) ) +
                              ( controllingAgentCandidatePriority > controlledAgentCandidatePriority ? 1 : 0 ) );

    return candidatePairPriority;
}

/*----------------------------------------------------------------------------*/

IceResult_t Ice_FinalizeStunPacket( IceContext_t * pContext,
                                    StunContext_t * pStunCtx,
                                    const uint8_t * pPassword,
                                    size_t passwordLength,
                                    size_t * pStunMessageBufferLength )
{
    IceResult_t iceResult = ICE_RESULT_OK;
    StunResult_t stunResult = STUN_RESULT_OK;
    uint8_t messageIntegrity[ STUN_ATTRIBUTE_INTEGRITY_VALUE_LENGTH ];
    uint16_t messageIntegrityLength = STUN_ATTRIBUTE_INTEGRITY_VALUE_LENGTH;
    uint8_t * pIntegrityCalculationData = NULL;
    uint16_t integrityCalculationDataLength = 0;
    uint8_t * pFingerprintCalculationData = NULL;
    uint16_t fingerprintCalculationDataLength = 0;
    uint32_t messageFingerprint = 0;

    if( pPassword != NULL )
    {
        /* Add Integrity attribute. */
        stunResult = StunSerializer_GetIntegrityBuffer( pStunCtx,
                                                        &( pIntegrityCalculationData ),
                                                        &( integrityCalculationDataLength ) );

        if( stunResult == STUN_RESULT_OK )
        {
            iceResult = pContext->cryptoFunctions.hmacFxn( pPassword,
                                                           passwordLength,
                                                           pIntegrityCalculationData,
                                                           ( size_t ) integrityCalculationDataLength,
                                                           &( messageIntegrity[ 0 ] ),
                                                           &( messageIntegrityLength ) );

            if( iceResult == ICE_RESULT_OK )
            {
                if( messageIntegrityLength == STUN_ATTRIBUTE_INTEGRITY_VALUE_LENGTH )
                {
                    stunResult = StunSerializer_AddAttributeIntegrity( pStunCtx,
                                                                       &( messageIntegrity[ 0 ] ),
                                                                       messageIntegrityLength );
                }
                else
                {
                    iceResult = ICE_RESULT_HMAC_ERROR;
                }
            }
        }
    }

    /* Add Fingerprint attribute. */
    if( ( iceResult == ICE_RESULT_OK ) &&
        ( stunResult == STUN_RESULT_OK ) )
    {
        stunResult = StunSerializer_GetFingerprintBuffer( pStunCtx,
                                                          &( pFingerprintCalculationData ),
                                                          &( fingerprintCalculationDataLength ) );

        if( stunResult == STUN_RESULT_OK )
        {
            iceResult = pContext->cryptoFunctions.crc32Fxn( 0,
                                                            pFingerprintCalculationData,
                                                            ( size_t ) fingerprintCalculationDataLength,
                                                            &( messageFingerprint ) );

            if( iceResult == ICE_RESULT_OK )
            {
                stunResult = StunSerializer_AddAttributeFingerprint( pStunCtx,
                                                                     messageFingerprint );
            }
        }
    }

    if( ( iceResult == ICE_RESULT_OK ) &&
        ( stunResult == STUN_RESULT_OK ) )
    {
        stunResult = StunSerializer_Finalize( pStunCtx,
                                              pStunMessageBufferLength );
    }

    if( stunResult != STUN_RESULT_OK )
    {
        iceResult = ICE_RESULT_STUN_ERROR;
    }

    return iceResult;
}

/*----------------------------------------------------------------------------*/

/* Ice_DeserializeStunPacket - This API deserializes a received STUN packet.
*/
IceHandleStunPacketResult_t Ice_DeserializeStunPacket( IceContext_t * pContext,
                                                       StunContext_t * pStunCtx,
                                                       const uint8_t * pPassword,
                                                       size_t passwordLength,
                                                       IceStunDeserializedPacketInfo_t * pDeserializedPacketInfo )
{
    IceHandleStunPacketResult_t result = ICE_HANDLE_STUN_PACKET_RESULT_OK;
    StunResult_t stunResult = STUN_RESULT_OK;
    IceResult_t iceResult = ICE_RESULT_OK;
    StunAttribute_t stunAttribute;
    uint8_t * pErrorPhase = NULL;
    uint16_t errorPhaseLength = 0;
    uint8_t * pIntegrityCalculationData = NULL;
    uint16_t integrityCalculationDataLength = 0;
    uint8_t messageIntegrity[ STUN_ATTRIBUTE_INTEGRITY_VALUE_LENGTH ];
    uint16_t messageIntegrityLength = STUN_ATTRIBUTE_INTEGRITY_VALUE_LENGTH;
    uint8_t * pFingerprintCalculationData = NULL;
    uint16_t fingerprintCalculationDataLength = 0;
    uint32_t fingerprint;
    uint32_t computedFingerprint;

    memset( pDeserializedPacketInfo,
            0,
            sizeof( IceStunDeserializedPacketInfo_t ) );

    while( ( stunResult == STUN_RESULT_OK ) && ( result == ICE_HANDLE_STUN_PACKET_RESULT_OK ) )
    {
        stunResult = StunDeserializer_GetNextAttribute( pStunCtx,
                                                        &( stunAttribute ) );

        if( stunResult == STUN_RESULT_OK )
        {
            switch( stunAttribute.attributeType )
            {
                case STUN_ATTRIBUTE_TYPE_ERROR_CODE:
                {
                    stunResult = StunDeserializer_ParseAttributeErrorCode( &( stunAttribute ),
                                                                           &( pDeserializedPacketInfo->errorCode ),
                                                                           &( pErrorPhase ),
                                                                           &( errorPhaseLength ) );
                }
                break;

                case STUN_ATTRIBUTE_TYPE_XOR_MAPPED_ADDRESS:
                {
                    stunResult = StunDeserializer_ParseAttributeAddress( pStunCtx,
                                                                         &( stunAttribute ),
                                                                         &( pDeserializedPacketInfo->transportAddress ) );
                }
                break;

                case STUN_ATTRIBUTE_TYPE_USE_CANDIDATE:
                {
                    pDeserializedPacketInfo->useCandidateFlag = 1;
                }
                break;

                case STUN_ATTRIBUTE_TYPE_PRIORITY:
                {
                    stunResult = StunDeserializer_ParseAttributePriority( pStunCtx,
                                                                          &( stunAttribute ),
                                                                          &( pDeserializedPacketInfo->priority ) );
                }
                break;

                case STUN_ATTRIBUTE_TYPE_MESSAGE_INTEGRITY:
                {
                    if( ( pPassword != NULL ) && ( passwordLength != 0 ) )
                    {
                        stunResult = StunDeserializer_GetIntegrityBuffer( pStunCtx,
                                                                          &( pIntegrityCalculationData ),
                                                                          &( integrityCalculationDataLength ) );

                        if( stunResult == STUN_RESULT_OK )
                        {
                            iceResult = pContext->cryptoFunctions.hmacFxn( pPassword,
                                                                           passwordLength,
                                                                           pIntegrityCalculationData,
                                                                           ( size_t ) integrityCalculationDataLength,
                                                                           &( messageIntegrity[ 0 ] ),
                                                                           &( messageIntegrityLength ) );

                            if( ( iceResult != ICE_RESULT_OK ) ||
                                ( messageIntegrityLength != STUN_ATTRIBUTE_INTEGRITY_VALUE_LENGTH ) ||
                                ( messageIntegrityLength != stunAttribute.attributeValueLength ) ||
                                ( memcmp( &( messageIntegrity[ 0 ] ),
                                          stunAttribute.pAttributeValue,
                                          stunAttribute.attributeValueLength ) != 0 ) )
                            {
                                result = ICE_HANDLE_STUN_PACKET_RESULT_INTEGRITY_MISMATCH;
                            }
                        }
                    }
                    else
                    {
                        result = ICE_HANDLE_STUN_PACKET_RESULT_DESERIALIZE_ERROR;
                    }
                }
                break;

                case STUN_ATTRIBUTE_TYPE_FINGERPRINT:
                {
                    stunResult = StunDeserializer_ParseAttributeFingerprint( pStunCtx,
                                                                             &( stunAttribute ),
                                                                             &( fingerprint ) );

                    if( stunResult == STUN_RESULT_OK )
                    {
                        stunResult = StunDeserializer_GetFingerprintBuffer( pStunCtx,
                                                                            &( pFingerprintCalculationData ),
                                                                            &( fingerprintCalculationDataLength ) );
                    }

                    if( stunResult == STUN_RESULT_OK )
                    {
                        iceResult = pContext->cryptoFunctions.crc32Fxn( 0,
                                                                        pFingerprintCalculationData,
                                                                        ( size_t ) fingerprintCalculationDataLength,
                                                                        &( computedFingerprint ) );

                        if( ( iceResult != ICE_RESULT_OK ) ||
                            ( fingerprint != computedFingerprint ) )
                        {
                            result = ICE_HANDLE_STUN_PACKET_RESULT_FINGERPRINT_MISMATCH;
                        }
                    }
                }
                break;

                default:
                    break;
            }
        }
    }

    if( stunResult != STUN_RESULT_NO_MORE_ATTRIBUTE_FOUND && result == ICE_HANDLE_STUN_PACKET_RESULT_OK )
    {
        result = ICE_HANDLE_STUN_PACKET_RESULT_DESERIALIZE_ERROR;
    }

    return result;
}

/*----------------------------------------------------------------------------*/

IceHandleStunPacketResult_t Ice_HandleStunBindingRequest( IceContext_t * pContext,
                                                          StunContext_t * pStunCtx,
                                                          const IceEndpoint_t * pLocalCandidateEndpoint,
                                                          const IceEndpoint_t * pRemoteCandidateEndpoint,
                                                          IceCandidatePair_t ** ppIceCandidatePair )
{
    size_t i;
    IceResult_t iceResult = ICE_RESULT_OK;
    IceHandleStunPacketResult_t handleStunPacketResult = ICE_HANDLE_STUN_PACKET_RESULT_OK;
    IceStunDeserializedPacketInfo_t deserializePacketInfo;
    IceRemoteCandidateInfo_t remoteCandidateInfo;
    IceCandidatePair_t * pIceCandidatePair = NULL;

    handleStunPacketResult = Ice_DeserializeStunPacket( pContext,
                                                        pStunCtx,
                                                        ( uint8_t * ) pContext->creds.pLocalPassword,
                                                        pContext->creds.localPasswordLength,
                                                        &( deserializePacketInfo ) );

    if( ( handleStunPacketResult == ICE_HANDLE_STUN_PACKET_RESULT_OK ) &&
        ( deserializePacketInfo.errorCode == 0 ) )
    {
        /* Do we already have a remote candidate with the same transport address
         * as pRemoteCandidateEndpoint->transportAddress? */
        for( i = 0; i < pContext->numRemoteCandidates; i++ )
        {
            if( Ice_IsSameTransportAddress( &( pContext->pRemoteCandidates[ i ].endpoint.transportAddress ),
                                            &( pRemoteCandidateEndpoint->transportAddress ) ) == 1 )
            {
                break;
            }
        }

        /* If we do not have a remote candidate with the same transport address
         * as pRemoteCandidateEndpoint->transportAddress, add a new remote
         * candidate with this address. */
        if( i == pContext->numRemoteCandidates )
        {
            remoteCandidateInfo.candidateType = ICE_CANDIDATE_TYPE_PEER_REFLEXIVE;
            remoteCandidateInfo.priority = deserializePacketInfo.priority;
            remoteCandidateInfo.remoteProtocol = ICE_SOCKET_PROTOCOL_NONE;
            remoteCandidateInfo.pEndpoint = pRemoteCandidateEndpoint;

            iceResult = Ice_AddRemoteCandidate( pContext, &( remoteCandidateInfo ) );
        }

        if( iceResult == ICE_RESULT_OK )
        {
            for( i = 0; i < pContext->numCandidatePairs; i++ )
            {
                if( ( Ice_IsSameTransportAddress( &( pContext->pCandidatePairs[ i ].pLocalCandidate->endpoint.transportAddress ),
                                                  &( pLocalCandidateEndpoint->transportAddress ) ) == 1 ) &&
                    ( Ice_IsSameTransportAddress( &( pContext->pCandidatePairs[ i ].pRemoteCandidate->endpoint.transportAddress ),
                                                  &( pRemoteCandidateEndpoint->transportAddress ) ) == 1 ) )
                {
                    pIceCandidatePair = &( pContext->pCandidatePairs[ i ] );
                    break;
                }
            }
        }

        if( pIceCandidatePair != NULL )
        {
            /* Did we receive a request for nomination? */
            if( ( deserializePacketInfo.useCandidateFlag == 1 ) &&
                ICE_STUN_CONNECTIVITY_CHECK_SUCCESSFUL( pIceCandidatePair->connectivityCheckFlags ) )
            {
                pIceCandidatePair->state = ICE_CANDIDATE_PAIR_STATE_NOMINATED;
                handleStunPacketResult = ICE_HANDLE_STUN_PACKET_RESULT_SEND_RESPONSE_FOR_NOMINATION;
            }
            else
            {
                /* Received a connectivity check request from the remote candidate. */
                pIceCandidatePair->connectivityCheckFlags |= ICE_STUN_REQUEST_RECEIVED_FLAG;

                if( ( pIceCandidatePair->connectivityCheckFlags & ICE_STUN_REQUEST_SENT_FLAG ) == 0 )
                {
                    /* We have not sent the connectivity check request to this
                     * candidate. The application needs to send 2 stun packets-
                     * 1. The connectivity check request from local to remote.
                     * 2. The response to the connectivity check request
                     *    received from remote. */
                    pIceCandidatePair->connectivityCheckFlags |= ICE_STUN_REQUEST_SENT_FLAG;
                    pIceCandidatePair->connectivityCheckFlags |= ICE_STUN_RESPONSE_SENT_FLAG;

                    handleStunPacketResult = ICE_HANDLE_STUN_PACKET_RESULT_SEND_TRIGGERED_CHECK;
                }
                else
                {
                     /* We have sent the connectivity check request to this
                      * candidate. The application needs to send 1 stun packet-
                      * 1. The response to the connectivity check request
                      *    received from remote. */
                    pIceCandidatePair->connectivityCheckFlags |= ICE_STUN_RESPONSE_SENT_FLAG;

                    handleStunPacketResult = ICE_HANDLE_STUN_PACKET_RESULT_SEND_RESPONSE_FOR_REMOTE_REQUEST;
                }
            }
        }
        else
        {
            handleStunPacketResult = ICE_HANDLE_STUN_PACKET_RESULT_CANDIDATE_PAIR_NOT_FOUND;
        }
    }

    if( pIceCandidatePair != NULL )
    {
        *ppIceCandidatePair = pIceCandidatePair;
    }

    return handleStunPacketResult;
}

/*----------------------------------------------------------------------------*/

IceHandleStunPacketResult_t Ice_HandleServerReflexiveResponse( IceContext_t * pContext,
                                                               StunContext_t * pStunCtx,
                                                               const IceEndpoint_t * pLocalCandidateEndpoint )
{
    size_t i;
    IceResult_t iceResult = ICE_RESULT_OK;
    IceHandleStunPacketResult_t handleStunPacketResult = ICE_HANDLE_STUN_PACKET_RESULT_OK;
    IceStunDeserializedPacketInfo_t deserializePacketInfo;
    IceCandidate_t * pLocalCandidate = NULL;

    handleStunPacketResult = Ice_DeserializeStunPacket( pContext,
                                                        pStunCtx,
                                                        NULL,
                                                        0,
                                                        &( deserializePacketInfo ) );

    if( ( handleStunPacketResult == ICE_HANDLE_STUN_PACKET_RESULT_OK ) &&
        ( deserializePacketInfo.errorCode == 0 ) &&
        ( deserializePacketInfo.transportAddress.family != 0 ) )
    {
        /* Do we have a server reflexive candidate with the same transport
         * address as pLocalCandidateEndpoint->transportAddress? */
        for( i = 0; i < pContext->numLocalCandidates; i++ )
        {
            if( ( pContext->pLocalCandidates[ i ].candidateType == ICE_CANDIDATE_TYPE_SERVER_REFLEXIVE ) &&
                ( Ice_IsSameTransportAddress( &( pContext->pLocalCandidates[ i ].endpoint.transportAddress ),
                                              &( pLocalCandidateEndpoint->transportAddress ) ) == 1 ) )
            {
                pLocalCandidate = &( pContext->pLocalCandidates[ i ] );
                break;
            }
        }

        if( pLocalCandidate != NULL )
        {
            memcpy( &( pLocalCandidate->endpoint.transportAddress ),
                    &( deserializePacketInfo.transportAddress ),
                    sizeof( IceTransportAddress_t ) );
            pLocalCandidate->endpoint.isPointToPoint = 0;

            pLocalCandidate->state = ICE_CANDIDATE_STATE_VALID;

            for( i = 0; ( i < pContext->numRemoteCandidates ) && ( iceResult == ICE_RESULT_OK ); i++ )
            {
                iceResult = Ice_AddCandidatePair( pContext,
                                                  pLocalCandidate,
                                                  &( pContext->pRemoteCandidates[ i ] ) );

            }

            handleStunPacketResult = ICE_HANDLE_STUN_PACKET_RESULT_UPDATED_SERVER_REFLEXIVE_CANDIDATE_ADDRESS;
        }
        else
        {
            handleStunPacketResult = ICE_HANDLE_STUN_PACKET_RESULT_CANDIDATE_NOT_FOUND;
        }
    }

    return handleStunPacketResult;
}

/*----------------------------------------------------------------------------*/

IceHandleStunPacketResult_t Ice_HandleConnectivityCheckResponse( IceContext_t * pContext,
                                                                 StunContext_t * pStunCtx,
                                                                 const StunHeader_t * pStunHeader,
                                                                 const IceEndpoint_t * pLocalCandidateEndpoint,
                                                                 const IceEndpoint_t * pRemoteCandidateEndpoint,
                                                                 IceCandidatePair_t ** ppIceCandidatePair )
{
    size_t i;
    IceHandleStunPacketResult_t handleStunPacketResult = ICE_HANDLE_STUN_PACKET_RESULT_OK;
    IceStunDeserializedPacketInfo_t deserializePacketInfo;
    IceCandidatePair_t * pIceCandidatePair = NULL;

    handleStunPacketResult = Ice_DeserializeStunPacket( pContext,
                                                        pStunCtx,
                                                        pContext->creds.pRemotePassword,
                                                        pContext->creds.remotePasswordLength,
                                                        &( deserializePacketInfo ) );

    if( handleStunPacketResult == ICE_HANDLE_STUN_PACKET_RESULT_OK )
    {
        if( deserializePacketInfo.errorCode == 0 )
        {
            for( i = 0; i < pContext->numCandidatePairs; i++ )
            {
                if( ( Ice_IsSameTransportAddress( &( pContext->pCandidatePairs[ i ].pLocalCandidate->endpoint.transportAddress ),
                                                  &( pLocalCandidateEndpoint->transportAddress ) ) == 1 ) &&
                    ( Ice_IsSameTransportAddress( &( pContext->pCandidatePairs[ i ].pRemoteCandidate->endpoint.transportAddress ),
                                                  &( pRemoteCandidateEndpoint->transportAddress ) ) == 1 ) )
                {
                    pIceCandidatePair = &( pContext->pCandidatePairs[ i ] );
                    break;
                }
            }

            if( pIceCandidatePair != NULL )
            {
                if( memcmp( &( pIceCandidatePair->transactionId[ 0 ] ),
                            pStunHeader->pTransactionId,
                            STUN_HEADER_TRANSACTION_ID_LENGTH ) == 0 )
                {
                    pIceCandidatePair->connectivityCheckFlags |= ICE_STUN_RESPONSE_RECEIVED_FLAG;

                    if( ICE_STUN_CONNECTIVITY_CHECK_SUCCESSFUL( pIceCandidatePair->connectivityCheckFlags ) )
                    {
                        if( pIceCandidatePair->state == ICE_CANDIDATE_PAIR_STATE_NOMINATED )
                        {
                            pIceCandidatePair->state = ICE_CANDIDATE_PAIR_STATE_SUCCEEDED;
                            handleStunPacketResult = ICE_HANDLE_STUN_PACKET_RESULT_CANDIDATE_PAIR_READY;
                        }
                        else
                        {
                            pIceCandidatePair->state = ICE_CANDIDATE_PAIR_STATE_VALID;
                            if( pContext->isControlling == 1 )
                            {
                                handleStunPacketResult = ICE_HANDLE_STUN_PACKET_RESULT_START_NOMINATION;
                            }
                            else
                            {
                                handleStunPacketResult = ICE_HANDLE_STUN_PACKET_RESULT_VALID_CANDIDATE_PAIR;
                            }
                        }
                    }
                    else
                    {
                        if( deserializePacketInfo.transportAddress.family != 0 )
                        {
                            if( ( pIceCandidatePair->pLocalCandidate->candidateType == ICE_CANDIDATE_TYPE_SERVER_REFLEXIVE ) &&
                                ( pIceCandidatePair->pRemoteCandidate->candidateType == ICE_CANDIDATE_TYPE_SERVER_REFLEXIVE ) &&
                                ( Ice_IsSameIpAddress( &( deserializePacketInfo.transportAddress ),
                                                       &( pIceCandidatePair->pLocalCandidate->endpoint.transportAddress ) ) == 0 ) )
                            {
                                pIceCandidatePair->pLocalCandidate->candidateType = ICE_CANDIDATE_TYPE_PEER_REFLEXIVE;

                                memcpy( &( pIceCandidatePair->pLocalCandidate->endpoint.transportAddress ),
                                        &( deserializePacketInfo.transportAddress ),
                                        sizeof( IceTransportAddress_t ) );
                                pIceCandidatePair->pLocalCandidate->endpoint.isPointToPoint = 0;

                                handleStunPacketResult = ICE_HANDLE_STUN_PACKET_RESULT_FOUND_PEER_REFLEXIVE_CANDIDATE;
                            }
                        }
                        else
                        {
                            /* No mapped address attribute found in STUN response. Dropping Packet. */
                            handleStunPacketResult = ICE_HANDLE_STUN_PACKET_RESULT_ADDRESS_ATTRIBUTE_NOT_FOUND;
                        }
                    }
                }
                else
                {
                    /* Dropping response packet because transaction id does not match.*/
                    handleStunPacketResult = ICE_HANDLE_STUN_PACKET_RESULT_MATCHING_TRANSACTION_ID_NOT_FOUND;
                }

                *ppIceCandidatePair = pIceCandidatePair;
            }
            else
            {
                /* Candidate Pair was not found using the local and remote addresses. */
                handleStunPacketResult = ICE_HANDLE_STUN_PACKET_RESULT_CANDIDATE_PAIR_NOT_FOUND;
            }
        }
        else
        {
            handleStunPacketResult = ICE_HANDLE_STUN_PACKET_RESULT_NON_ZERO_ERROR_CODE;
        }
    }

    return handleStunPacketResult;
}

/*----------------------------------------------------------------------------*/
