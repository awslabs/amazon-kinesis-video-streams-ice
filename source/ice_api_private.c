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
#define ICE_PRIORITY_RELAY_CANDIDATE_TYPE_PREFERENCE               0
#define ICE_PRIORITY_LOCAL_PREFERENCE                              65535

/*----------------------------------------------------------------------------*/

/* Follow https://datatracker.ietf.org/doc/html/rfc5389#section-15.4 to get the
 * long-term credential string. */
static IceResult_t CalculateLongTermCredential( IceContext_t * pContext,
                                                IceTurnServer_t * pTurnServer )
{
    IceResult_t result = ICE_RESULT_OK;
    const int bufferLength = ICE_SERVER_CONFIG_MAX_USER_NAME_LENGTH +
                             ICE_SERVER_CONFIG_MAX_REALM_LENGTH +
                             ICE_SERVER_CONFIG_MAX_PASSWORD_LENGTH +
                             2; /* 2 for two ":" between each value. */
    char buffer[ bufferLength ];
    int snprintfRetVal;
    uint16_t longTermPasswordLength;

    snprintfRetVal = snprintf( &( buffer[ 0 ] ),
                               bufferLength,
                               "%.*s:%.*s:%.*s",
                               ( int ) pTurnServer->userNameLength, &( pTurnServer->userName[ 0 ] ),
                               ( int ) pTurnServer->realmLength, &( pTurnServer->realm[ 0 ] ),
                               ( int ) pTurnServer->passwordLength, &( pTurnServer->password[ 0 ] ) );

    /* LCOV_EXCL_START */
    if( snprintfRetVal < 0 )
    {
        result = ICE_RESULT_SNPRINTF_ERROR;
    }
    /* LCOV_EXCL_STOP  */

    if( result == ICE_RESULT_OK )
    {
        longTermPasswordLength = ICE_SERVER_CONFIG_LONG_TERM_PASSWORD_LENGTH;
        result = pContext->cryptoFunctions.md5Fxn( ( const uint8_t * ) &( buffer[ 0 ] ),
                                                   snprintfRetVal,
                                                   &( pTurnServer->longTermPassword[ 0 ] ),
                                                   &( longTermPasswordLength ) );
    }


    if( result == ICE_RESULT_OK )
    {
        pTurnServer->longTermPasswordLength = longTermPasswordLength;
    }

    return result;
}

/*----------------------------------------------------------------------------*/

/* When we receive a unauthorized error code (401) for a TURN allocation/refresh
 * request, we extract nonce and realm from the response and calculate the long
 * term password based on these values. */
static IceHandleStunPacketResult_t UpdateIceServerInfo( IceContext_t * pContext,
                                                        IceCandidate_t * pLocalCandidate,
                                                        IceStunDeserializedPacketInfo_t * pDeserializePacketInfo )
{
    IceHandleStunPacketResult_t handleStunPacketResult = ICE_HANDLE_STUN_PACKET_RESULT_OK;
    IceResult_t iceResult;

    if( ( pDeserializePacketInfo->nonceLength > ICE_SERVER_CONFIG_MAX_NONCE_LENGTH ) ||
        ( pDeserializePacketInfo->realmLength > ICE_SERVER_CONFIG_MAX_REALM_LENGTH ) )
    {
        handleStunPacketResult = ICE_HANDLE_STUN_PACKET_RESULT_INVALID_RESPONSE;
    }

    if( handleStunPacketResult == ICE_HANDLE_STUN_PACKET_RESULT_OK )
    {
        if( pDeserializePacketInfo->nonceLength > 0 )
        {
            memcpy( &( pLocalCandidate->pTurnServer->nonce[ 0 ] ),
                    pDeserializePacketInfo->pNonce,
                    pDeserializePacketInfo->nonceLength );
            pLocalCandidate->pTurnServer->nonceLength = pDeserializePacketInfo->nonceLength;
        }

        if( pDeserializePacketInfo->realmLength > 0 )
        {
            memcpy( &( pLocalCandidate->pTurnServer->realm[ 0 ] ),
                    pDeserializePacketInfo->pRealm,
                    pDeserializePacketInfo->realmLength );
            pLocalCandidate->pTurnServer->realmLength = pDeserializePacketInfo->realmLength;

            iceResult = CalculateLongTermCredential( pContext,
                                                     pLocalCandidate->pTurnServer );

            if( iceResult != ICE_RESULT_OK )
            {
                handleStunPacketResult = ICE_HANDLE_STUN_PACKET_RESULT_LONG_TERM_CREDENTIAL_CALCULATION_ERROR;
            }
        }
    }

    return handleStunPacketResult;
}

/*----------------------------------------------------------------------------*/

static void ReleaseOtherCandidates( IceContext_t * pContext,
                                    const IceCandidatePair_t * pNominatedPair )
{
    size_t i;

    for( i = 0; i < pContext->numLocalCandidates; i++ )
    {
        if( &( pContext->pLocalCandidates[ i ] ) != pNominatedPair->pLocalCandidate )
        {
            ( void ) Ice_CloseCandidate( pContext, &( pContext->pLocalCandidates[ i ] ) );
        }
    }
}

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
        if( ( pLocalCandidate->candidateType == ICE_CANDIDATE_TYPE_RELAY ) &&
            ( pLocalCandidate->pTurnServer->nextAvailableTurnChannelNumber > ICE_DEFAULT_TURN_CHANNEL_NUMBER_MAX ) )
        {
            result = ICE_RESULT_MAX_CHANNEL_NUMBER_THRESHOLD;
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
        if( pLocalCandidate->candidateType == ICE_CANDIDATE_TYPE_RELAY )
        {
            pContext->pCandidatePairs[ candidatePairIndex ].state = ICE_CANDIDATE_PAIR_STATE_CREATE_PERMISSION;
            pContext->pCandidatePairs[ candidatePairIndex ].turnChannelNumber = pLocalCandidate->pTurnServer->nextAvailableTurnChannelNumber;
            pLocalCandidate->pTurnServer->nextAvailableTurnChannelNumber++;
        }
        else
        {
            pContext->pCandidatePairs[ candidatePairIndex ].state = ICE_CANDIDATE_PAIR_STATE_WAITING;
        }
        pContext->pCandidatePairs[ candidatePairIndex ].pLocalCandidate = pLocalCandidate;
        pContext->pCandidatePairs[ candidatePairIndex ].pRemoteCandidate = pRemoteCandidate;
        pContext->pCandidatePairs[ candidatePairIndex ].priority = candidatePairPriority;
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

        case ICE_CANDIDATE_TYPE_RELAY:
            typePreference = ICE_PRIORITY_RELAY_CANDIDATE_TYPE_PREFERENCE;
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

/* Ice_CreateRequestForConnectivityCheck - This API creates Stun Packet for
 * connectivity check to the remote candidate.
 */
IceResult_t Ice_CreateRequestForConnectivityCheck( IceContext_t * pContext,
                                                   IceCandidatePair_t * pIceCandidatePair,
                                                   uint8_t * pMessageBuffer,
                                                   size_t * pMessageBufferLength )
{
    StunContext_t stunCtx;
    StunHeader_t stunHeader;
    IceResult_t result = ICE_RESULT_OK;
    StunResult_t stunResult = STUN_RESULT_OK;
    uint8_t * pStunMessageStart;
    size_t stunMessageBufferLength;
    size_t stunMessageBufferSize;

    if( ( pContext == NULL ) ||
        ( pIceCandidatePair == NULL ) ||
        ( pMessageBuffer == NULL ) ||
        ( pMessageBufferLength == NULL ) )
    {
        result = ICE_RESULT_BAD_PARAM;
    }

    if( result == ICE_RESULT_OK )
    {
        /* For Relay candidate, reserve 4 bytes to add TURN channel data message
         * header. */
        if( pIceCandidatePair->pLocalCandidate->candidateType == ICE_CANDIDATE_TYPE_RELAY )
        {
            pStunMessageStart = &( pMessageBuffer[ ICE_TURN_CHANNEL_DATA_MESSAGE_HEADER_LENGTH ] );
            stunMessageBufferLength = *pMessageBufferLength - ICE_TURN_CHANNEL_DATA_MESSAGE_HEADER_LENGTH;
            stunMessageBufferSize = *pMessageBufferLength;
        }
        else
        {
            pStunMessageStart = pMessageBuffer;
            stunMessageBufferLength = *pMessageBufferLength;
        }
    }

    /* Serialize application data. */
    if( result == ICE_RESULT_OK )
    {
        stunHeader.messageType = STUN_MESSAGE_TYPE_BINDING_REQUEST;
        stunHeader.pTransactionId = &( pIceCandidatePair->transactionId[ 0 ] );

        stunResult = StunSerializer_Init( &( stunCtx ),
                                          pStunMessageStart,
                                          stunMessageBufferLength,
                                          &( stunHeader ) );

        if( stunResult == STUN_RESULT_OK )
        {
            stunResult = StunSerializer_AddAttributeUsername( &( stunCtx ),
                                                              pContext->creds.pCombinedUsername,
                                                              ( uint16_t ) pContext->creds.combinedUsernameLength );
        }

        if( stunResult == STUN_RESULT_OK )
        {
            stunResult = StunSerializer_AddAttributePriority( &( stunCtx ),
                                                              pIceCandidatePair->pLocalCandidate->priority );
        }

        if( stunResult == STUN_RESULT_OK )
        {
            if( pContext->isControlling == 0 )
            {
                stunResult = StunSerializer_AddAttributeIceControlled( &( stunCtx ),
                                                                       pContext->tieBreaker );
            }
            else
            {
                stunResult = StunSerializer_AddAttributeIceControlling( &( stunCtx ),
                                                                        pContext->tieBreaker );
            }
        }

        if( stunResult == STUN_RESULT_OK )
        {
            result = Ice_FinalizeStunPacket( pContext,
                                             &( stunCtx ),
                                             pContext->creds.pRemotePassword,
                                             pContext->creds.remotePasswordLength,
                                             &( stunMessageBufferLength ) );
        }
        else
        {
            result = ICE_RESULT_STUN_ERROR;
        }
    }

    if( ( result == ICE_RESULT_OK ) &&
        ( pIceCandidatePair->pLocalCandidate->candidateType == ICE_CANDIDATE_TYPE_RELAY ) )
    {
        /* For TURN candidate pair, create TURN channel header for connectivity check. */
        result = Ice_CreateTurnChannelDataMessage( pContext,
                                                   pIceCandidatePair,
                                                   pStunMessageStart,
                                                   stunMessageBufferLength,
                                                   &stunMessageBufferSize );
    }

    if( result == ICE_RESULT_OK )
    {
        pIceCandidatePair->connectivityCheckFlags |= ICE_STUN_REQUEST_SENT_FLAG;

        if( pIceCandidatePair->pLocalCandidate->candidateType == ICE_CANDIDATE_TYPE_RELAY )
        {
            *pMessageBufferLength = stunMessageBufferSize;
        }
        else
        {
            *pMessageBufferLength = stunMessageBufferLength;
        }
    }

    return result;
}

/*----------------------------------------------------------------------------*/

/* Ice_CreateRequestForNominatingCandidatePair - This API creates Stun Packet
 * for nomination of the valid candidate Pair sent by the Controlling ICE agent.
 */
IceResult_t Ice_CreateRequestForNominatingCandidatePair( IceContext_t * pContext,
                                                         IceCandidatePair_t * pIceCandidatePair,
                                                         uint8_t * pMessageBuffer,
                                                         size_t * pMessageBufferLength )
{
    StunContext_t stunCtx;
    StunHeader_t stunHeader;
    IceResult_t result = ICE_RESULT_OK;
    StunResult_t stunResult = STUN_RESULT_OK;
    uint8_t * pStunMessageStart;
    size_t stunMessageBufferLength;
    size_t stunMessageBufferSize;

    if( ( pContext == NULL ) ||
        ( pIceCandidatePair == NULL ) ||
        ( pMessageBuffer == NULL ) ||
        ( pMessageBufferLength == NULL ) )
    {
        result = ICE_RESULT_BAD_PARAM;
    }

    if( result == ICE_RESULT_OK )
    {
        /* For Relay candidate, reserve 4 bytes to add TURN channel data message
         * header. */
        if( pIceCandidatePair->pLocalCandidate->candidateType == ICE_CANDIDATE_TYPE_RELAY )
        {
            pStunMessageStart = &( pMessageBuffer[ ICE_TURN_CHANNEL_DATA_MESSAGE_HEADER_LENGTH ] );
            stunMessageBufferLength = *pMessageBufferLength - ICE_TURN_CHANNEL_DATA_MESSAGE_HEADER_LENGTH;
            stunMessageBufferSize = *pMessageBufferLength;
        }
        else
        {
            pStunMessageStart = pMessageBuffer;
            stunMessageBufferLength = *pMessageBufferLength;
        }
    }

    if( result == ICE_RESULT_OK )
    {
        stunHeader.messageType = STUN_MESSAGE_TYPE_BINDING_REQUEST;
        stunHeader.pTransactionId = &( pIceCandidatePair->transactionId[ 0 ] );

        stunResult = StunSerializer_Init( &( stunCtx ),
                                          pStunMessageStart,
                                          stunMessageBufferLength,
                                          &( stunHeader ) );

        if( stunResult == STUN_RESULT_OK )
        {
            stunResult = StunSerializer_AddAttributeUsername( &( stunCtx ),
                                                              pContext->creds.pCombinedUsername,
                                                              ( uint16_t ) pContext->creds.combinedUsernameLength );
        }

        if( stunResult == STUN_RESULT_OK )
        {
            stunResult = StunSerializer_AddAttributePriority( &( stunCtx ),
                                                              pIceCandidatePair->pLocalCandidate->priority );
        }

        if( stunResult == STUN_RESULT_OK )
        {
            stunResult = StunSerializer_AddAttributeIceControlling( &( stunCtx ),
                                                                    pContext->tieBreaker );
        }

        if( stunResult == STUN_RESULT_OK )
        {
            stunResult = StunSerializer_AddAttributeUseCandidate( &( stunCtx ) );
        }

        if( stunResult == STUN_RESULT_OK )
        {
            result = Ice_FinalizeStunPacket( pContext,
                                             &( stunCtx ),
                                             pContext->creds.pRemotePassword,
                                             pContext->creds.remotePasswordLength,
                                             &( stunMessageBufferLength ) );
        }
        else
        {
            result = ICE_RESULT_STUN_ERROR;
        }
    }

    if( ( result == ICE_RESULT_OK ) &&
        ( pIceCandidatePair->pLocalCandidate->candidateType == ICE_CANDIDATE_TYPE_RELAY ) )
    {
        result = Ice_CreateTurnChannelDataMessage( pContext,
                                                   pIceCandidatePair,
                                                   pStunMessageStart,
                                                   stunMessageBufferLength,
                                                   &stunMessageBufferSize );
    }

    if( result == ICE_RESULT_OK )
    {
        if( pIceCandidatePair->pLocalCandidate->candidateType == ICE_CANDIDATE_TYPE_RELAY )
        {
            *pMessageBufferLength = stunMessageBufferSize;
        }
        else
        {
            *pMessageBufferLength = stunMessageBufferLength;
        }
    }

    return result;
}

/*----------------------------------------------------------------------------*/

IceResult_t Ice_CreateServerReflexiveBindingRequest( IceContext_t * pContext,
                                                     IceCandidate_t * pIceCandidate,
                                                     uint8_t * pStunMessageBuffer,
                                                     size_t * pStunMessageBufferLength )
{
    IceResult_t result = ICE_RESULT_OK;
    StunContext_t stunCtx;
    StunHeader_t stunHeader;
    StunResult_t stunResult = STUN_RESULT_OK;
    TransactionIdStoreResult_t transactionIdStoreResult;

    if( TransactionIdStore_HasId( pContext->pStunBindingRequestTransactionIdStore,
                                  &( pIceCandidate->transactionId[ 0 ] ) ) != TRANSACTION_ID_STORE_RESULT_OK )
    {
        transactionIdStoreResult = TransactionIdStore_Insert( pContext->pStunBindingRequestTransactionIdStore,
                                                              &( pIceCandidate->transactionId[ 0 ] ) );

        if( transactionIdStoreResult != TRANSACTION_ID_STORE_RESULT_OK )
        {
            result = ICE_RESULT_TRANSACTION_ID_STORE_ERROR;
        }
    }

    if( result == ICE_RESULT_OK )
    {
        stunHeader.messageType = STUN_MESSAGE_TYPE_BINDING_REQUEST;
        stunHeader.pTransactionId = &( pIceCandidate->transactionId[ 0 ] );

        stunResult = StunSerializer_Init( &( stunCtx ),
                                          pStunMessageBuffer,
                                          *pStunMessageBufferLength,
                                          &( stunHeader ) );

        if( stunResult == STUN_RESULT_OK )
        {
            result = Ice_FinalizeStunPacket( pContext,
                                             &( stunCtx ),
                                             NULL,
                                             0,
                                             pStunMessageBufferLength );
        }
        else
        {
            result = ICE_RESULT_STUN_ERROR;
        }
    }

    return result;
}

/*----------------------------------------------------------------------------*/

IceResult_t Ice_CreateAllocationRequest( IceContext_t * pContext,
                                         IceCandidate_t * pIceCandidate,
                                         uint8_t * pStunMessageBuffer,
                                         size_t * pStunMessageBufferLength )
{
    IceResult_t result = ICE_RESULT_OK;
    StunContext_t stunCtx;
    StunHeader_t stunHeader;
    StunResult_t stunResult = STUN_RESULT_OK;

    if( pIceCandidate->pTurnServer == NULL )
    {
        result = ICE_RESULT_INVALID_CANDIDATE;
    }

    if( result == ICE_RESULT_OK )
    {
        stunHeader.messageType = STUN_MESSAGE_TYPE_ALLOCATE_REQUEST;
        stunHeader.pTransactionId = &( pIceCandidate->transactionId[ 0 ] );

        stunResult = StunSerializer_Init( &( stunCtx ),
                                          pStunMessageBuffer,
                                          *pStunMessageBufferLength,
                                          &( stunHeader ) );

        if( stunResult != STUN_RESULT_OK )
        {
            result = ICE_RESULT_STUN_ERROR;
        }
    }

    if( result == ICE_RESULT_OK )
    {
        stunResult = StunSerializer_AddAttributeLifetime( &( stunCtx ),
                                                          ICE_DEFAULT_TURN_ALLOCATION_LIFETIME_SECONDS );

        if( stunResult != STUN_RESULT_OK )
        {
            result = ICE_RESULT_STUN_ERROR_ADD_LIFETIME;
        }
    }

    if( result == ICE_RESULT_OK )
    {
        stunResult = StunSerializer_AddAttributeRequestedTransport( &( stunCtx ),
                                                                    STUN_ATTRIBUTE_REQUESTED_TRANSPORT_UDP );

        if( stunResult != STUN_RESULT_OK )
        {
            result = ICE_RESULT_STUN_ERROR_ADD_REQUESTED_TRANSPORT;
        }
    }

    if( result == ICE_RESULT_OK )
    {
        if( pIceCandidate->pTurnServer->userNameLength > 0U )
        {
            stunResult = StunSerializer_AddAttributeUsername( &( stunCtx ),
                                                              &( pIceCandidate->pTurnServer->userName[ 0 ] ),
                                                              pIceCandidate->pTurnServer->userNameLength );

            if( stunResult != STUN_RESULT_OK )
            {
                result = ICE_RESULT_STUN_ERROR_ADD_USERNAME;
            }
        }
    }

    if( result == ICE_RESULT_OK )
    {
        if( pIceCandidate->pTurnServer->realmLength > 0U )
        {
            stunResult = StunSerializer_AddAttributeRealm( &( stunCtx ),
                                                           &( pIceCandidate->pTurnServer->realm[ 0 ] ),
                                                           pIceCandidate->pTurnServer->realmLength );

            if( stunResult != STUN_RESULT_OK )
            {
                result = ICE_RESULT_STUN_ERROR_ADD_REALM;
            }
        }
    }

    if( result == ICE_RESULT_OK )
    {
        if( pIceCandidate->pTurnServer->nonceLength > 0U )
        {
            stunResult = StunSerializer_AddAttributeNonce( &( stunCtx ),
                                                           &( pIceCandidate->pTurnServer->nonce[ 0 ] ),
                                                           pIceCandidate->pTurnServer->nonceLength );

            if( stunResult != STUN_RESULT_OK )
            {
                result = ICE_RESULT_STUN_ERROR_ADD_NONCE;
            }
        }
    }

    if( result == ICE_RESULT_OK )
    {
        if( pIceCandidate->pTurnServer->longTermPasswordLength > 0 )
        {
            /* We already have generated long-term password. */
            result = Ice_FinalizeStunPacket( pContext,
                                             &( stunCtx ),
                                             &( pIceCandidate->pTurnServer->longTermPassword[ 0 ] ),
                                             pIceCandidate->pTurnServer->longTermPasswordLength,
                                             pStunMessageBufferLength );
        }
        else
        {
            result = Ice_FinalizeStunPacket( pContext,
                                             &( stunCtx ),
                                             NULL,
                                             0,
                                             pStunMessageBufferLength );
        }
    }

    return result;
}

/*----------------------------------------------------------------------------*/

IceResult_t Ice_CreateRefreshRequest( IceContext_t * pContext,
                                      IceCandidate_t * pIceCandidate,
                                      uint32_t lifetime,
                                      uint8_t * pStunMessageBuffer,
                                      size_t * pStunMessageBufferLength )
{
    IceResult_t result = ICE_RESULT_OK;
    StunContext_t stunCtx;
    StunHeader_t stunHeader;
    StunResult_t stunResult = STUN_RESULT_OK;

    if( pIceCandidate->pTurnServer == NULL )
    {
        result = ICE_RESULT_INVALID_CANDIDATE;
    }

    if( result == ICE_RESULT_OK )
    {
        stunHeader.messageType = STUN_MESSAGE_TYPE_REFRESH_REQUEST;
        stunHeader.pTransactionId = &( pIceCandidate->transactionId[ 0 ] );

        stunResult = StunSerializer_Init( &( stunCtx ),
                                          pStunMessageBuffer,
                                          *pStunMessageBufferLength,
                                          &( stunHeader ) );

        if( stunResult != STUN_RESULT_OK )
        {
            result = ICE_RESULT_STUN_ERROR;
        }
    }

    if( result == ICE_RESULT_OK )
    {
        stunResult = StunSerializer_AddAttributeLifetime( &( stunCtx ), lifetime );

        if( stunResult != STUN_RESULT_OK )
        {
            result = ICE_RESULT_STUN_ERROR_ADD_LIFETIME;
        }
    }

    if( result == ICE_RESULT_OK )
    {
        if( pIceCandidate->pTurnServer->userNameLength > 0U )
        {
            stunResult = StunSerializer_AddAttributeUsername( &( stunCtx ),
                                                              &( pIceCandidate->pTurnServer->userName[ 0 ] ),
                                                              pIceCandidate->pTurnServer->userNameLength );

            if( stunResult != STUN_RESULT_OK )
            {
                result = ICE_RESULT_STUN_ERROR_ADD_USERNAME;
            }
        }
    }

    if( result == ICE_RESULT_OK )
    {
        if( pIceCandidate->pTurnServer->realmLength > 0U )
        {
            stunResult = StunSerializer_AddAttributeRealm( &( stunCtx ),
                                                           &( pIceCandidate->pTurnServer->realm[ 0 ] ),
                                                           pIceCandidate->pTurnServer->realmLength );

            if( stunResult != STUN_RESULT_OK )
            {
                result = ICE_RESULT_STUN_ERROR_ADD_REALM;
            }
        }
    }

    if( result == ICE_RESULT_OK )
    {
        if( pIceCandidate->pTurnServer->nonceLength > 0U )
        {
            stunResult = StunSerializer_AddAttributeNonce( &( stunCtx ),
                                                           &( pIceCandidate->pTurnServer->nonce[ 0 ] ),
                                                           pIceCandidate->pTurnServer->nonceLength );

            if( stunResult != STUN_RESULT_OK )
            {
                result = ICE_RESULT_STUN_ERROR_ADD_NONCE;
            }
        }
    }

    if( result == ICE_RESULT_OK )
    {
        if( pIceCandidate->pTurnServer->longTermPasswordLength > 0 )
        {
            /* We already have generated long-term password. */
            result = Ice_FinalizeStunPacket( pContext,
                                             &( stunCtx ),
                                             &( pIceCandidate->pTurnServer->longTermPassword[ 0 ] ),
                                             pIceCandidate->pTurnServer->longTermPasswordLength,
                                             pStunMessageBufferLength );
        }
        else
        {
            result = Ice_FinalizeStunPacket( pContext,
                                             &( stunCtx ),
                                             NULL,
                                             0,
                                             pStunMessageBufferLength );
        }
    }

    return result;
}

/*----------------------------------------------------------------------------*/

/* CreateRequestForCreatePermission - This API creates Stun Packet for
 * TURN create permission.
 */
IceResult_t Ice_CreatePermissionRequest( IceContext_t * pContext,
                                         IceCandidatePair_t * pIceCandidatePair,
                                         uint8_t * pStunMessageBuffer,
                                         size_t * pStunMessageBufferLength )
{
    IceResult_t result = ICE_RESULT_OK;
    StunContext_t stunCtx;
    StunHeader_t stunHeader;
    StunResult_t stunResult = STUN_RESULT_OK;

    if( ( pIceCandidatePair->pLocalCandidate == NULL ) ||
        ( pIceCandidatePair->pRemoteCandidate == NULL ) )
    {
        result = ICE_RESULT_BAD_PARAM;
    }

    if( result == ICE_RESULT_OK )
    {
        if( ( pIceCandidatePair->pLocalCandidate->candidateType != ICE_CANDIDATE_TYPE_RELAY ) ||
            ( pIceCandidatePair->pLocalCandidate->pTurnServer == NULL ) )
        {
            result = ICE_RESULT_INVALID_CANDIDATE;
        }
    }

    if( result == ICE_RESULT_OK )
    {
        if( ( pIceCandidatePair->pLocalCandidate->pTurnServer->longTermPasswordLength == 0 ) ||
            ( pIceCandidatePair->pLocalCandidate->pTurnServer->realmLength == 0 ) ||
            ( pIceCandidatePair->pLocalCandidate->pTurnServer->nonceLength == 0 ) )
        {
            result = ICE_RESULT_INVALID_CANDIDATE_CREDENTIAL;
        }
    }

    if( result == ICE_RESULT_OK )
    {
        stunHeader.messageType = STUN_MESSAGE_TYPE_CREATE_PERMISSION_REQUEST;
        stunHeader.pTransactionId = &( pIceCandidatePair->transactionId[ 0 ] );

        stunResult = StunSerializer_Init( &( stunCtx ),
                                          pStunMessageBuffer,
                                          *pStunMessageBufferLength,
                                          &( stunHeader ) );

        if( stunResult != STUN_RESULT_OK )
        {
            result = ICE_RESULT_STUN_ERROR;
        }
    }

    if( result == ICE_RESULT_OK )
    {
        stunResult = StunSerializer_AddAttributeAddress( &( stunCtx ),
                                                         &( pIceCandidatePair->pRemoteCandidate->endpoint.transportAddress ),
                                                         STUN_ATTRIBUTE_TYPE_XOR_PEER_ADDRESS );

        if( stunResult != STUN_RESULT_OK )
        {
            result = ICE_RESULT_STUN_ERROR_ADD_XOR_PEER_ADDRESS;
        }
    }

    if( result == ICE_RESULT_OK )
    {
        stunResult = StunSerializer_AddAttributeUsername( &( stunCtx ),
                                                          &( pIceCandidatePair->pLocalCandidate->pTurnServer->userName[ 0 ] ),
                                                          pIceCandidatePair->pLocalCandidate->pTurnServer->userNameLength );

        if( stunResult != STUN_RESULT_OK )
        {
            result = ICE_RESULT_STUN_ERROR_ADD_USERNAME;
        }
    }

    if( result == ICE_RESULT_OK )
    {
        stunResult = StunSerializer_AddAttributeRealm( &( stunCtx ),
                                                       &( pIceCandidatePair->pLocalCandidate->pTurnServer->realm[ 0 ] ),
                                                       pIceCandidatePair->pLocalCandidate->pTurnServer->realmLength );

        if( stunResult != STUN_RESULT_OK )
        {
            result = ICE_RESULT_STUN_ERROR_ADD_REALM;
        }
    }

    if( result == ICE_RESULT_OK )
    {
        stunResult = StunSerializer_AddAttributeNonce( &( stunCtx ),
                                                       &( pIceCandidatePair->pLocalCandidate->pTurnServer->nonce[ 0 ] ),
                                                       pIceCandidatePair->pLocalCandidate->pTurnServer->nonceLength );

        if( stunResult != STUN_RESULT_OK )
        {
            result = ICE_RESULT_STUN_ERROR_ADD_NONCE;
        }
    }

    if( result == ICE_RESULT_OK )
    {
        result = Ice_FinalizeStunPacket( pContext,
                                         &( stunCtx ),
                                         &( pIceCandidatePair->pLocalCandidate->pTurnServer->longTermPassword[ 0 ] ),
                                         pIceCandidatePair->pLocalCandidate->pTurnServer->longTermPasswordLength,
                                         pStunMessageBufferLength );
    }

    return result;
}

/*----------------------------------------------------------------------------*/

/* CreateRequestForChannelBind - This API creates Stun Packet for
 * TURN channel bind.
 */
IceResult_t Ice_CreateChannelBindRequest( IceContext_t * pContext,
                                          IceCandidatePair_t * pIceCandidatePair,
                                          uint8_t * pStunMessageBuffer,
                                          size_t * pStunMessageBufferLength )
{
    IceResult_t result = ICE_RESULT_OK;
    StunContext_t stunCtx;
    StunHeader_t stunHeader;
    StunResult_t stunResult = STUN_RESULT_OK;

    if( ( pIceCandidatePair->pLocalCandidate == NULL ) ||
        ( pIceCandidatePair->pRemoteCandidate == NULL ) )
    {
        result = ICE_RESULT_BAD_PARAM;
    }

    if( result == ICE_RESULT_OK )
    {
        if( ( pIceCandidatePair->pLocalCandidate->candidateType != ICE_CANDIDATE_TYPE_RELAY ) ||
            ( pIceCandidatePair->pLocalCandidate->pTurnServer == NULL ) )
        {
            result = ICE_RESULT_INVALID_CANDIDATE;
        }
    }

    if( result == ICE_RESULT_OK )
    {
        if( ( pIceCandidatePair->pLocalCandidate->pTurnServer->longTermPasswordLength == 0 ) ||
            ( pIceCandidatePair->pLocalCandidate->pTurnServer->realmLength == 0 ) ||
            ( pIceCandidatePair->pLocalCandidate->pTurnServer->nonceLength == 0 ) )
        {
            result = ICE_RESULT_INVALID_CANDIDATE_CREDENTIAL;
        }
    }

    if( result == ICE_RESULT_OK )
    {
        stunHeader.messageType = STUN_MESSAGE_TYPE_CHANNEL_BIND_REQUEST;
        stunHeader.pTransactionId = &( pIceCandidatePair->transactionId[ 0 ] );

        stunResult = StunSerializer_Init( &( stunCtx ),
                                          pStunMessageBuffer,
                                          *pStunMessageBufferLength,
                                          &( stunHeader ) );

        if( stunResult != STUN_RESULT_OK )
        {
            result = ICE_RESULT_STUN_ERROR;
        }
    }

    if( result == ICE_RESULT_OK )
    {
        stunResult = StunSerializer_AddAttributeAddress( &( stunCtx ),
                                                         &( pIceCandidatePair->pRemoteCandidate->endpoint.transportAddress ),
                                                         STUN_ATTRIBUTE_TYPE_XOR_PEER_ADDRESS );

        if( stunResult != STUN_RESULT_OK )
        {
            result = ICE_RESULT_STUN_ERROR_ADD_XOR_PEER_ADDRESS;
        }
    }

    if( result == ICE_RESULT_OK )
    {
        stunResult = StunSerializer_AddAttributeChannelNumber( &( stunCtx ),
                                                               pIceCandidatePair->turnChannelNumber );

        if( stunResult != STUN_RESULT_OK )
        {
            result = ICE_RESULT_STUN_ERROR_ADD_CHANNEL_NUMBER;
        }
    }

    if( result == ICE_RESULT_OK )
    {
        stunResult = StunSerializer_AddAttributeUsername( &( stunCtx ),
                                                          &( pIceCandidatePair->pLocalCandidate->pTurnServer->userName[ 0 ] ),
                                                          pIceCandidatePair->pLocalCandidate->pTurnServer->userNameLength );

        if( stunResult != STUN_RESULT_OK )
        {
            result = ICE_RESULT_STUN_ERROR_ADD_USERNAME;
        }
    }

    if( result == ICE_RESULT_OK )
    {
        stunResult = StunSerializer_AddAttributeRealm( &( stunCtx ),
                                                       &( pIceCandidatePair->pLocalCandidate->pTurnServer->realm[ 0 ] ),
                                                       pIceCandidatePair->pLocalCandidate->pTurnServer->realmLength );

        if( stunResult != STUN_RESULT_OK )
        {
            result = ICE_RESULT_STUN_ERROR_ADD_REALM;
        }
    }

    if( result == ICE_RESULT_OK )
    {
        stunResult = StunSerializer_AddAttributeNonce( &( stunCtx ),
                                                       &( pIceCandidatePair->pLocalCandidate->pTurnServer->nonce[ 0 ] ),
                                                       pIceCandidatePair->pLocalCandidate->pTurnServer->nonceLength );

        if( stunResult != STUN_RESULT_OK )
        {
            result = ICE_RESULT_STUN_ERROR_ADD_NONCE;
        }
    }

    if( result == ICE_RESULT_OK )
    {
        result = Ice_FinalizeStunPacket( pContext,
                                         &( stunCtx ),
                                         &( pIceCandidatePair->pLocalCandidate->pTurnServer->longTermPassword[ 0 ] ),
                                         pIceCandidatePair->pLocalCandidate->pTurnServer->longTermPasswordLength,
                                         pStunMessageBufferLength );
    }

    return result;
}

/*----------------------------------------------------------------------------*/

/* Ice_DeserializeStunPacket - This API deserializes a received STUN packet. */
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

                case STUN_ATTRIBUTE_TYPE_XOR_RELAYED_ADDRESS:
                {
                    stunResult = StunDeserializer_ParseAttributeAddress( pStunCtx,
                                                                         &( stunAttribute ),
                                                                         &( pDeserializedPacketInfo->relayTransportAddress ) );
                }
                break;

                case STUN_ATTRIBUTE_TYPE_XOR_MAPPED_ADDRESS:
                {
                    stunResult = StunDeserializer_ParseAttributeAddress( pStunCtx,
                                                                         &( stunAttribute ),
                                                                         &( pDeserializedPacketInfo->peerTransportAddress ) );
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

                case STUN_ATTRIBUTE_TYPE_NONCE:
                {
                    pDeserializedPacketInfo->nonceLength = stunAttribute.attributeValueLength;
                    pDeserializedPacketInfo->pNonce = stunAttribute.pAttributeValue;
                }
                break;

                case STUN_ATTRIBUTE_TYPE_REALM:
                {
                    pDeserializedPacketInfo->realmLength = stunAttribute.attributeValueLength;
                    pDeserializedPacketInfo->pRealm = stunAttribute.pAttributeValue;
                }
                break;

                case STUN_ATTRIBUTE_TYPE_LIFETIME:
                {
                    stunResult = StunDeserializer_ParseAttributeLifetime( pStunCtx,
                                                                          &( stunAttribute ),
                                                                          &( pDeserializedPacketInfo->lifetimeSeconds ) );
                }
                break;

                default:
                    break;
            }
        }
    }

    if( ( stunResult != STUN_RESULT_NO_MORE_ATTRIBUTE_FOUND ) && ( result == ICE_HANDLE_STUN_PACKET_RESULT_OK ) )
    {
        result = ICE_HANDLE_STUN_PACKET_RESULT_DESERIALIZE_ERROR;
    }

    return result;
}

/*----------------------------------------------------------------------------*/

IceHandleStunPacketResult_t Ice_HandleStunBindingRequest( IceContext_t * pContext,
                                                          StunContext_t * pStunCtx,
                                                          const IceCandidate_t * pLocalCandidate,
                                                          const IceEndpoint_t * pRemoteCandidateEndpoint,
                                                          IceCandidatePair_t ** ppIceCandidatePair )
{
    IceResult_t iceResult = ICE_RESULT_OK;
    IceHandleStunPacketResult_t handleStunPacketResult = ICE_HANDLE_STUN_PACKET_RESULT_OK;
    IceStunDeserializedPacketInfo_t deserializePacketInfo;
    IceCandidatePair_t * pIceCandidatePair = NULL;
    IceRemoteCandidateInfo_t remoteCandidateInfo;
    size_t i;

    handleStunPacketResult = Ice_DeserializeStunPacket( pContext,
                                                        pStunCtx,
                                                        pContext->creds.pLocalPassword,
                                                        pContext->creds.localPasswordLength,
                                                        &( deserializePacketInfo ) );

    if( handleStunPacketResult == ICE_HANDLE_STUN_PACKET_RESULT_OK )
    {
        if( deserializePacketInfo.errorCode != 0 )
        {
            handleStunPacketResult = ICE_HANDLE_STUN_PACKET_RESULT_NON_ZERO_ERROR_CODE;
        }
    }

    if( handleStunPacketResult == ICE_HANDLE_STUN_PACKET_RESULT_OK )
    {
        if( pLocalCandidate->candidateType != ICE_CANDIDATE_TYPE_RELAY )
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

                iceResult = Ice_AddRemoteCandidate( pContext,
                                                    &( remoteCandidateInfo ) );
            }

            if( iceResult == ICE_RESULT_OK )
            {
                for( i = 0; i < pContext->numCandidatePairs; i++ )
                {
                    if( ( Ice_IsSameTransportAddress( &( pContext->pCandidatePairs[ i ].pLocalCandidate->endpoint.transportAddress ),
                                                      &( pLocalCandidate->endpoint.transportAddress ) ) == 1 ) &&
                        ( Ice_IsSameTransportAddress( &( pContext->pCandidatePairs[ i ].pRemoteCandidate->endpoint.transportAddress ),
                                                      &( pRemoteCandidateEndpoint->transportAddress ) ) == 1 ) )
                    {
                        pIceCandidatePair = &( pContext->pCandidatePairs[ i ] );
                        break;
                    }
                }
            }
        }
        else
        {
            pIceCandidatePair = *ppIceCandidatePair;
        }
    }

    if( handleStunPacketResult == ICE_HANDLE_STUN_PACKET_RESULT_OK )
    {
        if( pIceCandidatePair == NULL )
        {
            handleStunPacketResult = ICE_HANDLE_STUN_PACKET_RESULT_CANDIDATE_PAIR_NOT_FOUND;
        }
    }

    if( handleStunPacketResult == ICE_HANDLE_STUN_PACKET_RESULT_OK )
    {
        /* Received a connectivity check request from the remote candidate. */
        pIceCandidatePair->connectivityCheckFlags |= ICE_STUN_REQUEST_RECEIVED_FLAG;

        if( pContext->isControlling == 0 )
        {
            /* Controlled agent. */
            if( deserializePacketInfo.useCandidateFlag == 1 )
            {
                pIceCandidatePair->state = ICE_CANDIDATE_PAIR_STATE_NOMINATED;
            }

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

                /* Would the 4-way handshake be complete after sending the response? */
                if( ICE_STUN_CONNECTIVITY_CHECK_SUCCESSFUL( pIceCandidatePair->connectivityCheckFlags ) )
                {
                    if( pIceCandidatePair->state == ICE_CANDIDATE_PAIR_STATE_NOMINATED )
                    {
                        pIceCandidatePair->state = ICE_CANDIDATE_PAIR_STATE_SUCCEEDED;
                        pContext->pNominatedPair = pIceCandidatePair;
                        ReleaseOtherCandidates( pContext, pIceCandidatePair );
                    }
                    else
                    {
                        pIceCandidatePair->state = ICE_CANDIDATE_PAIR_STATE_VALID;
                    }
                }
            }
        }
        else
        {
            /* Controlling agent. */
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

                /* Would the 4-way handshake be complete after sending the response? */
                if( ICE_STUN_CONNECTIVITY_CHECK_SUCCESSFUL( pIceCandidatePair->connectivityCheckFlags ) )
                {
                    /* If we have not yet nominated a pair, we nominate this
                     * pair. The application would need to send a nomination
                     * request in addition to the response for the current
                     * request. */
                    if( pContext->pNominatedPair == NULL )
                    {
                        pIceCandidatePair->state = ICE_CANDIDATE_PAIR_STATE_NOMINATED;
                        pContext->pNominatedPair = pIceCandidatePair;

                        /* Generate the Transaction ID to be used in the
                         * nomination process. */
                        iceResult = pContext->cryptoFunctions.randomFxn( &( pIceCandidatePair->transactionId[ 0 ] ),
                                                                         STUN_HEADER_TRANSACTION_ID_LENGTH );
                        if( iceResult != ICE_RESULT_OK )
                        {
                            handleStunPacketResult = ICE_HANDLE_STUN_PACKET_RESULT_RANDOM_ERROR_CODE;
                        }
                        else
                        {
                            handleStunPacketResult = ICE_HANDLE_STUN_PACKET_RESULT_SEND_RESPONSE_AND_START_NOMINATION;
                        }
                    }
                }
            }
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
                                                               IceCandidate_t * pLocalCandidate )
{
    size_t i;
    IceResult_t iceResult = ICE_RESULT_OK;
    IceHandleStunPacketResult_t handleStunPacketResult = ICE_HANDLE_STUN_PACKET_RESULT_OK;
    IceStunDeserializedPacketInfo_t deserializePacketInfo;

    handleStunPacketResult = Ice_DeserializeStunPacket( pContext,
                                                        pStunCtx,
                                                        NULL,
                                                        0,
                                                        &( deserializePacketInfo ) );

    if( handleStunPacketResult == ICE_HANDLE_STUN_PACKET_RESULT_OK )
    {
        if( deserializePacketInfo.errorCode != 0 )
        {
            handleStunPacketResult = ICE_HANDLE_STUN_PACKET_RESULT_NON_ZERO_ERROR_CODE;
        }
    }

    if( handleStunPacketResult == ICE_HANDLE_STUN_PACKET_RESULT_OK )
    {
        if( ( deserializePacketInfo.peerTransportAddress.family != STUN_ADDRESS_IPv4 ) &&
            ( deserializePacketInfo.peerTransportAddress.family != STUN_ADDRESS_IPv6 ) )
        {
            handleStunPacketResult = ICE_HANDLE_STUN_PACKET_RESULT_INVALID_FAMILY_TYPE;
        }
    }

    if( handleStunPacketResult == ICE_HANDLE_STUN_PACKET_RESULT_OK )
    {
        if( pLocalCandidate->candidateType != ICE_CANDIDATE_TYPE_SERVER_REFLEXIVE )
        {
            handleStunPacketResult = ICE_HANDLE_STUN_PACKET_RESULT_INVALID_CANDIDATE_TYPE;
        }
    }

    if( handleStunPacketResult == ICE_HANDLE_STUN_PACKET_RESULT_OK )
    {
        /* Regenerate Transaction ID for next request. */
        iceResult = pContext->cryptoFunctions.randomFxn( &( pLocalCandidate->transactionId[ 0 ] ),
                                                         STUN_HEADER_TRANSACTION_ID_LENGTH );
        if( iceResult != ICE_RESULT_OK )
        {
            handleStunPacketResult = ICE_HANDLE_STUN_PACKET_RESULT_RANDOM_ERROR_CODE;
        }
    }

    if( handleStunPacketResult == ICE_HANDLE_STUN_PACKET_RESULT_OK )
    {
        memcpy( &( pLocalCandidate->endpoint.transportAddress ),
                &( deserializePacketInfo.peerTransportAddress ),
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

    return handleStunPacketResult;
}

/*----------------------------------------------------------------------------*/

IceHandleStunPacketResult_t Ice_HandleConnectivityCheckResponse( IceContext_t * pContext,
                                                                 StunContext_t * pStunCtx,
                                                                 const StunHeader_t * pStunHeader,
                                                                 const IceCandidate_t * pLocalCandidate,
                                                                 const IceEndpoint_t * pRemoteCandidateEndpoint,
                                                                 IceCandidatePair_t ** ppIceCandidatePair )
{
    IceResult_t iceResult = ICE_RESULT_OK;
    IceHandleStunPacketResult_t handleStunPacketResult = ICE_HANDLE_STUN_PACKET_RESULT_OK;
    IceStunDeserializedPacketInfo_t deserializePacketInfo;
    IceCandidatePair_t * pIceCandidatePair = NULL;
    IceResult_t result = ICE_RESULT_OK;
    size_t i;

    handleStunPacketResult = Ice_DeserializeStunPacket( pContext,
                                                        pStunCtx,
                                                        pContext->creds.pRemotePassword,
                                                        pContext->creds.remotePasswordLength,
                                                        &( deserializePacketInfo ) );

    if( handleStunPacketResult == ICE_HANDLE_STUN_PACKET_RESULT_OK )
    {
        if( deserializePacketInfo.errorCode != 0 )
        {
            handleStunPacketResult = ICE_HANDLE_STUN_PACKET_RESULT_NON_ZERO_ERROR_CODE;
        }
    }

    if( handleStunPacketResult == ICE_HANDLE_STUN_PACKET_RESULT_OK )
    {
        if( pLocalCandidate->candidateType != ICE_CANDIDATE_TYPE_RELAY )
        {
            for( i = 0; i < pContext->numCandidatePairs; i++ )
            {
                if( ( Ice_IsSameTransportAddress( &( pContext->pCandidatePairs[ i ].pLocalCandidate->endpoint.transportAddress ),
                                                  &( pLocalCandidate->endpoint.transportAddress ) ) == 1 ) &&
                    ( Ice_IsSameTransportAddress( &( pContext->pCandidatePairs[ i ].pRemoteCandidate->endpoint.transportAddress ),
                                                  &( pRemoteCandidateEndpoint->transportAddress ) ) == 1 ) )
                {
                    pIceCandidatePair = &( pContext->pCandidatePairs[ i ] );
                    break;
                }
            }
        }
        else
        {
            pIceCandidatePair = *ppIceCandidatePair;
        }
    }

    if( handleStunPacketResult == ICE_HANDLE_STUN_PACKET_RESULT_OK )
    {
        if( pIceCandidatePair == NULL )
        {
            handleStunPacketResult = ICE_HANDLE_STUN_PACKET_RESULT_CANDIDATE_PAIR_NOT_FOUND;
        }
    }

    if( handleStunPacketResult == ICE_HANDLE_STUN_PACKET_RESULT_OK )
    {
        if( memcmp( &( pIceCandidatePair->transactionId[ 0 ] ),
                    pStunHeader->pTransactionId,
                    STUN_HEADER_TRANSACTION_ID_LENGTH ) != 0 )
        {
            /* Dropping response packet because transaction id does not match.*/
            handleStunPacketResult = ICE_HANDLE_STUN_PACKET_RESULT_MATCHING_TRANSACTION_ID_NOT_FOUND;
        }
    }

    if( handleStunPacketResult == ICE_HANDLE_STUN_PACKET_RESULT_OK )
    {
        /* Regenerate Transaction ID for next request. */
        result = pContext->cryptoFunctions.randomFxn( &( pIceCandidatePair->transactionId[ 0 ] ),
                                                      STUN_HEADER_TRANSACTION_ID_LENGTH );
        if( result != ICE_RESULT_OK )
        {
            handleStunPacketResult = ICE_HANDLE_STUN_PACKET_RESULT_RANDOM_ERROR_CODE;
        }
    }

    if( handleStunPacketResult == ICE_HANDLE_STUN_PACKET_RESULT_OK )
    {
        pIceCandidatePair->connectivityCheckFlags |= ICE_STUN_RESPONSE_RECEIVED_FLAG;

        if( pContext->isControlling == 0 )
        {
            /* Controlled agent. */
            /* Is the 4-way connectivity check successful after receiving
             * the current response? */
            if( ICE_STUN_CONNECTIVITY_CHECK_SUCCESSFUL( pIceCandidatePair->connectivityCheckFlags ) )
            {
                if( pIceCandidatePair->state == ICE_CANDIDATE_PAIR_STATE_NOMINATED )
                {
                    pIceCandidatePair->state = ICE_CANDIDATE_PAIR_STATE_SUCCEEDED;
                    pContext->pSelectedPair = pIceCandidatePair;
                    handleStunPacketResult = ICE_HANDLE_STUN_PACKET_RESULT_CANDIDATE_PAIR_READY;

                    ReleaseOtherCandidates( pContext, pIceCandidatePair );
                }
                else
                {
                    pIceCandidatePair->state = ICE_CANDIDATE_PAIR_STATE_VALID;
                    handleStunPacketResult = ICE_HANDLE_STUN_PACKET_RESULT_VALID_CANDIDATE_PAIR;
                }
            }
        }
        else
        {
            /* Controlling agent. */
            /* Is the 4-way connectivity check successful after receiving
             * the current response? */
            if( ICE_STUN_CONNECTIVITY_CHECK_SUCCESSFUL( pIceCandidatePair->connectivityCheckFlags ) )
            {
                if( pIceCandidatePair->state == ICE_CANDIDATE_PAIR_STATE_NOMINATED )
                {
                    pIceCandidatePair->state = ICE_CANDIDATE_PAIR_STATE_SUCCEEDED;
                    pContext->pSelectedPair = pIceCandidatePair;
                    handleStunPacketResult = ICE_HANDLE_STUN_PACKET_RESULT_CANDIDATE_PAIR_READY;

                    ReleaseOtherCandidates( pContext, pIceCandidatePair );
                }
                else
                {
                    pContext->pNominatedPair = pIceCandidatePair;
                    pIceCandidatePair->state = ICE_CANDIDATE_PAIR_STATE_NOMINATED;

                    /* Generate the Transaction ID to be used in the
                     * nomination process. */
                    iceResult = pContext->cryptoFunctions.randomFxn( &( pIceCandidatePair->transactionId[ 0 ] ),
                                                                     STUN_HEADER_TRANSACTION_ID_LENGTH );
                    if( iceResult != ICE_RESULT_OK )
                    {
                        handleStunPacketResult = ICE_HANDLE_STUN_PACKET_RESULT_RANDOM_ERROR_CODE;
                    }
                    else
                    {
                        handleStunPacketResult = ICE_HANDLE_STUN_PACKET_RESULT_START_NOMINATION;
                    }
                }
            }
        }

        if( !ICE_STUN_CONNECTIVITY_CHECK_SUCCESSFUL( pIceCandidatePair->connectivityCheckFlags ) )
        {
            if( deserializePacketInfo.peerTransportAddress.family != 0 )
            {
                if( ( pIceCandidatePair->pLocalCandidate->candidateType == ICE_CANDIDATE_TYPE_SERVER_REFLEXIVE ) &&
                    ( pIceCandidatePair->pRemoteCandidate->candidateType == ICE_CANDIDATE_TYPE_SERVER_REFLEXIVE ) &&
                    ( Ice_IsSameIpAddress( &( deserializePacketInfo.peerTransportAddress ),
                                           &( pIceCandidatePair->pLocalCandidate->endpoint.transportAddress ) ) == 0 ) )
                {
                    pIceCandidatePair->pLocalCandidate->candidateType = ICE_CANDIDATE_TYPE_PEER_REFLEXIVE;

                    memcpy( &( pIceCandidatePair->pLocalCandidate->endpoint.transportAddress ),
                            &( deserializePacketInfo.peerTransportAddress ),
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

    if( pIceCandidatePair != NULL )
    {
        *ppIceCandidatePair = pIceCandidatePair;
    }

    return handleStunPacketResult;
}

/*----------------------------------------------------------------------------*/

IceHandleStunPacketResult_t Ice_HandleTurnAllocateSuccessResponse( IceContext_t * pContext,
                                                                   StunContext_t * pStunCtx,
                                                                   const StunHeader_t * pStunHeader,
                                                                   IceCandidate_t * pLocalCandidate,
                                                                   uint64_t currentTimeSeconds )
{
    IceHandleStunPacketResult_t handleStunPacketResult = ICE_HANDLE_STUN_PACKET_RESULT_OK;
    IceStunDeserializedPacketInfo_t deserializePacketInfo;
    IceResult_t iceResult = ICE_RESULT_OK;
    size_t i;

    if( ( pLocalCandidate->candidateType != ICE_CANDIDATE_TYPE_RELAY ) ||
        ( pLocalCandidate->pTurnServer == NULL ) ||
        ( pLocalCandidate->state != ICE_CANDIDATE_STATE_ALLOCATING ) )
    {
        handleStunPacketResult = ICE_HANDLE_STUN_PACKET_RESULT_INVALID_RESPONSE;
    }

    if( handleStunPacketResult == ICE_HANDLE_STUN_PACKET_RESULT_OK )
    {
        if( memcmp( pStunHeader->pTransactionId,
                    &( pLocalCandidate->transactionId[ 0 ] ),
                    STUN_HEADER_TRANSACTION_ID_LENGTH ) != 0 )
        {
            handleStunPacketResult = ICE_HANDLE_STUN_PACKET_RESULT_DROP_PACKET;
        }
    }

    if( handleStunPacketResult == ICE_HANDLE_STUN_PACKET_RESULT_OK )
    {
        handleStunPacketResult = Ice_DeserializeStunPacket( pContext,
                                                            pStunCtx,
                                                            &( pLocalCandidate->pTurnServer->longTermPassword[ 0 ] ),
                                                            pLocalCandidate->pTurnServer->longTermPasswordLength,
                                                            &( deserializePacketInfo ) );
    }

    if( handleStunPacketResult == ICE_HANDLE_STUN_PACKET_RESULT_OK )
    {
        if( deserializePacketInfo.errorCode != 0 )
        {
            handleStunPacketResult = ICE_HANDLE_STUN_PACKET_RESULT_NON_ZERO_ERROR_CODE;
        }
    }

    if( handleStunPacketResult == ICE_HANDLE_STUN_PACKET_RESULT_OK )
    {
        /* Regenerate Transaction ID for next request. */
        iceResult = pContext->cryptoFunctions.randomFxn( &( pLocalCandidate->transactionId[ 0 ] ),
                                                         STUN_HEADER_TRANSACTION_ID_LENGTH );
        if( iceResult != ICE_RESULT_OK )
        {
            handleStunPacketResult = ICE_HANDLE_STUN_PACKET_RESULT_RANDOM_ERROR_CODE;
        }
    }

    if( handleStunPacketResult == ICE_HANDLE_STUN_PACKET_RESULT_OK )
    {
        memcpy( &( pLocalCandidate->endpoint.transportAddress ),
                &( deserializePacketInfo.relayTransportAddress ),
                sizeof( IceTransportAddress_t ) );
        pLocalCandidate->endpoint.isPointToPoint = 0;
        pLocalCandidate->pTurnServer->nextAvailableTurnChannelNumber = ICE_DEFAULT_TURN_CHANNEL_NUMBER_MIN;
        pLocalCandidate->pTurnServer->turnAllocationExpirationTimeSeconds = currentTimeSeconds + deserializePacketInfo.lifetimeSeconds;

        pLocalCandidate->state = ICE_CANDIDATE_STATE_VALID;

        for( i = 0; ( i < pContext->numRemoteCandidates ) && ( iceResult == ICE_RESULT_OK ); i++ )
        {
            iceResult = Ice_AddCandidatePair( pContext,
                                              pLocalCandidate,
                                              &( pContext->pRemoteCandidates[ i ] ) );
        }

        handleStunPacketResult = ICE_HANDLE_STUN_PACKET_RESULT_UPDATED_RELAY_CANDIDATE_ADDRESS;
    }

    return handleStunPacketResult;
}

/*----------------------------------------------------------------------------*/

IceHandleStunPacketResult_t Ice_HandleTurnAllocateErrorResponse( IceContext_t * pContext,
                                                                 StunContext_t * pStunCtx,
                                                                 const StunHeader_t * pStunHeader,
                                                                 IceCandidate_t * pLocalCandidate )
{
    IceResult_t iceResult = ICE_RESULT_OK;
    IceHandleStunPacketResult_t handleStunPacketResult = ICE_HANDLE_STUN_PACKET_RESULT_OK;
    IceStunDeserializedPacketInfo_t deserializePacketInfo;

    if( ( pLocalCandidate->candidateType != ICE_CANDIDATE_TYPE_RELAY ) ||
        ( pLocalCandidate->pTurnServer == NULL ) ||
        ( pLocalCandidate->state != ICE_CANDIDATE_STATE_ALLOCATING ) )
    {
        handleStunPacketResult = ICE_HANDLE_STUN_PACKET_RESULT_INVALID_RESPONSE;
    }

    if( handleStunPacketResult == ICE_HANDLE_STUN_PACKET_RESULT_OK )
    {
        if( memcmp( pStunHeader->pTransactionId,
                    &( pLocalCandidate->transactionId[ 0 ] ),
                    STUN_HEADER_TRANSACTION_ID_LENGTH ) != 0 )
        {
            handleStunPacketResult = ICE_HANDLE_STUN_PACKET_RESULT_DROP_PACKET;
        }
    }

    if( handleStunPacketResult == ICE_HANDLE_STUN_PACKET_RESULT_OK )
    {
        handleStunPacketResult = Ice_DeserializeStunPacket( pContext,
                                                            pStunCtx,
                                                            &( pLocalCandidate->pTurnServer->longTermPassword[ 0 ] ),
                                                            pLocalCandidate->pTurnServer->longTermPasswordLength,
                                                            &( deserializePacketInfo ) );
    }

    if( handleStunPacketResult == ICE_HANDLE_STUN_PACKET_RESULT_OK )
    {
        /* Regenerate Transaction ID for next request. */
        iceResult = pContext->cryptoFunctions.randomFxn( &( pLocalCandidate->transactionId[ 0 ] ),
                                                         STUN_HEADER_TRANSACTION_ID_LENGTH );
        if( iceResult != ICE_RESULT_OK )
        {
            handleStunPacketResult = ICE_HANDLE_STUN_PACKET_RESULT_RANDOM_ERROR_CODE;
        }
    }

    if( handleStunPacketResult == ICE_HANDLE_STUN_PACKET_RESULT_OK )
    {
        switch( deserializePacketInfo.errorCode )
        {
            case STUN_ATTRIBUTE_ERROR_CODE_VALUE_SUCCESS:
            {
                handleStunPacketResult = ICE_HANDLE_STUN_PACKET_RESULT_INVALID_RESPONSE;
            }
            break;

            case STUN_ATTRIBUTE_ERROR_CODE_VALUE_STALE_NONCE:
            case STUN_ATTRIBUTE_ERROR_CODE_VALUE_UNAUTHORIZED:
            {
                handleStunPacketResult = UpdateIceServerInfo( pContext,
                                                              pLocalCandidate,
                                                              &( deserializePacketInfo ) );

                if( handleStunPacketResult == ICE_HANDLE_STUN_PACKET_RESULT_OK )
                {
                    handleStunPacketResult = ICE_HANDLE_STUN_PACKET_RESULT_SEND_ALLOCATION_REQUEST;
                }
            }
            break;

            default:
            {
                handleStunPacketResult = ICE_HANDLE_STUN_PACKET_RESULT_ALLOCATE_UNKNOWN_ERROR;
            }
            break;
        }
    }

    return handleStunPacketResult;
}

/*----------------------------------------------------------------------------*/

IceHandleStunPacketResult_t Ice_HandleTurnCreatePermissionSuccessResponse( IceContext_t * pContext,
                                                                           StunContext_t * pStunCtx,
                                                                           const StunHeader_t * pStunHeader,
                                                                           const IceCandidate_t * pLocalCandidate,
                                                                           uint64_t currentTimeSeconds,
                                                                           IceCandidatePair_t ** ppIceCandidatePair )
{
    size_t i;
    IceResult_t iceResult = ICE_RESULT_OK;
    IceHandleStunPacketResult_t handleStunPacketResult = ICE_HANDLE_STUN_PACKET_RESULT_OK;
    IceStunDeserializedPacketInfo_t deserializePacketInfo;
    IceCandidatePair_t * pIceCandidatePair = NULL;

    if( ( pLocalCandidate->candidateType != ICE_CANDIDATE_TYPE_RELAY ) ||
        ( pLocalCandidate->pTurnServer == NULL ) )
    {
        handleStunPacketResult = ICE_HANDLE_STUN_PACKET_RESULT_UNEXPECTED_RESPONSE;
    }

    if( handleStunPacketResult == ICE_HANDLE_STUN_PACKET_RESULT_OK )
    {
        handleStunPacketResult = Ice_DeserializeStunPacket( pContext,
                                                            pStunCtx,
                                                            &( pLocalCandidate->pTurnServer->longTermPassword[ 0 ] ),
                                                            pLocalCandidate->pTurnServer->longTermPasswordLength,
                                                            &( deserializePacketInfo ) );
    }

    if( handleStunPacketResult == ICE_HANDLE_STUN_PACKET_RESULT_OK )
    {
        if( deserializePacketInfo.errorCode != 0 )
        {
            handleStunPacketResult = ICE_HANDLE_STUN_PACKET_RESULT_NON_ZERO_ERROR_CODE;
        }
    }

    if( handleStunPacketResult == ICE_HANDLE_STUN_PACKET_RESULT_OK )
    {
        for( i = 0; i < pContext->numCandidatePairs; i++ )
        {
            /* In TURN connection, the remote endpoint is always the TURN server.
             * We, therefore, have to compare the Transaction ID to get the
             * remote candidate. */
            if( memcmp( &( pContext->pCandidatePairs[ i ].transactionId[ 0 ] ),
                        pStunHeader->pTransactionId,
                        STUN_HEADER_TRANSACTION_ID_LENGTH ) == 0 )
            {
                pIceCandidatePair = &( pContext->pCandidatePairs[ i ] );
                break;
            }
        }

        if( pIceCandidatePair == NULL )
        {
            handleStunPacketResult = ICE_HANDLE_STUN_PACKET_RESULT_CANDIDATE_PAIR_NOT_FOUND;
        }
    }

    if( handleStunPacketResult == ICE_HANDLE_STUN_PACKET_RESULT_OK )
    {
        if( ( pIceCandidatePair->state != ICE_CANDIDATE_PAIR_STATE_CREATE_PERMISSION ) &&
            ( pIceCandidatePair->state != ICE_CANDIDATE_PAIR_STATE_SUCCEEDED ) )
        {
            handleStunPacketResult = ICE_HANDLE_STUN_PACKET_RESULT_UNEXPECTED_RESPONSE;
        }
    }

    if( handleStunPacketResult == ICE_HANDLE_STUN_PACKET_RESULT_OK )
    {
        pIceCandidatePair->turnPermissionExpirationSeconds = currentTimeSeconds + ICE_DEFAULT_TURN_PERMISSION_LIFETIME_SECONDS;

        /* Regenerate Transaction ID for next request. */
        iceResult = pContext->cryptoFunctions.randomFxn( &( pIceCandidatePair->transactionId[ 0 ] ),
                                                         STUN_HEADER_TRANSACTION_ID_LENGTH );
        if( iceResult != ICE_RESULT_OK )
        {
            handleStunPacketResult = ICE_HANDLE_STUN_PACKET_RESULT_RANDOM_ERROR_CODE;
        }
    }

    if( handleStunPacketResult == ICE_HANDLE_STUN_PACKET_RESULT_OK )
    {
        /* Once the candidate pair received create permission success response,
         * we continue to do channel binding. */
        pIceCandidatePair->state = ICE_CANDIDATE_PAIR_STATE_CHANNEL_BIND;

        handleStunPacketResult = ICE_HANDLE_STUN_PACKET_RESULT_SEND_CHANNEL_BIND_REQUEST;
    }

    if( pIceCandidatePair != NULL )
    {
        *ppIceCandidatePair = pIceCandidatePair;
    }

    return handleStunPacketResult;
}

/*----------------------------------------------------------------------------*/

IceHandleStunPacketResult_t Ice_HandleTurnCreatePermissionErrorResponse( IceContext_t * pContext,
                                                                         StunContext_t * pStunCtx,
                                                                         const StunHeader_t * pStunHeader,
                                                                         const IceCandidate_t * pLocalCandidate,
                                                                         IceCandidatePair_t ** ppIceCandidatePair )
{
    size_t i;
    IceResult_t iceResult = ICE_RESULT_OK;
    IceHandleStunPacketResult_t handleStunPacketResult = ICE_HANDLE_STUN_PACKET_RESULT_OK;
    IceStunDeserializedPacketInfo_t deserializePacketInfo;
    IceCandidatePair_t * pIceCandidatePair = NULL;

    if( ( pLocalCandidate->candidateType != ICE_CANDIDATE_TYPE_RELAY ) ||
        ( pLocalCandidate->pTurnServer == NULL ) )
    {
        handleStunPacketResult = ICE_HANDLE_STUN_PACKET_RESULT_UNEXPECTED_RESPONSE;
    }

    if( handleStunPacketResult == ICE_HANDLE_STUN_PACKET_RESULT_OK )
    {
        handleStunPacketResult = Ice_DeserializeStunPacket( pContext,
                                                            pStunCtx,
                                                            &( pLocalCandidate->pTurnServer->longTermPassword[ 0 ] ),
                                                            pLocalCandidate->pTurnServer->longTermPasswordLength,
                                                            &( deserializePacketInfo ) );
    }

    if( handleStunPacketResult == ICE_HANDLE_STUN_PACKET_RESULT_OK )
    {
        for( i = 0; i < pContext->numCandidatePairs; i++ )
        {
            /* In TURN connection, the remote endpoint is always the TURN server.
             * We, therefore, have to compare the Transaction ID to get the
             * remote candidate. */
            if( memcmp( &( pContext->pCandidatePairs[ i ].transactionId[ 0 ] ),
                        pStunHeader->pTransactionId,
                        STUN_HEADER_TRANSACTION_ID_LENGTH ) == 0 )
            {
                pIceCandidatePair = &( pContext->pCandidatePairs[ i ] );
                break;
            }
        }

        if( pIceCandidatePair == NULL )
        {
            handleStunPacketResult = ICE_HANDLE_STUN_PACKET_RESULT_CANDIDATE_PAIR_NOT_FOUND;
        }
    }

    if( handleStunPacketResult == ICE_HANDLE_STUN_PACKET_RESULT_OK )
    {
        if( pIceCandidatePair->state != ICE_CANDIDATE_PAIR_STATE_CREATE_PERMISSION )
        {
            handleStunPacketResult = ICE_HANDLE_STUN_PACKET_RESULT_UNEXPECTED_RESPONSE;
        }
    }

    if( handleStunPacketResult == ICE_HANDLE_STUN_PACKET_RESULT_OK )
    {
        /* This candidate pair failed to create permission. */
        pIceCandidatePair->state = ICE_CANDIDATE_PAIR_STATE_INVALID;

        /* Regenerate Transaction ID for next request. */
        iceResult = pContext->cryptoFunctions.randomFxn( &( pIceCandidatePair->transactionId[ 0 ] ),
                                                         STUN_HEADER_TRANSACTION_ID_LENGTH );
        if( iceResult != ICE_RESULT_OK )
        {
            handleStunPacketResult = ICE_HANDLE_STUN_PACKET_RESULT_RANDOM_ERROR_CODE;
        }
    }

    if( pIceCandidatePair != NULL )
    {
        *ppIceCandidatePair = pIceCandidatePair;
    }

    return handleStunPacketResult;
}

/*----------------------------------------------------------------------------*/

IceHandleStunPacketResult_t Ice_HandleTurnChannelBindSuccessResponse( IceContext_t * pContext,
                                                                      StunContext_t * pStunCtx,
                                                                      const StunHeader_t * pStunHeader,
                                                                      const IceCandidate_t * pLocalCandidate,
                                                                      IceCandidatePair_t ** ppIceCandidatePair )
{
    size_t i;
    IceResult_t iceResult = ICE_RESULT_OK;
    IceHandleStunPacketResult_t handleStunPacketResult = ICE_HANDLE_STUN_PACKET_RESULT_OK;
    IceStunDeserializedPacketInfo_t deserializePacketInfo;
    IceCandidatePair_t * pIceCandidatePair = NULL;

    if( ( pLocalCandidate->candidateType != ICE_CANDIDATE_TYPE_RELAY ) ||
        ( pLocalCandidate->pTurnServer == NULL ) )
    {
        handleStunPacketResult = ICE_HANDLE_STUN_PACKET_RESULT_UNEXPECTED_RESPONSE;
    }

    if( handleStunPacketResult == ICE_HANDLE_STUN_PACKET_RESULT_OK )
    {
        handleStunPacketResult = Ice_DeserializeStunPacket( pContext,
                                                            pStunCtx,
                                                            &( pLocalCandidate->pTurnServer->longTermPassword[ 0 ] ),
                                                            pLocalCandidate->pTurnServer->longTermPasswordLength,
                                                            &( deserializePacketInfo ) );
    }

    if( handleStunPacketResult == ICE_HANDLE_STUN_PACKET_RESULT_OK )
    {
        if( deserializePacketInfo.errorCode != 0 )
        {
            handleStunPacketResult = ICE_HANDLE_STUN_PACKET_RESULT_NON_ZERO_ERROR_CODE;
        }
    }

    if( handleStunPacketResult == ICE_HANDLE_STUN_PACKET_RESULT_OK )
    {
        for( i = 0; i < pContext->numCandidatePairs; i++ )
        {
            /* In TURN connection, the remote endpoint is always the TURN server.
             * We, therefore, have to compare the Transaction ID to get the
             * remote candidate. */
            if( memcmp( &( pContext->pCandidatePairs[ i ].transactionId[ 0 ] ),
                        pStunHeader->pTransactionId,
                        STUN_HEADER_TRANSACTION_ID_LENGTH ) == 0 )
            {
                pIceCandidatePair = &( pContext->pCandidatePairs[ i ] );
                break;
            }
        }

        if( pIceCandidatePair == NULL )
        {
            handleStunPacketResult = ICE_HANDLE_STUN_PACKET_RESULT_CANDIDATE_PAIR_NOT_FOUND;
        }
    }

    if( handleStunPacketResult == ICE_HANDLE_STUN_PACKET_RESULT_OK )
    {
        if( pIceCandidatePair->state != ICE_CANDIDATE_PAIR_STATE_CHANNEL_BIND )
        {
            handleStunPacketResult = ICE_HANDLE_STUN_PACKET_RESULT_UNEXPECTED_RESPONSE;
        }
    }


    if( handleStunPacketResult == ICE_HANDLE_STUN_PACKET_RESULT_OK )
    {
        /* Regenerate Transaction ID for next request. */
        iceResult = pContext->cryptoFunctions.randomFxn( &( pIceCandidatePair->transactionId[ 0 ] ),
                                                         STUN_HEADER_TRANSACTION_ID_LENGTH );
        if( iceResult != ICE_RESULT_OK )
        {
            handleStunPacketResult = ICE_HANDLE_STUN_PACKET_RESULT_RANDOM_ERROR_CODE;
        }
    }

    if( handleStunPacketResult == ICE_HANDLE_STUN_PACKET_RESULT_OK )
    {
        /*
         * Validates the candidate pair's selection status:
         * - If already selected: Updates state to succeeded
         * - If not selected: Triggers connectivity check
         */
        if( pContext->pSelectedPair == pIceCandidatePair )
        {
            pIceCandidatePair->state = ICE_CANDIDATE_PAIR_STATE_SUCCEEDED;
            handleStunPacketResult = ICE_HANDLE_STUN_PACKET_RESULT_FRESH_CHANNEL_BIND_COMPLETE;
        }
        else
        {
            pIceCandidatePair->state = ICE_CANDIDATE_PAIR_STATE_WAITING;
            handleStunPacketResult = ICE_HANDLE_STUN_PACKET_RESULT_SEND_CONNECTIVITY_CHECK_REQUEST;
        }
    }

    if( pIceCandidatePair != NULL )
    {
        *ppIceCandidatePair = pIceCandidatePair;
    }

    return handleStunPacketResult;
}

/*----------------------------------------------------------------------------*/

IceHandleStunPacketResult_t Ice_HandleTurnChannelBindErrorResponse( IceContext_t * pContext,
                                                                    StunContext_t * pStunCtx,
                                                                    const StunHeader_t * pStunHeader,
                                                                    const IceCandidate_t * pLocalCandidate,
                                                                    IceCandidatePair_t ** ppIceCandidatePair )
{
    size_t i;
    IceResult_t iceResult = ICE_RESULT_OK;
    IceHandleStunPacketResult_t handleStunPacketResult = ICE_HANDLE_STUN_PACKET_RESULT_OK;
    IceStunDeserializedPacketInfo_t deserializePacketInfo;
    IceCandidatePair_t * pIceCandidatePair = NULL;

    if( ( pLocalCandidate->candidateType != ICE_CANDIDATE_TYPE_RELAY ) ||
        ( pLocalCandidate->pTurnServer == NULL ) )
    {
        handleStunPacketResult = ICE_HANDLE_STUN_PACKET_RESULT_UNEXPECTED_RESPONSE;
    }

    if( handleStunPacketResult == ICE_HANDLE_STUN_PACKET_RESULT_OK )
    {
        handleStunPacketResult = Ice_DeserializeStunPacket( pContext,
                                                            pStunCtx,
                                                            &( pLocalCandidate->pTurnServer->longTermPassword[ 0 ] ),
                                                            pLocalCandidate->pTurnServer->longTermPasswordLength,
                                                            &( deserializePacketInfo ) );
    }

    if( handleStunPacketResult == ICE_HANDLE_STUN_PACKET_RESULT_OK )
    {
        for( i = 0; i < pContext->numCandidatePairs; i++ )
        {
            /* In TURN connection, the remote endpoint is always the TURN server.
             * We, therefore, have to compare the Transaction ID to get the
             * remote candidate. */
            if( memcmp( &( pContext->pCandidatePairs[ i ].transactionId[ 0 ] ),
                        pStunHeader->pTransactionId,
                        STUN_HEADER_TRANSACTION_ID_LENGTH ) == 0 )
            {
                pIceCandidatePair = &( pContext->pCandidatePairs[ i ] );
                break;
            }
        }

        if( pIceCandidatePair == NULL )
        {
            handleStunPacketResult = ICE_HANDLE_STUN_PACKET_RESULT_CANDIDATE_PAIR_NOT_FOUND;
        }
    }

    if( handleStunPacketResult == ICE_HANDLE_STUN_PACKET_RESULT_OK )
    {
        if( pIceCandidatePair->state != ICE_CANDIDATE_PAIR_STATE_CHANNEL_BIND )
        {
            handleStunPacketResult = ICE_HANDLE_STUN_PACKET_RESULT_UNEXPECTED_RESPONSE;
        }
    }

    if( handleStunPacketResult == ICE_HANDLE_STUN_PACKET_RESULT_OK )
    {
        /* This candidate pair failed to create TURN channel binding. */
        pIceCandidatePair->state = ICE_CANDIDATE_PAIR_STATE_INVALID;

        /* Regenerate Transaction ID for next request. */
        iceResult = pContext->cryptoFunctions.randomFxn( &( pIceCandidatePair->transactionId[ 0 ] ),
                                                         STUN_HEADER_TRANSACTION_ID_LENGTH );
        if( iceResult != ICE_RESULT_OK )
        {
            handleStunPacketResult = ICE_HANDLE_STUN_PACKET_RESULT_RANDOM_ERROR_CODE;
        }
    }

    if( pIceCandidatePair != NULL )
    {
        *ppIceCandidatePair = pIceCandidatePair;
    }

    return handleStunPacketResult;
}

/*----------------------------------------------------------------------------*/

IceHandleStunPacketResult_t Ice_HandleTurnRefreshSuccessResponse( IceContext_t * pContext,
                                                                  StunContext_t * pStunCtx,
                                                                  const StunHeader_t * pStunHeader,
                                                                  IceCandidate_t * pLocalCandidate,
                                                                  uint64_t currentTimeSeconds )
{
    IceResult_t iceResult = ICE_RESULT_OK;
    IceHandleStunPacketResult_t handleStunPacketResult = ICE_HANDLE_STUN_PACKET_RESULT_OK;
    IceStunDeserializedPacketInfo_t deserializePacketInfo;

    if( ( pLocalCandidate->candidateType != ICE_CANDIDATE_TYPE_RELAY ) ||
        ( pLocalCandidate->pTurnServer == NULL ) )
    {
        handleStunPacketResult = ICE_HANDLE_STUN_PACKET_RESULT_UNEXPECTED_RESPONSE;
    }

    if( handleStunPacketResult == ICE_HANDLE_STUN_PACKET_RESULT_OK )
    {
        if( memcmp( pStunHeader->pTransactionId,
                    &( pLocalCandidate->transactionId[ 0 ] ),
                    STUN_HEADER_TRANSACTION_ID_LENGTH ) != 0 )
        {
            handleStunPacketResult = ICE_HANDLE_STUN_PACKET_RESULT_DROP_PACKET;
        }
    }

    if( handleStunPacketResult == ICE_HANDLE_STUN_PACKET_RESULT_OK )
    {
        handleStunPacketResult = Ice_DeserializeStunPacket( pContext,
                                                            pStunCtx,
                                                            &( pLocalCandidate->pTurnServer->longTermPassword[ 0 ] ),
                                                            pLocalCandidate->pTurnServer->longTermPasswordLength,
                                                            &( deserializePacketInfo ) );
    }

    if( handleStunPacketResult == ICE_HANDLE_STUN_PACKET_RESULT_OK )
    {
        /* Regenerate Transaction ID for next request. */
        iceResult = pContext->cryptoFunctions.randomFxn( &( pLocalCandidate->transactionId[ 0 ] ),
                                                         STUN_HEADER_TRANSACTION_ID_LENGTH );
        if( iceResult != ICE_RESULT_OK )
        {
            handleStunPacketResult = ICE_HANDLE_STUN_PACKET_RESULT_RANDOM_ERROR_CODE;
        }
    }

    if( handleStunPacketResult == ICE_HANDLE_STUN_PACKET_RESULT_OK )
    {
        if( pLocalCandidate->state == ICE_CANDIDATE_STATE_RELEASING )
        {
            /* Set state to released regardless of the response we received. */
            pLocalCandidate->state = ICE_CANDIDATE_STATE_INVALID;
            handleStunPacketResult = ICE_HANDLE_STUN_PACKET_RESULT_TURN_SESSION_TERMINATED;
        }
    }

    if( handleStunPacketResult == ICE_HANDLE_STUN_PACKET_RESULT_OK )
    {
        /* Update the expiry time for this TURN session. */
        pLocalCandidate->pTurnServer->turnAllocationExpirationTimeSeconds = currentTimeSeconds + deserializePacketInfo.lifetimeSeconds;
        handleStunPacketResult = ICE_HANDLE_STUN_PACKET_RESULT_FRESH_COMPLETE;
    }

    return handleStunPacketResult;
}

/*----------------------------------------------------------------------------*/

IceHandleStunPacketResult_t Ice_HandleTurnRefreshErrorResponse( IceContext_t * pContext,
                                                                StunContext_t * pStunCtx,
                                                                const StunHeader_t * pStunHeader,
                                                                IceCandidate_t * pLocalCandidate )
{
    IceResult_t iceResult = ICE_RESULT_OK;
    IceHandleStunPacketResult_t handleStunPacketResult = ICE_HANDLE_STUN_PACKET_RESULT_OK;
    IceStunDeserializedPacketInfo_t deserializePacketInfo;

    if( ( pLocalCandidate->candidateType != ICE_CANDIDATE_TYPE_RELAY ) ||
        ( pLocalCandidate->pTurnServer == NULL ) )
    {
        handleStunPacketResult = ICE_HANDLE_STUN_PACKET_RESULT_UNEXPECTED_RESPONSE;
    }

    if( handleStunPacketResult == ICE_HANDLE_STUN_PACKET_RESULT_OK )
    {
        if( memcmp( pStunHeader->pTransactionId,
                    &( pLocalCandidate->transactionId[ 0 ] ),
                    STUN_HEADER_TRANSACTION_ID_LENGTH ) != 0 )
        {
            handleStunPacketResult = ICE_HANDLE_STUN_PACKET_RESULT_DROP_PACKET;
        }
    }

    if( handleStunPacketResult == ICE_HANDLE_STUN_PACKET_RESULT_OK )
    {
        handleStunPacketResult = Ice_DeserializeStunPacket( pContext,
                                                            pStunCtx,
                                                            &( pLocalCandidate->pTurnServer->longTermPassword[ 0 ] ),
                                                            pLocalCandidate->pTurnServer->longTermPasswordLength,
                                                            &( deserializePacketInfo ) );
    }

    if( handleStunPacketResult == ICE_HANDLE_STUN_PACKET_RESULT_OK )
    {
        /* Regenerate Transaction ID for next request. */
        iceResult = pContext->cryptoFunctions.randomFxn( &( pLocalCandidate->transactionId[ 0 ] ),
                                                         STUN_HEADER_TRANSACTION_ID_LENGTH );
        if( iceResult != ICE_RESULT_OK )
        {
            handleStunPacketResult = ICE_HANDLE_STUN_PACKET_RESULT_RANDOM_ERROR_CODE;
        }
    }

    if( handleStunPacketResult == ICE_HANDLE_STUN_PACKET_RESULT_OK )
    {
        if( pLocalCandidate->state == ICE_CANDIDATE_STATE_RELEASING )
        {
            /* Set state to released regardless of the response we received. */
            pLocalCandidate->state = ICE_CANDIDATE_STATE_INVALID;
            handleStunPacketResult = ICE_HANDLE_STUN_PACKET_RESULT_TURN_SESSION_TERMINATED;
        }
    }

    if( handleStunPacketResult == ICE_HANDLE_STUN_PACKET_RESULT_OK )
    {
        switch( deserializePacketInfo.errorCode )
        {
            case STUN_ATTRIBUTE_ERROR_CODE_VALUE_SUCCESS:
            {
                handleStunPacketResult = ICE_HANDLE_STUN_PACKET_RESULT_INVALID_RESPONSE;
            }
            break;

            case STUN_ATTRIBUTE_ERROR_CODE_VALUE_STALE_NONCE:
            case STUN_ATTRIBUTE_ERROR_CODE_VALUE_UNAUTHORIZED:
            {
                handleStunPacketResult = UpdateIceServerInfo( pContext,
                                                              pLocalCandidate,
                                                              &( deserializePacketInfo ) );
            }
            break;

            default:
            {
                handleStunPacketResult = ICE_HANDLE_STUN_PACKET_RESULT_REFRESH_UNKNOWN_ERROR;
            }
            break;
        }
    }

    return handleStunPacketResult;
}

/*----------------------------------------------------------------------------*/
