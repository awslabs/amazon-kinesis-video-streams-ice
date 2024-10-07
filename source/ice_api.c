/* Standard includes. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* API includes. */
#include "ice_api.h"
#include "ice_api_private.h"

/* STUN includes. */
#include "stun_data_types.h"
#include "stun_serializer.h"
#include "stun_deserializer.h"

/*----------------------------------------------------------------------------*/

IceResult_t Ice_Init( IceContext_t * pContext,
                      const IceInitInfo_t * pInitInfo )
{
    IceResult_t result = ICE_RESULT_OK;

    if( ( pContext == NULL ) ||
        ( pInitInfo == NULL ) ||
        ( pInitInfo->pLocalCandidatesArray == NULL ) ||
        ( pInitInfo->pRemoteCandidatesArray == NULL ) ||
        ( pInitInfo->pCandidatePairsArray == NULL ) ||
        ( pInitInfo->pStunBindingRequestTransactionIdStore == NULL ) ||
        ( pInitInfo->cryptoFunctions.randomFxn == NULL ) ||
        ( pInitInfo->cryptoFunctions.crc32Fxn == NULL ) ||
        ( pInitInfo->cryptoFunctions.hmacFxn == NULL ) ||
        ( pInitInfo->creds.pLocalUsername == NULL ) ||
        ( pInitInfo->creds.pLocalPassword == NULL ) ||
        ( pInitInfo->creds.pRemoteUsername == NULL ) ||
        ( pInitInfo->creds.pRemotePassword == NULL ) ||
        ( pInitInfo->creds.pCombinedUsername == NULL ) )
    {
        result = ICE_RESULT_BAD_PARAM;
    }

    if( result == ICE_RESULT_OK )
    {
        memset( pContext,
                0,
                sizeof( IceContext_t ) );

        pContext->creds = pInitInfo->creds;

        pContext->pLocalCandidates = pInitInfo->pLocalCandidatesArray;
        pContext->maxLocalCandidates = pInitInfo->localCandidatesArrayLength;
        pContext->numLocalCandidates = 0;

        pContext->pRemoteCandidates = pInitInfo->pRemoteCandidatesArray;
        pContext->maxRemoteCandidates = pInitInfo->remoteCandidatesArrayLength;
        pContext->numRemoteCandidates = 0;

        pContext->pCandidatePairs = pInitInfo->pCandidatePairsArray;
        pContext->maxCandidatePairs = pInitInfo->candidatePairsArrayLength;
        pContext->numCandidatePairs = 0;

        pContext->isControlling = pInitInfo->isControlling;
        pContext->pStunBindingRequestTransactionIdStore = pInitInfo->pStunBindingRequestTransactionIdStore;

        pContext->cryptoFunctions = pInitInfo->cryptoFunctions;
    }

    if( result == ICE_RESULT_OK )
    {
        result = pContext->cryptoFunctions.randomFxn( ( uint8_t * ) &( pContext->tieBreaker ),
                                                      sizeof( pContext->tieBreaker ) );
    }

    return result;
}

/*----------------------------------------------------------------------------*/

IceResult_t Ice_AddHostCandidate( IceContext_t * pContext,
                                  const IceEndpoint_t * pEndpoint )
{
    size_t i;
    IceResult_t result = ICE_RESULT_OK;
    IceCandidate_t * pHostCandidate = NULL;

    if( ( pContext == NULL ) ||
        ( pEndpoint == NULL ) )
    {
        result = ICE_RESULT_BAD_PARAM;
    }

    if( result == ICE_RESULT_OK )
    {
        if( pContext->numLocalCandidates == pContext->maxLocalCandidates )
        {
            result = ICE_RESULT_MAX_CANDIDATE_THRESHOLD;
        }
    }

    if( result == ICE_RESULT_OK )
    {
        pHostCandidate = &( pContext->pLocalCandidates[ pContext->numLocalCandidates ] );
        pContext->numLocalCandidates += 1;

        pHostCandidate->candidateType = ICE_CANDIDATE_TYPE_HOST;
        pHostCandidate->isRemote = 0;
        memcpy( &( pHostCandidate->endpoint ),
                pEndpoint,
                sizeof( IceEndpoint_t ) );
        pHostCandidate->priority = Ice_ComputeCandidatePriority( ICE_CANDIDATE_TYPE_HOST,
                                                                 pEndpoint->isPointToPoint );
        pHostCandidate->remoteProtocol = ICE_SOCKET_PROTOCOL_NONE;
        pHostCandidate->state = ICE_CANDIDATE_STATE_VALID;

        /* Create candidate pairs with all the existing remote candidates. */
        for( i = 0; ( i < pContext->numRemoteCandidates ) && ( result == ICE_RESULT_OK ); i++ )
        {
            if( pContext->pRemoteCandidates[ i ].state == ICE_CANDIDATE_STATE_VALID )
            {
                result = Ice_AddCandidatePair( pContext,
                                               pHostCandidate,
                                               &( pContext->pRemoteCandidates[ i ] ) );
            }
        }
    }

    return result;
}

/*----------------------------------------------------------------------------*/

IceResult_t Ice_AddServerReflexiveCandidate( IceContext_t * pContext,
                                             const IceEndpoint_t * pEndpoint,
                                             uint8_t * pStunMessageBuffer,
                                             size_t * pStunMessageBufferLength )
{
    StunContext_t stunCtx;
    StunHeader_t stunHeader;
    IceResult_t result = ICE_RESULT_OK;
    StunResult_t stunResult = STUN_RESULT_OK;
    TransactionIdStoreResult_t transactionIdStoreResult;
    IceCandidate_t * pServerReflexiveCandidate = NULL;
    uint8_t transactionId[ STUN_HEADER_TRANSACTION_ID_LENGTH ];

    if( ( pContext == NULL ) ||
        ( pEndpoint == NULL ) ||
        ( pStunMessageBuffer == NULL ) ||
        ( pStunMessageBufferLength == NULL ) )
    {
        result = ICE_RESULT_BAD_PARAM;
    }

    if( result == ICE_RESULT_OK )
    {
        if( pContext->numLocalCandidates == pContext->maxLocalCandidates )
        {
            result = ICE_RESULT_MAX_CANDIDATE_THRESHOLD;
        }
    }

    if( result == ICE_RESULT_OK )
    {
        pServerReflexiveCandidate = &( pContext->pLocalCandidates[ pContext->numLocalCandidates ] );
        pContext->numLocalCandidates += 1;

        pServerReflexiveCandidate->candidateType = ICE_CANDIDATE_TYPE_SERVER_REFLEXIVE;
        pServerReflexiveCandidate->isRemote = 0;
        memcpy( &( pServerReflexiveCandidate->endpoint ),
                pEndpoint,
                sizeof( IceEndpoint_t ) );
        pServerReflexiveCandidate->priority = Ice_ComputeCandidatePriority( ICE_CANDIDATE_TYPE_SERVER_REFLEXIVE,
                                                                            pEndpoint->isPointToPoint );
        pServerReflexiveCandidate->remoteProtocol = ICE_SOCKET_PROTOCOL_NONE;
        pServerReflexiveCandidate->state = ICE_CANDIDATE_STATE_NEW;
    }

    if( result == ICE_RESULT_OK )
    {
        result = pContext->cryptoFunctions.randomFxn( &( transactionId[ 0 ] ),
                                                      STUN_HEADER_TRANSACTION_ID_LENGTH );
    }

    if( result == ICE_RESULT_OK )
    {
        stunHeader.messageType = STUN_MESSAGE_TYPE_BINDING_REQUEST;
        stunHeader.pTransactionId = &( transactionId[ 0 ] );

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

    if( result == ICE_RESULT_OK )
    {
        transactionIdStoreResult = TransactionIdStore_Insert( pContext->pStunBindingRequestTransactionIdStore,
                                                              &( transactionId[ 0 ] ) );

        if( transactionIdStoreResult != TRANSACTION_ID_STORE_RESULT_OK )
        {
            result = ICE_RESULT_TRANSACTION_ID_STORE_ERROR;
        }
    }

    return result;
}

/*----------------------------------------------------------------------------*/

IceResult_t Ice_AddRemoteCandidate( IceContext_t * pContext,
                                    const IceRemoteCandidateInfo_t * pRemoteCandidateInfo )
{
    size_t i;
    IceResult_t result = ICE_RESULT_OK;
    IceCandidate_t * pRemoteCandidate = NULL;

    if( ( pContext == NULL ) ||
        ( pRemoteCandidateInfo == NULL ) )
    {
        result = ICE_RESULT_BAD_PARAM;
    }

    if( result == ICE_RESULT_OK )
    {
        if( pContext->numRemoteCandidates == pContext->maxRemoteCandidates )
        {
            result = ICE_RESULT_MAX_CANDIDATE_THRESHOLD;
        }
    }

    if( result == ICE_RESULT_OK )
    {
        /* Do we already have a remote candidate with the same transport (IP
         * and port) address? */
        for( i = 0; i < pContext->numRemoteCandidates; i++ )
        {
            if( Ice_IsSameTransportAddress( &( pContext->pRemoteCandidates[ i ].endpoint.transportAddress ),
                                            &( pRemoteCandidateInfo->pEndpoint->transportAddress ) ) == 1 )
            {
                break;
            }
        }

        /* Only add a remote candidate if we do not have a remote candidate with
         * the same transport (IP and port) address already. */
        if( i == pContext->numRemoteCandidates )
        {
            pRemoteCandidate = &( pContext->pRemoteCandidates[ pContext->numRemoteCandidates ] );
            pContext->numRemoteCandidates += 1;

            pRemoteCandidate->candidateType = pRemoteCandidateInfo->candidateType;
            pRemoteCandidate->isRemote = 1;
            pRemoteCandidate->priority = pRemoteCandidateInfo->priority;
            pRemoteCandidate->remoteProtocol = pRemoteCandidateInfo->remoteProtocol;
            pRemoteCandidate->state = ICE_CANDIDATE_STATE_VALID;
            memcpy( &( pRemoteCandidate->endpoint ),
                    pRemoteCandidateInfo->pEndpoint,
                    sizeof( IceEndpoint_t ) );

            /* Create candidate pairs with all the existing local candidates. */
            for( i = 0; ( i < pContext->numLocalCandidates ) && ( result == ICE_RESULT_OK ); i++ )
            {
                if( pContext->pLocalCandidates[ i ].state == ICE_CANDIDATE_STATE_VALID )
                {
                    result = Ice_AddCandidatePair( pContext,
                                                   &( pContext->pLocalCandidates[ i ] ),
                                                   pRemoteCandidate );
                }
            }
        }
    }

    return result;
}

/*----------------------------------------------------------------------------*/

/* Ice_CreateRequestForConnectivityCheck - This API creates Stun Packet for
 * connectivity check to the remote candidate.
 */
IceResult_t Ice_CreateRequestForConnectivityCheck( IceContext_t * pContext,
                                                   IceCandidatePair_t * pIceCandidatePair,
                                                   uint8_t * pStunMessageBuffer,
                                                   size_t * pStunMessageBufferLength )
{
    StunContext_t stunCtx;
    StunHeader_t stunHeader;
    IceResult_t result = ICE_RESULT_OK;
    StunResult_t stunResult = STUN_RESULT_OK;

    if( ( pContext == NULL ) ||
        ( pIceCandidatePair == NULL ) ||
        ( pStunMessageBuffer == NULL ) ||
        ( pStunMessageBufferLength == NULL ) )
    {
        result = ICE_RESULT_BAD_PARAM;
    }

    if( result == ICE_RESULT_OK )
    {
        stunHeader.messageType = STUN_MESSAGE_TYPE_BINDING_REQUEST;
        stunHeader.pTransactionId = &( pIceCandidatePair->transactionId[ 0 ] );

        stunResult = StunSerializer_Init( &( stunCtx ),
                                          pStunMessageBuffer,
                                          *pStunMessageBufferLength,
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
                                             pStunMessageBufferLength );
        }
        else
        {
            result = ICE_RESULT_STUN_ERROR;
        }
    }

    if( result == ICE_RESULT_OK )
    {
        pIceCandidatePair->connectivityCheckFlags |= ICE_STUN_REQUEST_SENT_FLAG;
    }

    return result;
}

/*----------------------------------------------------------------------------*/

/* Ice_CreateRequestForNominatingCandidatePair - This API creates Stun Packet
 * for nomination of the valid candidate Pair sent by the Controlling ICE agent.
 */
IceResult_t Ice_CreateRequestForNominatingCandidatePair( IceContext_t * pContext,
                                                         IceCandidatePair_t * pIceCandidatePair,
                                                         uint8_t * pStunMessageBuffer,
                                                         size_t * pStunMessageBufferLength )
{
    StunContext_t stunCtx;
    StunHeader_t stunHeader;
    IceResult_t result = ICE_RESULT_OK;
    StunResult_t stunResult = STUN_RESULT_OK;

    if( ( pContext == NULL ) ||
        ( pIceCandidatePair == NULL ) ||
        ( pStunMessageBuffer == NULL ) ||
        ( pStunMessageBufferLength == NULL ) )
    {
        result = ICE_RESULT_BAD_PARAM;
    }

    if( result == ICE_RESULT_OK )
    {
        stunHeader.messageType = STUN_MESSAGE_TYPE_BINDING_REQUEST;
        stunHeader.pTransactionId = &( pIceCandidatePair->transactionId[ 0 ] );

        stunResult = StunSerializer_Init( &( stunCtx ),
                                          pStunMessageBuffer,
                                          *pStunMessageBufferLength,
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

/* Ice_CreateResponseForRequest - This API creates Stun Packet for response to a
 * Stun Binding Request.
 */
IceResult_t Ice_CreateResponseForRequest( IceContext_t * pContext,
                                          const IceCandidatePair_t * pIceCandidatePair,
                                          uint8_t * pTransactionId,
                                          uint8_t * pStunMessageBuffer,
                                          size_t * pStunMessageBufferLength )
{
    StunContext_t stunCtx;
    StunHeader_t stunHeader;
    IceResult_t result = ICE_RESULT_OK;
    StunResult_t stunResult = STUN_RESULT_OK;

    if( ( pContext == NULL ) ||
        ( pIceCandidatePair == NULL ) ||
        ( pTransactionId == NULL ) ||
        ( pStunMessageBuffer == NULL ) ||
        ( pStunMessageBufferLength == NULL ) )
    {
        result = ICE_RESULT_BAD_PARAM;
    }

    if( result == ICE_RESULT_OK )
    {
        stunHeader.messageType = STUN_MESSAGE_TYPE_BINDING_SUCCESS_RESPONSE;
        stunHeader.pTransactionId = pTransactionId;

        stunResult = StunSerializer_Init( &( stunCtx ),
                                          pStunMessageBuffer,
                                          *pStunMessageBufferLength,
                                          &( stunHeader ) );

        if( stunResult == STUN_RESULT_OK )
        {
            stunResult = StunSerializer_AddAttributeXorMappedAddress( &( stunCtx ),
                                                                      &( pIceCandidatePair->pRemoteCandidate->endpoint.transportAddress ) );
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
                                             pContext->creds.pLocalPassword,
                                             pContext->creds.localPasswordLength,
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

/* Ice_HandleStunPacket - This API handles the processing of Stun Packet.
 */
IceHandleStunPacketResult_t Ice_HandleStunPacket( IceContext_t * pContext,
                                                  uint8_t * pReceivedStunMessage,
                                                  size_t receivedStunMessageLength,
                                                  const IceEndpoint_t * pLocalCandidateEndpoint,
                                                  const IceEndpoint_t * pRemoteCandidateEndpoint,
                                                  uint8_t ** ppTransactionId,
                                                  IceCandidatePair_t ** ppIceCandidatePair )
{
    IceHandleStunPacketResult_t handleStunPacketResult = ICE_HANDLE_STUN_PACKET_RESULT_OK;
    TransactionIdStoreResult_t transactionIdStoreResult;
    StunResult_t stunResult = STUN_RESULT_BASE;
    StunContext_t stunCtx;
    StunHeader_t stunHeader;

    if( ( pContext == NULL ) ||
        ( pReceivedStunMessage == NULL ) ||
        ( pLocalCandidateEndpoint == NULL ) ||
        ( pRemoteCandidateEndpoint == NULL ) ||
        ( ppTransactionId == NULL ) ||
        ( ppIceCandidatePair == NULL ) )
    {
        handleStunPacketResult = ICE_HANDLE_STUN_PACKET_RESULT_BAD_PARAM;
    }

    if( handleStunPacketResult == ICE_HANDLE_STUN_PACKET_RESULT_OK )
    {
        stunResult = StunDeserializer_Init( &( stunCtx ),
                                            pReceivedStunMessage,
                                            receivedStunMessageLength,
                                            &( stunHeader ) );
    }

    if( stunResult == STUN_RESULT_OK )
    {
        switch( stunHeader.messageType )
        {
            case STUN_MESSAGE_TYPE_BINDING_REQUEST:
            {
                handleStunPacketResult = Ice_HandleStunBindingRequest( pContext,
                                                                       &( stunCtx ),
                                                                       pLocalCandidateEndpoint,
                                                                       pRemoteCandidateEndpoint,
                                                                       ppIceCandidatePair );
            }
            break;

            case STUN_MESSAGE_TYPE_BINDING_SUCCESS_RESPONSE:
            {
                transactionIdStoreResult = TransactionIdStore_HasId( pContext->pStunBindingRequestTransactionIdStore,
                                                                     stunHeader.pTransactionId );

                if( transactionIdStoreResult == TRANSACTION_ID_STORE_RESULT_OK )
                {
                    handleStunPacketResult = Ice_HandleServerReflexiveResponse( pContext,
                                                                                &( stunCtx ),
                                                                                pLocalCandidateEndpoint );

                    ( void ) TransactionIdStore_Remove( pContext->pStunBindingRequestTransactionIdStore,
                                                        stunHeader.pTransactionId );
                }
                else
                {
                    handleStunPacketResult = Ice_HandleConnectivityCheckResponse( pContext,
                                                                                  &( stunCtx ),
                                                                                  &( stunHeader ),
                                                                                  pLocalCandidateEndpoint,
                                                                                  pRemoteCandidateEndpoint,
                                                                                  ppIceCandidatePair );
                }
            }
            break;

            case STUN_MESSAGE_TYPE_BINDING_INDICATION:
            {
                handleStunPacketResult = ICE_HANDLE_STUN_PACKET_RESULT_STUN_BINDING_INDICATION;
            }
            break;

            default:
            {
                handleStunPacketResult = ICE_HANDLE_STUN_PACKET_RESULT_INVALID_PACKET_TYPE;
            }
            break;
        }

        *ppTransactionId = stunHeader.pTransactionId;
    }
    else
    {
        handleStunPacketResult = ICE_HANDLE_STUN_PACKET_RESULT_DESERIALIZE_ERROR;
    }

    return handleStunPacketResult;
}

/*------------------------------------------------------------------------------------------------------------------*/

/* Ice_GetValidLocalCandidateCount - Get Local Candidate count.
 */
IceResult_t Ice_GetLocalCandidateCount( IceContext_t * pContext,
                                        size_t * pNumLocalCandidates )
{
    IceResult_t result = ICE_RESULT_OK;

    if( ( pContext == NULL ) ||
        ( pNumLocalCandidates == NULL ) )
    {
        result = ICE_RESULT_BAD_PARAM;
    }

    if( result == ICE_RESULT_OK )
    {
        *pNumLocalCandidates = pContext->numLocalCandidates;
    }

    return result;
}

/*----------------------------------------------------------------------------*/

/* Ice_GetValidRemoteCandidateCount - Get Remote Candidate count.
 */
IceResult_t Ice_GetRemoteCandidateCount( IceContext_t * pContext,
                                         size_t * pNumRemoteCandidates )
{
    IceResult_t result = ICE_RESULT_OK;

    if( ( pContext == NULL ) ||
        ( pNumRemoteCandidates == NULL ) )
    {
        result = ICE_RESULT_BAD_PARAM;
    }

    if( result == ICE_RESULT_OK )
    {
        *pNumRemoteCandidates = pContext->numRemoteCandidates;
    }

    return result;
}

/*----------------------------------------------------------------------------*/

/* Ice_GetValidCandidatePairCount - Get Candidate Pair Count.
 */
IceResult_t Ice_GetCandidatePairCount( IceContext_t * pContext,
                                       size_t * pNumCandidatePairs )
{
    IceResult_t result = ICE_RESULT_OK;

    if( ( pContext == NULL ) ||
        ( pNumCandidatePairs == NULL ) )
    {
        result = ICE_RESULT_BAD_PARAM;
    }

    if( result == ICE_RESULT_OK )
    {
        *pNumCandidatePairs = pContext->numCandidatePairs;
    }

    return result;
}

/*----------------------------------------------------------------------------*/
