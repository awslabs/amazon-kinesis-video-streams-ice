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

#define ICE_CANDIDATE_ID_START ( 0x7000 )

/* Helper macros. */
#define ICE_WRITE_UINT16   ( pContext->readWriteFunctions.writeUint16Fn )
#define ICE_READ_UINT16    ( pContext->readWriteFunctions.readUint16Fn )

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
        ( pInitInfo->pTurnServerArray == NULL ) ||
        ( pInitInfo->pStunBindingRequestTransactionIdStore == NULL ) ||
        ( pInitInfo->cryptoFunctions.randomFxn == NULL ) ||
        ( pInitInfo->cryptoFunctions.crc32Fxn == NULL ) ||
        ( pInitInfo->cryptoFunctions.hmacFxn == NULL ) ||
        ( pInitInfo->cryptoFunctions.md5Fxn == NULL ) ||
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

        pContext->pTurnServers = pInitInfo->pTurnServerArray;
        pContext->maxTurnServers = pInitInfo->turnServerArrayLength;
        pContext->numTurnServers = 0;

        pContext->isControlling = pInitInfo->isControlling;
        pContext->pStunBindingRequestTransactionIdStore = pInitInfo->pStunBindingRequestTransactionIdStore;

        pContext->cryptoFunctions = pInitInfo->cryptoFunctions;

        pContext->nextCandidateId = ICE_CANDIDATE_ID_START;

        Stun_InitReadWriteFunctions( &( pContext->readWriteFunctions ) );
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

        pHostCandidate->candidateId = pContext->nextCandidateId;
        pContext->nextCandidateId++;

        /* Create candidate pairs with all the existing remote candidates. */
        for( i = 0; ( i < pContext->numRemoteCandidates ) && ( result == ICE_RESULT_OK ); i++ )
        {
            result = Ice_AddCandidatePair( pContext,
                                           pHostCandidate,
                                           &( pContext->pRemoteCandidates[ i ] ) );
        }
    }

    return result;
}

/*----------------------------------------------------------------------------*/

IceResult_t Ice_AddServerReflexiveCandidate( IceContext_t * pContext,
                                             const IceEndpoint_t * pEndpoint )
{
    IceResult_t result = ICE_RESULT_OK;
    IceCandidate_t * pServerReflexiveCandidate = NULL;

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
        pServerReflexiveCandidate = &( pContext->pLocalCandidates[ pContext->numLocalCandidates ] );

        result = pContext->cryptoFunctions.randomFxn( &( pServerReflexiveCandidate->transactionId[ 0 ] ),
                                                      STUN_HEADER_TRANSACTION_ID_LENGTH );

        if( result != ICE_RESULT_OK )
        {
            result = ICE_RESULT_RANDOM_GENERATION_ERROR;
        }
    }

    if( result == ICE_RESULT_OK )
    {
        /* Consume the candidate form the array. */
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

        pServerReflexiveCandidate->candidateId = pContext->nextCandidateId;
        pContext->nextCandidateId++;
    }

    return result;
}

/*----------------------------------------------------------------------------*/

IceResult_t Ice_AddRelayCandidate( IceContext_t * pContext,
                                   const IceEndpoint_t * pEndpoint,
                                   const char * pTurnServerUsername,
                                   size_t turnServerUsernameLength,
                                   const char * pTurnServerPassword,
                                   size_t turnServerPasswordLength )
{
    IceResult_t result = ICE_RESULT_OK;
    IceCandidate_t * pRelayCandidate = NULL;
    IceTurnServer_t * pTurnServer = NULL;

    if( ( pContext == NULL ) ||
        ( pEndpoint == NULL ) ||
        ( pTurnServerUsername == NULL ) ||
        ( pTurnServerPassword == NULL ) ||
        ( turnServerUsernameLength > ICE_SERVER_CONFIG_MAX_USER_NAME_LENGTH ) ||
        ( turnServerPasswordLength > ICE_SERVER_CONFIG_MAX_PASSWORD_LENGTH ) )
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
        if( pContext->numTurnServers == pContext->maxTurnServers )
        {
            result = ICE_RESULT_MAX_TURN_SERVER_THRESHOLD;
        }
    }

    if( result == ICE_RESULT_OK )
    {
        pRelayCandidate = &( pContext->pLocalCandidates[ pContext->numLocalCandidates ] );

        result = pContext->cryptoFunctions.randomFxn( &( pRelayCandidate->transactionId[ 0 ] ),
                                                      STUN_HEADER_TRANSACTION_ID_LENGTH );

        if( result != ICE_RESULT_OK )
        {
            result = ICE_RESULT_RANDOM_GENERATION_ERROR;
        }
    }

    if( result == ICE_RESULT_OK )
    {
        /* Consume the candidate form the array. */
        pContext->numLocalCandidates += 1;

        pTurnServer = &( pContext->pTurnServers[ pContext->numTurnServers ] );
        pContext->numTurnServers += 1;
        memset( pTurnServer, 0, sizeof( IceTurnServer_t ) );

        memcpy( &( pTurnServer->userName[ 0 ] ),
                pTurnServerUsername,
                turnServerUsernameLength );
        pTurnServer->userNameLength = turnServerUsernameLength;

        memcpy( &( pTurnServer->password[ 0 ] ),
                pTurnServerPassword,
                turnServerPasswordLength );
        pTurnServer->passwordLength = turnServerPasswordLength;

        pRelayCandidate->pTurnServer = pTurnServer;
        pRelayCandidate->candidateType = ICE_CANDIDATE_TYPE_RELAY;
        pRelayCandidate->isRemote = 0;
        memcpy( &( pRelayCandidate->endpoint ),
                pEndpoint,
                sizeof( IceEndpoint_t ) );
        pRelayCandidate->priority = Ice_ComputeCandidatePriority( ICE_CANDIDATE_TYPE_RELAY,
                                                                  pEndpoint->isPointToPoint );
        pRelayCandidate->remoteProtocol = ICE_SOCKET_PROTOCOL_NONE;
        pRelayCandidate->state = ICE_CANDIDATE_STATE_ALLOCATING;

        pRelayCandidate->candidateId = pContext->nextCandidateId;
        pContext->nextCandidateId++;
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

            pRemoteCandidate->candidateId = pContext->nextCandidateId;
            pContext->nextCandidateId++;

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

IceResult_t Ice_CloseCandidatePair( IceContext_t * pContext,
                                    IceCandidatePair_t * pIceCandidatePair )
{
    IceResult_t result = ICE_RESULT_OK;
    size_t i;

    if( ( pContext == NULL ) ||
        ( pIceCandidatePair == NULL ) )
    {
        result = ICE_RESULT_BAD_PARAM;
    }

    if( result == ICE_RESULT_OK )
    {
        for( i = 0; i < pContext->numCandidatePairs; i++ )
        {
            if( &( pContext->pCandidatePairs[ i ] ) == pIceCandidatePair )
            {
                break;
            }
        }

        if( i == pContext->numCandidatePairs )
        {
            result = ICE_RESULT_INVALID_CANDIDATE_PAIR;
        }
    }

    if( result == ICE_RESULT_OK )
    {
        pIceCandidatePair->state = ICE_CANDIDATE_PAIR_STATE_FROZEN;
    }

    return result;
}

/*----------------------------------------------------------------------------*/

IceResult_t Ice_CloseCandidate( IceContext_t * pContext,
                                IceCandidate_t * pLocalCandidate )
{
    IceResult_t result = ICE_RESULT_OK;
    size_t i;

    if( ( pContext == NULL ) ||
        ( pLocalCandidate == NULL ) )
    {
        result = ICE_RESULT_BAD_PARAM;
    }

    if( result == ICE_RESULT_OK )
    {
        for( i = 0; i < pContext->numLocalCandidates; i++ )
        {
            if( &( pContext->pLocalCandidates[ i ] ) == pLocalCandidate )
            {
                break;
            }
        }

        if( i == pContext->numLocalCandidates )
        {
            result = ICE_RESULT_INVALID_CANDIDATE;
        }
    }

    if( result == ICE_RESULT_OK )
    {
        /* Relay candidates in "Allocating" or "Valid" state need to release
         * resources on the Turn server. */
        if( pLocalCandidate->candidateType == ICE_CANDIDATE_TYPE_RELAY )
        {
            if( ( pLocalCandidate->state == ICE_CANDIDATE_STATE_ALLOCATING ) ||
                ( pLocalCandidate->state == ICE_CANDIDATE_STATE_VALID ) )
            {
                pLocalCandidate->state = ICE_CANDIDATE_STATE_RELEASING;

                /* Regenerate Transaction Id to be used in the TURN request to
                 * release resources on the TURN server. */
                ( void ) pContext->cryptoFunctions.randomFxn( &( pLocalCandidate->transactionId[ 0 ] ),
                                                              STUN_HEADER_TRANSACTION_ID_LENGTH );
            }
        }
        else
        {
            pLocalCandidate->state = ICE_CANDIDATE_STATE_INVALID;
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
        ( pTransactionId == NULL ) ||
        ( pMessageBuffer == NULL ) ||
        ( pMessageBufferLength == NULL ) ||
        ( ( pIceCandidatePair->pLocalCandidate->candidateType == ICE_CANDIDATE_TYPE_RELAY ) &&
          ( *pMessageBufferLength < ICE_TURN_CHANNEL_DATA_MESSAGE_HEADER_LENGTH ) ) )
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
        stunHeader.messageType = STUN_MESSAGE_TYPE_BINDING_SUCCESS_RESPONSE;
        stunHeader.pTransactionId = pTransactionId;

        stunResult = StunSerializer_Init( &( stunCtx ),
                                          pStunMessageStart,
                                          stunMessageBufferLength,
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

IceResult_t Ice_HandleTurnPacket( IceContext_t * pContext,
                                  const uint8_t * pReceivedTurnMessage,
                                  size_t receivedTurnMessageLength,
                                  IceCandidate_t * pLocalCandidate,
                                  const uint8_t ** ppTurnPayload,
                                  uint16_t * pTurnPayloadLength,
                                  IceCandidatePair_t ** ppIceCandidatePair )
{
    IceResult_t result = ICE_RESULT_OK;
    size_t i;
    IceCandidatePair_t * pCandidatePair = NULL;
    uint16_t channelNumber, messageLength;

    if( ( pContext == NULL ) ||
        ( pReceivedTurnMessage == NULL ) ||
        ( pLocalCandidate == NULL ) ||
        ( ppTurnPayload == NULL ) ||
        ( pTurnPayloadLength == NULL ) ||
        ( ppIceCandidatePair == NULL ) )
    {
        result = ICE_RESULT_BAD_PARAM;
    }

    if( result == ICE_RESULT_OK )
    {
        if( ( receivedTurnMessageLength < ICE_TURN_CHANNEL_DATA_MESSAGE_HEADER_LENGTH ) ||
            ( ( pReceivedTurnMessage[ 0 ] & 0xF0 ) != 0x40 ) )
        {
            result = ICE_RESULT_TURN_INVALID_MESSAGE;
        }
    }

    if( result == ICE_RESULT_OK )
    {
        if( ( pLocalCandidate->candidateType != ICE_CANDIDATE_TYPE_RELAY ) ||
            ( pLocalCandidate->state != ICE_CANDIDATE_STATE_VALID ) )
        {
            result = ICE_RESULT_TURN_UNEXPECTED_MESSAGE;
        }
    }

    if( result == ICE_RESULT_OK )
    {
        channelNumber = ICE_READ_UINT16( &( pReceivedTurnMessage[ ICE_TURN_CHANNEL_DATA_MESSAGE_CHANNEL_NUMBER_OFFSET ] ) );
        messageLength = ICE_READ_UINT16( &( pReceivedTurnMessage[ ICE_TURN_CHANNEL_DATA_MESSAGE_LENGTH_OFFSET ] ) );

        if( receivedTurnMessageLength < ( size_t ) ( messageLength + ICE_TURN_CHANNEL_DATA_MESSAGE_HEADER_LENGTH ) )
        {
            result = ICE_RESULT_TURN_INVALID_MESSAGE;
        }
    }

    if( result == ICE_RESULT_OK )
    {
        for( i = 0; i < pContext->numCandidatePairs; i++ )
        {
            if( ( Ice_IsSameTransportAddress( &( pContext->pCandidatePairs[ i ].pLocalCandidate->endpoint.transportAddress ),
                                              &( pLocalCandidate->endpoint.transportAddress ) ) == 1 ) &&
                ( channelNumber == pContext->pCandidatePairs[ i ].turnChannelNumber ) )
            {
                pCandidatePair = &( pContext->pCandidatePairs[ i ] );
                break;
            }
        }

        if( pCandidatePair == NULL )
        {
            result = ICE_RESULT_TURN_CANDIDATE_PAIR_NOT_FOUND;
        }
    }

    if( result == ICE_RESULT_OK )
    {
        /* Update output parameters. */
        *ppTurnPayload = &( pReceivedTurnMessage[ ICE_TURN_CHANNEL_DATA_MESSAGE_HEADER_LENGTH ] );
        *pTurnPayloadLength = messageLength;
        *ppIceCandidatePair = pCandidatePair;
    }

    return result;
}

/*----------------------------------------------------------------------------*/

/* Ice_HandleStunPacket - This API handles the processing of Stun Packet. */
IceHandleStunPacketResult_t Ice_HandleStunPacket( IceContext_t * pContext,
                                                  uint8_t * pReceivedStunMessage,
                                                  size_t receivedStunMessageLength,
                                                  IceCandidate_t * pLocalCandidate,
                                                  const IceEndpoint_t * pRemoteCandidateEndpoint,
                                                  uint64_t currentTimeSeconds,
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
        ( pLocalCandidate == NULL ) ||
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

        if( stunResult == STUN_RESULT_OK )
        {
            switch( stunHeader.messageType )
            {
                case STUN_MESSAGE_TYPE_BINDING_REQUEST:
                {
                    handleStunPacketResult = Ice_HandleStunBindingRequest( pContext,
                                                                           &( stunCtx ),
                                                                           pLocalCandidate,
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
                                                                                    pLocalCandidate );

                        ( void ) TransactionIdStore_Remove( pContext->pStunBindingRequestTransactionIdStore,
                                                            stunHeader.pTransactionId );
                    }
                    else
                    {
                        handleStunPacketResult = Ice_HandleConnectivityCheckResponse( pContext,
                                                                                      &( stunCtx ),
                                                                                      &( stunHeader ),
                                                                                      pLocalCandidate,
                                                                                      pRemoteCandidateEndpoint,
                                                                                      ppIceCandidatePair );
                    }
                }
                break;

                case STUN_MESSAGE_TYPE_ALLOCATE_SUCCESS_RESPONSE:
                {
                    handleStunPacketResult = Ice_HandleTurnAllocateSuccessResponse( pContext,
                                                                                    &( stunCtx ),
                                                                                    &( stunHeader ),
                                                                                    pLocalCandidate,
                                                                                    currentTimeSeconds );
                }
                break;

                case STUN_MESSAGE_TYPE_ALLOCATE_ERROR_RESPONSE:
                {
                    handleStunPacketResult = Ice_HandleTurnAllocateErrorResponse( pContext,
                                                                                  &( stunCtx ),
                                                                                  &( stunHeader ),
                                                                                  pLocalCandidate );
                }
                break;

                case STUN_MESSAGE_TYPE_CREATE_PERMISSION_SUCCESS_RESPONSE:
                {
                    handleStunPacketResult = Ice_HandleTurnCreatePermissionSuccessResponse( pContext,
                                                                                            &( stunCtx ),
                                                                                            &( stunHeader ),
                                                                                            pLocalCandidate,
                                                                                            currentTimeSeconds,
                                                                                            ppIceCandidatePair );
                }
                break;

                case STUN_MESSAGE_TYPE_CREATE_PERMISSION_ERROR_RESPONSE:
                {
                    handleStunPacketResult = Ice_HandleTurnCreatePermissionErrorResponse( pContext,
                                                                                          &( stunCtx ),
                                                                                          &( stunHeader ),
                                                                                          pLocalCandidate,
                                                                                          ppIceCandidatePair );
                }
                break;

                case STUN_MESSAGE_TYPE_CHANNEL_BIND_SUCCESS_RESPONSE:
                {
                    handleStunPacketResult = Ice_HandleTurnChannelBindSuccessResponse( pContext,
                                                                                       &( stunCtx ),
                                                                                       &( stunHeader ),
                                                                                       pLocalCandidate,
                                                                                       ppIceCandidatePair );
                }
                break;

                case STUN_MESSAGE_TYPE_CHANNEL_BIND_ERROR_RESPONSE:
                {
                    handleStunPacketResult = Ice_HandleTurnChannelBindErrorResponse( pContext,
                                                                                     &( stunCtx ),
                                                                                     &( stunHeader ),
                                                                                     pLocalCandidate,
                                                                                     ppIceCandidatePair );
                }
                break;

                case STUN_MESSAGE_TYPE_REFRESH_SUCCESS_RESPONSE:
                {
                    handleStunPacketResult = Ice_HandleTurnRefreshSuccessResponse( pContext,
                                                                                   &( stunCtx ),
                                                                                   &( stunHeader ),
                                                                                   pLocalCandidate,
                                                                                   currentTimeSeconds );
                }
                break;

                case STUN_MESSAGE_TYPE_REFRESH_ERROR_RESPONSE:
                {
                    handleStunPacketResult = Ice_HandleTurnRefreshErrorResponse( pContext,
                                                                                 &( stunCtx ),
                                                                                 &( stunHeader ),
                                                                                 pLocalCandidate );
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
            handleStunPacketResult = ICE_HANDLE_STUN_PACKET_RESULT_NOT_STUN_PACKET;
        }
    }

    return handleStunPacketResult;
}

/*----------------------------------------------------------------------------*/

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

IceResult_t Ice_CreateNextCandidateRequest( IceContext_t * pContext,
                                            IceCandidate_t * pIceCandidate,
                                            uint64_t currentTimeSeconds,
                                            uint8_t * pStunMessageBuffer,
                                            size_t * pStunMessageBufferLength )
{
    IceResult_t result = ICE_RESULT_OK;

    if( ( pContext == NULL ) ||
        ( pIceCandidate == NULL ) ||
        ( pStunMessageBuffer == NULL ) ||
        ( pStunMessageBufferLength == NULL ) ||
        ( pIceCandidate->isRemote != 0 ) )
    {
        result = ICE_RESULT_BAD_PARAM;
    }

    if( result == ICE_RESULT_OK )
    {
        if( pIceCandidate->candidateType == ICE_CANDIDATE_TYPE_SERVER_REFLEXIVE )
        {
            /* Generate STUN request for server reflexive candidate to query
             * external IP address. */
            if( pIceCandidate->state == ICE_CANDIDATE_STATE_NEW )
            {
                result = Ice_CreateServerReflexiveBindingRequest( pContext,
                                                                  pIceCandidate,
                                                                  pStunMessageBuffer,
                                                                  pStunMessageBufferLength );
            }
            else
            {
                /* If the server reflexive candidate already has the external IP
                 * address, no action is needed. */
                result = ICE_RESULT_NO_NEXT_ACTION;
            }
        }
        else if( pIceCandidate->candidateType == ICE_CANDIDATE_TYPE_RELAY )
        {
            if( pIceCandidate->state == ICE_CANDIDATE_STATE_ALLOCATING )
            {
                /* Generate TURN allocation request for relay candidate to
                 * allocate resources on the TURN server. */
                result = Ice_CreateAllocationRequest( pContext,
                                                      pIceCandidate,
                                                      pStunMessageBuffer,
                                                      pStunMessageBufferLength );
            }
            else if( pIceCandidate->state == ICE_CANDIDATE_STATE_RELEASING )
            {
                /* Generate request for relay candidate to release resources on
                 * the TURN server. */
                result = Ice_CreateRefreshRequest( pContext,
                                                   pIceCandidate,
                                                   0U,
                                                   pStunMessageBuffer,
                                                   pStunMessageBufferLength );
            }
            else if( ( currentTimeSeconds + ICE_TURN_ALLOCATION_REFRESH_GRACE_PERIOD_SECONDS ) >= pIceCandidate->pTurnServer->turnAllocationExpirationTimeSeconds )
            {
                /* Generate request for relay candidate to refresh allocation on
                 * the TURN server. */
                result = Ice_CreateRefreshRequest( pContext,
                                                   pIceCandidate,
                                                   ICE_DEFAULT_TURN_ALLOCATION_LIFETIME_SECONDS,
                                                   pStunMessageBuffer,
                                                   pStunMessageBufferLength );
            }
            else
            {
                result = ICE_RESULT_NO_NEXT_ACTION;
            }
        }
        else
        {
            result = ICE_RESULT_NO_NEXT_ACTION;
        }
    }

    return result;
}

/*----------------------------------------------------------------------------*/

IceResult_t Ice_CreateNextPairRequest( IceContext_t * pContext,
                                       IceCandidatePair_t * pIceCandidatePair,
                                       uint64_t currentTimeSeconds,
                                       uint8_t * pStunMessageBuffer,
                                       size_t * pStunMessageBufferLength )
{
    IceResult_t result = ICE_RESULT_OK;

    if( ( pContext == NULL ) ||
        ( pIceCandidatePair == NULL ) ||
        ( pStunMessageBuffer == NULL ) ||
        ( pStunMessageBufferLength == NULL ) )
    {
        result = ICE_RESULT_BAD_PARAM;
    }
    else if( ( pIceCandidatePair->pLocalCandidate == NULL ) ||
             ( pIceCandidatePair->pRemoteCandidate == NULL ) )
    {
        result = ICE_RESULT_INVALID_CANDIDATE_PAIR;
    }
    else
    {
        /* Empty else marker. */
    }

    if( result == ICE_RESULT_OK )
    {
        switch( pIceCandidatePair->state )
        {
            case ICE_CANDIDATE_PAIR_STATE_WAITING:
            {
                /* Generate STUN request for connectivity check. */
                result = Ice_CreateRequestForConnectivityCheck( pContext,
                                                                pIceCandidatePair,
                                                                pStunMessageBuffer,
                                                                pStunMessageBufferLength );
            }
            break;

            case ICE_CANDIDATE_PAIR_STATE_NOMINATED:
            {
                if( pContext->isControlling == 1 )
                {
                    /* Generate request for nominating a candidate pair. */
                    result = Ice_CreateRequestForNominatingCandidatePair( pContext,
                                                                          pIceCandidatePair,
                                                                          pStunMessageBuffer,
                                                                          pStunMessageBufferLength );
                }
                else
                {
                    /* Controlled ICE agent might receive USE-CANDIDATE in
                     * connectivity check stage which would transition the
                     * pair's state to nominated. We still keep sending
                     * connectivity checks requests until connectivity check is
                     * successful at which point the pair's state would
                     * transition to succeeded. */
                    result = Ice_CreateRequestForConnectivityCheck( pContext,
                                                                    pIceCandidatePair,
                                                                    pStunMessageBuffer,
                                                                    pStunMessageBufferLength );
                }
            }
            break;

            case ICE_CANDIDATE_PAIR_STATE_CREATE_PERMISSION:
            {
                /* Generate request to create permission on the TURN server. */
                result = Ice_CreatePermissionRequest( pContext,
                                                      pIceCandidatePair,
                                                      pStunMessageBuffer,
                                                      pStunMessageBufferLength );
            }
            break;

            case ICE_CANDIDATE_PAIR_STATE_CHANNEL_BIND:
            {
                /* Generate request for binding a channel number to a remote peer. */
                result = Ice_CreateChannelBindRequest( pContext,
                                                       pIceCandidatePair,
                                                       pStunMessageBuffer,
                                                       pStunMessageBufferLength );
            }
            break;

            case ICE_CANDIDATE_PAIR_STATE_SUCCEEDED:
            {
                result = ICE_RESULT_NO_NEXT_ACTION;

                if( ( pIceCandidatePair->pLocalCandidate->candidateType == ICE_CANDIDATE_TYPE_RELAY ) &&
                    ( pIceCandidatePair->pLocalCandidate->state == ICE_CANDIDATE_STATE_VALID ) &&
                    ( ( currentTimeSeconds + ICE_TURN_PERMISSION_REFRESH_GRACE_PERIOD_SECONDS ) >= pIceCandidatePair->turnPermissionExpirationSeconds ) )
                {
                    result = Ice_CreatePermissionRequest( pContext,
                                                          pIceCandidatePair,
                                                          pStunMessageBuffer,
                                                          pStunMessageBufferLength );
                }
            }
            break;

            /* Intentional fall through. */
            case ICE_CANDIDATE_PAIR_STATE_VALID:
            case ICE_CANDIDATE_PAIR_STATE_FROZEN:
            default:
            {
                /* Do nothing. */
                result = ICE_RESULT_NO_NEXT_ACTION;
            }
            break;
        }
    }

    return result;
}

/*----------------------------------------------------------------------------*/

IceResult_t Ice_CreateTurnChannelDataMessage( IceContext_t * pContext,
                                              const IceCandidatePair_t * pIceCandidatePair,
                                              uint8_t * pTurnPayload,
                                              size_t turnPayloadLength,
                                              size_t * pTotalBufferLength )
{
    IceResult_t result = ICE_RESULT_OK;
    uint8_t * pChannelDataHeader = NULL;
    /* Calculate the padding by rounding up to 4. */
    uint16_t padding = ( ( turnPayloadLength + 3 ) & ~3 ) - turnPayloadLength;

    if( ( pContext == NULL ) ||
        ( pIceCandidatePair == NULL ) ||
        ( pTurnPayload == NULL ) ||
        ( pTotalBufferLength == NULL ) )
    {
        result = ICE_RESULT_BAD_PARAM;
    }
    else if( *pTotalBufferLength < ICE_TURN_CHANNEL_DATA_MESSAGE_HEADER_LENGTH + turnPayloadLength + padding )
    {
        result = ICE_RESULT_OUT_OF_MEMORY;
    }
    else
    {
        /* Empty else marker. */
    }

    if( result == ICE_RESULT_OK )
    {
        if( ( pIceCandidatePair->state == ICE_CANDIDATE_PAIR_STATE_INVALID ) ||
            ( pIceCandidatePair->state == ICE_CANDIDATE_PAIR_STATE_FROZEN ) )
        {
            result = ICE_RESULT_TURN_CHANNEL_DATA_HEADER_NOT_REQUIRED;
        }
    }

    if( result == ICE_RESULT_OK )
    {
        pChannelDataHeader = pTurnPayload - ICE_TURN_CHANNEL_DATA_MESSAGE_HEADER_LENGTH;

        ICE_WRITE_UINT16( &( pChannelDataHeader[ ICE_TURN_CHANNEL_DATA_MESSAGE_CHANNEL_NUMBER_OFFSET ] ),
                          pIceCandidatePair->turnChannelNumber );
        ICE_WRITE_UINT16( &( pChannelDataHeader[ ICE_TURN_CHANNEL_DATA_MESSAGE_LENGTH_OFFSET ] ),
                          turnPayloadLength );

        *pTotalBufferLength = turnPayloadLength + ICE_TURN_CHANNEL_DATA_MESSAGE_HEADER_LENGTH + padding;
    }

    return result;
}

/*----------------------------------------------------------------------------*/
