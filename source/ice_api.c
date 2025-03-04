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

static IceResult_t CreateServerReflexiveBindingRequest( IceContext_t * pContext,
                                                        IceCandidate_t * pIceCandidate,
                                                        uint8_t * pStunMessageBuffer,
                                                        size_t * pStunMessageBufferLength )
{
    IceResult_t result = ICE_RESULT_OK;
    StunContext_t stunCtx;
    StunHeader_t stunHeader;
    StunResult_t stunResult = STUN_RESULT_OK;
    TransactionIdStoreResult_t transactionIdStoreResult;

    /* Other input parameters are checked before calling. */
    if( TransactionIdStore_HasId( pContext->pStunBindingRequestTransactionIdStore, pIceCandidate->transactionId ) != TRANSACTION_ID_STORE_RESULT_OK )
    {
        result = pContext->cryptoFunctions.randomFxn( pIceCandidate->transactionId,
                                                      STUN_HEADER_TRANSACTION_ID_LENGTH );

        if( result == ICE_RESULT_OK )
        {
            transactionIdStoreResult = TransactionIdStore_Insert( pContext->pStunBindingRequestTransactionIdStore,
                                                                  pIceCandidate->transactionId );

            if( transactionIdStoreResult != TRANSACTION_ID_STORE_RESULT_OK )
            {
                result = ICE_RESULT_TRANSACTION_ID_STORE_ERROR;
            }
        }
    }

    if( result == ICE_RESULT_OK )
    {
        stunHeader.messageType = STUN_MESSAGE_TYPE_BINDING_REQUEST;
        stunHeader.pTransactionId = pIceCandidate->transactionId;

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

static IceResult_t CreateAllocationRequest( IceContext_t * pContext,
                                            IceCandidate_t * pIceCandidate,
                                            uint8_t * pStunMessageBuffer,
                                            size_t * pStunMessageBufferLength )
{
    IceResult_t result = ICE_RESULT_OK;
    StunContext_t stunCtx;
    StunHeader_t stunHeader;
    StunResult_t stunResult = STUN_RESULT_OK;
    TransactionIdStoreResult_t transactionIdStoreResult;

    /* Other input parameters are checked before calling. */
    if( TransactionIdStore_HasId( pContext->pStunBindingRequestTransactionIdStore, pIceCandidate->transactionId ) != TRANSACTION_ID_STORE_RESULT_OK )
    {
        result = pContext->cryptoFunctions.randomFxn( pIceCandidate->transactionId,
                                                      STUN_HEADER_TRANSACTION_ID_LENGTH );

        if( result == ICE_RESULT_OK )
        {
            transactionIdStoreResult = TransactionIdStore_Insert( pContext->pStunBindingRequestTransactionIdStore,
                                                                  pIceCandidate->transactionId );

            if( transactionIdStoreResult != TRANSACTION_ID_STORE_RESULT_OK )
            {
                result = ICE_RESULT_TRANSACTION_ID_STORE_ERROR;
            }
        }
    }

    if( result == ICE_RESULT_OK )
    {
        stunHeader.messageType = STUN_MESSAGE_TYPE_ALLOCATE_REQUEST;
        stunHeader.pTransactionId = pIceCandidate->transactionId;

        stunResult = StunSerializer_Init( &stunCtx,
                                          pStunMessageBuffer,
                                          *pStunMessageBufferLength,
                                          &stunHeader );

        if( stunResult != STUN_RESULT_OK )
        {
            result = ICE_RESULT_STUN_ERROR;
        }
    }

    if( result == ICE_RESULT_OK )
    {
        stunResult = StunSerializer_AddAttributeLifetime( &stunCtx, ICE_DEFAULT_TURN_ALLOCATION_LIFETIME_SECONDS );

        if( stunResult != STUN_RESULT_OK )
        {
            result = ICE_RESULT_STUN_ERROR_ADD_LIFETIME;
        }
    }

    if( result == ICE_RESULT_OK )
    {
        stunResult = StunSerializer_AddAttributeRequestedTransport( &stunCtx, STUN_ATTRIBUTE_REQUESTED_TRANSPORT_UDP );

        if( stunResult != STUN_RESULT_OK )
        {
            result = ICE_RESULT_STUN_ERROR_ADD_REQUESTED_TRANSPORT;
        }
    }

    if( result == ICE_RESULT_OK )
    {
        if( pIceCandidate->iceServerInfo.userNameLength > 0U )
        {
            stunResult = StunSerializer_AddAttributeUsername( &stunCtx, pIceCandidate->iceServerInfo.userName, pIceCandidate->iceServerInfo.userNameLength );

            if( stunResult != STUN_RESULT_OK )
            {
                result = ICE_RESULT_STUN_ERROR_ADD_USERNAME;
            }
        }
    }

    if( result == ICE_RESULT_OK )
    {
        if( pIceCandidate->iceServerInfo.realmLength > 0U )
        {
            stunResult = StunSerializer_AddAttributeRealm( &stunCtx, pIceCandidate->iceServerInfo.realm, pIceCandidate->iceServerInfo.realmLength );

            if( stunResult != STUN_RESULT_OK )
            {
                result = ICE_RESULT_STUN_ERROR_ADD_REALM;
            }
        }
    }

    if( result == ICE_RESULT_OK )
    {
        if( pIceCandidate->iceServerInfo.nonceLength > 0U )
        {
            stunResult = StunSerializer_AddAttributeNonce( &stunCtx, pIceCandidate->iceServerInfo.nonce, pIceCandidate->iceServerInfo.nonceLength );

            if( stunResult != STUN_RESULT_OK )
            {
                result = ICE_RESULT_STUN_ERROR_ADD_NONCE;
            }
        }
    }

    if( result == ICE_RESULT_OK )
    {
        if( pIceCandidate->iceServerInfo.realmLength > 0 )
        {
            /* We already have long-term key retrieved from username, realm and password. */
            result = Ice_FinalizeStunPacket( pContext,
                                             &( stunCtx ),
                                             pIceCandidate->iceServerInfo.longTermPassword,
                                             pIceCandidate->iceServerInfo.longTermPasswordLength,
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

static IceResult_t CreateRefreshRequest( IceContext_t * pContext,
                                         IceCandidate_t * pIceCandidate,
                                         uint32_t lifetime,
                                         uint8_t * pStunMessageBuffer,
                                         size_t * pStunMessageBufferLength )
{
    IceResult_t result = ICE_RESULT_OK;
    StunContext_t stunCtx;
    StunHeader_t stunHeader;
    StunResult_t stunResult = STUN_RESULT_OK;
    TransactionIdStoreResult_t transactionIdStoreResult;

    /* Other input parameters are checked before calling. */
    if( TransactionIdStore_HasId( pContext->pStunBindingRequestTransactionIdStore, pIceCandidate->transactionId ) != TRANSACTION_ID_STORE_RESULT_OK )
    {
        result = pContext->cryptoFunctions.randomFxn( pIceCandidate->transactionId,
                                                      STUN_HEADER_TRANSACTION_ID_LENGTH );

        if( result == ICE_RESULT_OK )
        {
            transactionIdStoreResult = TransactionIdStore_Insert( pContext->pStunBindingRequestTransactionIdStore,
                                                                  pIceCandidate->transactionId );

            if( transactionIdStoreResult != TRANSACTION_ID_STORE_RESULT_OK )
            {
                result = ICE_RESULT_TRANSACTION_ID_STORE_ERROR;
            }
        }
    }

    if( result == ICE_RESULT_OK )
    {
        stunHeader.messageType = STUN_MESSAGE_TYPE_REFRESH_REQUEST;
        stunHeader.pTransactionId = pIceCandidate->transactionId;

        stunResult = StunSerializer_Init( &stunCtx,
                                          pStunMessageBuffer,
                                          *pStunMessageBufferLength,
                                          &stunHeader );

        if( stunResult != STUN_RESULT_OK )
        {
            result = ICE_RESULT_STUN_ERROR;
        }
    }

    if( result == ICE_RESULT_OK )
    {
        stunResult = StunSerializer_AddAttributeLifetime( &stunCtx, lifetime );

        if( stunResult != STUN_RESULT_OK )
        {
            result = ICE_RESULT_STUN_ERROR_ADD_LIFETIME;
        }
    }

    if( result == ICE_RESULT_OK )
    {
        if( pIceCandidate->iceServerInfo.userNameLength > 0U )
        {
            stunResult = StunSerializer_AddAttributeUsername( &stunCtx, pIceCandidate->iceServerInfo.userName, pIceCandidate->iceServerInfo.userNameLength );

            if( stunResult != STUN_RESULT_OK )
            {
                result = ICE_RESULT_STUN_ERROR_ADD_USERNAME;
            }
        }
    }

    if( result == ICE_RESULT_OK )
    {
        if( pIceCandidate->iceServerInfo.realmLength > 0U )
        {
            stunResult = StunSerializer_AddAttributeRealm( &stunCtx, pIceCandidate->iceServerInfo.realm, pIceCandidate->iceServerInfo.realmLength );

            if( stunResult != STUN_RESULT_OK )
            {
                result = ICE_RESULT_STUN_ERROR_ADD_REALM;
            }
        }
    }

    if( result == ICE_RESULT_OK )
    {
        if( pIceCandidate->iceServerInfo.nonceLength > 0U )
        {
            stunResult = StunSerializer_AddAttributeNonce( &stunCtx, pIceCandidate->iceServerInfo.nonce, pIceCandidate->iceServerInfo.nonceLength );

            if( stunResult != STUN_RESULT_OK )
            {
                result = ICE_RESULT_STUN_ERROR_ADD_NONCE;
            }
        }
    }

    if( result == ICE_RESULT_OK )
    {
        if( pIceCandidate->iceServerInfo.realmLength > 0 )
        {
            /* We already have long-term key retrieved from username, realm and password. */
            result = Ice_FinalizeStunPacket( pContext,
                                             &( stunCtx ),
                                             pIceCandidate->iceServerInfo.longTermPassword,
                                             pIceCandidate->iceServerInfo.longTermPasswordLength,
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
static IceResult_t CreateRequestForCreatePermission( IceContext_t * pContext,
                                                     IceCandidatePair_t * pIceCandidatePair,
                                                     uint8_t * pStunMessageBuffer,
                                                     size_t * pStunMessageBufferLength )
{
    IceResult_t result = ICE_RESULT_OK;
    StunContext_t stunCtx;
    StunHeader_t stunHeader;
    StunResult_t stunResult = STUN_RESULT_OK;

    /* Other input parameters are checked before calling. */
    if( ( pIceCandidatePair->pLocalCandidate == NULL ) ||
        ( pIceCandidatePair->pRemoteCandidate == NULL ) )
    {
        result = ICE_RESULT_BAD_PARAM;
    }
    else if( pIceCandidatePair->pLocalCandidate->candidateType != ICE_CANDIDATE_TYPE_RELAY )
    {
        result = ICE_RESULT_INVALID_CANDIDATE_TYPE;
    }
    else if( ( pIceCandidatePair->pLocalCandidate->iceServerInfo.longTermPasswordLength <= 0 ) ||
             ( pIceCandidatePair->pLocalCandidate->iceServerInfo.realmLength <= 0 ) ||
             ( pIceCandidatePair->pLocalCandidate->iceServerInfo.nonceLength <= 0 ) )
    {
        result = ICE_RESULT_INVALID_CANDIDATE_CREDENTIAL;
    }
    else
    {
        /* Empty else marker. */
    }

    if( result == ICE_RESULT_OK )
    {
        stunHeader.messageType = STUN_MESSAGE_TYPE_CREATE_PERMISSION_REQUEST;
        stunHeader.pTransactionId = pIceCandidatePair->transactionId;

        stunResult = StunSerializer_Init( &stunCtx,
                                          pStunMessageBuffer,
                                          *pStunMessageBufferLength,
                                          &stunHeader );

        if( stunResult != STUN_RESULT_OK )
        {
            result = ICE_RESULT_STUN_ERROR;
        }
    }

    if( result == ICE_RESULT_OK )
    {
        stunResult = StunSerializer_AddAttributeAddress( &stunCtx,
                                                         &pIceCandidatePair->pRemoteCandidate->endpoint.transportAddress,
                                                         STUN_ATTRIBUTE_TYPE_XOR_PEER_ADDRESS );

        if( stunResult != STUN_RESULT_OK )
        {
            result = ICE_RESULT_STUN_ERROR_ADD_XOR_PEER_ADDRESS;
        }
    }

    if( result == ICE_RESULT_OK )
    {
        stunResult = StunSerializer_AddAttributeUsername( &stunCtx, pIceCandidatePair->pLocalCandidate->iceServerInfo.userName, pIceCandidatePair->pLocalCandidate->iceServerInfo.userNameLength );

        if( stunResult != STUN_RESULT_OK )
        {
            result = ICE_RESULT_STUN_ERROR_ADD_USERNAME;
        }
    }

    if( result == ICE_RESULT_OK )
    {
        stunResult = StunSerializer_AddAttributeRealm( &stunCtx, pIceCandidatePair->pLocalCandidate->iceServerInfo.realm, pIceCandidatePair->pLocalCandidate->iceServerInfo.realmLength );

        if( stunResult != STUN_RESULT_OK )
        {
            result = ICE_RESULT_STUN_ERROR_ADD_REALM;
        }
    }

    if( result == ICE_RESULT_OK )
    {
        stunResult = StunSerializer_AddAttributeNonce( &stunCtx, pIceCandidatePair->pLocalCandidate->iceServerInfo.nonce, pIceCandidatePair->pLocalCandidate->iceServerInfo.nonceLength );

        if( stunResult != STUN_RESULT_OK )
        {
            result = ICE_RESULT_STUN_ERROR_ADD_NONCE;
        }
    }

    if( result == ICE_RESULT_OK )
    {
        /* We already have long-term key retrieved from username, realm and password. */
        result = Ice_FinalizeStunPacket( pContext,
                                         &stunCtx,
                                         pIceCandidatePair->pLocalCandidate->iceServerInfo.longTermPassword,
                                         pIceCandidatePair->pLocalCandidate->iceServerInfo.longTermPasswordLength,
                                         pStunMessageBufferLength );
    }

    return result;
}

/*----------------------------------------------------------------------------*/

/* CreateRequestForChannelBind - This API creates Stun Packet for
 * TURN channel bind.
 */
static IceResult_t CreateRequestForChannelBind( IceContext_t * pContext,
                                                IceCandidatePair_t * pIceCandidatePair,
                                                uint8_t * pStunMessageBuffer,
                                                size_t * pStunMessageBufferLength )
{
    IceResult_t result = ICE_RESULT_OK;
    StunContext_t stunCtx;
    StunHeader_t stunHeader;
    StunResult_t stunResult = STUN_RESULT_OK;

    /* Other input parameters are checked before calling. */
    if( ( pIceCandidatePair->pLocalCandidate == NULL ) ||
        ( pIceCandidatePair->pRemoteCandidate == NULL ) )
    {
        result = ICE_RESULT_BAD_PARAM;
    }
    else if( pIceCandidatePair->pLocalCandidate->candidateType != ICE_CANDIDATE_TYPE_RELAY )
    {
        result = ICE_RESULT_INVALID_CANDIDATE_TYPE;
    }
    else if( ( pIceCandidatePair->pLocalCandidate->iceServerInfo.longTermPasswordLength <= 0 ) ||
             ( pIceCandidatePair->pLocalCandidate->iceServerInfo.realmLength <= 0 ) ||
             ( pIceCandidatePair->pLocalCandidate->iceServerInfo.nonceLength <= 0 ) )
    {
        result = ICE_RESULT_INVALID_CANDIDATE_CREDENTIAL;
    }
    else
    {
        /* Empty else marker. */
    }

    if( result == ICE_RESULT_OK )
    {
        stunHeader.messageType = STUN_MESSAGE_TYPE_CHANNEL_BIND_REQUEST;
        stunHeader.pTransactionId = pIceCandidatePair->transactionId;

        stunResult = StunSerializer_Init( &stunCtx,
                                          pStunMessageBuffer,
                                          *pStunMessageBufferLength,
                                          &stunHeader );

        if( stunResult != STUN_RESULT_OK )
        {
            result = ICE_RESULT_STUN_ERROR;
        }
    }

    if( result == ICE_RESULT_OK )
    {
        stunResult = StunSerializer_AddAttributeAddress( &stunCtx,
                                                         &pIceCandidatePair->pRemoteCandidate->endpoint.transportAddress,
                                                         STUN_ATTRIBUTE_TYPE_XOR_PEER_ADDRESS );

        if( stunResult != STUN_RESULT_OK )
        {
            result = ICE_RESULT_STUN_ERROR_ADD_XOR_PEER_ADDRESS;
        }
    }

    if( result == ICE_RESULT_OK )
    {
        stunResult = StunSerializer_AddAttributeChannelNumber( &stunCtx, pIceCandidatePair->turnChannelNumber );

        if( stunResult != STUN_RESULT_OK )
        {
            result = ICE_RESULT_STUN_ERROR_ADD_CHANNEL_NUMBER;
        }
    }

    if( result == ICE_RESULT_OK )
    {
        stunResult = StunSerializer_AddAttributeUsername( &stunCtx, pIceCandidatePair->pLocalCandidate->iceServerInfo.userName, pIceCandidatePair->pLocalCandidate->iceServerInfo.userNameLength );

        if( stunResult != STUN_RESULT_OK )
        {
            result = ICE_RESULT_STUN_ERROR_ADD_USERNAME;
        }
    }

    if( result == ICE_RESULT_OK )
    {
        stunResult = StunSerializer_AddAttributeRealm( &stunCtx, pIceCandidatePair->pLocalCandidate->iceServerInfo.realm, pIceCandidatePair->pLocalCandidate->iceServerInfo.realmLength );

        if( stunResult != STUN_RESULT_OK )
        {
            result = ICE_RESULT_STUN_ERROR_ADD_REALM;
        }
    }

    if( result == ICE_RESULT_OK )
    {
        stunResult = StunSerializer_AddAttributeNonce( &stunCtx, pIceCandidatePair->pLocalCandidate->iceServerInfo.nonce, pIceCandidatePair->pLocalCandidate->iceServerInfo.nonceLength );

        if( stunResult != STUN_RESULT_OK )
        {
            result = ICE_RESULT_STUN_ERROR_ADD_NONCE;
        }
    }

    if( result == ICE_RESULT_OK )
    {
        /* We already have long-term key retrieved from username, realm and password. */
        result = Ice_FinalizeStunPacket( pContext,
                                         &stunCtx,
                                         pIceCandidatePair->pLocalCandidate->iceServerInfo.longTermPassword,
                                         pIceCandidatePair->pLocalCandidate->iceServerInfo.longTermPasswordLength,
                                         pStunMessageBufferLength );
    }

    return result;
}

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
        ( pInitInfo->cryptoFunctions.md5Fxn == NULL ) ||
        ( pInitInfo->creds.pLocalUsername == NULL ) ||
        ( pInitInfo->creds.pLocalPassword == NULL ) ||
        ( pInitInfo->creds.pRemoteUsername == NULL ) ||
        ( pInitInfo->creds.pRemotePassword == NULL ) ||
        ( pInitInfo->creds.pCombinedUsername == NULL ) ||
        ( pInitInfo->getCurrentTimeSecondsFxn == NULL ) )
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
        pContext->getCurrentTimeSecondsFxn = pInitInfo->getCurrentTimeSecondsFxn;

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

        pHostCandidate->candidateId = pContext->nextCandidateId++;

        /* Create candidate pairs with all the existing remote candidates. */
        for( i = 0; ( i < pContext->numRemoteCandidates ) && ( result == ICE_RESULT_OK ); i++ )
        {
            result = Ice_AddCandidatePair( pContext,
                                           pHostCandidate,
                                           &( pContext->pRemoteCandidates[ i ] ),
                                           NULL );
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
    IceResult_t result = ICE_RESULT_OK;
    IceCandidate_t * pServerReflexiveCandidate = NULL;

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

        pServerReflexiveCandidate->candidateId = pContext->nextCandidateId++;
    }

    if( result == ICE_RESULT_OK )
    {
        result = CreateServerReflexiveBindingRequest( pContext,
                                                      pServerReflexiveCandidate,
                                                      pStunMessageBuffer,
                                                      pStunMessageBufferLength );
    }

    return result;
}

/*----------------------------------------------------------------------------*/

IceResult_t Ice_AddRelayCandidate( IceContext_t * pContext,
                                   const IceEndpoint_t * pEndpoint,
                                   char * pUsername,
                                   size_t usernameLength,
                                   char * pPassword,
                                   size_t passwordLength )
{
    IceResult_t result = ICE_RESULT_OK;
    IceCandidate_t * pRelayCandidate = NULL;

    if( ( pContext == NULL ) ||
        ( pEndpoint == NULL ) ||
        ( pUsername == NULL ) ||
        ( pPassword == NULL ) )
    {
        result = ICE_RESULT_BAD_PARAM;
    }
    else if( ( usernameLength > ICE_SERVER_CONFIG_MAX_USER_NAME_LENGTH ) ||
             ( passwordLength > ICE_SERVER_CONFIG_MAX_PASSWORD_LENGTH ) )
    {
        result = ICE_RESULT_BAD_PARAM;
    }
    else
    {
        /* Empty else marker. */
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
        pRelayCandidate = &( pContext->pLocalCandidates[ pContext->numLocalCandidates ] );
        pContext->numLocalCandidates += 1;

        memcpy( pRelayCandidate->iceServerInfo.userName, pUsername, ICE_SERVER_CONFIG_MAX_USER_NAME_LENGTH );
        pRelayCandidate->iceServerInfo.userNameLength = usernameLength;

        memcpy( pRelayCandidate->iceServerInfo.password, pPassword, ICE_SERVER_CONFIG_MAX_PASSWORD_LENGTH );
        pRelayCandidate->iceServerInfo.passwordLength = passwordLength;

        pRelayCandidate->candidateType = ICE_CANDIDATE_TYPE_RELAY;
        pRelayCandidate->isRemote = 0;
        memcpy( &( pRelayCandidate->endpoint ),
                pEndpoint,
                sizeof( IceEndpoint_t ) );
        pRelayCandidate->priority = Ice_ComputeCandidatePriority( ICE_CANDIDATE_TYPE_RELAY,
                                                                  pEndpoint->isPointToPoint );
        pRelayCandidate->remoteProtocol = ICE_SOCKET_PROTOCOL_NONE;
        pRelayCandidate->state = ICE_CANDIDATE_STATE_ALLOCATING;

        pRelayCandidate->candidateId = pContext->nextCandidateId++;
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
    IceCandidatePair_t * pIceCandidatePair = NULL;

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
            pRemoteCandidate->candidateId = pContext->nextCandidateId++;

            /* Create candidate pairs with all the existing local candidates. */
            for( i = 0; ( i < pContext->numLocalCandidates ) && ( result == ICE_RESULT_OK ); i++ )
            {
                if( pContext->pLocalCandidates[ i ].state == ICE_CANDIDATE_STATE_VALID )
                {
                    result = Ice_AddCandidatePair( pContext,
                                                   &( pContext->pLocalCandidates[ i ] ),
                                                   pRemoteCandidate,
                                                   &pIceCandidatePair );

                    /* Update turn channel number when the local candidate type is relay. */
                    if( ( result == ICE_RESULT_OK ) && ( pContext->pLocalCandidates[ i ].candidateType == ICE_CANDIDATE_TYPE_RELAY ) )
                    {
                        pIceCandidatePair->turnChannelNumber = pContext->pLocalCandidates[ i ].nextAvailableTurnChannelNumber;
                        pContext->pLocalCandidates[ i ].nextAvailableTurnChannelNumber++;
                    }
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
            if( &pContext->pCandidatePairs[i] == pIceCandidatePair )
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
                                                  IceCandidate_t * pLocalCandidate,
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
                    transactionIdStoreResult = TransactionIdStore_HasId( pContext->pStunBindingRequestTransactionIdStore,
                                                                         stunHeader.pTransactionId );

                    if( transactionIdStoreResult == TRANSACTION_ID_STORE_RESULT_OK )
                    {
                        handleStunPacketResult = Ice_HandleTurnAllocateSuccessResponse( pContext,
                                                                                        &( stunCtx ),
                                                                                        &( stunHeader ),
                                                                                        pLocalCandidate );

                        ( void ) TransactionIdStore_Remove( pContext->pStunBindingRequestTransactionIdStore,
                                                            stunHeader.pTransactionId );
                    }
                    else
                    {
                        /* Drop the packet if we haven't sent the allocation request. */
                        handleStunPacketResult = ICE_HANDLE_STUN_PACKET_RESULT_DROP_PACKET;
                    }
                }
                break;

                case STUN_MESSAGE_TYPE_ALLOCATE_ERROR_RESPONSE:
                {
                    transactionIdStoreResult = TransactionIdStore_HasId( pContext->pStunBindingRequestTransactionIdStore,
                                                                         stunHeader.pTransactionId );

                    if( transactionIdStoreResult == TRANSACTION_ID_STORE_RESULT_OK )
                    {
                        handleStunPacketResult = Ice_HandleTurnAllocateErrorResponse( pContext,
                                                                                      &( stunCtx ),
                                                                                      &( stunHeader ),
                                                                                      pLocalCandidate );

                        ( void ) TransactionIdStore_Remove( pContext->pStunBindingRequestTransactionIdStore,
                                                            stunHeader.pTransactionId );
                    }
                    else
                    {
                        /* Drop the packet if we haven't sent the allocation request. */
                        handleStunPacketResult = ICE_HANDLE_STUN_PACKET_RESULT_DROP_PACKET;
                    }
                }
                break;

                case STUN_MESSAGE_TYPE_CREATE_PERMISSION_SUCCESS_RESPONSE:
                {
                    handleStunPacketResult = Ice_HandleTurnCreatePermissionSuccessResponse( pContext,
                                                                                            &( stunCtx ),
                                                                                            &( stunHeader ),
                                                                                            pLocalCandidate,
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
                    transactionIdStoreResult = TransactionIdStore_HasId( pContext->pStunBindingRequestTransactionIdStore,
                                                                         stunHeader.pTransactionId );

                    if( transactionIdStoreResult == TRANSACTION_ID_STORE_RESULT_OK )
                    {
                        handleStunPacketResult = Ice_HandleTurnRefreshSuccessResponse( pContext,
                                                                                       &( stunCtx ),
                                                                                       &( stunHeader ),
                                                                                       pLocalCandidate );

                        ( void ) TransactionIdStore_Remove( pContext->pStunBindingRequestTransactionIdStore,
                                                            stunHeader.pTransactionId );
                    }
                    else
                    {
                        /* Drop the packet if we haven't sent the allocation request. */
                        handleStunPacketResult = ICE_HANDLE_STUN_PACKET_RESULT_DROP_PACKET;
                    }
                }
                break;

                case STUN_MESSAGE_TYPE_REFRESH_ERROR_RESPONSE:
                {
                    transactionIdStoreResult = TransactionIdStore_HasId( pContext->pStunBindingRequestTransactionIdStore,
                                                                         stunHeader.pTransactionId );

                    if( transactionIdStoreResult == TRANSACTION_ID_STORE_RESULT_OK )
                    {
                        handleStunPacketResult = Ice_HandleTurnRefreshErrorResponse( pContext,
                                                                                     &( stunCtx ),
                                                                                     &( stunHeader ),
                                                                                     pLocalCandidate );

                        ( void ) TransactionIdStore_Remove( pContext->pStunBindingRequestTransactionIdStore,
                                                            stunHeader.pTransactionId );
                    }
                    else
                    {
                        /* Drop the packet if we haven't sent the allocation request. */
                        handleStunPacketResult = ICE_HANDLE_STUN_PACKET_RESULT_DROP_PACKET;
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
                                            uint8_t * pStunMessageBuffer,
                                            size_t * pStunMessageBufferLength )
{
    IceResult_t result = ICE_RESULT_OK;

    if( ( pContext == NULL ) ||
        ( pIceCandidate == NULL ) ||
        ( pStunMessageBuffer == NULL ) ||
        ( pStunMessageBufferLength == NULL ) )
    {
        result = ICE_RESULT_BAD_PARAM;
    }
    else if( pIceCandidate->isRemote != 0 )
    {
        result = ICE_RESULT_INVALID_CANDIDATE;
    }
    else
    {
        /* Empty else marker. */
    }

    if( result == ICE_RESULT_OK )
    {
        if( pIceCandidate->candidateType == ICE_CANDIDATE_TYPE_SERVER_REFLEXIVE )
        {
            /* Generate STUN request for srflx candidate to query external IP address. */
            if( pIceCandidate->state == ICE_CANDIDATE_STATE_NEW )
            {
                result = CreateServerReflexiveBindingRequest( pContext,
                                                              pIceCandidate,
                                                              pStunMessageBuffer,
                                                              pStunMessageBufferLength );
            }
            else
            {
                /* If the srflx candidate already have the external IP address,
                 * then we return ICE_RESULT_NO_NEXT_ACTION. */
                result = ICE_RESULT_NO_NEXT_ACTION;
            }
        }
        else if( pIceCandidate->candidateType == ICE_CANDIDATE_TYPE_RELAY )
        {
            /* Generate TURN Allocation request for relay candidate to allocate TURN resource. */
            if( pIceCandidate->state == ICE_CANDIDATE_STATE_ALLOCATING )
            {
                result = CreateAllocationRequest( pContext,
                                                  pIceCandidate,
                                                  pStunMessageBuffer,
                                                  pStunMessageBufferLength );
            }
            else if( pIceCandidate->state == ICE_CANDIDATE_STATE_RELEASING )
            {
                result = CreateRefreshRequest( pContext,
                                               pIceCandidate,
                                               0U,
                                               pStunMessageBuffer,
                                               pStunMessageBufferLength );
            }
            else
            {
                /* If the srflx candidate already have the external IP address,
                 * then we return ICE_RESULT_NO_NEXT_ACTION. */
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
                    /* Generate nominate binding request. */
                    result = Ice_CreateRequestForNominatingCandidatePair( pContext,
                                                                          pIceCandidatePair,
                                                                          pStunMessageBuffer,
                                                                          pStunMessageBufferLength );
                }
                else
                {
                    /* Controlled side might receive USE-CANDIDATE in connectivity check stage.
                     * So we keep sending connectivity check even though we're in nominated state.
                     * Note that controlled side will mark state into succeed when receive USE-CANDIDATE
                     * Binding Request. */
                    result = Ice_CreateRequestForConnectivityCheck( pContext,
                                                                    pIceCandidatePair,
                                                                    pStunMessageBuffer,
                                                                    pStunMessageBufferLength );
                }
            }
            break;

            case ICE_CANDIDATE_PAIR_STATE_CREATE_PERMISSION:
            {
                /* Generate STUN request for TURN create permission. */
                result = CreateRequestForCreatePermission( pContext,
                                                           pIceCandidatePair,
                                                           pStunMessageBuffer,
                                                           pStunMessageBufferLength );
            }
            break;

            case ICE_CANDIDATE_PAIR_STATE_CHANNEL_BIND:
            {
                /* Generate STUN request for TURN create permission. */
                result = CreateRequestForChannelBind( pContext,
                                                      pIceCandidatePair,
                                                      pStunMessageBuffer,
                                                      pStunMessageBufferLength );
            }
            break;

            case ICE_CANDIDATE_PAIR_STATE_VALID:
            case ICE_CANDIDATE_PAIR_STATE_SUCCEEDED:
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

IceResult_t Ice_AppendTurnChannelHeader( IceContext_t * pContext,
                                         IceCandidatePair_t * pIceCandidatePair,
                                         const uint8_t * pInputBuffer,
                                         size_t inputBufferLength,
                                         uint8_t * pOutputBuffer,
                                         size_t * pOutputBufferLength )
{
    IceResult_t result = ICE_RESULT_OK;
    /* Calculate the padding by rounding up to 4. */
    uint16_t padding = ( ( inputBufferLength + 3 ) & ~3 ) - inputBufferLength;

    if( ( pContext == NULL ) ||
        ( pIceCandidatePair == NULL ) ||
        ( pInputBuffer == NULL ) ||
        ( pOutputBuffer == NULL ) ||
        ( pOutputBufferLength == NULL ) )
    {
        result = ICE_RESULT_BAD_PARAM;
    }
    else if( inputBufferLength + ICE_TURN_CHANNEL_DATA_HEADER_LENGTH + padding > *pOutputBufferLength )
    {
        /* We always append 4 bytes prefix into TURN channel message. */
        result = ICE_RESULT_OUT_OF_MEMORY;
    }
    else if( ( pIceCandidatePair->state != ICE_CANDIDATE_PAIR_STATE_WAITING ) &&
             ( pIceCandidatePair->state != ICE_CANDIDATE_PAIR_STATE_VALID ) &&
             ( pIceCandidatePair->state != ICE_CANDIDATE_PAIR_STATE_NOMINATED ) &&
             ( pIceCandidatePair->state != ICE_CANDIDATE_PAIR_STATE_SUCCEEDED ) )
    {
        result = ICE_RESULT_TURN_PREFIX_NOT_REQUIRED;
    }
    else
    {
        /* Empty else marker. */
    }

    if( result == ICE_RESULT_OK )
    {
        IceTurnChannelMessageHeader_t * pTurnChannelMessageHdr = ( IceTurnChannelMessageHeader_t * ) pOutputBuffer;

        /* Append the channel number and payload length, followed by the payload itself.  
         * Finally, add padding to ensure the packet is 4-byte aligned. */
        memcpy( pOutputBuffer + ICE_TURN_CHANNEL_DATA_HEADER_LENGTH, pInputBuffer, inputBufferLength );
        pContext->readWriteFunctions.writeUint16Fn( ( uint8_t * ) &pTurnChannelMessageHdr->channelNumber, pIceCandidatePair->turnChannelNumber );
        pContext->readWriteFunctions.writeUint16Fn( ( uint8_t * ) &pTurnChannelMessageHdr->messageLength, inputBufferLength );
        memset( pOutputBuffer + ICE_TURN_CHANNEL_DATA_HEADER_LENGTH + inputBufferLength, 0, padding );
        *pOutputBufferLength = 4U + inputBufferLength + padding;
    }

    return result;
}

/*----------------------------------------------------------------------------*/

IceResult_t Ice_RemoveTurnChannelHeader( IceContext_t * pContext,
                                         IceCandidate_t * pIceLocalCandidate,
                                         const uint8_t * pInputBuffer,
                                         size_t inputBufferLength,
                                         uint8_t * pOutputBuffer,
                                         size_t * pOutputBufferLength,
                                         IceCandidatePair_t ** ppIceCandidatePair )
{
    IceResult_t result = ICE_RESULT_OK;
    size_t i;
    IceCandidatePair_t * pCandidatePair = NULL;
    IceTurnChannelMessageHeader_t turnChannelMessageHdr;

    if( ( pContext == NULL ) ||
        ( pIceLocalCandidate == NULL ) ||
        ( pInputBuffer == NULL ) ||
        ( pOutputBuffer == NULL ) ||
        ( pOutputBufferLength == NULL ) )
    {
        result = ICE_RESULT_BAD_PARAM;
    }
    else if( inputBufferLength < ICE_TURN_CHANNEL_DATA_HEADER_LENGTH )
    {
        /* The data is less than channel message header. */
        result = ICE_RESULT_DATA_TOO_SMALL;
    }
    else if( inputBufferLength - ICE_TURN_CHANNEL_DATA_HEADER_LENGTH > *pOutputBufferLength )
    {
        /* The output buffer size is too small to store result. */
        result = ICE_RESULT_OUT_OF_MEMORY;
    }
    else if( pIceLocalCandidate->candidateType != ICE_CANDIDATE_TYPE_RELAY )
    {
        result = ICE_RESULT_TURN_PREFIX_NOT_REQUIRED;
    }
    else if( pIceLocalCandidate->state != ICE_CANDIDATE_STATE_VALID )
    {
        result = ICE_RESULT_TURN_PREFIX_NOT_REQUIRED;
    }
    else if( ( pInputBuffer[0] & 0xF0 ) != 0x40 )
    {
        /* The first byte must be channel number, which must be in the range of 0x4000~0x4FFF. */
        result = ICE_RESULT_TURN_PREFIX_NOT_REQUIRED;
    }
    else
    {
        /* Empty else marker. */
    }

    if( result == ICE_RESULT_OK )
    {
        turnChannelMessageHdr.channelNumber = pContext->readWriteFunctions.readUint16Fn( ( uint8_t * ) &pOutputBuffer[ 0 ] );
        turnChannelMessageHdr.messageLength = pContext->readWriteFunctions.readUint16Fn( ( uint8_t * ) &pOutputBuffer[ 2 ] );

        if( turnChannelMessageHdr.messageLength > inputBufferLength - ICE_TURN_CHANNEL_DATA_HEADER_LENGTH )
        {
            result = ICE_RESULT_TURN_LENGTH_INVALID;
        }
    }

    if( result == ICE_RESULT_OK )
    {
        for( i = 0; i < pContext->numCandidatePairs; i++ )
        {
            if( ( Ice_IsSameTransportAddress( &( pContext->pCandidatePairs[i].pLocalCandidate->endpoint.transportAddress ),
                                              &( pIceLocalCandidate->endpoint.transportAddress ) ) == 1 ) &&
                ( turnChannelMessageHdr.channelNumber == pContext->pCandidatePairs[i].turnChannelNumber ) )
            {
                pCandidatePair = &pContext->pCandidatePairs[i];
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
        /* Move the buffer for 4 bytes to remove channel message header. */
        memcpy( pOutputBuffer, pInputBuffer + ICE_TURN_CHANNEL_DATA_HEADER_LENGTH, turnChannelMessageHdr.messageLength );
        *pOutputBufferLength = turnChannelMessageHdr.messageLength;

        if( ppIceCandidatePair != NULL )
        {
            *ppIceCandidatePair = pCandidatePair;
        }
    }

    return result;
}

/*----------------------------------------------------------------------------*/

IceResult_t Ice_CheckTurnConnection( IceContext_t * pContext,
                                     IceCandidatePair_t * pIceCandidatePair )
{
    IceResult_t result = ICE_RESULT_OK;
    IceCandidate_t * pLocalCandidate = NULL;
    uint64_t currentTime;

    if( ( pContext == NULL ) || ( pIceCandidatePair == NULL ) )
    {
        result = ICE_RESULT_BAD_PARAM;
    }

    if( result == ICE_RESULT_OK )
    {
        pLocalCandidate = pIceCandidatePair->pLocalCandidate;

        if( ( pLocalCandidate->candidateType != ICE_CANDIDATE_TYPE_RELAY ) ||
            ( pLocalCandidate->state != ICE_CANDIDATE_STATE_VALID ) )
        {
            result = ICE_RESULT_NO_NEXT_ACTION;
        }
    }

    /* Check allocation expiration. */
    if( result == ICE_RESULT_OK )
    {
        currentTime = pContext->getCurrentTimeSecondsFxn();
        if( currentTime + ICE_TURN_ALLOCATION_REFRESH_GRACE_PERIOD_SECONDS >= pLocalCandidate->turnAllocationExpirationSeconds )
        {
            result = ICE_RESULT_NEED_REFRESH_CANDIDATE;
        }
    }

    /* Check permission expiration. */
    if( result == ICE_RESULT_OK )
    {
        if( currentTime + ICE_TURN_PERMISSION_REFRESH_GRACE_PERIOD_SECONDS >= pIceCandidatePair->turnPermissionExpirationSeconds )
        {
            result = ICE_RESULT_NEED_REFRESH_PERMISSION;
        }
    }

    if( result == ICE_RESULT_OK )
    {
        result = ICE_RESULT_NO_NEXT_ACTION;
    }

    return result;
}

/*----------------------------------------------------------------------------*/

IceResult_t Ice_CreateTurnRefreshRequest( IceContext_t * pContext,
                                          IceCandidate_t * pIceCandidate,
                                          uint8_t * pStunMessageBuffer,
                                          size_t * pStunMessageBufferLength )
{
    IceResult_t result = ICE_RESULT_OK;

    if( ( pContext == NULL ) || ( pIceCandidate == NULL ) || ( pStunMessageBuffer == NULL ) || ( pStunMessageBufferLength == NULL ) )
    {
        result = ICE_RESULT_BAD_PARAM;
    }
    else if( ( pIceCandidate->candidateType != ICE_CANDIDATE_TYPE_RELAY ) ||
             ( pIceCandidate->state != ICE_CANDIDATE_STATE_VALID ) ||
             ( pContext->getCurrentTimeSecondsFxn() + ICE_TURN_ALLOCATION_REFRESH_GRACE_PERIOD_SECONDS < pIceCandidate->turnAllocationExpirationSeconds ) )
    {
        result = ICE_RESULT_NO_NEXT_ACTION;
    }
    else
    {
        /* Empty else marker. */
    }

    if( result == ICE_RESULT_OK )
    {
        result = CreateRefreshRequest( pContext,
                                       pIceCandidate,
                                       ICE_DEFAULT_TURN_ALLOCATION_LIFETIME_SECONDS,
                                       pStunMessageBuffer,
                                       pStunMessageBufferLength );
    }

    return result;
}

/*----------------------------------------------------------------------------*/

IceResult_t Ice_CreateTurnRefreshPermissionRequest( IceContext_t * pContext,
                                                    IceCandidatePair_t * pIceCandidatePair,
                                                    uint8_t * pStunMessageBuffer,
                                                    size_t * pStunMessageBufferLength )
{
    IceResult_t result = ICE_RESULT_OK;
    uint64_t currentTime;
    IceCandidate_t * pLocalCandidate = NULL;

    if( ( pContext == NULL ) || ( pIceCandidatePair == NULL ) || ( pStunMessageBuffer == NULL ) || ( pStunMessageBufferLength == NULL ) )
    {
        result = ICE_RESULT_BAD_PARAM;
    }

    if( result == ICE_RESULT_OK )
    {
        pLocalCandidate = pIceCandidatePair->pLocalCandidate;

        if( ( pLocalCandidate == NULL ) ||
            ( pLocalCandidate->candidateType != ICE_CANDIDATE_TYPE_RELAY ) ||
            ( pIceCandidatePair->state != ICE_CANDIDATE_PAIR_STATE_SUCCEEDED ) )
        {
            result = ICE_RESULT_NO_NEXT_ACTION;
        }
    }

    /* Check permission expiration. */
    if( result == ICE_RESULT_OK )
    {
        currentTime = pContext->getCurrentTimeSecondsFxn();
        if( currentTime + ICE_TURN_PERMISSION_REFRESH_GRACE_PERIOD_SECONDS < pIceCandidatePair->turnPermissionExpirationSeconds )
        {
            result = ICE_RESULT_NO_NEXT_ACTION;
        }
    }

    if( result == ICE_RESULT_OK )
    {
        result = CreateRequestForCreatePermission( pContext,
                                                   pIceCandidatePair,
                                                   pStunMessageBuffer,
                                                   pStunMessageBufferLength );
    }

    return result;
}

/*----------------------------------------------------------------------------*/
