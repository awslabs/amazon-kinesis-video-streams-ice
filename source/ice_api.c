/* Standard includes. */
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>

/* API includes. */
#include "ice_api.h"
#include "ice_api_private.h"

/* STUN API includes. */
#include "stun_data_types.h"
#include "stun_serializer.h"
#include "stun_deserializer.h"

/*------------------------------------------------------------------------------------------------------------------*/

/* Ice_CreateIceAgent - The application calls this API for starting a new 
 * ICE agent. */

IceResult_t Ice_CreateIceAgent( IceAgent_t * pIceAgent,
                                char * pLocalUsername,
                                char * pLocalPassword,
                                char * pRemoteUsername,
                                char * pRemotePassword,
                                char * pCombinedUsername,
                                TransactionIdStore_t * pBuffer,
                                Ice_ComputeRandom computeRandomFunction,
                                Ice_ComputeCrc32 computeCRC32Function,
                                Ice_ComputeHMAC computeHMACFunction )
{
    int i;
    IceResult_t retStatus = ICE_RESULT_OK;

    if( ( pIceAgent == NULL ) ||
        ( pLocalPassword == NULL ) ||
        ( strlen( pLocalPassword ) > ( ICE_MAX_CONFIG_CREDENTIAL_LEN + 1 ) ) ||
        ( pLocalUsername == NULL ) ||
        ( strlen( pLocalUsername ) > ( ICE_MAX_CONFIG_USER_NAME_LEN + 1 ) ) ||
        ( pRemotePassword == NULL ) ||
        ( strlen( pRemotePassword ) > ( ICE_MAX_CONFIG_CREDENTIAL_LEN + 1 ) ) ||
        ( pRemoteUsername == NULL ) ||
        ( strlen( pRemoteUsername ) > ( ICE_MAX_CONFIG_USER_NAME_LEN + 1 ) ) ||
        ( pCombinedUsername == NULL ) ||
        ( strlen( pCombinedUsername ) > ( ( ICE_MAX_CONFIG_USER_NAME_LEN + 1 ) << 1 ) ) ||
        ( pBuffer == NULL ) )
    {
        retStatus = ICE_RESULT_BAD_PARAM;
    }

    if( retStatus == ICE_RESULT_OK )
    {
        memset( pIceAgent,
                0,
                sizeof( IceAgent_t ) );

        memcpy( pIceAgent->localUsername,
                pLocalUsername,
                strlen( pLocalUsername ) );
        memcpy( pIceAgent->localPassword,
                pLocalPassword,
                strlen( pLocalPassword ) );
        memcpy( pIceAgent->remoteUsername,
                pRemoteUsername,
                strlen( pRemoteUsername ) );
        memcpy( pIceAgent->remotePassword,
                pRemotePassword,
                strlen( pRemotePassword ) );
        memcpy( pIceAgent->combinedUserName,
                pCombinedUsername,
                strlen( pCombinedUsername ) );

        pIceAgent->pStunBindingRequestTransactionIdStore = pBuffer;
        retStatus = Ice_CreateTransactionIdStore( ICE_DEFAULT_MAX_STORED_TRANSACTION_ID_COUNT,
                                                  pIceAgent->pStunBindingRequestTransactionIdStore );
    }

    if( retStatus == ICE_RESULT_OK )
    {
        pIceAgent->isControlling = 0;

        pIceAgent->computeRandom = computeRandomFunction;
        pIceAgent->computeCRC32 = computeCRC32Function;
        pIceAgent->computeHMAC = computeHMACFunction;

        /* This field is required as an attribute during creation of STUN packet. */
        pIceAgent->tieBreaker = pIceAgent->computeRandom();
    }

    return retStatus;
}
/*------------------------------------------------------------------------------------------------------------------*/

/* Ice_AddHostCandidate - The application calls this API for adding host candidate. */

IceResult_t Ice_AddHostCandidate( IceAgent_t * pIceAgent,
                                  const IceIPAddress_t ipAddr,
                                  IceCandidate_t ** ppCandidate )
{
    IceResult_t retStatus = ICE_RESULT_OK;
    int localCandidateCount = 0;
    IceCandidate_t * pIceCandidate = NULL;

    if( ( pIceAgent == NULL ) ||
        ( ppCandidate == NULL ) )
    {
        retStatus = ICE_RESULT_BAD_PARAM;
    }
    else
    {
        localCandidateCount = Ice_GetValidLocalCandidateCount( pIceAgent );

        if( localCandidateCount >= ICE_MAX_LOCAL_CANDIDATE_COUNT )
        {
            retStatus = ICE_RESULT_MAX_CANDIDATE_THRESHOLD;
        }
        else
        {
            pIceCandidate = &( pIceAgent->localCandidates[ localCandidateCount ] );
        }

        if( retStatus == ICE_RESULT_OK )
        {
            pIceCandidate->isRemote = 0;
            memcpy( &( pIceCandidate->ipAddress ),
                    &( ipAddr ),
                    sizeof( IceIPAddress_t ) );
            pIceCandidate->iceCandidateType = ICE_CANDIDATE_TYPE_HOST;
            pIceCandidate->state = ICE_CANDIDATE_STATE_VALID;
            pIceCandidate->priority = Ice_ComputeCandidatePriority( pIceCandidate );
        }

        if( retStatus == ICE_RESULT_OK )
        {
            *ppCandidate = pIceCandidate;
        }
    }

    return retStatus;
}
/*------------------------------------------------------------------------------------------------------------------*/

/* Ice_AddSrflxCandidate - The application calls this API for adding Server Reflexive candidate. */

IceResult_t Ice_AddSrflxCandidate( IceAgent_t * pIceAgent,
                                   const IceIPAddress_t ipAddr,
                                   IceCandidate_t ** ppCandidate,
                                   uint8_t * pTransactionIdBuffer,
                                   uint8_t ** ppSendStunMessageBuffer,
                                   uint32_t * pSendStunMessageBufferLength )
{
    IceResult_t retStatus = ICE_RESULT_OK;
    int localCandidateCount = 0;
    IceCandidate_t * pIceCandidate = NULL;

    if( ( pIceAgent == NULL ) ||
        ( ppCandidate == NULL ) ||
        ( ppSendStunMessageBuffer == NULL ) ||
        ( pSendStunMessageBufferLength == NULL ) ||
        ( pTransactionIdBuffer == NULL ) )
    {
        retStatus = ICE_RESULT_BAD_PARAM;
    }
    else
    {
        localCandidateCount = Ice_GetValidLocalCandidateCount( pIceAgent );

        if( localCandidateCount >= ICE_MAX_LOCAL_CANDIDATE_COUNT )
        {
            retStatus = ICE_RESULT_MAX_CANDIDATE_THRESHOLD;
        }
        else
        {
            pIceCandidate = &( pIceAgent->localCandidates[ localCandidateCount ] );
        }

        if( retStatus == ICE_RESULT_OK )
        {
            pIceCandidate->isRemote = 0;
            memcpy( &( pIceCandidate->ipAddress ),
                    &( ipAddr ),
                    sizeof( IceIPAddress_t ) );
            pIceCandidate->iceCandidateType = ICE_CANDIDATE_TYPE_SERVER_REFLEXIVE;
            pIceCandidate->state = ICE_CANDIDATE_STATE_NEW;
            pIceCandidate->priority = Ice_ComputeCandidatePriority( pIceCandidate );

            retStatus = Ice_CreateRequestForSrflxCandidate( pIceAgent,
                                                            &( pIceAgent->stunMessageBuffer[ 0 ] ),
                                                            pTransactionIdBuffer,
                                                            pSendStunMessageBufferLength );

            if( retStatus == ICE_RESULT_OK )
            {
                *ppSendStunMessageBuffer = &( pIceAgent->stunMessageBuffer[ 0 ] );
                *ppCandidate = pIceCandidate;
            }
        }
    }

    return retStatus;
}
/*------------------------------------------------------------------------------------------------------------------*/

/* Ice_AddRemoteCandidate - The application calls this API for adding remote candidates. */

IceResult_t Ice_AddRemoteCandidate( IceAgent_t * pIceAgent,
                                    IceCandidateType_t iceCandidateType,
                                    IceCandidate_t ** ppCandidate,
                                    const IceIPAddress_t ipAddr,
                                    IceSocketProtocol_t remoteProtocol,
                                    const uint32_t priority )
{
    int i;
    int remoteCandidateCount = 0;
    IceResult_t retStatus = ICE_RESULT_OK;
    IceCandidate_t * pIceCandidate = NULL;

    if( ( pIceAgent == NULL ) ||
        ( ppCandidate == NULL ) )
    {
        retStatus = ICE_RESULT_BAD_PARAM;
    }
    else
    {
        remoteCandidateCount = Ice_GetValidRemoteCandidateCount( pIceAgent );

        if( remoteCandidateCount >= ICE_MAX_REMOTE_CANDIDATE_COUNT )
        {
            retStatus = ICE_RESULT_MAX_CANDIDATE_THRESHOLD;
        }
        else
        {
            pIceCandidate = &( pIceAgent->remoteCandidates[ remoteCandidateCount ] );
        }

        if( retStatus == ICE_RESULT_OK )
        {
            pIceCandidate->isRemote = true;
            memcpy( &( pIceCandidate->ipAddress ),
                    &( ipAddr ),
                    sizeof( IceIPAddress_t ) );
            pIceCandidate->state = ICE_CANDIDATE_STATE_VALID;
            pIceCandidate->priority = priority;
            pIceCandidate->iceCandidateType = iceCandidateType;
            pIceCandidate->remoteProtocol = remoteProtocol;
        }

        if( retStatus == ICE_RESULT_OK )
        {
            *ppCandidate = pIceCandidate;

            for( i = 0; ( ( i < Ice_GetValidLocalCandidateCount( pIceAgent ) ) && ( retStatus == ICE_RESULT_OK ) ); i++ )
            {
                if( pIceAgent->localCandidates[ i ].state == ICE_CANDIDATE_STATE_VALID )
                {
                    retStatus = Ice_CreateCandidatePair( pIceAgent,
                                                         &( pIceAgent->localCandidates[ i ] ),
                                                         pIceCandidate );
                }
            }
        }
    }

    return retStatus;
}

/*------------------------------------------------------------------------------------------------------------------*/

/* Ice_CreateRequestForSrflxCandidate - This API creates Stun Packet for sending Srflx candidate request to ICE STUN server. */

IceResult_t Ice_CreateRequestForSrflxCandidate( IceAgent_t * pIceAgent,
                                                uint8_t * pStunMessageBuffer,
                                                uint8_t * pTransactionIdBuffer,
                                                uint32_t * pSendStunMessageBufferLength )
{
    StunContext_t stunCxt;
    StunHeader_t stunHeader;
    IceResult_t retStatus = ICE_RESULT_OK;
    uint8_t needTransactionIDGeneration = 1;
    uint8_t isStunBindingRequest = 1;

    if( ( pIceAgent == NULL ) ||
        ( pStunMessageBuffer == NULL ) ||
        ( pTransactionIdBuffer == NULL ) ||
        ( pSendStunMessageBufferLength == NULL ) )
    {
        retStatus = ICE_RESULT_BAD_PARAM;
    }

    if( retStatus == ICE_RESULT_OK )
    {
        retStatus = Ice_InitializeStunPacket( pIceAgent,
                                              &( stunCxt ),
                                              pTransactionIdBuffer,
                                              pStunMessageBuffer,
                                              &( stunHeader ),
                                              needTransactionIDGeneration,
                                              isStunBindingRequest );

        if( retStatus == ICE_RESULT_OK )
        {
            Ice_TransactionIdStoreInsert( pIceAgent->pStunBindingRequestTransactionIdStore,
                                          stunHeader.pTransactionId );

            retStatus = Ice_PackageStunPacket( pIceAgent,
                                               &( stunCxt ),
                                               NULL,
                                               0,
                                               pSendStunMessageBufferLength );
        }
    }

    return retStatus;
}

/*------------------------------------------------------------------------------------------------------------------*/

/* Ice_CreateRequestForNominatingValidCandidatePair - This API creates Stun Packet for nomination of the valid candidate Pair sent by the Controlling ICE agent. */

IceResult_t Ice_CreateRequestForNominatingValidCandidatePair( IceAgent_t * pIceAgent,
                                                              uint8_t ** ppSendStunMessageBuffer,
                                                              uint32_t * pSendStunMessageBufferLength,
                                                              IceCandidatePair_t * pIceCandidatePair,
                                                              uint8_t * pTransactionIdBuffer )
{
    StunContext_t stunCxt;
    StunHeader_t stunHeader;
    IceResult_t retStatus = ICE_RESULT_OK;
    StunResult_t stunRetStatus = STUN_RESULT_OK;
    uint8_t needTransactionIDGeneration = 1;
    uint8_t isStunBindingRequest = 1;

    if( ( pIceAgent == NULL ) ||
        ( ppSendStunMessageBuffer == NULL ) ||
        ( pSendStunMessageBufferLength == NULL ) ||
        ( pTransactionIdBuffer == NULL ) ||
        ( pIceCandidatePair == NULL ) )
    {
        retStatus = ICE_RESULT_BAD_PARAM;
    }

    if( retStatus == ICE_RESULT_OK )
    {
        retStatus = Ice_InitializeStunPacket( pIceAgent,
                                              &( stunCxt ),
                                              pTransactionIdBuffer,
                                              &( pIceAgent->stunMessageBuffer[ 0 ] ),
                                              &( stunHeader ),
                                              needTransactionIDGeneration,
                                              isStunBindingRequest );

        if( retStatus == ICE_RESULT_OK )
        {
            stunRetStatus = StunSerializer_AddAttributeUsername( &( stunCxt ),
                                                                 pIceAgent->combinedUserName,
                                                                 strlen( pIceAgent->combinedUserName ) );
        }

        if( stunRetStatus == STUN_RESULT_OK )
        {
            stunRetStatus = StunSerializer_AddAttributePriority( &( stunCxt ),
                                                                 pIceCandidatePair->pLocal->priority );
        }

        if( stunRetStatus == STUN_RESULT_OK )
        {
            stunRetStatus = StunSerializer_AddAttributeIceControlling( &( stunCxt ),
                                                                       pIceAgent->tieBreaker );
        }

        if( stunRetStatus == STUN_RESULT_OK )
        {
            stunRetStatus = StunSerializer_AddAttributeUseCandidate( &( stunCxt ) );
        }

        if( stunRetStatus == STUN_RESULT_OK )
        {
            memcpy( pIceCandidatePair->pTransactionIdStore,
                    stunHeader.pTransactionId,
                    STUN_HEADER_TRANSACTION_ID_LENGTH );

            retStatus = Ice_PackageStunPacket( pIceAgent,
                                               &( stunCxt ),
                                               ( uint8_t * ) pIceAgent->remotePassword,
                                               ( uint32_t ) strlen( pIceAgent->remotePassword ) * sizeof( char ),
                                               pSendStunMessageBufferLength );
        }

        if( retStatus == ICE_RESULT_OK )
        {
            *ppSendStunMessageBuffer = &( pIceAgent->stunMessageBuffer[ 0 ] );
        }
    }

    return retStatus;
}

/*------------------------------------------------------------------------------------------------------------------*/

/* Ice_CreateRequestForConnectivityCheck - This API creates Stun Packet for connectivity check to the remote candidate . */

IceResult_t Ice_CreateRequestForConnectivityCheck( IceAgent_t * pIceAgent,
                                                   uint8_t ** ppSendStunMessageBuffer,
                                                   uint32_t * pSendStunMessageBufferLength,
                                                   uint8_t * pTransactionIdBuffer,
                                                   IceCandidatePair_t * pIceCandidatePair )
{
    StunContext_t stunCxt;
    StunHeader_t stunHeader;
    IceResult_t retStatus = ICE_RESULT_OK;
    StunResult_t stunRetStatus = STUN_RESULT_OK;
    uint8_t needTransactionIDGeneration = 1;
    uint8_t isStunBindingRequest = 1;

    if( ( pIceAgent == NULL ) ||
        ( ppSendStunMessageBuffer == NULL ) ||
        ( pSendStunMessageBufferLength == NULL ) ||
        ( pTransactionIdBuffer == NULL ) ||
        ( pIceCandidatePair == NULL ) )
    {
        retStatus = ICE_RESULT_BAD_PARAM;
    }

    if( retStatus == ICE_RESULT_OK )
    {
        retStatus = Ice_InitializeStunPacket( pIceAgent,
                                              &( stunCxt ),
                                              pTransactionIdBuffer,
                                              &( pIceAgent->stunMessageBuffer[ 0 ] ),
                                              &( stunHeader ),
                                              needTransactionIDGeneration,
                                              isStunBindingRequest );

        if( retStatus == ICE_RESULT_OK )
        {
            stunRetStatus = StunSerializer_AddAttributeUsername( &( stunCxt ),
                                                                 pIceAgent->combinedUserName,
                                                                 strlen( pIceAgent->combinedUserName ) );
        }

        if( stunRetStatus == STUN_RESULT_OK )
        {
            stunRetStatus = StunSerializer_AddAttributePriority( &( stunCxt ),
                                                                 pIceCandidatePair->pLocal->priority );
        }

        if( stunRetStatus == STUN_RESULT_OK )
        {
            if( pIceAgent->isControlling == 0 )
            {
                stunRetStatus = StunSerializer_AddAttributeIceControlled( &( stunCxt ),
                                                                          pIceAgent->tieBreaker );
            }
            else
            {
                stunRetStatus = StunSerializer_AddAttributeIceControlling( &( stunCxt ),
                                                                           pIceAgent->tieBreaker );
            }
        }

        if( stunRetStatus == STUN_RESULT_OK )
        {
            memcpy( pIceCandidatePair->pTransactionIdStore,
                    stunHeader.pTransactionId,
                    STUN_HEADER_TRANSACTION_ID_LENGTH );

            retStatus = Ice_PackageStunPacket( pIceAgent,
                                               &( stunCxt ),
                                               ( uint8_t * ) pIceAgent->remotePassword,
                                               ( uint32_t ) strlen( pIceAgent->remotePassword ) * sizeof( char ),
                                               pSendStunMessageBufferLength );
        }

        if( retStatus == ICE_RESULT_OK )
        {
            *ppSendStunMessageBuffer = &( pIceAgent->stunMessageBuffer[ 0 ] );
            pIceCandidatePair->connectivityChecks |= ( 1 << ICE_STUN_REQUEST_LOCAL_REMOTE_BIT0 );
        }
    }

    return retStatus;
}
/*------------------------------------------------------------------------------------------------------------------*/

/* Ice_CreateResponseForRequest - This API creates Stun Packet for response to a Stun Binding Request. */

IceResult_t Ice_CreateResponseForRequest( IceAgent_t * pIceAgent,
                                          uint8_t ** ppSendStunMessageBuffer,
                                          uint32_t * pSendStunMessageBufferLength,
                                          IceIPAddress_t * pSrcAddr,
                                          uint8_t * pTransactionIdBuffer )
{
    StunContext_t stunCxt;
    StunHeader_t stunHeader;
    StunAttributeAddress_t stunMappedAddress;
    IceResult_t retStatus = ICE_RESULT_OK;
    StunResult_t stunRetStatus = STUN_RESULT_OK;
    uint8_t needTransactionIDGeneration = 0;
    uint8_t isStunBindingRequest = 0;

    if( ( pIceAgent == NULL ) ||
        ( ppSendStunMessageBuffer == NULL ) ||
        ( pSendStunMessageBufferLength == NULL ) ||
        ( pSrcAddr == NULL ) ||
        ( pTransactionIdBuffer == NULL ) )
    {
        retStatus = ICE_RESULT_BAD_PARAM;
    }

    if( retStatus == ICE_RESULT_OK )
    {
        retStatus = Ice_InitializeStunPacket( pIceAgent,
                                              &( stunCxt ),
                                              pTransactionIdBuffer,
                                              &( pIceAgent->stunMessageBuffer[ 0 ] ),
                                              &( stunHeader ),
                                              needTransactionIDGeneration,
                                              isStunBindingRequest );
    }

    if( retStatus == ICE_RESULT_OK )
    {
        memcpy( &( stunMappedAddress ),
                &( pSrcAddr->ipAddress ),
                sizeof( StunAttributeAddress_t ) );
        stunRetStatus = StunSerializer_AddAttributeXorMappedAddress( &( stunCxt ),
                                                                     &( stunMappedAddress ) );
    }

    if( stunRetStatus == STUN_RESULT_OK )
    {
        if( pIceAgent->isControlling == 0 )
        {
            stunRetStatus = StunSerializer_AddAttributeIceControlled( &( stunCxt ),
                                                                      pIceAgent->tieBreaker );
        }
        else
        {
            stunRetStatus = StunSerializer_AddAttributeIceControlling( &( stunCxt ),
                                                                       pIceAgent->tieBreaker );
        }
    }

    if( stunRetStatus == STUN_RESULT_OK )
    {
        retStatus = Ice_PackageStunPacket( pIceAgent,
                                           &( stunCxt ),
                                           ( uint8_t * ) pIceAgent->localPassword,
                                           ( uint32_t ) strlen( pIceAgent->localPassword ) * sizeof( char ),
                                           pSendStunMessageBufferLength );
    }

    if( retStatus == ICE_RESULT_OK )
    {
        *ppSendStunMessageBuffer = &( pIceAgent->stunMessageBuffer[ 0 ] );
    }

    return retStatus;
}

/*------------------------------------------------------------------------------------------------------------------*/

/* Ice_HandleStunPacket - This API handles the processing of Stun Response. */

IceStunPacketHandleResult_t Ice_HandleStunPacket( IceAgent_t * pIceAgent,
                                                  uint8_t * pReceivedStunMessageBuffer,
                                                  uint32_t receivedStunMessageBufferLength,
                                                  uint8_t ** ppSendTransactionIdBuffer,
                                                  uint8_t ** ppSendStunMessageBuffer,
                                                  uint32_t * pSendStunMessageBufferLength,
                                                  IceIPAddress_t * pLocalCandidateAddress,
                                                  IceIPAddress_t * pRemoteCandidateAddress,
                                                  IceCandidatePair_t ** ppIceCandidatePair )
{
    StunContext_t stunCxt;
    StunHeader_t stunHeader;
    StunAttribute_t stunAttribute;
    IceIPAddress_t newIpAddr;
    IceStunDeserializedPacketInfo_t deserializePacketInfo;
    IceResult_t iceRetStatus = ICE_RESULT_OK;
    IceStunPacketHandleResult_t iceStunPacketHandleStatus = ICE_RESULT_STUN_DESERIALIZE_OK;
    StunResult_t stunResult = STUN_RESULT_OK;
    bool foundLocalCandidate = false;
    bool foundCandidatePair = false;
    IceCandidate_t * pLocalCandidate = NULL;
    IceCandidatePair_t * pIceCandidatePair = NULL;

    if( ( pIceAgent == NULL ) ||
        ( pReceivedStunMessageBuffer == NULL ) ||
        ( receivedStunMessageBufferLength > ICE_STUN_MESSAGE_BUFFER_SIZE ) ||
        ( ppSendTransactionIdBuffer == NULL ) ||
        ( pLocalCandidateAddress == NULL ) ||
        ( pRemoteCandidateAddress == NULL ) ||
        ( ppSendStunMessageBuffer == NULL ) ||
        ( pSendStunMessageBufferLength == NULL ) ||
        ( ppIceCandidatePair == NULL ) )
    {
        iceRetStatus = ICE_RESULT_BAD_PARAM;
    }

    /* Initialize STUN context for deserializing. */
    if( iceRetStatus == ICE_RESULT_OK )
    {
        stunResult = StunDeserializer_Init( &( stunCxt ),
                                            pReceivedStunMessageBuffer,
                                            receivedStunMessageBufferLength,
                                            &( stunHeader ) );
    }

    if( stunResult == STUN_RESULT_OK )
    {
        switch( stunHeader.messageType )
        {
            case STUN_MESSAGE_TYPE_BINDING_REQUEST:

                iceStunPacketHandleStatus = Ice_DeserializeStunPacket( pIceAgent,
                                                                       &( stunCxt ), &( stunHeader ),
                                                                       &( stunAttribute ),
                                                                       ( uint8_t * ) pIceAgent->localPassword,
                                                                       ( uint32_t ) strlen( pIceAgent->localPassword ) * sizeof( char ),
                                                                       &deserializePacketInfo );

                if( ( iceStunPacketHandleStatus == ICE_RESULT_STUN_DESERIALIZE_OK ) && ( deserializePacketInfo.errorCode == 0 ) )
                {
                    iceRetStatus = Ice_CheckPeerReflexiveCandidate( pIceAgent,
                                                                    pRemoteCandidateAddress,
                                                                    NULL,
                                                                    deserializePacketInfo.priority,
                                                                    true );

                    if( iceRetStatus == ICE_RESULT_OK )
                    {
                        foundCandidatePair = Ice_FindCandidatePairWithLocalAndRemoteAddr( pIceAgent,
                                                                                          pLocalCandidateAddress,
                                                                                          pRemoteCandidateAddress,
                                                                                          &pIceCandidatePair );
                    }

                    if( foundCandidatePair )
                    {
                        /* Check if received candidate with USE_CANDIDATE FLAG */
                        if( ( deserializePacketInfo.useCandidateFlag == 1 ) && ( pIceCandidatePair->connectivityChecks == ICE_CONNECTIVITY_SUCCESS_FLAG ) )
                        {
                            pIceCandidatePair->state = ICE_CANDIDATE_PAIR_STATE_NOMINATED;
                            iceStunPacketHandleStatus = ICE_RESULT_SEND_RESPONSE_FOR_NOMINATION;
                        }
                        else
                        {
                            /* Received a connection request from remote candidate. */
                            pIceCandidatePair->connectivityChecks |= ( 1 << ICE_STUN_REQUEST_REMOTE_LOCAL_BIT2 );

                            if( ( pIceCandidatePair->connectivityChecks & 1 ) == 0 )
                            {
                                /* Create a request from local to remote candidate. */
                                pIceCandidatePair->connectivityChecks |= ( 1 << ICE_STUN_REQUEST_LOCAL_REMOTE_BIT0 );
                                /* Create a response for received request. */
                                pIceCandidatePair->connectivityChecks |= ( 1 << ICE_STUN_RESPONSE_REMOTE_LOCAL_BIT3 );

                                /* The application needs to send 2 stun packets. */
                                iceStunPacketHandleStatus = ICE_RESULT_SEND_TRIGGERED_CHECK;
                            }
                            else
                            {
                                /* Create a response for received request. */
                                pIceCandidatePair->connectivityChecks |= ( 1 << ICE_STUN_RESPONSE_REMOTE_LOCAL_BIT3 );

                                /* The application needs to send 1 stun packet. */
                                iceStunPacketHandleStatus = ICE_RESULT_SEND_RESPONSE_FOR_REMOTE_REQUEST;
                            }
                        }

                        /* The application always needs to send a response for the request received from remote candidate.
                         * So the transaction ID needs to be returned back to the application always in theis sceanrio. */
                        *ppSendTransactionIdBuffer = stunHeader.pTransactionId;
                    }
                    else
                    {
                        /* Candidate Pair was not found using the local and remote IP address. */
                        iceStunPacketHandleStatus = ICE_RESULT_NOT_FOUND_CANDIDATE_PAIR;
                    }
                }

                break;

            case STUN_MESSAGE_TYPE_BINDING_SUCCESS_RESPONSE:
                foundLocalCandidate = Ice_FindCandidateFromIP( pIceAgent,
                                                               &pLocalCandidate,
                                                               *pLocalCandidateAddress,
                                                               0 );

                if( Ice_TransactionIdStoreHasId( pIceAgent->pStunBindingRequestTransactionIdStore,
                                                 pReceivedStunMessageBuffer + STUN_HEADER_TRANSACTION_ID_OFFSET ) )
                {
                    iceStunPacketHandleStatus = Ice_DeserializeStunPacket( pIceAgent,
                                                                           &( stunCxt ),
                                                                           &( stunHeader ),
                                                                           &( stunAttribute ),
                                                                           NULL,
                                                                           0,
                                                                           &( deserializePacketInfo ) );

                    if( ( iceStunPacketHandleStatus == ICE_RESULT_STUN_DESERIALIZE_OK ) && ( deserializePacketInfo.errorCode == 0 ) && ( &( deserializePacketInfo.stunAttributeAddress ) != NULL ) )
                    {
                        if( foundLocalCandidate )
                        {
                            iceRetStatus = Ice_HandleServerReflexiveCandidateResponse( pIceAgent,
                                                                                       &( deserializePacketInfo.stunAttributeAddress ),
                                                                                       pLocalCandidate );

                            if( iceRetStatus == ICE_RESULT_OK )
                            {
                                Ice_TransactionIdStoreRemove( pIceAgent->pStunBindingRequestTransactionIdStore,
                                                              pReceivedStunMessageBuffer + STUN_HEADER_TRANSACTION_ID_OFFSET );
                            }

                            iceStunPacketHandleStatus = ICE_RESULT_UPDATED_SRFLX_CANDIDATE_ADDRESS;
                        }
                        else
                        {
                            /* Local candidate was not found. */
                            iceStunPacketHandleStatus = ICE_RESULT_NOT_FOUND_CANDIDATE;
                        }
                    }
                }
                else
                {
                    iceStunPacketHandleStatus = Ice_DeserializeStunPacket( pIceAgent,
                                                                           &( stunCxt ),
                                                                           &( stunHeader ),
                                                                           &( stunAttribute ),
                                                                           ( uint8_t * ) pIceAgent->remotePassword,
                                                                           ( uint32_t ) strlen( pIceAgent->remotePassword ) * sizeof( char ),
                                                                           &( deserializePacketInfo ) );

                    if( ( iceStunPacketHandleStatus == ICE_RESULT_STUN_DESERIALIZE_OK ) && ( deserializePacketInfo.errorCode == 0 ) )
                    {
                        foundCandidatePair = Ice_FindCandidatePairWithLocalAndRemoteAddr( pIceAgent,
                                                                                          pLocalCandidateAddress,
                                                                                          pRemoteCandidateAddress,
                                                                                          &( pIceCandidatePair ) );

                        if( foundCandidatePair )
                        {
                            if( memcmp( pIceCandidatePair->pTransactionIdStore,
                                        pReceivedStunMessageBuffer + STUN_HEADER_TRANSACTION_ID_OFFSET,
                                        STUN_HEADER_TRANSACTION_ID_LENGTH ) == 0 )
                            {
                                if( !( pIceCandidatePair->connectivityChecks & 2 ) )
                                {
                                    pIceCandidatePair->connectivityChecks |= ( 1 << ICE_STUN_RESPONSE_LOCAL_REMOTE_BIT1 );
                                }

                                if( pIceCandidatePair->connectivityChecks == ICE_CONNECTIVITY_SUCCESS_FLAG )
                                {
                                    if( pIceCandidatePair->state == ICE_CANDIDATE_PAIR_STATE_NOMINATED )
                                    {
                                        pIceCandidatePair->state = ICE_CANDIDATE_PAIR_STATE_SUCCEEDED;
                                        iceStunPacketHandleStatus = ICE_RESULT_CANDIDATE_PAIR_READY;
                                    }
                                    else
                                    {
                                        pIceCandidatePair->state = ICE_CANDIDATE_PAIR_STATE_VALID;
                                        /* This step would be called for controlling ICE agent. */
                                        iceStunPacketHandleStatus = ICE_RESULT_START_NOMINATION;
                                    }
                                }
                                else
                                {
                                    if( &( deserializePacketInfo.stunAttributeAddress ) != NULL )
                                    {
                                        if( ( pIceCandidatePair->pLocal->iceCandidateType == ICE_CANDIDATE_TYPE_SERVER_REFLEXIVE ) &&
                                            ( pIceCandidatePair->pRemote->iceCandidateType == ICE_CANDIDATE_TYPE_SERVER_REFLEXIVE ) &&
                                            ( Ice_IsSameIpAddress( &( deserializePacketInfo.stunAttributeAddress ),
                                                                   &( pIceCandidatePair->pLocal->ipAddress.ipAddress ),
                                                                   false ) == 0 ) )
                                        {
                                            memcpy( &( newIpAddr.ipAddress ),
                                                    &( deserializePacketInfo.stunAttributeAddress ),
                                                    sizeof( StunAttributeAddress_t ) );
                                            newIpAddr.isPointToPoint = 0;

                                            iceRetStatus = Ice_CheckPeerReflexiveCandidate( pIceAgent,
                                                                                            &( newIpAddr ),
                                                                                            pLocalCandidate,
                                                                                            pIceCandidatePair->pLocal->priority,
                                                                                            false );

                                            if( iceRetStatus == ICE_RESULT_OK )
                                            {
                                                iceStunPacketHandleStatus = ICE_RESULT_FOUND_PEER_REFLEXIVE_CANDIDATE;
                                            }
                                        }
                                    }
                                    else
                                    {
                                        /* No mapped address attribute found in STUN response. Dropping Packet. */
                                        iceStunPacketHandleStatus = ICE_RESULT_NOT_FOUND_ADDRESS_ATTRIBUTE;
                                    }
                                }
                            }
                            else
                            {
                                /* Dropping response packet because transaction id does not match.*/
                                iceStunPacketHandleStatus = ICE_RESULT_NOT_FOUND_MATCHING_TRANSACTION_ID;
                            }
                        }
                        else
                        {
                            /* Candidate Pair was not found using the local and remote IP address. */
                            iceStunPacketHandleStatus = ICE_RESULT_NOT_FOUND_CANDIDATE_PAIR;
                        }
                    }
                }

                break;

            case STUN_MESSAGE_TYPE_BINDING_INDICATION:
                /* Received STUN binding indication */
                iceStunPacketHandleStatus = ICE_RESULT_STUN_BINDING_INDICATION;
                break;

            default:
                /* STUN packet received is neither a Binding Request nor a Response. */
                iceStunPacketHandleStatus = ICE_RESULT_STUN_INVALID_PACKET_TYPE;
                break;
        }
    }

    if( foundCandidatePair )
    {
        *ppIceCandidatePair = pIceCandidatePair;
    }

    return iceStunPacketHandleStatus;
}

/*------------------------------------------------------------------------------------------------------------------*/

/* Ice_GetValidLocalCandidateCount - Get valid Local Candidate count */

int Ice_GetValidLocalCandidateCount( IceAgent_t * pIceAgent )
{
    int i = ICE_RESULT_NO_VALID_LOCAL_CANDIDATE;

    if( pIceAgent != NULL )
    {
        for( i = 0; i < ICE_MAX_LOCAL_CANDIDATE_COUNT; i++ )
        {
            if( pIceAgent->localCandidates[ i ].state == ICE_CANDIDATE_STATE_INVALID )
            {
                break;
            }
        }
    }

    return( i );
}
/*------------------------------------------------------------------------------------------------------------------*/

/* Ice_GetValidRemoteCandidateCount - Get valid Remote Candidate count */

int Ice_GetValidRemoteCandidateCount( IceAgent_t * pIceAgent )
{
    int i = ICE_RESULT_NO_VALID_REMOTE_CANDIDATE;

    if( pIceAgent != NULL )
    {
        for( i = 0; i < ICE_MAX_REMOTE_CANDIDATE_COUNT; i++ )
        {
            if( pIceAgent->remoteCandidates[ i ].state == ICE_CANDIDATE_STATE_INVALID )
            {
                break;
            }
        }
    }

    return( i );
}
/*------------------------------------------------------------------------------------------------------------------*/

/* Ice_GetValidCandidatePairCount - Get valid Candidate Pair Count */

int Ice_GetValidCandidatePairCount( IceAgent_t * pIceAgent )
{
    int i = ICE_RESULT_NO_VALID_CANDIDATE_PAIR;

    if( pIceAgent != NULL )
    {
        for( i = 0; i < ICE_MAX_CANDIDATE_PAIR_COUNT; i++ )
        {
            if( pIceAgent->iceCandidatePairs[ i ].state == ICE_CANDIDATE_PAIR_STATE_INVALID )
            {
                break;
            }
        }
    }

    return( i );
}
/*------------------------------------------------------------------------------------------------------------------*/
