#include "ice_api.h"

/* STUN defines. */
#include "stun_data_types.h"
#include "stun_serializer.h"
#include "stun_deserializer.h"

/* Standard defines. */
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>

/* Ice_CreateIceAgent - The application calls this API for starting a new ICE agent. */

IceResult_t Ice_CreateIceAgent( IceAgent_t * pIceAgent,
                                char * pLocalUsername,
                                char * pLocalPassword,
                                char * pRemoteUsername,
                                char * pRemotePassword,
                                char * pCombinedUsername,
                                TransactionIdStore_t * pBuffer,
                                Ice_ComputeCrc32 computeCRC32,
                                Ice_ComputeHMAC computeHMAC )
{
    IceResult_t retStatus = ICE_RESULT_OK;
    int i;

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
        strcpy( pIceAgent->localUsername,
                pLocalUsername );
        strcpy( pIceAgent->localPassword,
                pLocalPassword );
        strcpy( pIceAgent->remoteUsername,
                pRemoteUsername );
        strcpy( pIceAgent->remotePassword,
                pRemotePassword );
        strcpy( pIceAgent->combinedUserName,
                pCombinedUsername );

        pIceAgent->stunMessageBufferUsedCount = 0;
        pIceAgent->isControlling = 0;
        pIceAgent->tieBreaker = ( uint64_t )rand(); // required as an attribute for STUN packet

        memset( pIceAgent->localCandidates, 0, sizeof( pIceAgent->localCandidates ) );
        memset( pIceAgent->remoteCandidates, 0, sizeof( pIceAgent->remoteCandidates ) );
        memset( pIceAgent->stunMessageBuffers, 0, sizeof( pIceAgent->stunMessageBuffers ) );
        memset( pIceAgent->iceCandidatePairs, 0, sizeof( pIceAgent->iceCandidatePairs ) );

        pIceAgent->pStunBindingRequestTransactionIdStore = pBuffer;
        retStatus = Ice_CreateTransactionIdStore( ICE_DEFAULT_MAX_STORED_TRANSACTION_ID_COUNT,
                                                  pIceAgent->pStunBindingRequestTransactionIdStore );
    }

    if( retStatus == ICE_RESULT_OK )
    {
        pIceAgent->computeCRC32 = computeCRC32;
        pIceAgent->computeHMAC = computeHMAC;
    }
    return retStatus;
}
/*------------------------------------------------------------------------------------------------------------------*/

/* Ice_AddHostCandidate - The application calls this API for adding host candidate. */

IceResult_t Ice_AddHostCandidate( const IceIPAddress_t ipAddr,
                                  IceAgent_t * pIceAgent,
                                  IceCandidate_t ** ppCandidate )
{
    IceResult_t retStatus = ICE_RESULT_OK;
    IceCandidate_t * pIceCandidate;
    int localCandidateCount;

    if( ( pIceAgent == NULL ) ||
        ( ppCandidate == NULL ) )
    {
        retStatus = ICE_RESULT_BAD_PARAM;
    }

    if( retStatus == ICE_RESULT_OK )
    {
        localCandidateCount = Ice_GetValidLocalCandidateCount( pIceAgent );
    }

    if( localCandidateCount >= ICE_MAX_LOCAL_CANDIDATE_COUNT )
    {
        retStatus = ICE_RESULT_MAX_CANDIDATE_THRESHOLD;
    }
    else
    {
        pIceCandidate = &pIceAgent->localCandidates[localCandidateCount];
    }

    if( retStatus == ICE_RESULT_OK )
    {
        pIceCandidate->isRemote = 0;
        pIceCandidate->ipAddress = ipAddr;
        pIceCandidate->iceCandidateType = ICE_CANDIDATE_TYPE_HOST;
        pIceCandidate->state = ICE_CANDIDATE_STATE_VALID;
        pIceCandidate->priority = Ice_ComputeCandidatePriority( pIceCandidate );
    }

    if( retStatus == ICE_RESULT_OK )
    {
        *ppCandidate = pIceCandidate;
    }

    return retStatus;
}
/*------------------------------------------------------------------------------------------------------------------*/

/* Ice_AddSrflxCandidate - The application calls this API for adding Server Reflex candidate. */

IceResult_t Ice_AddSrflxCandidate( const IceIPAddress_t ipAddr,
                                   IceAgent_t * pIceAgent,
                                   IceCandidate_t ** ppCandidate,
                                   uint8_t * pTransactionIdBuffer,
                                   uint8_t ** ppSendStunMessageBuffer,
                                   uint32_t * pSendStunMessageBufferLength )
{
    IceResult_t retStatus = ICE_RESULT_OK;
    IceCandidate_t * pIceCandidate;
    int localCandidateCount;

    if( ( pIceAgent == NULL ) ||
        ( ppCandidate == NULL ) ||
        ( ppSendStunMessageBuffer == NULL ) ||
        ( pSendStunMessageBufferLength == NULL ) ||
        ( pTransactionIdBuffer == NULL ) )
    {
        retStatus = ICE_RESULT_BAD_PARAM;
    }

    localCandidateCount = Ice_GetValidLocalCandidateCount( pIceAgent );

    if( localCandidateCount >= ICE_MAX_LOCAL_CANDIDATE_COUNT )
    {
        retStatus = ICE_RESULT_MAX_CANDIDATE_THRESHOLD;
    }
    else
    {
        pIceCandidate = &pIceAgent->localCandidates[localCandidateCount];
    }

    if( retStatus == ICE_RESULT_OK )
    {
        pIceCandidate->isRemote = 0;
        pIceCandidate->ipAddress = ipAddr;
        pIceCandidate->iceCandidateType = ICE_CANDIDATE_TYPE_SERVER_REFLEXIVE;
        pIceCandidate->state = ICE_CANDIDATE_STATE_NEW;
        pIceCandidate->priority = Ice_ComputeCandidatePriority( pIceCandidate );

        retStatus = Ice_CreateRequestForSrflxCandidate( pIceAgent,
                                                        pIceAgent->stunMessageBuffers[pIceAgent->stunMessageBufferUsedCount++],
                                                        pTransactionIdBuffer,
                                                        pSendStunMessageBufferLength );

        if( retStatus == ICE_RESULT_OK )
        {
            *ppSendStunMessageBuffer = pIceAgent->stunMessageBuffers[pIceAgent->stunMessageBufferUsedCount - 1];
            *ppCandidate = pIceCandidate;
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
    IceResult_t retStatus = ICE_RESULT_OK;
    IceCandidate_t * pIceCandidate;
    int i;
    int remoteCandidateCount;

    if( ( pIceAgent == NULL ) ||
        ( ppCandidate == NULL ) )
    {
        retStatus = ICE_RESULT_BAD_PARAM;
    }

    remoteCandidateCount = Ice_GetValidRemoteCandidateCount( pIceAgent );

    if( remoteCandidateCount >= ICE_MAX_REMOTE_CANDIDATE_COUNT )
    {
        retStatus = ICE_RESULT_MAX_CANDIDATE_THRESHOLD;
    }
    else
    {
        pIceCandidate = &pIceAgent->remoteCandidates[remoteCandidateCount];
    }

    if( retStatus == ICE_RESULT_OK )
    {
        pIceCandidate->isRemote = 1;
        pIceCandidate->ipAddress = ipAddr;
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
            if( pIceAgent->localCandidates[i].state == ICE_CANDIDATE_STATE_VALID )
            {
                retStatus = Ice_CreateCandidatePair( pIceAgent,
                                                     &( pIceAgent->localCandidates[i] ),
                                                     pIceCandidate );
            }
        }
    }

    return retStatus;
}
/*------------------------------------------------------------------------------------------------------------------*/

/*  Ice_checkRemotePeerReflexiveCandidate - The library calls this API for creating remote peer reflexive candidates on receiving a STUN binding request. */

static IceResult_t Ice_CheckPeerReflexiveCandidate( IceAgent_t * pIceAgent,
                                                    IceIPAddress_t * pIpAddr,
                                                    uint32_t priority,
                                                    bool isRemote )
{
    IceResult_t retStatus = ICE_RESULT_OK;
    IceCandidate_t * pPeerReflexiveCandidate;
    bool foundDuplicatedCandidate = false;

    if( ( pIceAgent == NULL ) ||
        ( pIpAddr == NULL ) )
    {
        retStatus = ICE_RESULT_BAD_PARAM;
    }

    if( retStatus == ICE_RESULT_OK )
    {
        foundDuplicatedCandidate = Ice_FindCandidateFromIp( pIceAgent, *pIpAddr, isRemote, &pPeerReflexiveCandidate );
        if( !foundDuplicatedCandidate )
        {
            retStatus = Ice_AddRemoteCandidate( pIceAgent,
                                                ICE_CANDIDATE_TYPE_PEER_REFLEXIVE,
                                                &pPeerReflexiveCandidate,
                                                *pIpAddr,
                                                0,
                                                priority );
        }
    }

    return retStatus;
}
/*------------------------------------------------------------------------------------------------------------------*/

/*  Ice_CreateCandidatePair - The library calls this API for creating candidate pair between a local and remote candidate . */

IceResult_t Ice_CreateCandidatePair( IceAgent_t * pIceAgent,
                                     IceCandidate_t * pLocalCandidate,
                                     IceCandidate_t * pRemoteCandidate )
{
    IceResult_t retStatus = ICE_RESULT_OK;
    int iceCandidatePairCount;
    IceCandidatePair_t * pIceCandidatePair;

    if( ( pIceAgent == NULL ) ||
        ( pLocalCandidate == NULL ) ||
        ( pRemoteCandidate == NULL ) )
    {
        retStatus = ICE_RESULT_BAD_PARAM;
    }

    if( retStatus == ICE_RESULT_OK )
    {
        iceCandidatePairCount = Ice_GetValidCandidatePairCount( pIceAgent );

        if( iceCandidatePairCount == ICE_MAX_CANDIDATE_PAIR_COUNT )
        {
            retStatus = ICE_RESULT_MAX_CANDIDATE_PAIR_THRESHOLD;
        }
        else
        {
            pIceCandidatePair = &( pIceAgent->iceCandidatePairs[iceCandidatePairCount] );
        }

        if( retStatus == ICE_RESULT_OK )
        {
            pIceCandidatePair->pLocal = pLocalCandidate;
            pIceCandidatePair->pRemote = pRemoteCandidate;
            pIceCandidatePair->state = ICE_CANDIDATE_PAIR_STATE_WAITING;
            pIceCandidatePair->priority = Ice_ComputeCandidatePairPriority( pIceCandidatePair,
                                                                            pIceAgent->isControlling );
            pIceCandidatePair->connectivityChecks = 0;

            retStatus = Ice_CreateTransactionIdStore( ICE_DEFAULT_MAX_STORED_TRANSACTION_ID_COUNT,
                                                      pIceCandidatePair->pTransactionIdStore );
        }

        if( retStatus == ICE_RESULT_OK )
        {
            Ice_InsertCandidatePair( pIceAgent, pIceCandidatePair, iceCandidatePairCount );
        }
    }

    return retStatus;
}

/*------------------------------------------------------------------------------------------------------------------*/

/* Ice_insertCandidatePair : This API is called internally to insert candidate paits based on decreasing priority. */

static void Ice_InsertCandidatePair( IceAgent_t * pIceAgent,
                                     IceCandidatePair_t * pIceCandidatePair,
                                     int iceCandidatePairCount )
{
    int i;
    int pivot = -1;
    IceCandidatePair_t pivotCandidatePair = *pIceCandidatePair;

    for( i = 0; i < iceCandidatePairCount; i++ )
    {
        if( pivotCandidatePair.priority >= pIceAgent->iceCandidatePairs[i].priority )
        {
            pivot = i;
            break;
        }
    }

    if( pivot == -1 )
    {
        pivot = iceCandidatePairCount;
    }
    else
    {
        for( i = iceCandidatePairCount; i > pivot; i-- )
        {
            pIceAgent->iceCandidatePairs[i] = pIceAgent->iceCandidatePairs[i - 1];
        }
    }

    pIceAgent->iceCandidatePairs[pivot] = pivotCandidatePair;

    return;
}

/*------------------------------------------------------------------------------------------------------------------*/

/* Ice_UpdateSrflxCandidateAddress : This API will be called by processStunPacket, if the binding request is for finding srflx candidate to update the candidate address */

IceResult_t Ice_UpdateSrflxCandidateAddress( IceAgent_t * pIceAgent,
                                             IceCandidate_t * pCandidate,
                                             const IceIPAddress_t * pIpAddr )
{
    IceResult_t retStatus = ICE_RESULT_OK;
    int i;

    if( ( pIceAgent == NULL ) ||
        ( pCandidate == NULL ) ||
        ( pIpAddr == NULL ) ||
        ( pCandidate->iceCandidateType != ICE_CANDIDATE_TYPE_SERVER_REFLEXIVE ) )
    {
        retStatus = ICE_RESULT_BAD_PARAM;
    }

    pCandidate->ipAddress = *pIpAddr;
    pCandidate->state = ICE_CANDIDATE_STATE_VALID;

    for( i = 0; ( ( i < Ice_GetValidRemoteCandidateCount( pIceAgent ) ) && ( retStatus == ICE_RESULT_OK ) ); i++ )
    {
        retStatus = Ice_CreateCandidatePair( pIceAgent,
                                             pCandidate,
                                             &( pIceAgent->remoteCandidates[i] ) );
    }

    return retStatus;
}

/*------------------------------------------------------------------------------------------------------------------*/

/* Ice_InitializeStunPacket - This API populates the Stun packet, whose memory has been allocated by the application.
 *  4 types of packets need to be created:
 *   1. Send Srflx Request
 *   2. Connectivity Check
 *   3. During nomination - USE_CANDIDATE flag
 *   4. Send Response to Remote Candidates
 */
IceResult_t Ice_InitializeStunPacket( StunContext_t * pStunCxt,
                                      uint8_t * pTransactionId,
                                      uint8_t * pStunMessageBuffer,
                                      StunHeader_t * pStunHeader,
                                      uint8_t isGenerateTransactionID,
                                      uint8_t isStunBindingRequest )
{
    IceResult_t retStatus = ICE_RESULT_OK;
    int i;

    if( ( pStunCxt == NULL ) ||
        ( pTransactionId == NULL ) ||
        ( pStunMessageBuffer == NULL ) ||
        ( pStunHeader == NULL ) )
    {
        retStatus = ICE_RESULT_BAD_PARAM;
    }

    pStunHeader->pTransactionId = pTransactionId;

    /* STUN header */
    if( retStatus == ICE_RESULT_OK )
    {
        if( isStunBindingRequest )
        {
            pStunHeader->messageType = STUN_MESSAGE_TYPE_BINDING_REQUEST;
        }
        else
        {
            pStunHeader->messageType = STUN_MESSAGE_TYPE_BINDING_SUCCESS_RESPONSE;
        }

        /* isGenerateTransactionID variable is used to define how the transactionId buffer
         * of the Stun Header is populated. It has the following values:
         *  a. 0 --> Populate values with the passed transactionId Buffer as an argument.
         *  b. 1 --> Populate values with randomized values.
         *  c. 2 --> Populate values with randomized values, for creating Srflx request.
         */
        if( isGenerateTransactionID == 1 )
        {
            for( i = 0; i < STUN_HEADER_TRANSACTION_ID_LENGTH; i++ )
            {
                pStunHeader->pTransactionId[i] = ( uint8_t )( rand() % 0x100 );
            }
        }
        else if( isGenerateTransactionID == 0 )
        {
            memcpy( &( pStunHeader->pTransactionId[0] ),
                    &( pTransactionId[0] ),
                    STUN_HEADER_TRANSACTION_ID_LENGTH );
        }

        /* Create a STUN message. */
        retStatus = StunSerializer_Init( pStunCxt,
                                         pStunMessageBuffer,
                                         ICE_STUN_MESSAGE_BUFFER_SIZE, // Keeping the  STUN packet buffer size = 1024 , if required, the size can be dynamic as well.
                                         pStunHeader );
    }

    return retStatus;
}

/*------------------------------------------------------------------------------------------------------------------*/

/* Ice_PackageStunPacket - This API takes care of the serialization of the Stun Packet and appends the requited attributes .*/

IceResult_t Ice_PackageStunPacket( IceAgent_t * pIceAgent,
                                   StunContext_t * pStunCxt,
                                   uint8_t * pPassword,
                                   uint32_t passwordLen,
                                   uint32_t * pStunMessageBufferLength )
{
    IceResult_t retStatus = ICE_RESULT_OK;
    uint8_t * pIntBuffer;
    uint8_t * pFinBuffer;
    uint8_t messageIntegrity[STUN_HMAC_VALUE_LENGTH];
    uint32_t hmacLen, crc32, stunMessageLength;
    uint16_t bufferLength;

    if( ( pIceAgent == NULL ) ||
        ( pStunCxt == NULL ) ||
        ( ( pPassword == NULL ) && ( passwordLen > 0 ) ) ||
        ( ( pPassword != NULL ) && ( passwordLen == 0 ) ) ||
        ( pStunMessageBufferLength == NULL ) )
    {
        retStatus = ICE_RESULT_BAD_PARAM;
    }

    // Add Integrity attribute
    if( ( retStatus == ICE_RESULT_OK ) && ( pPassword != NULL ) )
    {
        retStatus = StunSerializer_GetIntegrityBuffer( pStunCxt,
                                                       &pIntBuffer,
                                                       &bufferLength );

        if( ( pIntBuffer != NULL ) && ( retStatus == ICE_RESULT_OK ) )
        {
            pIceAgent->computeHMAC( pPassword, ( int32_t )passwordLen, pIntBuffer, bufferLength, messageIntegrity, &hmacLen );
        }

        retStatus = StunSerializer_AddAttributeIntegrity( pStunCxt,
                                                          messageIntegrity,
                                                          STUN_HMAC_VALUE_LENGTH );
    }

    // Add Fingerprint attribute
    if( retStatus == ICE_RESULT_OK )
    {
        retStatus = StunSerializer_GetFingerprintBuffer( pStunCxt,
                                                         &pFinBuffer,
                                                         &bufferLength );

        if( ( pFinBuffer != NULL ) && ( retStatus == ICE_RESULT_OK ) )
        {
            crc32 = pIceAgent->computeCRC32( 0, pFinBuffer, bufferLength );
        }
        retStatus = StunSerializer_AddAttributeFingerprint( pStunCxt,
                                                            crc32 );
    }

    if( retStatus == ICE_RESULT_OK )
    {
        retStatus = StunSerializer_Finalize( pStunCxt,
                                             &( stunMessageLength ) );
    }

    if( retStatus == ICE_RESULT_OK )
    {
        *pStunMessageBufferLength = stunMessageLength;
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
    IceResult_t retStatus = ICE_RESULT_OK;
    StunContext_t stunCxt;
    StunHeader_t stunHeader;

    if( ( pIceAgent == NULL ) ||
        ( pStunMessageBuffer == NULL ) ||
        ( pTransactionIdBuffer == NULL ) ||
        ( pSendStunMessageBufferLength == NULL ) )
    {
        retStatus = ICE_RESULT_BAD_PARAM;
    }

    if( retStatus == ICE_RESULT_OK )
    {
        retStatus = Ice_InitializeStunPacket( &stunCxt,
                                              pTransactionIdBuffer,
                                              pStunMessageBuffer,
                                              &stunHeader,
                                              1,
                                              1 );

        if( retStatus == ICE_RESULT_OK )
        {
            Ice_TransactionIdStoreInsert( pIceAgent->pStunBindingRequestTransactionIdStore,
                                          stunHeader.pTransactionId );

            retStatus = Ice_PackageStunPacket( pIceAgent,
                                               &stunHeader,
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
    IceResult_t retStatus = ICE_RESULT_OK;
    StunContext_t stunCxt;
    StunHeader_t stunHeader;

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
        retStatus = Ice_InitializeStunPacket( &stunCxt,
                                              pTransactionIdBuffer,
                                              pIceAgent->stunMessageBuffers[pIceAgent->stunMessageBufferUsedCount++],
                                              &stunHeader,
                                              1,
                                              1 );

        if( retStatus == ICE_RESULT_OK )
        {
            retStatus = StunSerializer_AddAttributeUsername( &stunCxt,
                                                             pIceAgent->combinedUserName,
                                                             strlen( pIceAgent->combinedUserName ) );
        }

        if( retStatus == ICE_RESULT_OK )
        {
            retStatus = StunSerializer_AddAttributePriority( &stunCxt,
                                                             pIceCandidatePair->pLocal->priority );
        }

        if( retStatus == ICE_RESULT_OK )
        {
            retStatus = StunSerializer_AddAttributeIceControlling( &stunCxt,
                                                                   pIceAgent->tieBreaker );
        }

        if( retStatus == ICE_RESULT_OK )
        {
            retStatus = StunSerializer_AddAttributeUseCandidate( &stunCxt );
        }

        if( retStatus == ICE_RESULT_OK )
        {
            Ice_TransactionIdStoreInsert( pIceCandidatePair->pTransactionIdStore,
                                          stunHeader.pTransactionId );

            retStatus = Ice_PackageStunPacket( pIceAgent,
                                               &stunCxt,
                                               ( uint8_t * )pIceAgent->remotePassword,
                                               ( uint32_t )strlen( pIceAgent->remotePassword ) * sizeof( char ),
                                               pSendStunMessageBufferLength );
        }

        if( retStatus == ICE_RESULT_OK )
        {
            *ppSendStunMessageBuffer = pIceAgent->stunMessageBuffers[pIceAgent->stunMessageBufferUsedCount - 1];
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
    IceResult_t retStatus = ICE_RESULT_OK;
    StunContext_t stunCxt;
    StunHeader_t stunHeader;

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
        retStatus = Ice_InitializeStunPacket( &stunCxt,
                                              pTransactionIdBuffer,
                                              pIceAgent->stunMessageBuffers[pIceAgent->stunMessageBufferUsedCount++],
                                              &stunHeader,
                                              1,
                                              1 );

        if( retStatus == ICE_RESULT_OK )
        {
            retStatus = StunSerializer_AddAttributeUsername( &stunCxt,
                                                             pIceAgent->combinedUserName,
                                                             strlen( pIceAgent->combinedUserName ) );
        }

        if( retStatus == ICE_RESULT_OK )
        {
            retStatus = StunSerializer_AddAttributePriority( &stunCxt,
                                                             0 );
        }

        if( retStatus == ICE_RESULT_OK )
        {
            if( pIceAgent->isControlling == 0 )
            {
                retStatus = StunSerializer_AddAttributeIceControlled( &stunCxt,
                                                                      pIceAgent->tieBreaker );
            }
            else
            {
                retStatus = StunSerializer_AddAttributeIceControlling( &stunCxt,
                                                                       pIceAgent->tieBreaker );
            }
        }

        if( retStatus == ICE_RESULT_OK )
        {
            Ice_TransactionIdStoreInsert( pIceCandidatePair->pTransactionIdStore,
                                          stunHeader.pTransactionId );

            retStatus = Ice_PackageStunPacket( pIceAgent,
                                               &stunCxt,
                                               ( uint8_t * )pIceAgent->remotePassword,
                                               ( uint32_t )strlen( pIceAgent->remotePassword ) * sizeof( char ),
                                               pSendStunMessageBufferLength );
        }
        if( retStatus == ICE_RESULT_OK )
        {
            *ppSendStunMessageBuffer = pIceAgent->stunMessageBuffers[pIceAgent->stunMessageBufferUsedCount - 1];
            pIceCandidatePair->connectivityChecks |= 1 << 1;
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
    IceResult_t retStatus = ICE_RESULT_OK;
    StunContext_t stunCxt;
    StunHeader_t stunHeader;
    StunAttributeAddress_t stunMappedAddress;

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
        retStatus = Ice_InitializeStunPacket( &stunCxt,
                                              pTransactionIdBuffer,
                                              pIceAgent->stunMessageBuffers[pIceAgent->stunMessageBufferUsedCount++],
                                              &stunHeader,
                                              1,
                                              0 );
    }

    if( retStatus == ICE_RESULT_OK )
    {
        stunMappedAddress = pSrcAddr->ipAddress;
        retStatus = StunSerializer_AddAttributeXorMappedAddress( &stunCxt,
                                                                 &stunMappedAddress );
    }

    if( retStatus == ICE_RESULT_OK )
    {
        if( pIceAgent->isControlling == 0 )
        {
            retStatus = StunSerializer_AddAttributeIceControlled( &stunCxt,
                                                                  pIceAgent->tieBreaker );
        }
        else
        {
            retStatus = StunSerializer_AddAttributeIceControlling( &stunCxt,
                                                                   pIceAgent->tieBreaker );
        }
    }

    if( retStatus == ICE_RESULT_OK )
    {
        retStatus = Ice_PackageStunPacket( pIceAgent,
                                           &stunCxt,
                                           ( uint8_t * )pIceAgent->localPassword,
                                           ( uint32_t )strlen( pIceAgent->localPassword ) * sizeof( char ),
                                           pSendStunMessageBufferLength );
    }

    if( retStatus == ICE_RESULT_OK )
    {
        *ppSendStunMessageBuffer = pIceAgent->stunMessageBuffers[pIceAgent->stunMessageBufferUsedCount - 1];
    }
    return retStatus;
}
/*------------------------------------------------------------------------------------------------------------------*/

/* Ice_DeserializeStunPacket - This API deserializes a received STUN packet . */

IceResult_t Ice_DeserializeStunPacket( StunContext_t * pStunCxt,
                                       StunHeader_t * pStunHeader,
                                       StunAttribute_t * pStunAttribute,
                                       StunAttributeAddress_t * pStunAttributeAddress,
                                       uint32_t * pPriority )
{

    IceResult_t retStatus = ICE_RESULT_OK;

    if( ( pStunCxt == NULL ) ||
        ( pStunHeader == NULL ) ||
        ( pStunAttribute == NULL ) ||
        ( pStunAttributeAddress == NULL ) ||
        ( pPriority == NULL ) )
    {
        retStatus = ICE_RESULT_BAD_PARAM;
    }

    while( retStatus == ICE_RESULT_OK )
    {
        retStatus = StunDeserializer_GetNextAttribute( pStunCxt,
                                                       pStunAttribute );

        if( retStatus == ICE_RESULT_OK )
        {
            switch( pStunAttribute->attributeType )
            {
            case STUN_ATTRIBUTE_TYPE_XOR_MAPPED_ADDRESS:
            {
                retStatus = StunDeserializer_ParseAttributeAddress( pStunCxt,
                                                                    pStunAttribute,
                                                                    pStunAttributeAddress );
                retStatus = ICE_RESULT_UPDATE_SRFLX_CANDIDATE;
            }
            break;
            case STUN_ATTRIBUTE_TYPE_USE_CANDIDATE:
            {
                retStatus = ICE_RESULT_USE_CANDIDATE_FLAG;
            }
            break;
            case STUN_ATTRIBUTE_TYPE_PRIORITY:
            {
                retStatus = StunDeserializer_ParseAttributePriority( pStunCxt,
                                                                     pStunAttribute,
                                                                     pPriority );
            }
            break;
            default:
                break;
            }
        }
    }
    return retStatus;
}
/*------------------------------------------------------------------------------------------------------------------*/

/*
 +-----+-----+-----+-----+-----+
 |     | BIT3| BIT2| BIT1| BIT0|
 +-----+-----+-----+-----+-----+

    This depicts the connectivityChecks in a candidate pair, these 4 bits show which bit stands for which STUN request/ response.

     1. BIT0 - STUN request from local candidate to remote candidate.
     2. BIT1 - STUN response from remote candidate to local candidate.
     3. BIT2 - STUN request from remote candidate to local candidate.
     4. BIT3 - STUN response from local candidate to remote candidate.

 */

/* Ice_HandleStunPacket - This API handles the processing of Stun Response. */

IceResult_t Ice_HandleStunPacket( IceAgent_t * pIceAgent,
                                  uint8_t * pReceivedStunMessageBuffer,
                                  uint32_t receivedStunMessageBufferLength,
                                  uint8_t * pTransactionIdBuffer,
                                  uint8_t ** ppSendStunMessageBuffer,
                                  uint32_t * pSendStunMessageBufferLength,
                                  IceIPAddress_t * pLocalCandidateAddress,
                                  IceIPAddress_t * pRemoteCandidateAddress,
                                  IceCandidatePair_t ** ppIceCandidatePair )
{
    IceResult_t retStatus = ICE_RESULT_OK;
    uint32_t priority = 0;
    StunContext_t stunCxt;
    StunHeader_t stunHeader;
    StunAttribute_t stunAttribute;
    StunAttributeAddress_t stunAttributeAddress;
    IceCandidate_t * pLocalCandidate;
    IceCandidate_t * pRemoteCandidate;
    IceCandidatePair_t * pIceCandidatePair;
    IceIPAddress_t newIpAddr;
    bool foundLocalCandidate = false;
    bool foundRemoteCandidate = false;
    bool foundCandidatePair = false;

    if( ( pIceAgent == NULL ) ||
        ( pReceivedStunMessageBuffer == NULL ) ||
        ( receivedStunMessageBufferLength > ICE_STUN_MESSAGE_BUFFER_SIZE ) ||
        ( pTransactionIdBuffer == NULL ) ||
        ( pLocalCandidateAddress == NULL ) ||
        ( pRemoteCandidateAddress == NULL ) ||
        ( ppSendStunMessageBuffer == NULL ) ||
        ( pSendStunMessageBufferLength == NULL ) )
    {
        retStatus = ICE_RESULT_BAD_PARAM;
    }

    /* Initialize STUN context for deserializing. */
    if( retStatus == ICE_RESULT_OK )
    {
        retStatus = StunDeserializer_Init( &stunCxt,
                                           pReceivedStunMessageBuffer,
                                           receivedStunMessageBufferLength,
                                           &stunHeader );
    }

    if( retStatus == ICE_RESULT_OK )
    {
        retStatus = Ice_DeserializeStunPacket( &stunCxt,
                                               &stunHeader,
                                               &stunAttribute,
                                               &stunAttributeAddress,
                                               &priority );
    }

    if( ( retStatus == ICE_RESULT_OK ) ||
        ( retStatus == ICE_RESULT_UPDATE_SRFLX_CANDIDATE ) ||
        ( retStatus == ICE_RESULT_USE_CANDIDATE_FLAG ) )
    {
        switch( stunHeader.messageType )
        {
        case STUN_MESSAGE_TYPE_BINDING_REQUEST:
        {
            retStatus = Ice_CheckPeerReflexiveCandidate( pIceAgent,
                                                         pRemoteCandidateAddress,
                                                         priority,
                                                         true );
            if( retStatus == ICE_RESULT_OK )
            {
                foundCandidatePair = Ice_FindCandidatePairWithLocalAndRemoteAddr( pIceAgent,
                                                                                  pLocalCandidateAddress,
                                                                                  pRemoteCandidateAddress,
                                                                                  &pIceCandidatePair );
            }

            if( foundCandidatePair )
            {
                /* Check if received candidate with USE_CANDIDATE FLAG */
                if( ( retStatus == ICE_RESULT_USE_CANDIDATE_FLAG ) && ( pIceCandidatePair->connectivityChecks == ICE_CONNECTIVITY_SUCCESS_FLAG ) )
                {
                    pIceCandidatePair->state = ICE_CANDIDATE_PAIR_STATE_NOMINATED;
                    retStatus = ICE_RESULT_SEND_RESPONSE_FOR_NOMINATION;
                }
                else
                {
                    pIceCandidatePair->connectivityChecks |= 1 << 2; //Received a connection request from remote candidate.

                    if( ( pIceCandidatePair->connectivityChecks & 1 ) == 0 )
                    {
                        /* Create a request from local to remote candidate. */
                        pIceCandidatePair->connectivityChecks |= 1 << 0;
                        /* Create a response for received request. */
                        pIceCandidatePair->connectivityChecks |= 1 << 3;

                        retStatus = ICE_RESULT_SEND_TRIGGERED_CHECK; //The application needs to send 2 stun packets.
                    }
                    else
                    {
                        /* Create a response for received request. */
                        pIceCandidatePair->connectivityChecks |= 1 << 3;

                        retStatus = ICE_RESULT_SEND_RESPONSE_FOR_REMOTE_REQUEST; //The application needs to send 1 stun packet.
                    }
                }
            }
            else
            {
                retStatus = ICE_RESULT_CANDIDATE_PAIR_NOT_FOUND; // Candidate Pair was not found using the local and remote IP address.
            }

        }
        break;
        case STUN_MESSAGE_TYPE_BINDING_SUCCESS_RESPONSE:
        {
            if( Ice_TransactionIdStoreHasId( pIceAgent->pStunBindingRequestTransactionIdStore,
                                             pReceivedStunMessageBuffer + STUN_HEADER_TRANSACTION_ID_OFFSET ) )
            {
                if( retStatus == ICE_RESULT_UPDATE_SRFLX_CANDIDATE )
                {
                    foundLocalCandidate = Ice_FindCandidateFromIp( pIceAgent,
                                                                   *pLocalCandidateAddress,
                                                                   0,
                                                                   &pLocalCandidate );

                    if( foundLocalCandidate )
                    {
                        retStatus = Ice_HandleServerReflexiveCandidateResponse( pIceAgent,
                                                                                &stunAttributeAddress,
                                                                                pLocalCandidate );

                        if( retStatus == ICE_RESULT_OK )
                        {
                            Ice_TransactionIdStoreRemove( pIceAgent->pStunBindingRequestTransactionIdStore,
                                                          pReceivedStunMessageBuffer + STUN_HEADER_TRANSACTION_ID_OFFSET );
                        }

                        retStatus = ICE_RESULT_UPDATED_SRFLX_CANDIDATE_ADDRESS;
                    }
                    else
                    {
                        retStatus = ICE_RESULT_CANDIDATE_NOT_FOUND; //Local candidate was not found.
                    }
                }
            }
            else
            {
                foundCandidatePair = Ice_FindCandidatePairWithLocalAndRemoteAddr( pIceAgent,
                                                                                  pLocalCandidateAddress,
                                                                                  pRemoteCandidateAddress,
                                                                                  &pIceCandidatePair );

                if( foundCandidatePair )
                {
                    if( Ice_TransactionIdStoreHasId( pIceCandidatePair->pTransactionIdStore,
                                                     pReceivedStunMessageBuffer + STUN_HEADER_TRANSACTION_ID_OFFSET ) )
                    {
                        if( pIceCandidatePair->connectivityChecks & 2 == 0 )
                        {
                            pIceCandidatePair->connectivityChecks |= 1 << 1;
                        }

                        if( pIceCandidatePair->connectivityChecks == ICE_CONNECTIVITY_SUCCESS_FLAG )
                        {
                            if( pIceCandidatePair->state == ICE_CANDIDATE_PAIR_STATE_NOMINATED )
                            {
                                pIceCandidatePair->state = ICE_CANDIDATE_PAIR_STATE_SUCCEEDED;
                                retStatus = ICE_RESULT_CANDIDATE_PAIR_READY;
                            }
                            else
                            {
                                pIceCandidatePair->state = ICE_CANDIDATE_PAIR_STATE_VALID;
                                retStatus = ICE_RESULT_START_NOMINATION;
                            }
                        }
                        else
                        {
                            if( &stunAttributeAddress != NULL )
                            {
                                if( ( pIceCandidatePair->pLocal->iceCandidateType == ICE_CANDIDATE_TYPE_SERVER_REFLEXIVE ) &&
                                    ( pIceCandidatePair->pRemote->iceCandidateType == ICE_CANDIDATE_TYPE_SERVER_REFLEXIVE ) &&
                                    ( Ice_IsSameIpAddress( &stunAttributeAddress,
                                                           &pIceCandidatePair->pLocal->ipAddress.ipAddress,
                                                           false ) == 0 ) )
                                {
                                    printf( "Local Candidate IP address does not match with XOR mapped address in binding response.\n" );

                                    newIpAddr.ipAddress = stunAttributeAddress;
                                    newIpAddr.isPointToPoint = 0;

                                    retStatus = Ice_CheckPeerReflexiveCandidate( pIceAgent,
                                                                                 &newIpAddr,
                                                                                 pIceCandidatePair->pLocal->priority,
                                                                                 false );
                                }
                            }
                            else
                            {
                                printf( "No mapped address attribute found in STUN response. Dropping Packet.\n" );
                            }
                        }
                    }
                    else
                    {
                        printf( "Dropping response packet because transaction id does not match.\n" );
                    }
                }
                else
                {
                    retStatus = ICE_RESULT_CANDIDATE_PAIR_NOT_FOUND; // Candidate Pair was not found using the local and remote IP address.
                }
            }
        }
        break;
        case STUN_MESSAGE_TYPE_BINDING_INDICATION:
            printf( "Received STUN binding indication.\n" );
            break;
        default:
            printf( "STUN packet received is neither a Binding Request nor a Response.\n" );
            break;
        }
    }

    if( retStatus != ICE_RESULT_CANDIDATE_PAIR_NOT_FOUND )
    {
        *ppIceCandidatePair = pIceCandidatePair;
    }

    return retStatus;
}

/*------------------------------------------------------------------------------------------------------------------*/

/* Ice_HandleServerReflexiveCandidateResponse - 1. Parse STUN Binding Response from the STUN server to get Server Reflexive candidate.
                                                2. Add the Server Reflexive candidate to the ICE Library. */

IceResult_t Ice_HandleServerReflexiveCandidateResponse( IceAgent_t * pIceAgent,
                                                        StunAttributeAddress_t * pStunMappedAddress,
                                                        IceCandidate_t * pLocalCandidate )
{
    IceResult_t retStatus = ICE_RESULT_OK;
    IceIPAddress_t ipAddr;

    if( ( pIceAgent == NULL ) ||
        ( pStunMappedAddress == NULL ) ||
        ( pLocalCandidate == NULL ) )
    {
        retStatus = ICE_RESULT_BAD_PARAM;
    }

    if( retStatus == ICE_RESULT_OK )
    {
        ipAddr.ipAddress = *( pStunMappedAddress );
        ipAddr.isPointToPoint = 0;

        retStatus = Ice_UpdateSrflxCandidateAddress( pIceAgent,
                                                     pLocalCandidate,
                                                     &ipAddr );
    }

    return retStatus;
}
/*------------------------------------------------------------------------------------------------------------------*/

/* Ice_GetValidLocalCandidateCount - Get valid Local Candidate count */

int Ice_GetValidLocalCandidateCount( IceAgent_t * pIceAgent )
{
    int i = -1;

    if( pIceAgent != NULL )
    {
        for( i = 0; i < ICE_MAX_LOCAL_CANDIDATE_COUNT; i++ )
        {
            if( pIceAgent->localCandidates[i].state == ICE_CANDIDATE_STATE_INVALID )
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
    int i = -1;

    if( pIceAgent != NULL )
    {
        for( i = 0; i < ICE_MAX_REMOTE_CANDIDATE_COUNT; i++ )
        {
            if( pIceAgent->remoteCandidates[i].state == ICE_CANDIDATE_STATE_INVALID )
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
    int i = -1;

    if( pIceAgent != NULL )
    {
        for( i = 0; i < ICE_MAX_CANDIDATE_PAIR_COUNT; i++ )
        {
            if( pIceAgent->iceCandidatePairs[i].state == ICE_CANDIDATE_PAIR_STATE_INVALID )
            {
                break;
            }
        }
    }
    return( i );
}
/*------------------------------------------------------------------------------------------------------------------*/

/* Ice_ComputeCandidatePriority - Compute the candidate priority */

static uint32_t Ice_ComputeCandidatePriority( IceCandidate_t * pIceCandidate )
{
    uint32_t typePreference = 0, localPreference = 0;

    switch( pIceCandidate->iceCandidateType )
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
    }

    if( !pIceCandidate->ipAddress.isPointToPoint )
    {
        localPreference = ICE_PRIORITY_LOCAL_PREFERENCE;
    }

    return( ( 1 << 24 ) * ( typePreference ) + ( 1 << 8 ) * ( localPreference ) + 255 );
}
/*------------------------------------------------------------------------------------------------------------------*/

/* Ice_ComputeCandidatePairPriority - Compute the candidate pair priority. */

static uint64_t Ice_ComputeCandidatePairPriority( IceCandidatePair_t * pIceCandidatePair,
                                                  uint32_t isLocalControlling )
{
    uint64_t controllingAgentCandidatePri = pIceCandidatePair->pLocal->priority;
    uint64_t controlledAgentCandidatePri = pIceCandidatePair->pRemote->priority;

    if( isLocalControlling == 0 )
    {
        controllingAgentCandidatePri = controlledAgentCandidatePri;
        controlledAgentCandidatePri = pIceCandidatePair->pLocal->priority;
    }

    return( ( ( uint64_t )1 << 32 ) * ( controllingAgentCandidatePri >= controlledAgentCandidatePri ? controlledAgentCandidatePri : controllingAgentCandidatePri ) +
            2 * ( controllingAgentCandidatePri >= controlledAgentCandidatePri ? controllingAgentCandidatePri : controlledAgentCandidatePri ) + ( controllingAgentCandidatePri > controlledAgentCandidatePri ? 1 : 0 ) );
}
/*------------------------------------------------------------------------------------------------------------------*/

/* Ice_CreateTransactionIdStore - Creates the Transaction ID Store. */

static IceResult_t Ice_CreateTransactionIdStore( uint32_t maxIdCount,
                                                 TransactionIdStore_t * pTransactionIdStore )
{
    IceResult_t retStatus = ICE_RESULT_OK;

    if( ( pTransactionIdStore == NULL ) || ( maxIdCount > ICE_MAX_STORED_TRANSACTION_ID_COUNT ) || ( maxIdCount < 0 ) )
    {
        retStatus = ICE_RESULT_BAD_PARAM;
    }

    if( retStatus == ICE_RESULT_OK )
    {
        pTransactionIdStore->pTransactionIds = ( uint8_t * )( pTransactionIdStore + 1 );
        pTransactionIdStore->maxTransactionIdsCount = maxIdCount;
    }

    return retStatus;
}
/*------------------------------------------------------------------------------------------------------------------*/

/* Ice_TransactionIdStoreInsert - Inserts the Transaction in the IceAgent Transaction ID Store. */

static void Ice_TransactionIdStoreInsert( TransactionIdStore_t * pTransactionIdStore,
                                          uint8_t * pTransactionId )
{
    uint8_t * storeLocation = NULL;
    uint32_t transactionIDCount;

    if( pTransactionIdStore != NULL )
    {
        storeLocation = pTransactionIdStore->pTransactionIds + ( ( pTransactionIdStore->nextTransactionIdIndex % pTransactionIdStore->maxTransactionIdsCount ) * STUN_HEADER_TRANSACTION_ID_LENGTH );
        memcpy( storeLocation,
                pTransactionId,
                STUN_HEADER_TRANSACTION_ID_LENGTH );

        pTransactionIdStore->nextTransactionIdIndex = ( pTransactionIdStore->nextTransactionIdIndex + 1 ) % pTransactionIdStore->maxTransactionIdsCount;

        if( pTransactionIdStore->nextTransactionIdIndex == pTransactionIdStore->earliestTransactionIdIndex )
        {
            pTransactionIdStore->earliestTransactionIdIndex =
                ( pTransactionIdStore->earliestTransactionIdIndex + 1 ) % pTransactionIdStore->maxTransactionIdsCount;
            return;
        }

        transactionIDCount = ( ( pTransactionIdStore->transactionIdCount + 1 ) > ( pTransactionIdStore->maxTransactionIdsCount ) ) ? pTransactionIdStore->maxTransactionIdsCount : ( pTransactionIdStore->transactionIdCount + 1 );

        pTransactionIdStore->transactionIdCount = transactionIDCount;
    }
}
/*------------------------------------------------------------------------------------------------------------------*/

/* Ice_TransactionIdStoreHasId - Checks if the transaction is present in the Transaction ID Store. */

static bool Ice_TransactionIdStoreHasId( TransactionIdStore_t * pTransactionIdStore,
                                         uint8_t * pTransactionId )
{
    bool idFound = false;
    int i, j;

    if( pTransactionIdStore != NULL )
    {
        for( i = pTransactionIdStore->earliestTransactionIdIndex, j = 0; j < pTransactionIdStore->maxTransactionIdsCount && !idFound; ++j )
        {
            if( memcmp( pTransactionId,
                        pTransactionIdStore->pTransactionIds + i * STUN_HEADER_TRANSACTION_ID_LENGTH,
                        STUN_HEADER_TRANSACTION_ID_LENGTH ) == 0 )
            {
                idFound = true;
            }
            i = ( i + 1 ) % pTransactionIdStore->maxTransactionIdsCount;
        }
    }
    return idFound;
}
/*------------------------------------------------------------------------------------------------------------------*/

/* Ice_TransactionIdStoreRemove - Inserts the Transaction in the IceAgent Transaction ID Store. */

static void Ice_TransactionIdStoreRemove( TransactionIdStore_t * pTransactionIdStore,
                                          uint8_t * pTransactionId )
{
    uint32_t i, j;

    if( pTransactionIdStore != NULL )
    {
        for( i = pTransactionIdStore->earliestTransactionIdIndex, j = 0; j < pTransactionIdStore->maxTransactionIdsCount; ++j )
        {
            if( memcmp( pTransactionId,
                        pTransactionIdStore->pTransactionIds + i * STUN_HEADER_TRANSACTION_ID_LENGTH,
                        STUN_HEADER_TRANSACTION_ID_LENGTH ) == 0 )
            {
                memset( pTransactionIdStore->pTransactionIds + i * STUN_HEADER_TRANSACTION_ID_LENGTH,
                        0x00,
                        STUN_HEADER_TRANSACTION_ID_LENGTH );
                return;
            }

            i = ( i + 1 ) % pTransactionIdStore->maxTransactionIdsCount;
        }
    }
}
/*------------------------------------------------------------------------------------------------------------------*/

/* Ice_FindCandidateFromIp - This API is called internally to search for a candidate with a given IP. */

static bool Ice_FindCandidateFromIp( IceAgent_t * pIceAgent,
                                     IceIPAddress_t iceIpAddress,
                                     bool isRemote,
                                     IceCandidate_t ** ppCandidate )
{
    int i;
    StunAttributeAddress_t stunAddress;
    uint32_t addrLen;
    bool foundCandidate = false;

    if( ( pIceAgent != NULL ) && ( ppCandidate != NULL ) )
    {
        stunAddress = iceIpAddress.ipAddress;
        addrLen = ICE_IS_IPV4_ADDR( stunAddress ) ? STUN_IPV4_ADDRESS_SIZE : STUN_IPV6_ADDRESS_SIZE;

        if( isRemote == false )
        {
            for( i = 0; i < Ice_GetValidLocalCandidateCount( pIceAgent ); i++ )
            {
                if( Ice_IsSameIpAddress( &stunAddress, &pIceAgent->localCandidates[i].ipAddress.ipAddress, true ) == true )
                {
                    *ppCandidate = &pIceAgent->localCandidates[i];
                    foundCandidate = true;
                    break;
                }
            }
        }
        else
        {
            for( i = 0; i < Ice_GetValidRemoteCandidateCount( pIceAgent ); i++ )
            {
                if( Ice_IsSameIpAddress( &stunAddress, &pIceAgent->remoteCandidates[i].ipAddress.ipAddress, true ) == true )
                {
                    *ppCandidate = &pIceAgent->remoteCandidates[i];
                    foundCandidate = true;
                    break;
                }
            }
        }
    }
    return foundCandidate;
}
/*------------------------------------------------------------------------------------------------------------------*/

/* Ice_FindCandidatePairWithLocalAndRemoteAddr - This API is called internally to find a candidate pair given the local and remote IP addresses. */

static bool Ice_FindCandidatePairWithLocalAndRemoteAddr( IceAgent_t * pIceAgent,
                                                         IceIPAddress_t * pSrcAddr,
                                                         IceIPAddress_t * pRemoteAddr,
                                                         IceCandidatePair_t ** ppCandidatePair )
{
    int i;
    int candidatePairCount;
    IceCandidatePair_t iceCandidatePair;
    bool found = false;

    if( ( pIceAgent == NULL ) ||
        ( pSrcAddr == NULL ) ||
        ( pRemoteAddr == NULL ) ||
        ( ppCandidatePair == NULL ) )
    {
        *ppCandidatePair = NULL;
        return false;
    }

    candidatePairCount = Ice_GetValidCandidatePairCount( pIceAgent );
    for( i = 0; i < candidatePairCount; i++ )
    {
        iceCandidatePair = pIceAgent->iceCandidatePairs[i];
        if( ( Ice_IsSameIpAddress( &( iceCandidatePair.pLocal->ipAddress.ipAddress ), &( pSrcAddr->ipAddress ), true ) ) && ( Ice_IsSameIpAddress( &( iceCandidatePair.pRemote->ipAddress.ipAddress ), &( pRemoteAddr->ipAddress ), true ) ) )
        {
            *ppCandidatePair = &( pIceAgent->iceCandidatePairs[i] );
            found = true;
        }
    }

    return found;
}
/*------------------------------------------------------------------------------------------------------------------*/

/* Ice_IsSameIpAddress - This API is called internally to check if two IPAddress are same. */

static bool Ice_IsSameIpAddress( StunAttributeAddress_t * pAddr1,
                                 StunAttributeAddress_t * pAddr2,
                                 bool checkPort )
{
    bool ret;
    uint32_t addrLen;

    if( ( pAddr1 == NULL ) || ( pAddr2 == NULL ) )
    {
        return false;
    }

    addrLen = ICE_IS_IPV4_ADDR( *pAddr1 ) ? STUN_IPV4_ADDRESS_SIZE : STUN_IPV6_ADDRESS_SIZE;

    ret = ( pAddr1->family == pAddr2->family && memcmp( pAddr1->address, pAddr2->address, addrLen ) == 0 && ( !checkPort || pAddr1->port == pAddr2->port ) );

    return ret;
}
/*------------------------------------------------------------------------------------------------------------------*/
