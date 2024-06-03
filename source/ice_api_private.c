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

/* Ice_IsSameIpAddress - This API is called internally to check if two IPAddresses are same. */

bool Ice_IsSameIpAddress( StunAttributeAddress_t * pAddr1,
                          StunAttributeAddress_t * pAddr2,
                          bool checkPort )
{
    bool isSameAddress = false;
    uint32_t addrLen = 0;

    if( ( pAddr1 == NULL ) || ( pAddr2 == NULL ) )
    {
        isSameAddress = false;
    }
    else
    {
        addrLen = ICE_IS_IPV4_ADDR( *pAddr1 ) ? STUN_IPV4_ADDRESS_SIZE : STUN_IPV6_ADDRESS_SIZE;

        isSameAddress = ( pAddr1->family == pAddr2->family &&
                          ( memcmp( pAddr1->address,
                                    pAddr2->address,
                                    addrLen ) == 0 ) &&
                          ( !checkPort || pAddr1->port == pAddr2->port ) );
    }

    return isSameAddress;
}

/*------------------------------------------------------------------------------------------------------------------*/

/* Ice_FindCandidateFromIP - This API is called internally to search for a candidate with a given IP. */

bool Ice_FindCandidateFromIP( IceAgent_t * pIceAgent,
                              IceCandidate_t ** ppCandidate,
                              IceIPAddress_t iceIpAddress,
                              bool isRemote )
{
    int i;
    StunAttributeAddress_t stunAddress;
    uint32_t addrLen = 0;
    bool foundCandidate = false;

    if( ( pIceAgent != NULL ) && ( ppCandidate != NULL ) )
    {
        memcpy( &( stunAddress ),
                &( iceIpAddress.ipAddress ),
                sizeof( StunAttributeAddress_t ) );
        addrLen = ICE_IS_IPV4_ADDR( stunAddress ) ? STUN_IPV4_ADDRESS_SIZE : STUN_IPV6_ADDRESS_SIZE;

        if( !isRemote )
        {
            for( i = 0; i < Ice_GetValidLocalCandidateCount( pIceAgent ); i++ )
            {
                if( Ice_IsSameIpAddress( &( stunAddress ),
                                         &( pIceAgent->localCandidates[ i ].ipAddress.ipAddress ),
                                         true ) == true )
                {
                    *ppCandidate = &( pIceAgent->localCandidates[ i ] );
                    foundCandidate = true;
                    break;
                }
            }
        }
        else
        {
            for( i = 0; i < Ice_GetValidRemoteCandidateCount( pIceAgent ); i++ )
            {
                if( Ice_IsSameIpAddress( &( stunAddress ),
                                         &( pIceAgent->remoteCandidates[ i ].ipAddress.ipAddress ),
                                         true ) == true )
                {
                    *ppCandidate = &( pIceAgent->remoteCandidates[ i ] );
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

bool Ice_FindCandidatePairWithLocalAndRemoteAddr( IceAgent_t * pIceAgent,
                                                  IceIPAddress_t * pSrcAddr,
                                                  IceIPAddress_t * pRemoteAddr,
                                                  IceCandidatePair_t ** ppCandidatePair )
{
    int i;
    IceCandidatePair_t iceCandidatePair;
    int candidatePairCount = 0;
    bool found = false;

    if( ( pIceAgent == NULL ) ||
        ( pSrcAddr == NULL ) ||
        ( pRemoteAddr == NULL ) ||
        ( ppCandidatePair == NULL ) )
    {
        found = false;
    }
    else
    {
        candidatePairCount = Ice_GetValidCandidatePairCount( pIceAgent );

        for( i = 0; i < candidatePairCount; i++ )
        {
            iceCandidatePair = pIceAgent->iceCandidatePairs[ i ];

            if( ( Ice_IsSameIpAddress( &( iceCandidatePair.pLocal->ipAddress.ipAddress ),
                                       &( pSrcAddr->ipAddress ),
                                       true ) ) && ( Ice_IsSameIpAddress( &( iceCandidatePair.pRemote->ipAddress.ipAddress ),
                                                                          &( pRemoteAddr->ipAddress ),
                                                                          true ) ) )
            {
                *ppCandidatePair = &( pIceAgent->iceCandidatePairs[ i ] );
                found = true;
            }
        }
    }

    return found;
}

/*------------------------------------------------------------------------------------------------------------------*/

/* Ice_CreateTransactionIdStore - Creates the Transaction ID Store. */

IceResult_t Ice_CreateTransactionIdStore( uint32_t maxIdCount,
                                          TransactionIdStore_t * pTransactionIdStore )
{
    IceResult_t retStatus = ICE_RESULT_OK;

    if( ( pTransactionIdStore == NULL ) ||
        ( maxIdCount > ICE_MAX_STORED_TRANSACTION_ID_COUNT ) ||
        ( maxIdCount < 0 ) )
    {
        retStatus = ICE_RESULT_BAD_PARAM;
    }

    if( retStatus == ICE_RESULT_OK )
    {
        pTransactionIdStore->pTransactionIds = ( uint8_t * ) ( pTransactionIdStore + 1 );
        pTransactionIdStore->maxTransactionIdsCount = maxIdCount;
    }

    return retStatus;
}

/*------------------------------------------------------------------------------------------------------------------*/

/* Ice_TransactionIdStoreInsert - Inserts the Transaction in the IceAgent Transaction ID Store. */

void Ice_TransactionIdStoreInsert( TransactionIdStore_t * pTransactionIdStore,
                                   uint8_t * pTransactionId )
{
    uint8_t * storeLocation = NULL;
    uint32_t transactionIDCount = 0;

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
        }

        transactionIDCount = ( ( pTransactionIdStore->transactionIdCount + 1 ) > ( pTransactionIdStore->maxTransactionIdsCount ) ) ? pTransactionIdStore->maxTransactionIdsCount : ( pTransactionIdStore->transactionIdCount + 1 );

        pTransactionIdStore->transactionIdCount = transactionIDCount;
    }

    return;
}

/*------------------------------------------------------------------------------------------------------------------*/

/* Ice_TransactionIdStoreHasId - Checks if the transaction is present in the Transaction ID Store. */

bool Ice_TransactionIdStoreHasId( TransactionIdStore_t * pTransactionIdStore,
                                  uint8_t * pTransactionId )
{
    bool idFound = false;
    uint32_t i, j;

    if( pTransactionIdStore != NULL )
    {
        for( i = pTransactionIdStore->earliestTransactionIdIndex, j = 0; j < pTransactionIdStore->maxTransactionIdsCount && !idFound; ++j )
        {
            if( memcmp( pTransactionId,
                        ( pTransactionIdStore->pTransactionIds + ( i * STUN_HEADER_TRANSACTION_ID_LENGTH ) ),
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

void Ice_TransactionIdStoreRemove( TransactionIdStore_t * pTransactionIdStore,
                                   uint8_t * pTransactionId )
{
    uint32_t i, j;

    if( ( pTransactionIdStore != NULL ) && ( pTransactionId != NULL ) )
    {
        for( i = pTransactionIdStore->earliestTransactionIdIndex, j = 0; j < pTransactionIdStore->maxTransactionIdsCount; ++j )
        {
            if( memcmp( pTransactionId,
                        ( pTransactionIdStore->pTransactionIds + ( i * STUN_HEADER_TRANSACTION_ID_LENGTH ) ),
                        STUN_HEADER_TRANSACTION_ID_LENGTH ) == 0 )
            {
                memset( ( pTransactionIdStore->pTransactionIds + ( i * STUN_HEADER_TRANSACTION_ID_LENGTH ) ),
                        0x00,
                        STUN_HEADER_TRANSACTION_ID_LENGTH );
                break;
            }

            i = ( i + 1 ) % pTransactionIdStore->maxTransactionIdsCount;
        }
    }

    return;
}

/*------------------------------------------------------------------------------------------------------------------*/

/* Ice_CreateCandidatePair - The library calls this API for creating candidate pair between a local and remote candidate . */

IceResult_t Ice_CreateCandidatePair( IceAgent_t * pIceAgent,
                                     IceCandidate_t * pLocalCandidate,
                                     IceCandidate_t * pRemoteCandidate )
{
    IceResult_t retStatus = ICE_RESULT_OK;
    int iceCandidatePairCount = 0;
    IceCandidatePair_t * pIceCandidatePair = NULL;

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
            pIceCandidatePair = &( pIceAgent->iceCandidatePairs[ iceCandidatePairCount ] );
        }

        if( retStatus == ICE_RESULT_OK )
        {
            pIceCandidatePair->pLocal = pLocalCandidate;
            pIceCandidatePair->pRemote = pRemoteCandidate;
            pIceCandidatePair->state = ICE_CANDIDATE_PAIR_STATE_WAITING;
            pIceCandidatePair->priority = Ice_ComputeCandidatePairPriority( pIceCandidatePair,
                                                                            pIceAgent->isControlling );
            pIceCandidatePair->connectivityChecks = 0;
        }

        if( retStatus == ICE_RESULT_OK )
        {
            memset( pIceCandidatePair->pTransactionIdStore,
                    0x00,
                    ICE_DEFAULT_MAX_STORED_TRANSACTION_ID_COUNT );
            retStatus = Ice_InsertCandidatePair( pIceAgent,
                                                 pIceCandidatePair,
                                                 iceCandidatePairCount );
        }
    }

    return retStatus;
}

/*------------------------------------------------------------------------------------------------------------------*/

/* Ice_insertCandidatePair : This API is called internally to insert candidate pairs based on decreasing priority. */

IceResult_t Ice_InsertCandidatePair( IceAgent_t * pIceAgent,
                                     IceCandidatePair_t * pIceCandidatePair,
                                     int iceCandidatePairCount )
{
    int i;
    IceResult_t retStatus = ICE_RESULT_OK;
    IceCandidatePair_t pivotCandidatePair = *pIceCandidatePair;
    int pivot = iceCandidatePairCount;

    if( ( pIceAgent != NULL ) && ( pIceCandidatePair != NULL ) )
    {
        for( i = 0; i < iceCandidatePairCount; i++ )
        {
            if( pivotCandidatePair.priority >= pIceAgent->iceCandidatePairs[ i ].priority )
            {
                pivot = i;
                break;
            }
        }

        for( i = iceCandidatePairCount; i > pivot; i-- )
        {
            pIceAgent->iceCandidatePairs[ i ] = pIceAgent->iceCandidatePairs[ i - 1 ];
        }

        pIceAgent->iceCandidatePairs[ pivot ] = pivotCandidatePair;
    }
    else
    {
        retStatus = ICE_RESULT_BAD_PARAM;
    }

    return retStatus;
}

/*------------------------------------------------------------------------------------------------------------------*/

/*  Ice_CheckRemotePeerReflexiveCandidate - The library calls this API for creating remote peer reflexive candidates on receiving a STUN binding request. */

IceResult_t Ice_CheckPeerReflexiveCandidate( IceAgent_t * pIceAgent,
                                             IceIPAddress_t * pIpAddr,
                                             IceCandidate_t * pLocalCandidate,
                                             uint32_t priority,
                                             bool isRemote )
{
    IceResult_t retStatus = ICE_RESULT_OK;
    IceCandidate_t * pPeerReflexiveCandidate = NULL;
    bool foundDuplicatedCandidate = false;

    if( ( pIceAgent == NULL ) ||
        ( pIpAddr == NULL ) ||
        ( !isRemote && ( pLocalCandidate == NULL ) ) )
    {
        retStatus = ICE_RESULT_BAD_PARAM;
    }

    if( retStatus == ICE_RESULT_OK )
    {
        if( !isRemote )
        {
            pLocalCandidate->iceCandidateType = ICE_CANDIDATE_TYPE_PEER_REFLEXIVE;
            memcpy( &( pLocalCandidate->ipAddress ),
                    pIpAddr,
                    sizeof( IceIPAddress_t ) );
        }
        else
        {
            foundDuplicatedCandidate = Ice_FindCandidateFromIP( pIceAgent,
                                                                &( pPeerReflexiveCandidate ),
                                                                *pIpAddr,
                                                                isRemote );

            if( !foundDuplicatedCandidate )
            {
                retStatus = Ice_AddRemoteCandidate( pIceAgent,
                                                    ICE_CANDIDATE_TYPE_PEER_REFLEXIVE,
                                                    &( pPeerReflexiveCandidate ),
                                                    *pIpAddr,
                                                    0,
                                                    priority );
            }
        }
    }

    return retStatus;
}
/*------------------------------------------------------------------------------------------------------------------*/

/* Ice_ComputeCandidatePriority - Compute the candidate priority */

uint32_t Ice_ComputeCandidatePriority( IceCandidate_t * pIceCandidate )
{
    uint32_t typePreference = 0;
    uint32_t localPreference = 0;
    uint32_t candidatePriority = 0;

    if( pIceCandidate != NULL )
    {
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

            default:
                break;
        }

        if( !pIceCandidate->ipAddress.isPointToPoint )
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
    }

    return candidatePriority;
}

/*------------------------------------------------------------------------------------------------------------------*/

/* Ice_ComputeCandidatePairPriority - Compute the candidate pair priority. */

uint64_t Ice_ComputeCandidatePairPriority( IceCandidatePair_t * pIceCandidatePair,
                                           uint32_t isLocalControlling )
{
    uint64_t controllingAgentCandidatePri = pIceCandidatePair->pLocal->priority;
    uint64_t controlledAgentCandidatePri = pIceCandidatePair->pRemote->priority;
    uint64_t candidatePairPriority = 0;

    if( pIceCandidatePair != NULL )
    {
        if( isLocalControlling == 0 )
        {
            controllingAgentCandidatePri = controlledAgentCandidatePri;
            controlledAgentCandidatePri = pIceCandidatePair->pLocal->priority;
        }

        /* https://tools.ietf.org/html/rfc5245#appendix-B.5 */
        candidatePairPriority = ( ( ( uint64_t ) 1 << 32 ) * ( controllingAgentCandidatePri >= controlledAgentCandidatePri ? controlledAgentCandidatePri : controllingAgentCandidatePri ) +
                                  2 * ( controllingAgentCandidatePri >= controlledAgentCandidatePri ? controllingAgentCandidatePri : controlledAgentCandidatePri ) + ( controllingAgentCandidatePri > controlledAgentCandidatePri ? 1 : 0 ) );
    }

    return candidatePairPriority;
}

/*------------------------------------------------------------------------------------------------------------------*/

/* Ice_UpdateSrflxCandidateAddress : This API will be called by processStunPacket, if the binding request is for finding srflx candidate to update the candidate address */

IceResult_t Ice_UpdateSrflxCandidateAddress( IceAgent_t * pIceAgent,
                                             IceCandidate_t * pCandidate,
                                             const IceIPAddress_t * pIpAddr )
{
    int i;
    IceResult_t retStatus = ICE_RESULT_OK;

    if( ( pIceAgent == NULL ) ||
        ( pCandidate == NULL ) ||
        ( pIpAddr == NULL ) ||
        ( pCandidate->iceCandidateType != ICE_CANDIDATE_TYPE_SERVER_REFLEXIVE ) )
    {
        retStatus = ICE_RESULT_BAD_PARAM;
    }
    else
    {
        memcpy( &( pCandidate->ipAddress ),
                pIpAddr,
                sizeof( IceIPAddress_t ) );
        pCandidate->state = ICE_CANDIDATE_STATE_VALID;

        for( i = 0; ( ( i < Ice_GetValidRemoteCandidateCount( pIceAgent ) ) && ( retStatus == ICE_RESULT_OK ) ); i++ )
        {
            retStatus = Ice_CreateCandidatePair( pIceAgent,
                                                 pCandidate,
                                                 &( pIceAgent->remoteCandidates[ i ] ) );
        }
    }

    return retStatus;
}

/*------------------------------------------------------------------------------------------------------------------*/

/* Ice_HandleServerReflexiveCandidateResponse - 1. Parse STUN Binding Response from the STUN server to get Server Reflexive candidate.
 *                                              2. Add the Server Reflexive candidate to the ICE Library. */

IceResult_t Ice_HandleServerReflexiveCandidateResponse( IceAgent_t * pIceAgent,
                                                        StunAttributeAddress_t * pStunMappedAddress,
                                                        IceCandidate_t * pLocalCandidate )
{
    IceIPAddress_t ipAddr;
    IceResult_t retStatus = ICE_RESULT_OK;

    if( ( pIceAgent == NULL ) ||
        ( pStunMappedAddress == NULL ) ||
        ( pLocalCandidate == NULL ) )
    {
        retStatus = ICE_RESULT_BAD_PARAM;
    }

    if( retStatus == ICE_RESULT_OK )
    {
        memcpy( &( ipAddr.ipAddress ),
                pStunMappedAddress,
                sizeof( StunAttributeAddress_t ) );
        ipAddr.isPointToPoint = 0;

        retStatus = Ice_UpdateSrflxCandidateAddress( pIceAgent,
                                                     pLocalCandidate,
                                                     &( ipAddr ) );
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
IceResult_t Ice_InitializeStunPacket( IceAgent_t * pIceAgent,
                                      StunContext_t * pStunCxt,
                                      uint8_t * pTransactionId,
                                      uint8_t * pStunMessageBuffer,
                                      StunHeader_t * pStunHeader,
                                      uint8_t isGenerateTransactionID,
                                      uint8_t isStunBindingRequest )
{
    int i;
    IceResult_t retStatus = ICE_RESULT_OK;
    StunResult_t stunRetStatus = STUN_RESULT_OK;

    if( ( pIceAgent == NULL ) ||
        ( pStunCxt == NULL ) ||
        ( pTransactionId == NULL ) ||
        ( pStunMessageBuffer == NULL ) ||
        ( pStunHeader == NULL ) )
    {
        retStatus = ICE_RESULT_BAD_PARAM;
    }

    /* STUN header */
    if( retStatus == ICE_RESULT_OK )
    {
        pStunHeader->pTransactionId = pTransactionId;

        if( isStunBindingRequest )
        {
            pStunHeader->messageType = STUN_MESSAGE_TYPE_BINDING_REQUEST;
        }
        else
        {
            pStunHeader->messageType = STUN_MESSAGE_TYPE_BINDING_SUCCESS_RESPONSE;
        }

        if( isGenerateTransactionID )
        {
            for( i = 0; i < STUN_HEADER_TRANSACTION_ID_LENGTH; i++ )
            {
                pStunHeader->pTransactionId[ i ] = ( uint8_t ) ( pIceAgent->computeRandom() % 0x100 );
            }
        }
        else
        {
            memcpy( &( pStunHeader->pTransactionId[ 0 ] ),
                    &( pTransactionId[ 0 ] ),
                    STUN_HEADER_TRANSACTION_ID_LENGTH );
        }

        /* Create a STUN message. */
        stunRetStatus = StunSerializer_Init( pStunCxt,
                                             pStunMessageBuffer,
                                             ICE_STUN_MESSAGE_BUFFER_SIZE,
                                             pStunHeader );
    }

    if( stunRetStatus == STUN_RESULT_OK )
    {
        retStatus = ICE_RESULT_OK;
    }
    else
    {
        retStatus = ICE_RESULT_STUN_ERROR;
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
    uint8_t messageIntegrity[ STUN_HMAC_VALUE_LENGTH ];
    IceResult_t iceRetStatus = ICE_RESULT_OK;
    StunResult_t stunRetStatus = STUN_RESULT_OK;
    uint16_t bufferLength = 0;
    uint32_t hmacLen = 0;
    uint32_t crc32 = 0;
    uint32_t stunMessageLength = 0;
    uint8_t * pIntBuffer = NULL;
    uint8_t * pFinBuffer = NULL;

    if( ( pIceAgent == NULL ) ||
        ( pStunCxt == NULL ) ||
        ( ( pPassword == NULL ) && ( passwordLen > 0 ) ) ||
        ( ( pPassword != NULL ) && ( passwordLen == 0 ) ) ||
        ( pStunMessageBufferLength == NULL ) )
    {
        iceRetStatus = ICE_RESULT_BAD_PARAM;
    }

    /* Adding Integrity attribute */
    if( ( iceRetStatus == ICE_RESULT_OK ) && ( pPassword != NULL ) )
    {
        stunRetStatus = StunSerializer_GetIntegrityBuffer( pStunCxt,
                                                           &( pIntBuffer ),
                                                           &( bufferLength ) );

        if( ( pIntBuffer != NULL ) && ( stunRetStatus == STUN_RESULT_OK ) )
        {
            pIceAgent->computeHMAC( pPassword,
                                    ( int32_t ) passwordLen,
                                    pIntBuffer,
                                    bufferLength,
                                    messageIntegrity,
                                    &( hmacLen ) );
        }

        stunRetStatus = StunSerializer_AddAttributeIntegrity( pStunCxt,
                                                              messageIntegrity,
                                                              STUN_HMAC_VALUE_LENGTH );
    }

    /* Adding Fingerprint attribute */
    if( stunRetStatus == STUN_RESULT_OK )
    {
        stunRetStatus = StunSerializer_GetFingerprintBuffer( pStunCxt,
                                                             &( pFinBuffer ),
                                                             &( bufferLength ) );

        if( ( pFinBuffer != NULL ) && ( stunRetStatus == STUN_RESULT_OK ) )
        {
            crc32 = pIceAgent->computeCRC32( 0,
                                             pFinBuffer,
                                             bufferLength );
        }

        stunRetStatus = StunSerializer_AddAttributeFingerprint( pStunCxt,
                                                                crc32 );
    }

    if( stunRetStatus == STUN_RESULT_OK )
    {
        stunRetStatus = StunSerializer_Finalize( pStunCxt,
                                                 &( stunMessageLength ) );
    }

    if( stunRetStatus == STUN_RESULT_OK )
    {
        *pStunMessageBufferLength = stunMessageLength;
    }

    if( stunRetStatus == STUN_RESULT_OK )
    {
        iceRetStatus = ICE_RESULT_OK;
    }
    else
    {
        iceRetStatus = ICE_RESULT_STUN_ERROR;
    }

    return iceRetStatus;
}

/*------------------------------------------------------------------------------------------------------------------*/

/* Ice_DeserializeStunPacket - This API deserializes a received STUN packet . */

IceStunPacketHandleResult_t Ice_DeserializeStunPacket( IceAgent_t * pIceAgent,
                                                       StunContext_t * pStunCxt,
                                                       StunHeader_t * pStunHeader,
                                                       StunAttribute_t * pStunAttribute,
                                                       uint8_t * pPassword,
                                                       uint32_t passwordLen,
                                                       IceStunDeserializedPacketInfo_t * pDeserializedPacketInfo )
{
    uint8_t messageIntegrity[ STUN_HMAC_VALUE_LENGTH ];
    IceStunPacketHandleResult_t iceRetStatus = ICE_RESULT_STUN_DESERIALIZE_OK;
    StunResult_t stunRetStatus = STUN_RESULT_OK;
    uint16_t errorPhaseLength = 0;
    uint32_t hmacLen = 0;
    uint32_t stunMessageLength = 0;
    uint8_t * pErrorPhase = NULL;
    uint8_t * pIntBuffer = NULL;
    uint8_t * pFinBuffer = NULL;


    /* The value of crc32 and crc32Fingerprint are kept different , to allow
     * STUN to recognise error in case of deserialization failure. */
    uint32_t crc32 = 0;
    uint32_t crc32Fingerprint = 1;
    uint16_t bufferLength;

    if( ( pStunCxt == NULL ) ||
        ( pStunHeader == NULL ) ||
        ( pStunAttribute == NULL ) ||
        ( pDeserializedPacketInfo == NULL ) )
    {
        iceRetStatus = ICE_RESULT_BAD_PARAM;
    }
    else
    {
        /* Initialize the ICE deserialized packet structure. */
        pDeserializedPacketInfo->useCandidateFlag = 0;
        pDeserializedPacketInfo->errorCode = 0;
        pDeserializedPacketInfo->priority = 0;

        while( ( stunRetStatus == STUN_RESULT_OK ) && ( iceRetStatus == ICE_RESULT_STUN_DESERIALIZE_OK ) )
        {
            stunRetStatus = StunDeserializer_GetNextAttribute( pStunCxt,
                                                               pStunAttribute );

            if( stunRetStatus == STUN_RESULT_OK )
            {
                switch( pStunAttribute->attributeType )
                {
                    case STUN_ATTRIBUTE_TYPE_ERROR_CODE:
                        stunRetStatus = StunDeserializer_ParseAttributeErrorCode( pStunAttribute,
                                                                                  &( pDeserializedPacketInfo->errorCode ),
                                                                                  &( pErrorPhase ),
                                                                                  &( errorPhaseLength ) );
                        break;

                    case STUN_ATTRIBUTE_TYPE_XOR_MAPPED_ADDRESS:
                        stunRetStatus = StunDeserializer_ParseAttributeAddress( pStunCxt,
                                                                                pStunAttribute,
                                                                                &( pDeserializedPacketInfo->stunAttributeAddress ) );
                        break;

                    case STUN_ATTRIBUTE_TYPE_USE_CANDIDATE:
                        pDeserializedPacketInfo->useCandidateFlag = 1;
                        break;

                    case STUN_ATTRIBUTE_TYPE_PRIORITY:
                        stunRetStatus = StunDeserializer_ParseAttributePriority( pStunCxt,
                                                                                 pStunAttribute,
                                                                                 &( pDeserializedPacketInfo->priority ) );
                        break;

                    case STUN_ATTRIBUTE_TYPE_MESSAGE_INTEGRITY:

                        if( ( pPassword != NULL ) && ( passwordLen != 0 ) )
                        {
                            stunRetStatus = StunDeserializer_GetIntegrityBuffer( pStunCxt,
                                                                                 &( pIntBuffer ),
                                                                                 &( bufferLength ) );

                            if( ( pIntBuffer != NULL ) && ( stunRetStatus == STUN_RESULT_OK ) )
                            {
                                pIceAgent->computeHMAC( pPassword,
                                                        ( int32_t ) passwordLen,
                                                        pIntBuffer,
                                                        bufferLength,
                                                        messageIntegrity,
                                                        &( hmacLen ) );

                                if( memcmp( messageIntegrity, pStunAttribute->pAttributeValue, STUN_HMAC_VALUE_LENGTH ) != 0 )
                                {
                                    iceRetStatus = ICE_RESULT_STUN_INTEGRITY_MISMATCH;
                                }
                            }
                        }
                        else
                        {
                            stunRetStatus = STUN_RESULT_INVALID_ATTRIBUTE_LENGTH;
                        }

                        break;

                    case STUN_ATTRIBUTE_TYPE_FINGERPRINT:
                        stunRetStatus = StunDeserializer_ParseAttributeFingerprint( pStunCxt,
                                                                                    pStunAttribute,
                                                                                    &( crc32Fingerprint ) );

                        if( stunRetStatus == STUN_RESULT_OK )
                        {
                            stunRetStatus = StunDeserializer_GetFingerprintBuffer( pStunCxt,
                                                                                   &( pFinBuffer ),
                                                                                   &( bufferLength ) );
                        }

                        if( stunRetStatus == STUN_RESULT_OK )
                        {
                            crc32 = pIceAgent->computeCRC32( 0,
                                                             pFinBuffer,
                                                             bufferLength );
                        }

                        if( crc32 != crc32Fingerprint )
                        {
                            iceRetStatus = ICE_RESULT_STUN_FINGERPRINT_MISMATCH;
                        }

                        break;

                    default:
                        break;
                }
            }
        }
    }

    return iceRetStatus;
}
/*------------------------------------------------------------------------------------------------------------------*/
