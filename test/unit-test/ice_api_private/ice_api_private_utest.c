/* Unity includes. */
#include "unity.h"
#include "catch_assert.h"

/* Standard includes. */
#include <stdlib.h>
#include <time.h>
#include <string.h>

/* API includes. */
#include "ice_api.h"
#include "ice_api_private.h"

/* ===========================  EXTERN VARIABLES    =========================== */

#define CRC32_POLYNOMIAL    0xEDB88320

/*
 * IP Address used in the tests.
 */
uint8_t ipAddress[] = { 0xC0, 0xA8, 0x01, 0x64 }; /* "192.168.1.100". */

/*
 * Arrays used in the tests.
 */
#define LOCAL_CANDIDATE_ARRAY_SIZE               10
#define REMOTE_CANDIDATE_ARRAY_SIZE              10
#define CANDIDATE_PAIR_ARRAY_SIZE                100
#define RELAY_EXTENSION_ARRAY_SIZE               10
#define TRANSACTION_ID_SLOTS_ARRAY_ARRAY_SIZE    32

IceInitInfo_t initInfo;
TransactionIdStore_t transactionIdStore;
IceCandidate_t localCandidateArray[ LOCAL_CANDIDATE_ARRAY_SIZE ];
IceCandidate_t remoteCandidateArray[ REMOTE_CANDIDATE_ARRAY_SIZE ];
IceCandidatePair_t candidatePairArray[ CANDIDATE_PAIR_ARRAY_SIZE ];
IceRelayExtension_t relayExtensionArray[ RELAY_EXTENSION_ARRAY_SIZE ];
TransactionIdSlot_t transactionIdSlots[ TRANSACTION_ID_SLOTS_ARRAY_ARRAY_SIZE ];

/* ===========================  EXTERN FUNCTIONS   =========================== */

uint64_t testGetCurrentTime( void )
{
    return ( uint64_t ) time( NULL );
}

/*-----------------------------------------------------------*/

IceResult_t testRandomFxn( uint8_t * pDest,
                           size_t length )
{
    size_t i;

    /* Fill the buffer with a repeating pattern. */
    for( i = 0; i < length; i++ )
    {
        pDest[ i ] = ( uint8_t ) ( i % 256 );
    }

    return ICE_RESULT_OK;
}

/*-----------------------------------------------------------*/

IceResult_t testCrc32Fxn( uint32_t initialResult,
                          const uint8_t * pBuffer,
                          size_t bufferLength,
                          uint32_t * pCalculatedCrc32 )
{
    size_t i, j;
    uint32_t crc32 = initialResult;

    /* Calculate the CRC32 using a simple algorithm. */
    for( i = 0; i < bufferLength; i++ )
    {
        crc32 ^= pBuffer[ i ];

        for( j = 0; j < 8; j++ )
        {
            if( ( crc32 & 1 ) != 0 )
            {
                crc32 = ( crc32 >> 1 ) ^ CRC32_POLYNOMIAL;
            }
            else
            {
                crc32 = ( crc32 >> 1 );
            }
        }
    }

    /* Store the calculated CRC32 value. */
    *pCalculatedCrc32 = crc32;

    return ICE_RESULT_OK;
}

/*-----------------------------------------------------------*/

IceResult_t testHmacFxn( const uint8_t * pPassword,
                         size_t passwordLength,
                         const uint8_t * pBuffer,
                         size_t bufferLength,
                         uint8_t * pOutputBuffer,
                         uint16_t * pOutputBufferLength )
{
    /* Assume a fixed HMAC output length of 20 bytes (160 bits). */
    const uint16_t hmacLength = 20;
    uint16_t i;
    IceResult_t result = ICE_RESULT_OK;

    if( *pOutputBufferLength < hmacLength )
    {
        result = ICE_RESULT_BAD_PARAM;
    }

    if( result == ICE_RESULT_OK )
    {
        /* Calculate the HMAC using a simple algorithm. */
        for( i = 0; i < hmacLength; i++ )
        {
            pOutputBuffer[ i ] = pPassword[ i % passwordLength ] ^
                                 pBuffer[ i % bufferLength ];
        }

        /* Update the output buffer length. */
        *pOutputBufferLength = hmacLength;
    }

    return result;
}

/*-----------------------------------------------------------*/

IceResult_t testMd5Fxn( const uint8_t * pBuffer,
                        size_t bufferLength,
                        uint8_t * pOutputBuffer,
                        uint16_t * pOutputBufferLength )
{
    IceResult_t ret = ICE_RESULT_OK;
    const uint16_t md5Length = 16U;
    uint16_t i;

    if( ( pBuffer == NULL ) || ( pOutputBuffer == NULL ) || ( pOutputBufferLength == NULL ) )
    {
        ret = ICE_RESULT_MD5_ERROR;
    }
    else if( *pOutputBufferLength < md5Length )
    {
        ret = ICE_RESULT_MD5_ERROR;
    }
    else
    {
        /* Empty else marker. */
    }

    if( ret == ICE_RESULT_OK )
    {
        /* Fake MD5 implementation. */
        memset( pOutputBuffer, 0, md5Length );
        for( i = 0; i < bufferLength; i++ )
        {
            pOutputBuffer[ i % md5Length ] = ( uint8_t )( pOutputBuffer[ i % md5Length ] + pBuffer[ i ] );
        }
    }

    if( ret == ICE_RESULT_OK )
    {
        /* MD5 result is always 16 bytes. */
        *pOutputBufferLength = md5Length;
    }

    return ret;
}

/*-----------------------------------------------------------*/

/*
 * The following function is used to Initialize the initInfo For each Test case.
 */
static void Info_Init_For_Tests( void )
{
    TransactionIdStoreResult_t result;

    result = TransactionIdStore_Init( &( transactionIdStore ),
                                      &( transactionIdSlots[ 0 ] ),
                                      TRANSACTION_ID_SLOTS_ARRAY_ARRAY_SIZE );
    TEST_ASSERT_EQUAL( TRANSACTION_ID_STORE_RESULT_OK,
                       result );

    initInfo.pLocalCandidatesArray = &( localCandidateArray[ 0 ] );
    initInfo.pRemoteCandidatesArray = &( remoteCandidateArray[ 0 ] );
    initInfo.pCandidatePairsArray = &( candidatePairArray[ 0 ] );
    initInfo.pRelayExtensionsArray = &( relayExtensionArray[ 0 ] );
    initInfo.pStunBindingRequestTransactionIdStore = &( transactionIdStore );
    initInfo.cryptoFunctions.randomFxn = testRandomFxn;
    initInfo.cryptoFunctions.crc32Fxn = testCrc32Fxn;
    initInfo.cryptoFunctions.hmacFxn = testHmacFxn;
    initInfo.cryptoFunctions.md5Fxn = testMd5Fxn;
    initInfo.getCurrentTimeSecondsFxn = testGetCurrentTime;
    initInfo.creds.pLocalUsername = ( uint8_t * ) "localUsername";
    initInfo.creds.localUsernameLength = strlen( "localUsername" );
    initInfo.creds.pLocalPassword = ( uint8_t * ) "localPassword";
    initInfo.creds.localPasswordLength = strlen( "localPassword" );
    initInfo.creds.pRemoteUsername = ( uint8_t * ) "remoteUsername";
    initInfo.creds.remoteUsernameLength = strlen( "remoteUsername" );
    initInfo.creds.pRemotePassword = ( uint8_t * ) "remotePassword";
    initInfo.creds.remotePasswordLength = strlen( "remotePassword" );
    initInfo.creds.pCombinedUsername = ( uint8_t * ) "combinedUsername";
    initInfo.creds.combinedUsernameLength = strlen( "combinedUsername" );
    initInfo.localCandidatesArrayLength = LOCAL_CANDIDATE_ARRAY_SIZE;
    initInfo.remoteCandidatesArrayLength = REMOTE_CANDIDATE_ARRAY_SIZE;
    initInfo.candidatePairsArrayLength = CANDIDATE_PAIR_ARRAY_SIZE;
    initInfo.relayExtensionsArrayLength = RELAY_EXTENSION_ARRAY_SIZE;
    initInfo.isControlling = 1;
}

/*-----------------------------------------------------------*/

void setUp( void )
{
    memset( &( localCandidateArray[ 0 ] ),
            0,
            LOCAL_CANDIDATE_ARRAY_SIZE * sizeof( IceCandidate_t ) );

    memset( &( remoteCandidateArray[ 0 ] ),
            0,
            REMOTE_CANDIDATE_ARRAY_SIZE * sizeof( IceCandidate_t ) );

    memset( &( candidatePairArray[ 0 ] ),
            0,
            CANDIDATE_PAIR_ARRAY_SIZE * sizeof( IceCandidatePair_t ) );

    memset( &( relayExtensionArray[ 0 ] ),
            0,
            RELAY_EXTENSION_ARRAY_SIZE * sizeof( IceRelayExtension_t ) );

    memset( &( transactionIdSlots[ 0 ] ),
            0,
            TRANSACTION_ID_SLOTS_ARRAY_ARRAY_SIZE * sizeof( TransactionIdSlot_t ) );

    memset( &( initInfo ),
            0,
            sizeof( IceInitInfo_t ) );

    memset( &( transactionIdStore ),
            0,
            sizeof( TransactionIdStore_t ) );

    Info_Init_For_Tests();
}

/*-----------------------------------------------------------*/

void tearDown( void )
{
}

/* ==============================  Test Cases  ============================== */

/**
 * @brief Validate ICE Add Candidate Pair fail functionality for Bad Parameters.
 */
void test_iceAddCandidatePair_BadParams( void )
{
    IceContext_t context = { 0 };
    IceCandidate_t localCandidate = { 0 };
    IceCandidate_t remoteCandidate = { 0 };
    IceResult_t result;

    result = Ice_AddCandidatePair( NULL,
                                   &( localCandidate ),
                                   &( remoteCandidate ),
                                   NULL );

    TEST_ASSERT_EQUAL( ICE_RESULT_BAD_PARAM,
                       result );

    result = Ice_AddCandidatePair( &( context ),
                                   NULL,
                                   &( remoteCandidate ),
                                   NULL );

    TEST_ASSERT_EQUAL( ICE_RESULT_BAD_PARAM,
                       result );

    result = Ice_AddCandidatePair( &( context ),
                                   &( localCandidate ),
                                   NULL,
                                   NULL );

    TEST_ASSERT_EQUAL( ICE_RESULT_BAD_PARAM,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate ICE Add Candidate Pair fail functionality for max threshold.
 */
void test_iceAddCandidatePair_MaxCandidatePairThreshold( void )
{
    IceContext_t context = { 0 };
    IceCandidate_t localCandidate = { 0 };
    IceCandidate_t remoteCandidate = { 0 };
    IceResult_t result;

    result = Ice_Init( &( context ),
                       &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       result );

    /* Simulate having max possible candidate pairs. */
    context.numCandidatePairs = CANDIDATE_PAIR_ARRAY_SIZE;

    result = Ice_AddCandidatePair( &( context ),
                                   &( localCandidate ),
                                   &( remoteCandidate ),
                                   NULL );

    TEST_ASSERT_EQUAL( ICE_RESULT_MAX_CANDIDATE_PAIR_THRESHOLD,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate ICE Add Candidate Pair fail functionality for missing relay extension
 * of local relay candidate.
 */
void test_iceAddCandidatePair_LocalRelayCandidateMissingRelayExtension( void )
{
    IceContext_t context = { 0 };
    IceCandidate_t localCandidate = { 0 };
    IceCandidate_t remoteCandidate = { 0 };
    IceResult_t result;

    result = Ice_Init( &( context ),
                       &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       result );

    localCandidate.pRelayExtension = NULL;
    localCandidate.candidateType = ICE_CANDIDATE_TYPE_RELAY;

    result = Ice_AddCandidatePair( &( context ),
                                   &( localCandidate ),
                                   &( remoteCandidate ),
                                   NULL );

    TEST_ASSERT_EQUAL( ICE_RESULT_NULL_RELAY_EXTENSION,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate ICE Add Candidate Pair fail functionality for
 * reaching maximum TURN channel number
 */
void test_iceAddCandidatePair_MaxTurnChannelNumber( void )
{
    IceContext_t context = { 0 };
    IceCandidate_t localCandidate = { 0 };
    IceCandidate_t remoteCandidate = { 0 };
    IceResult_t result;

    result = Ice_Init( &( context ),
                       &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       result );

    context.numRelayExtensions = 1;
    localCandidate.pRelayExtension = &context.pRelayExtensionsArray[ 0 ];
    localCandidate.candidateType = ICE_CANDIDATE_TYPE_RELAY;
    localCandidate.pRelayExtension->nextAvailableTurnChannelNumber = ICE_DEFAULT_TURN_CHANNEL_NUMBER_MAX + 1;

    result = Ice_AddCandidatePair( &( context ),
                                   &( localCandidate ),
                                   &( remoteCandidate ),
                                   NULL );

    TEST_ASSERT_EQUAL( ICE_RESULT_MAX_CHANNEL_NUMBER_ID,
                       result );
}

/*-----------------------------------------------------------*/

// /**
//  * @brief Validate ICE Add Candidate Pair fail functionality for NULL stun context.
//  */
// void test_iceFinalizeStunPacket_StunError_NullStunContext( void )
// {
//     IceContext_t context = { 0 };
//     size_t bufferLength = 128;
//     IceResult_t result;

//     result = Ice_Init( &( context ),
//                        &( initInfo ) );

//     TEST_ASSERT_EQUAL( ICE_RESULT_OK,
//                        result );

//     result = Ice_FinalizeStunPacket( &( context ),
//                                      NULL,
//                                      context.creds.pLocalPassword,
//                                      context.creds.localPasswordLength,
//                                      &( bufferLength ) );

//     TEST_ASSERT_EQUAL( ICE_RESULT_STUN_ERROR,
//                        result );
// }

// /*-----------------------------------------------------------*/

// /**
//  * @brief Validate ICE Same Transport Address check fail functionality for Bad Parameters.
//  */
// void test_iceIsSameTransportAddress_BadParms( void )
// {
//     IceTransportAddress_t transportAddress1;
//     IceTransportAddress_t transportAddress2;
//     uint8_t result;

//     transportAddress1.port = 3478;
//     transportAddress1.family = 0;
//     memcpy( ( void * ) &( transportAddress1.address[ 0 ] ),
//             ( const void * ) &( ipAddress[ 0 ] ),
//             sizeof( ipAddress ) );

//     transportAddress2.port = 3478;
//     transportAddress2.family = 1;
//     memcpy( ( void * ) &( transportAddress2.address[ 0 ] ),
//             ( const void * ) ipAddress,
//             sizeof( ipAddress ) );

//     result = Ice_IsSameTransportAddress( NULL,
//                                          &( transportAddress2 ) );

//     TEST_ASSERT_EQUAL( 0,
//                        result );

//     result = Ice_IsSameTransportAddress( &( transportAddress1 ),
//                                          NULL );

//     TEST_ASSERT_EQUAL( 0,
//                        result );
// }

// /*-----------------------------------------------------------*/

// /**
//  * @brief Validate ICE Same Transport Address check fail functionality.
//  */
// void test_iceIsSameTransportAddress_DifferentFamily( void )
// {
//     IceTransportAddress_t transportAddress1;
//     IceTransportAddress_t transportAddress2;
//     uint8_t result;

//     transportAddress1.port = 3478;
//     transportAddress1.family = 0;
//     memcpy( ( void * ) &( transportAddress1.address[ 0 ] ),
//             ( const void * ) &( ipAddress[ 0 ] ),
//             sizeof( ipAddress ) );

//     transportAddress2.port = 3478;
//     transportAddress2.family = 1;
//     memcpy( ( void * ) &( transportAddress2.address[ 0 ] ),
//             ( const void * ) &( ipAddress[ 0 ] ),
//             sizeof( ipAddress ) );

//     result = Ice_IsSameTransportAddress( &( transportAddress1 ),
//                                          &( transportAddress2 ) );

//     TEST_ASSERT_EQUAL( 0,
//                        result );
// }

// /*-----------------------------------------------------------*/

// /**
//  * @brief Validate ICE Same Transport Address check fail functionality.
//  */
// void test_iceIsSameTransportAddress_DifferentPort( void )
// {
//     IceTransportAddress_t transportAddress1;
//     IceTransportAddress_t transportAddress2;
//     uint8_t result;

//     transportAddress1.port = 3478;
//     transportAddress1.family = 1;
//     memcpy( ( void * ) &( transportAddress1.address[ 0 ] ),
//             ( const void * ) &( ipAddress[ 0 ] ),
//             sizeof( ipAddress ) );

//     transportAddress2.port = 2002;
//     transportAddress2.family = 1;
//     memcpy( ( void * ) &( transportAddress2.address[ 0 ] ),
//             ( const void * ) &( ipAddress[ 0 ] ),
//             sizeof( ipAddress ) );

//     result = Ice_IsSameTransportAddress( &( transportAddress1 ),
//                                          &( transportAddress2 ) );

//     TEST_ASSERT_EQUAL( 0,
//                        result );
// }

// /*-----------------------------------------------------------*/

// /**
//  * @brief Validate ICE Same Transport Address check fail functionality.
//  */
// void test_iceIsSameTransportAddress_DifferentIpAddress( void )
// {
//     IceTransportAddress_t transportAddress1;
//     IceTransportAddress_t transportAddress2;
//     uint8_t ipAddress1[] = { 0xC0, 0xA8, 0x01, 0x64 }; /* "192.168.1.100". */
//     uint8_t ipAddress2[] = { 0x78, 0xA8, 0x01, 0x6E }; /* "192.168.1.110". */
//     uint8_t result;

//     transportAddress1.port = 3478;
//     transportAddress1.family = 1;
//     memcpy( ( void * ) &( transportAddress1.address[ 0 ] ),
//             ( const void * ) &( ipAddress1[ 0 ] ),
//             sizeof( ipAddress1 ) );

//     transportAddress2.port = 3478;
//     transportAddress2.family = 1;
//     memcpy( ( void * ) &( transportAddress2.address[ 0 ] ),
//             ( const void * ) &( ipAddress2[ 0 ] ),
//             sizeof( ipAddress2 ) );


//     result = Ice_IsSameTransportAddress( &( transportAddress1 ),
//                                          &( transportAddress2 ) );

//     TEST_ASSERT_EQUAL( 0,
//                        result );
// }

// /*-----------------------------------------------------------*/

// /**
//  * @brief Validate ICE Same IP Address check fail functionality.
//  */
// void test_iceIsSameIPAddress_BadParams( void )
// {
//     IceTransportAddress_t transportAddress1;
//     IceTransportAddress_t transportAddress2;
//     uint8_t result;

//     transportAddress1.family = 0x01;
//     transportAddress2.family = 0x02;

//     result = Ice_IsSameIpAddress( NULL,
//                                   &( transportAddress2 ) );

//     TEST_ASSERT_EQUAL( 0,
//                        result );

//     result = Ice_IsSameIpAddress( &( transportAddress1 ),
//                                   NULL );

//     TEST_ASSERT_EQUAL( 0,
//                        result );
// }

// /*-----------------------------------------------------------*/

// /**
//  * @brief Validate ICE Same IP Address check fail functionality.
//  */
// void test_iceIsSameIPAddress_DifferentIpAddress( void )
// {
//     IceTransportAddress_t transportAddress1;
//     IceTransportAddress_t transportAddress2;
//     uint8_t ipAddress[] = { 0xC0, 0xA8, 0x01, 0x64 };        /* "192.168.1.100". */
//     uint8_t ipAddress2[] = { 0x78, 0xA8, 0x01, 0x6E };       /* "192.168.1.110". */
//     uint8_t result;

//     transportAddress1.family = 0x01;
//     memcpy( ( void * ) &( transportAddress1.address[ 0 ] ),
//             ( const void * ) ipAddress,
//             sizeof( ipAddress ) );

//     transportAddress2.family = 0x01;
//     memcpy( ( void * ) &( transportAddress2.address[ 0 ] ),
//             ( const void * ) ipAddress2,
//             sizeof( ipAddress2 ) );


//     result = Ice_IsSameIpAddress( &( transportAddress1 ),
//                                   &( transportAddress2 ) );

//     TEST_ASSERT_EQUAL( 0,
//                        result );
// }

// /*-----------------------------------------------------------*/

// /**
//  * @brief Validate ICE Compute Candidate Priority check fail functionality.
//  */
// void test_iceComputeCandidatePriority_Invalid( void )
// {
//     IceCandidateType_t candidateType;
//     uint8_t isPointToPoint;
//     uint64_t result;

//     candidateType = 5; /* Unkown Type. */
//     isPointToPoint = 1;

//     /* Priority calculation formula:
//      * priority = ( 2^24 ) * ( type preference ) +
//      *            ( 2^8 )  * ( local preference) +
//      *            ( 2^0 )  * ( 256 - component ID ).
//      *
//      * In this test,
//      * priority = ( 2^24 ) * ( 0 ) + ( 2^8 ) * ( 0 ) + 255 = 255.
//      */

//     result = Ice_ComputeCandidatePriority( candidateType,
//                                            isPointToPoint );

//     TEST_ASSERT_EQUAL( 255,
//                        result );
// }

// /*-----------------------------------------------------------*/

// /**
//  * @brief Validate ICE Compute Candidate Priority check functionality for Peer Reflexive Candidate Type.
//  */
// void test_iceComputeCandidatePriority_PeerReflexive( void )
// {
//     IceCandidateType_t candidateType;
//     uint8_t isPointToPoint;
//     uint64_t result;

//     candidateType = ICE_CANDIDATE_TYPE_PEER_REFLEXIVE;
//     isPointToPoint = 1;

//     /* Priority calculation formula:
//      * priority = ( 2^24 ) * ( type preference ) +
//      *            ( 2^8 )  * ( local preference) +
//      *            ( 2^0 )  * ( 256 - component ID ).
//      *
//      * In this test,
//      * priority = ( 2^24 ) * ( 110 ) + ( 2^8 ) * ( 0 ) + 255 = 1845494015.
//      */

//     result = Ice_ComputeCandidatePriority( candidateType,
//                                            isPointToPoint );

//     TEST_ASSERT_EQUAL( 1845494015,
//                        result );
// }

// /*-----------------------------------------------------------*/

// /**
//  * @brief Validate ICE Compute Candidate Priority check functionality for Relayed Candidate Type.
//  */
// void test_iceComputeCandidatePriority_Relayed( void )
// {
//     IceCandidateType_t candidateType;
//     uint8_t isPointToPoint;
//     uint64_t result;

//     candidateType = ICE_CANDIDATE_TYPE_RELAY;
//     isPointToPoint = 1;

//     /* Priority calculation formula:
//      * priority = ( 2^24 ) * ( type preference ) +
//      *            ( 2^8 )  * ( local preference) +
//      *            ( 2^0 )  * ( 256 - component ID ).
//      *
//      * In this test,
//      * priority = ( 2^24 ) * ( 0 ) + ( 2^8 ) * ( 0 ) + 255 = 255.
//      */

//     result = Ice_ComputeCandidatePriority( candidateType,
//                                            isPointToPoint );

//     TEST_ASSERT_EQUAL( 255,
//                        result );
// }

/*-----------------------------------------------------------*/
