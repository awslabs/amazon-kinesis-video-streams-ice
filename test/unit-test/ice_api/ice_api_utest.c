/* Unity includes. */
#include "unity.h"
#include "catch_assert.h"

/* Standard includes. */
#include <stdlib.h>
#include <time.h>
#include <string.h>

/* API includes. */
#include "ice_api.h"

/* ===========================  EXTERN VARIABLES    =========================== */

/*
 * The priority is calculated for a host candidate where pCandidate.isPointToPoint = 1.
 */
#define HOST_CANDIDATE_PRIORITY                2113929471

/*
 * The priority is calculated for a host candidate where pCandidate.isPointToPoint = 0.
 */
#define HOST_CANDIDATE_PRIORITY_MULTICAST      2130706431
#define SERVER_REFLEXIVE_CANDIDATE_PRIORITY    1694498815
#define RELAY_CANDIDATE_PRIORITY               16777215
#define CRC32_POLYNOMIAL                       0xEDB88320

/*
 * IP Address used in the tests.
 */
uint8_t ipAddress[] = { 0xC0, 0xA8, 0x01, 0x64 };        /* "192.168.1.100". */

/*
 * Arrays used in the tests.
 */
#define LOCAL_CANDIDATE_ARRAY_SIZE               10
#define REMOTE_CANDIDATE_ARRAY_SIZE              10
#define CANDIDATE_PAIR_ARRAY_SIZE                100
#define RELAY_EXTENSION_ARRAY_SIZE               10
#define TRANSACTION_ID_SLOTS_ARRAY_ARRAY_SIZE    32

/* Specific TURN channel number used for testing. */
#define TEST_TURN_CHANNEL_NUMBER_START           ( 0x4010 )

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

uint64_t testGetCurrentTime_FixedZero( void )
{
    return ( uint64_t ) 0U;
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

IceResult_t testRandomFxn_Wrong( uint8_t * pDest,
                                 size_t length )
{
    ( void ) pDest;
    ( void ) length;
    return ICE_RESULT_RANDOM_GENERATION_ERROR;
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

IceResult_t testCrc32Fxn_ReturnError( uint32_t initialResult,
                                      const uint8_t * pBuffer,
                                      size_t bufferLength,
                                      uint32_t * pCalculatedCrc32 )
{
    ( void ) initialResult;
    ( void ) pBuffer;
    ( void ) bufferLength;
    ( void ) pCalculatedCrc32;

    return ICE_RESULT_CRC32_ERROR;
}

/*-----------------------------------------------------------*/

IceResult_t testCrc32Fxn_Fixed( uint32_t initialResult,
                                const uint8_t * pBuffer,
                                size_t bufferLength,
                                uint32_t * pCalculatedCrc32 )
{
    uint32_t crc32 = 0x5354554E;

    ( void ) initialResult;
    ( void ) pBuffer;
    ( void ) bufferLength;

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
    /* Assume a fixed HMAC output length of 20 bytes (160-bit). */
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

IceResult_t testHmacFxn_FixedFF( const uint8_t * pPassword,
                                 size_t passwordLength,
                                 const uint8_t * pBuffer,
                                 size_t bufferLength,
                                 uint8_t * pOutputBuffer,
                                 uint16_t * pOutputBufferLength )
{
    /* Assume a fixed HMAC output length of 20 bytes (160-bit). */
    const uint16_t hmacLength = 20;
    uint16_t i;
    IceResult_t result = ICE_RESULT_OK;

    ( void ) pPassword;
    ( void ) passwordLength;
    ( void ) pBuffer;
    ( void ) bufferLength;

    if( *pOutputBufferLength < hmacLength )
    {
        result = ICE_RESULT_BAD_PARAM;
    }

    if( result == ICE_RESULT_OK )
    {
        /* Calculate the HMAC using a simple algorithm. */
        for( i = 0; i < hmacLength; i++ )
        {
            pOutputBuffer[ i ] = 0xFF;
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

IceResult_t testHmacFxn_Wrong( const uint8_t * pPassword,
                               size_t passwordLength,
                               const uint8_t * pBuffer,
                               size_t bufferLength,
                               uint8_t * pOutputBuffer,
                               uint16_t * pOutputBufferLength )
{
    /* Assume a fixed HMAC output length of 16 bytes (128 bits). */
    const uint16_t hmacLength = 16;                 /* This HMAC Lenght is not correct */
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

IceResult_t testHmacFxn_ReturnError( const uint8_t * pPassword,
                                     size_t passwordLength,
                                     const uint8_t * pBuffer,
                                     size_t bufferLength,
                                     uint8_t * pOutputBuffer,
                                     uint16_t * pOutputBufferLength )
{
    ( void ) pPassword;
    ( void ) passwordLength;
    ( void ) pBuffer;
    ( void ) bufferLength;
    ( void ) pOutputBuffer;
    ( void ) pOutputBufferLength;

    return ICE_RESULT_HMAC_ERROR;
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
 * @brief Validate ICE Init fail functionality for Bad Parameters.
 */
void test_iceInit_BadParams( void )
{
    IceContext_t context = { 0 };
    IceResult_t result;
    uint8_t localUsername[ 10 ];
    uint8_t localPassword[ 10 ];
    uint8_t remoteUsername[ 10 ];
    uint8_t remotePassword[ 10 ];

    result = Ice_Init( NULL,
                       &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_BAD_PARAM,
                       result );

    result = Ice_Init( &( context ),
                       NULL );

    TEST_ASSERT_EQUAL( ICE_RESULT_BAD_PARAM,
                       result );

    initInfo.pLocalCandidatesArray = NULL;

    result = Ice_Init( &( context ),
                       &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_BAD_PARAM,
                       result );

    initInfo.pLocalCandidatesArray = &( localCandidateArray[ 0 ] );
    initInfo.pRemoteCandidatesArray = NULL;

    result = Ice_Init( &( context ),
                       &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_BAD_PARAM,
                       result );

    initInfo.pRemoteCandidatesArray = &( remoteCandidateArray[ 0 ] );
    initInfo.pCandidatePairsArray = NULL;

    result = Ice_Init( &( context ),
                       &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_BAD_PARAM,
                       result );

    initInfo.pCandidatePairsArray = &( candidatePairArray[ 0 ] );
    initInfo.pRelayExtensionsArray = NULL;

    result = Ice_Init( &( context ),
                       &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_BAD_PARAM,
                       result );

    initInfo.pRelayExtensionsArray = &( relayExtensionArray[ 0 ] );
    initInfo.pStunBindingRequestTransactionIdStore = NULL;

    result = Ice_Init( &( context ),
                       &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_BAD_PARAM,
                       result );

    initInfo.pStunBindingRequestTransactionIdStore = &( transactionIdStore );
    initInfo.cryptoFunctions.randomFxn = NULL;

    result = Ice_Init( &( context ),
                       &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_BAD_PARAM,
                       result );

    initInfo.cryptoFunctions.randomFxn = testRandomFxn;
    initInfo.cryptoFunctions.crc32Fxn = NULL;

    result = Ice_Init( &( context ),
                       &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_BAD_PARAM,
                       result );

    initInfo.cryptoFunctions.crc32Fxn = testCrc32Fxn;
    initInfo.cryptoFunctions.hmacFxn = NULL;

    result = Ice_Init( &( context ),
                       &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_BAD_PARAM,
                       result );

    initInfo.cryptoFunctions.hmacFxn = testHmacFxn;
    initInfo.cryptoFunctions.md5Fxn = NULL;

    result = Ice_Init( &( context ),
                       &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_BAD_PARAM,
                       result );

    initInfo.cryptoFunctions.md5Fxn = testMd5Fxn;
    initInfo.getCurrentTimeSecondsFxn = NULL;

    result = Ice_Init( &( context ),
                       &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_BAD_PARAM,
                       result );

    initInfo.getCurrentTimeSecondsFxn = testGetCurrentTime;
    initInfo.creds.pLocalUsername = NULL;

    result = Ice_Init( &( context ),
                       &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_BAD_PARAM,
                       result );

    initInfo.creds.pLocalUsername = &( localUsername[ 0 ] );
    initInfo.creds.pLocalPassword = NULL;

    result = Ice_Init( &( context ),
                       &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_BAD_PARAM,
                       result );

    initInfo.creds.pLocalPassword = &( localPassword[ 0 ] );
    initInfo.creds.pRemoteUsername = NULL;

    result = Ice_Init( &( context ),
                       &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_BAD_PARAM,
                       result );

    initInfo.creds.pRemoteUsername = &( remoteUsername[ 0 ] );
    initInfo.creds.pRemotePassword = NULL;

    result = Ice_Init( &( context ),
                       &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_BAD_PARAM,
                       result );

    initInfo.creds.pRemotePassword = &( remotePassword[ 0 ] );
    initInfo.creds.pCombinedUsername = NULL;

    result = Ice_Init( &( context ),
                       &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_BAD_PARAM,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate ICE Init functionality.
 */
void test_iceInit( void )
{
    IceContext_t context = { 0 };
    IceResult_t result;

    result = Ice_Init( &( context ),
                       &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       result );

    TEST_ASSERT_EQUAL( initInfo.creds.localUsernameLength,
                       context.creds.localUsernameLength );
    TEST_ASSERT_EQUAL_UINT8_ARRAY( initInfo.creds.pLocalUsername,
                                   context.creds.pLocalUsername,
                                   initInfo.creds.localUsernameLength );

    TEST_ASSERT_EQUAL( initInfo.creds.localPasswordLength,
                       context.creds.localPasswordLength );
    TEST_ASSERT_EQUAL_UINT8_ARRAY( initInfo.creds.pLocalPassword,
                                   context.creds.pLocalPassword,
                                   initInfo.creds.localPasswordLength );

    TEST_ASSERT_EQUAL( initInfo.creds.remoteUsernameLength,
                       context.creds.remoteUsernameLength );
    TEST_ASSERT_EQUAL_UINT8_ARRAY( initInfo.creds.pRemoteUsername,
                                   context.creds.pRemoteUsername,
                                   initInfo.creds.remoteUsernameLength );

    TEST_ASSERT_EQUAL( initInfo.creds.remotePasswordLength,
                       context.creds.remotePasswordLength );
    TEST_ASSERT_EQUAL_UINT8_ARRAY( initInfo.creds.pRemotePassword,
                                   context.creds.pRemotePassword,
                                   initInfo.creds.remotePasswordLength );

    TEST_ASSERT_EQUAL( initInfo.creds.combinedUsernameLength,
                       context.creds.combinedUsernameLength );
    TEST_ASSERT_EQUAL_UINT8_ARRAY( initInfo.creds.pCombinedUsername,
                                   context.creds.pCombinedUsername,
                                   initInfo.creds.combinedUsernameLength );

    TEST_ASSERT_EQUAL( &( localCandidateArray[ 0 ] ),
                       context.pLocalCandidates );
    TEST_ASSERT_EQUAL( 10,
                       context.maxLocalCandidates );
    TEST_ASSERT_EQUAL( 0,
                       context.numLocalCandidates );

    TEST_ASSERT_EQUAL( &( remoteCandidateArray[ 0 ] ),
                       context.pRemoteCandidates );
    TEST_ASSERT_EQUAL( 10,
                       context.maxRemoteCandidates );
    TEST_ASSERT_EQUAL( 0,
                       context.numRemoteCandidates );

    TEST_ASSERT_EQUAL( &( candidatePairArray[ 0 ] ),
                       context.pCandidatePairs );
    TEST_ASSERT_EQUAL( 100,
                       context.maxCandidatePairs );
    TEST_ASSERT_EQUAL( 0,
                       context.numCandidatePairs );

    TEST_ASSERT_EQUAL( 1,
                       context.isControlling );
    TEST_ASSERT_EQUAL( &( transactionIdStore ),
                       context.pStunBindingRequestTransactionIdStore );
    TEST_ASSERT_EQUAL( testRandomFxn,
                       context.cryptoFunctions.randomFxn );
    TEST_ASSERT_EQUAL( testCrc32Fxn,
                       context.cryptoFunctions.crc32Fxn );
    TEST_ASSERT_EQUAL( testHmacFxn,
                       context.cryptoFunctions.hmacFxn );
    TEST_ASSERT_EQUAL( 0,
                       context.numLocalCandidates );
    TEST_ASSERT_EQUAL( 0,
                       context.numRemoteCandidates );
    TEST_ASSERT_EQUAL( 0,
                       context.numCandidatePairs );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate ICE Add Host Candidate fail functionality for Bad Parameters.
 */
void test_iceAddHostCandidate_BadParams( void )
{
    IceContext_t context = { 0 };
    IceEndpoint_t endPoint = { 0 };
    IceResult_t result;

    result = Ice_AddHostCandidate( NULL,
                                   &( endPoint ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_BAD_PARAM,
                       result );

    result = Ice_AddHostCandidate( &( context ),
                                   NULL );

    TEST_ASSERT_EQUAL( ICE_RESULT_BAD_PARAM,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate ICE Add Host Candidate fail functionality for Max Candidate Threshold.
 */
void test_iceAddHostCandidate_MaxCandidateThreshold( void )
{
    IceContext_t context = { 0 };
    IceEndpoint_t endPoint = { 0 };
    IceResult_t result;

    result = Ice_Init( &( context ),
                       &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       result );

    context.numLocalCandidates = 1000;
    context.maxLocalCandidates = 1000;

    result = Ice_AddHostCandidate( &( context ),
                                   &( endPoint ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_MAX_CANDIDATE_THRESHOLD,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate ICE Add Host Candidate functionality.
 */
void test_iceAddHostCandidate( void )
{
    IceContext_t context = { 0 };
    IceEndpoint_t endPoint = { 0 };
    IceResult_t result;

    result = Ice_Init( &( context ),
                       &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       result );

    endPoint.isPointToPoint = 1;
    endPoint.transportAddress.family = 0;
    endPoint.transportAddress.port = 8080;
    memcpy( ( void * ) &( endPoint.transportAddress.address[ 0 ] ),
            ( const void * ) ipAddress,
            sizeof( ipAddress ) );

    result = Ice_AddHostCandidate( &( context ),
                                   &( endPoint ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       result );
    TEST_ASSERT_EQUAL( 1,
                       context.numLocalCandidates );
    TEST_ASSERT_EQUAL( ICE_CANDIDATE_TYPE_HOST,
                       context.pLocalCandidates[ 0 ].candidateType );
    TEST_ASSERT_EQUAL( 0,
                       context.pLocalCandidates[ 0 ].isRemote );
    TEST_ASSERT_EQUAL( HOST_CANDIDATE_PRIORITY,
                       context.pLocalCandidates[ 0 ].priority );
    TEST_ASSERT_EQUAL( ICE_SOCKET_PROTOCOL_NONE,
                       context.pLocalCandidates[ 0 ].remoteProtocol );
    TEST_ASSERT_EQUAL( ICE_CANDIDATE_STATE_VALID,
                       context.pLocalCandidates[ 0 ].state );
    TEST_ASSERT_EQUAL( 1,
                       context.pLocalCandidates[ 0 ].endpoint.isPointToPoint );
    TEST_ASSERT_EQUAL( 0,
                       context.pLocalCandidates[ 0 ].endpoint.transportAddress.family );
    TEST_ASSERT_EQUAL( 8080,
                       context.pLocalCandidates[ 0 ].endpoint.transportAddress.port );
    TEST_ASSERT_EQUAL_UINT8_ARRAY( ipAddress,
                                   context.pLocalCandidates[ 0 ].endpoint.transportAddress.address, sizeof( ipAddress ) );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate Ice_AddHostCandidate return fail when it
 * fail to generate candidate pair.
 */
void test_iceAddHostCandidate_CandidatePairFull( void )
{
    IceContext_t context = { 0 };
    IceEndpoint_t endPoint = { 0 };
    IceResult_t result;

    result = Ice_Init( &( context ),
                       &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       result );

    endPoint.isPointToPoint = 1;
    endPoint.transportAddress.family = 0;
    endPoint.transportAddress.port = 8080;
    memcpy( ( void * ) &( endPoint.transportAddress.address[ 0 ] ),
            ( const void * ) ipAddress,
            sizeof( ipAddress ) );

    /* Set 2 remote candidate to trigger adding candidate pair flow. */
    context.numRemoteCandidates = 2;

    /* Set full candidate pair to make adding candidate pair fail. */
    context.numCandidatePairs = CANDIDATE_PAIR_ARRAY_SIZE;

    result = Ice_AddHostCandidate( &( context ),
                                   &( endPoint ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_MAX_CANDIDATE_PAIR_THRESHOLD,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate ICE Add Server Reflexive Candidate fail functionality for Bad Parameters.
 */
void test_iceAddServerReflexiveCandidate_BadParams( void )
{
    IceContext_t context = { 0 };
    IceEndpoint_t endPoint = { 0 };
    IceResult_t result;

    result = Ice_AddServerReflexiveCandidate( NULL,
                                              &( endPoint ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_BAD_PARAM,
                       result );

    result = Ice_AddServerReflexiveCandidate( &( context ),
                                              NULL );

    TEST_ASSERT_EQUAL( ICE_RESULT_BAD_PARAM,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate ICE Add Server Reflexive Candidate fail functionality for Max Candidate Threshold.
 */
void test_iceAddServerReflexiveCandidate_MaxCandidateThreshold( void )
{
    IceContext_t context = { 0 };
    IceEndpoint_t endPoint = { 0 };
    IceResult_t result;

    result = Ice_Init( &( context ),
                       &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       result );

    /* Mark the local candidate array as full. */
    context.numLocalCandidates = LOCAL_CANDIDATE_ARRAY_SIZE;

    result = Ice_AddServerReflexiveCandidate( &( context ),
                                              &( endPoint ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_MAX_CANDIDATE_THRESHOLD,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate ICE Add Server Reflexive Candidate functionality.
 */
void test_iceAddServerReflexiveCandidate( void )
{
    IceResult_t result;
    IceContext_t context = { 0 };
    IceEndpoint_t endPoint = { 0 };

    result = Ice_Init( &( context ),
                       &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       result );

    result = Ice_AddServerReflexiveCandidate( &( context ),
                                              &( endPoint ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       result );
    TEST_ASSERT_EQUAL( 1,
                       context.numLocalCandidates );
    TEST_ASSERT_EQUAL( ICE_CANDIDATE_TYPE_SERVER_REFLEXIVE,
                       context.pLocalCandidates[ 0 ].candidateType );
    TEST_ASSERT_EQUAL( 0,
                       context.pLocalCandidates[ 0 ].isRemote );
    TEST_ASSERT_EQUAL( SERVER_REFLEXIVE_CANDIDATE_PRIORITY,
                       context.pLocalCandidates[ 0 ].priority );
    TEST_ASSERT_EQUAL( ICE_SOCKET_PROTOCOL_NONE,
                       context.pLocalCandidates[ 0 ].remoteProtocol );
    TEST_ASSERT_EQUAL( ICE_CANDIDATE_STATE_NEW,
                       context.pLocalCandidates[ 0 ].state );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate ICE Add Relay Candidate fail functionality for Bad Parameters.
 */
void test_iceAddRelayCandidate_BadParams( void )
{
    IceContext_t context = { 0 };
    IceEndpoint_t endPoint = { 0 };
    char * pUsername = "username";
    size_t usernameLength = strlen( pUsername );
    char * pPassword = "password";
    size_t passwordLength = strlen( pPassword );
    IceResult_t result;

    result = Ice_AddRelayCandidate( NULL,
                                    &( endPoint ),
                                    pUsername,
                                    usernameLength,
                                    pPassword,
                                    passwordLength );

    TEST_ASSERT_EQUAL( ICE_RESULT_BAD_PARAM,
                       result );

    result = Ice_AddRelayCandidate( &( context ),
                                    NULL,
                                    pUsername,
                                    usernameLength,
                                    pPassword,
                                    passwordLength );

    TEST_ASSERT_EQUAL( ICE_RESULT_BAD_PARAM,
                       result );

    result = Ice_AddRelayCandidate( &( context ),
                                    &( endPoint ),
                                    NULL,
                                    usernameLength,
                                    pPassword,
                                    passwordLength );

    TEST_ASSERT_EQUAL( ICE_RESULT_BAD_PARAM,
                       result );

    result = Ice_AddRelayCandidate( &( context ),
                                    &( endPoint ),
                                    pUsername,
                                    usernameLength,
                                    NULL,
                                    passwordLength );

    TEST_ASSERT_EQUAL( ICE_RESULT_BAD_PARAM,
                       result );

    result = Ice_AddRelayCandidate( &( context ),
                                    &( endPoint ),
                                    pUsername,
                                    ICE_SERVER_CONFIG_MAX_USER_NAME_LENGTH + 1,
                                    pPassword,
                                    passwordLength );

    TEST_ASSERT_EQUAL( ICE_RESULT_BAD_PARAM,
                       result );

    result = Ice_AddRelayCandidate( &( context ),
                                    &( endPoint ),
                                    pUsername,
                                    usernameLength,
                                    pPassword,
                                    ICE_SERVER_CONFIG_MAX_PASSWORD_LENGTH + 1 );

    TEST_ASSERT_EQUAL( ICE_RESULT_BAD_PARAM,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate ICE Add Relay Candidate fail functionality for Max Candidate Threshold.
 */
void test_iceAddRelayCandidate_MaxCandidateThreshold( void )
{
    IceContext_t context = { 0 };
    IceEndpoint_t endPoint = { 0 };
    char * pUsername = "username";
    size_t usernameLength = strlen( pUsername );
    char * pPassword = "password";
    size_t passwordLength = strlen( pPassword );
    IceResult_t result;

    result = Ice_Init( &( context ),
                       &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       result );

    /* Mark the local candidate array as full. */
    context.numLocalCandidates = LOCAL_CANDIDATE_ARRAY_SIZE;

    result = Ice_AddRelayCandidate( &( context ),
                                    &( endPoint ),
                                    pUsername,
                                    usernameLength,
                                    pPassword,
                                    passwordLength );

    TEST_ASSERT_EQUAL( ICE_RESULT_MAX_CANDIDATE_THRESHOLD,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Tests that Ice_AddRelayCandidate get failure while
 * using random function to generate transaction ID.
 */
void test_iceAddRelayCandidate_RandomReturnFail( void )
{
    IceContext_t context = { 0 };
    IceEndpoint_t endPoint = { 0 };
    char * pUsername = "username";
    size_t usernameLength = strlen( pUsername );
    char * pPassword = "password";
    size_t passwordLength = strlen( pPassword );
    IceResult_t result;

    result = Ice_Init( &( context ),
                       &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       result );

    /* Ice uses random to generate tie breaker. So we overwrite it after init. */
    context.cryptoFunctions.randomFxn = testRandomFxn_Wrong;

    result = Ice_AddRelayCandidate( &( context ),
                                    &( endPoint ),
                                    pUsername,
                                    usernameLength,
                                    pPassword,
                                    passwordLength );

    TEST_ASSERT_EQUAL( ICE_RESULT_RANDOM_GENERATION_ERROR,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Tests that Ice_AddRelayCandidate return failure when fail
 * to allocate relay extension.
 */
void test_iceAddRelayCandidate_NoAvailableRelayExtension( void )
{
    IceContext_t context = { 0 };
    IceEndpoint_t endPoint = { 0 };
    char * pUsername = "username";
    size_t usernameLength = strlen( pUsername );
    char * pPassword = "password";
    size_t passwordLength = strlen( pPassword );
    IceResult_t result;

    result = Ice_Init( &( context ),
                       &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       result );

    context.numRelayExtensions = context.maxRelayExtensions;

    result = Ice_AddRelayCandidate( &( context ),
                                    &( endPoint ),
                                    pUsername,
                                    usernameLength,
                                    pPassword,
                                    passwordLength );

    TEST_ASSERT_EQUAL( ICE_RESULT_MAX_RELAY_EXTENSION,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate ICE Add Relay Candidate functionality.
 */
void test_iceAddRelayCandidate( void )
{
    IceContext_t context = { 0 };
    IceEndpoint_t endPoint = { 0 };
    char * pUsername = "username";
    size_t usernameLength = strlen( pUsername );
    char * pPassword = "password";
    size_t passwordLength = strlen( pPassword );
    IceResult_t result;

    result = Ice_Init( &( context ),
                       &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       result );

    result = Ice_AddRelayCandidate( &( context ),
                                    &( endPoint ),
                                    pUsername,
                                    usernameLength,
                                    pPassword,
                                    passwordLength );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       result );
    TEST_ASSERT_EQUAL( 1,
                       context.numLocalCandidates );
    TEST_ASSERT_EQUAL( ICE_CANDIDATE_TYPE_RELAY,
                       context.pLocalCandidates[ 0 ].candidateType );
    TEST_ASSERT_EQUAL( 0,
                       context.pLocalCandidates[ 0 ].isRemote );
    TEST_ASSERT_EQUAL( RELAY_CANDIDATE_PRIORITY,
                       context.pLocalCandidates[ 0 ].priority );
    TEST_ASSERT_EQUAL( ICE_SOCKET_PROTOCOL_NONE,
                       context.pLocalCandidates[ 0 ].remoteProtocol );
    TEST_ASSERT_EQUAL( ICE_CANDIDATE_STATE_ALLOCATING,
                       context.pLocalCandidates[ 0 ].state );
    TEST_ASSERT_NOT_EQUAL( NULL,
                           context.pLocalCandidates[ 0 ].pRelayExtension );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate ICE Add Remote Candidate fail functionality for Bad Parameters.
 */
void test_iceAddRemoteCandidate_BadParams( void )
{
    IceContext_t context = { 0 };
    IceRemoteCandidateInfo_t remoteCandidateInfo = { 0 };
    IceResult_t result;

    result = Ice_AddRemoteCandidate( NULL,
                                     &( remoteCandidateInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_BAD_PARAM,
                       result );

    result = Ice_AddRemoteCandidate( &( context ),
                                     NULL );

    TEST_ASSERT_EQUAL( ICE_RESULT_BAD_PARAM,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate ICE Add Remote Candidate fail functionality for Max Candidate Threshold.
 */
void test_iceAddRemoteCandidate_MaxCandidateThreshold( void )
{
    IceContext_t context = { 0 };
    IceRemoteCandidateInfo_t remoteCandidateInfo = { 0 };
    IceResult_t result;

    result = Ice_Init( &( context ),
                       &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       result );

    /* Mark the remote candidate array as full. */
    context.numRemoteCandidates = REMOTE_CANDIDATE_ARRAY_SIZE;

    result = Ice_AddRemoteCandidate( &( context ),
                                     &( remoteCandidateInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_MAX_CANDIDATE_THRESHOLD,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate ICE Add Remote Candidate functionality.
 */
void test_iceAddRemoteCandidate( void )
{
    IceContext_t context = { 0 };
    IceRemoteCandidateInfo_t remoteCandidateInfo = { 0 };
    IceRemoteCandidateInfo_t remoteCandidateInfo2 = { 0 };
    IceEndpoint_t endpoint = { 0 };
    IceResult_t result;

    result = Ice_Init( &( context ),
                       &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       result );

    endpoint.isPointToPoint = 1;
    endpoint.transportAddress.family = 0;
    endpoint.transportAddress.port = 8080;
    memcpy( ( void * ) &( endpoint.transportAddress.address[ 0 ] ),
            ( const void * ) ipAddress,
            sizeof( ipAddress ) );

    remoteCandidateInfo.candidateType = ICE_CANDIDATE_TYPE_HOST;
    remoteCandidateInfo.remoteProtocol = ICE_SOCKET_PROTOCOL_UDP;
    remoteCandidateInfo.priority = 1000;
    remoteCandidateInfo.pEndpoint = &( endpoint );

    result = Ice_AddRemoteCandidate( &( context ),
                                     &( remoteCandidateInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       result );

    endpoint.transportAddress.family = 1;
    endpoint.transportAddress.port = 8009;

    remoteCandidateInfo2.candidateType = ICE_CANDIDATE_TYPE_SERVER_REFLEXIVE;
    remoteCandidateInfo2.remoteProtocol = ICE_SOCKET_PROTOCOL_TCP;
    remoteCandidateInfo2.priority = 500;
    remoteCandidateInfo2.pEndpoint = &( endpoint );

    result = Ice_AddRemoteCandidate( &( context ),
                                     &( remoteCandidateInfo2 ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       result );
    TEST_ASSERT_EQUAL( 2,
                       context.numRemoteCandidates );
    /* Verify first remote candidate. */
    TEST_ASSERT_EQUAL( ICE_CANDIDATE_TYPE_HOST,
                       context.pRemoteCandidates[ 0 ].candidateType );
    TEST_ASSERT_EQUAL( 1,
                       context.pRemoteCandidates[ 0 ].isRemote );
    TEST_ASSERT_EQUAL( ICE_SOCKET_PROTOCOL_UDP,
                       context.pRemoteCandidates[ 0 ].remoteProtocol );
    TEST_ASSERT_EQUAL( 1000,
                       context.pRemoteCandidates[ 0 ].priority );
    TEST_ASSERT_EQUAL( 1,
                       context.pRemoteCandidates[ 0 ].endpoint.isPointToPoint );
    TEST_ASSERT_EQUAL( 8080,
                       context.pRemoteCandidates[ 0 ].endpoint.transportAddress.port );
    TEST_ASSERT_EQUAL_UINT8_ARRAY( ipAddress,
                                   context.pRemoteCandidates[ 0 ].endpoint.transportAddress.address,
                                   sizeof( ipAddress ) );
    TEST_ASSERT_EQUAL( 0,
                       context.pRemoteCandidates[ 0 ].endpoint.transportAddress.family );
    /* Verify second remote candidate. */
    TEST_ASSERT_EQUAL( ICE_CANDIDATE_TYPE_SERVER_REFLEXIVE,
                       context.pRemoteCandidates[ 1 ].candidateType );
    TEST_ASSERT_EQUAL( 1,
                       context.pRemoteCandidates[ 1 ].isRemote );
    TEST_ASSERT_EQUAL( ICE_SOCKET_PROTOCOL_TCP,
                       context.pRemoteCandidates[ 1 ].remoteProtocol );
    TEST_ASSERT_EQUAL( 500,
                       context.pRemoteCandidates[ 1 ].priority );
    TEST_ASSERT_EQUAL( 1,
                       context.pRemoteCandidates[ 1 ].endpoint.isPointToPoint );
    TEST_ASSERT_EQUAL( 8009,
                       context.pRemoteCandidates[ 1 ].endpoint.transportAddress.port );
    TEST_ASSERT_EQUAL_UINT8_ARRAY( ipAddress,
                                   context.pRemoteCandidates[ 0 ].endpoint.transportAddress.address,
                                   sizeof( ipAddress ) );
    TEST_ASSERT_EQUAL( 1,
                       context.pRemoteCandidates[ 1 ].endpoint.transportAddress.family );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate Ice_AddRemoteCandidate return fail when it
 * fail to generate candidate pair.
 */
void test_iceAddRemoteCandidate_CandidatePairFull( void )
{
    IceContext_t context = { 0 };
    IceRemoteCandidateInfo_t remoteCandidateInfo = { 0 };
    IceEndpoint_t endpoint = { 0 };
    IceResult_t result;

    result = Ice_Init( &( context ),
                       &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       result );

    endpoint.isPointToPoint = 1;
    endpoint.transportAddress.family = 0;
    endpoint.transportAddress.port = 8080;
    memcpy( ( void * ) &( endpoint.transportAddress.address[ 0 ] ),
            ( const void * ) ipAddress,
            sizeof( ipAddress ) );

    /* Set 2 local candidate to trigger adding candidate pair flow. */
    context.numLocalCandidates = 2;
    context.pLocalCandidates[0].state = ICE_CANDIDATE_STATE_VALID;
    context.pLocalCandidates[0].candidateType = ICE_CANDIDATE_TYPE_HOST;
    context.pLocalCandidates[1].state = ICE_CANDIDATE_STATE_VALID;
    context.pLocalCandidates[1].candidateType = ICE_CANDIDATE_TYPE_HOST;

    /* Set full candidate pair to make adding candidate pair fail. */
    context.numCandidatePairs = CANDIDATE_PAIR_ARRAY_SIZE;

    remoteCandidateInfo.candidateType = ICE_CANDIDATE_TYPE_HOST;
    remoteCandidateInfo.remoteProtocol = ICE_SOCKET_PROTOCOL_UDP;
    remoteCandidateInfo.priority = 1000;
    remoteCandidateInfo.pEndpoint = &( endpoint );

    result = Ice_AddRemoteCandidate( &( context ),
                                     &( remoteCandidateInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_MAX_CANDIDATE_PAIR_THRESHOLD,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate Ice_AddRemoteCandidate return fail when it
 * fail to generate candidate pair.
 */
void test_iceAddRemoteCandidate_AddCandidatePairForLocalRelayCandidate( void )
{
    IceContext_t context = { 0 };
    IceRemoteCandidateInfo_t remoteCandidateInfo = { 0 };
    IceEndpoint_t endpoint = { 0 };
    IceResult_t result;

    result = Ice_Init( &( context ),
                       &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       result );

    endpoint.isPointToPoint = 1;
    endpoint.transportAddress.family = 0;
    endpoint.transportAddress.port = 8080;
    memcpy( ( void * ) &( endpoint.transportAddress.address[ 0 ] ),
            ( const void * ) ipAddress,
            sizeof( ipAddress ) );

    /* Set 2 local candidate to trigger adding candidate pair flow. */
    context.numLocalCandidates = 1;
    context.pLocalCandidates[0].state = ICE_CANDIDATE_STATE_VALID;
    context.pLocalCandidates[0].candidateType = ICE_CANDIDATE_TYPE_RELAY;
    context.numRelayExtensions = 1;
    context.pLocalCandidates[0].pRelayExtension = &( context.pRelayExtensionsArray[0] );
    context.pLocalCandidates[0].pRelayExtension->nextAvailableTurnChannelNumber = TEST_TURN_CHANNEL_NUMBER_START;

    remoteCandidateInfo.candidateType = ICE_CANDIDATE_TYPE_HOST;
    remoteCandidateInfo.remoteProtocol = ICE_SOCKET_PROTOCOL_UDP;
    remoteCandidateInfo.priority = 1000;
    remoteCandidateInfo.pEndpoint = &( endpoint );

    result = Ice_AddRemoteCandidate( &( context ),
                                     &( remoteCandidateInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       result );
    TEST_ASSERT_EQUAL( 1,
                       context.numRemoteCandidates );
    /* Verify first remote candidate. */
    TEST_ASSERT_EQUAL( ICE_CANDIDATE_TYPE_HOST,
                       context.pRemoteCandidates[ 0 ].candidateType );
    TEST_ASSERT_EQUAL( 1,
                       context.pRemoteCandidates[ 0 ].isRemote );
    TEST_ASSERT_EQUAL( ICE_SOCKET_PROTOCOL_UDP,
                       context.pRemoteCandidates[ 0 ].remoteProtocol );
    TEST_ASSERT_EQUAL( 1000,
                       context.pRemoteCandidates[ 0 ].priority );
    TEST_ASSERT_EQUAL( 1,
                       context.pRemoteCandidates[ 0 ].endpoint.isPointToPoint );
    TEST_ASSERT_EQUAL( 8080,
                       context.pRemoteCandidates[ 0 ].endpoint.transportAddress.port );
    TEST_ASSERT_EQUAL_UINT8_ARRAY( ipAddress,
                                   context.pRemoteCandidates[ 0 ].endpoint.transportAddress.address,
                                   sizeof( ipAddress ) );
    TEST_ASSERT_EQUAL( 0,
                       context.pRemoteCandidates[ 0 ].endpoint.transportAddress.family );
    /* Verify candidate pair. */
    TEST_ASSERT_EQUAL( 1,
                       context.numCandidatePairs );
    TEST_ASSERT_EQUAL_PTR( context.pCandidatePairs[0].pLocalCandidate,
                           &context.pLocalCandidates[0] );
    TEST_ASSERT_EQUAL( TEST_TURN_CHANNEL_NUMBER_START,
                       context.pCandidatePairs[0].turnChannelNumber );
    TEST_ASSERT_EQUAL( TEST_TURN_CHANNEL_NUMBER_START + 1,
                       context.pCandidatePairs[0].pLocalCandidate->pRelayExtension->nextAvailableTurnChannelNumber );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate ICE Add Remote Candidate functionality where remote candidate
 * with same transport address exists.
 */
void test_iceAddRemoteCandidate_SameTransportAddress( void )
{
    IceContext_t context = { 0 };
    IceRemoteCandidateInfo_t remoteCandidateInfo = { 0 };
    IceEndpoint_t endpoint = { 0 };
    IceResult_t result;

    result = Ice_Init( &( context ),
                       &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       result );

    endpoint.isPointToPoint = 1;
    endpoint.transportAddress.family = 0;
    endpoint.transportAddress.port = 8080;
    memcpy( ( void * ) &( endpoint.transportAddress.address[ 0 ] ),
            ( const void * ) ipAddress,
            sizeof( ipAddress ) );

    remoteCandidateInfo.candidateType = ICE_CANDIDATE_TYPE_HOST;
    remoteCandidateInfo.remoteProtocol = ICE_SOCKET_PROTOCOL_UDP;
    remoteCandidateInfo.priority = 1000;
    remoteCandidateInfo.pEndpoint = &( endpoint );

    result = Ice_AddRemoteCandidate( &( context ),
                                     &( remoteCandidateInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       result );

    result = Ice_AddRemoteCandidate( &( context ),
                                     &( remoteCandidateInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       result );
    TEST_ASSERT_EQUAL( 1,
                       context.numRemoteCandidates );
    /* Verify first remote candidate. */
    TEST_ASSERT_EQUAL( ICE_CANDIDATE_TYPE_HOST,
                       context.pRemoteCandidates[ 0 ].candidateType );
    TEST_ASSERT_EQUAL( 1,
                       context.pRemoteCandidates[ 0 ].isRemote );
    TEST_ASSERT_EQUAL( ICE_SOCKET_PROTOCOL_UDP,
                       context.pRemoteCandidates[ 0 ].remoteProtocol );
    TEST_ASSERT_EQUAL( 1000,
                       context.pRemoteCandidates[ 0 ].priority );
    TEST_ASSERT_EQUAL( 1,
                       context.pRemoteCandidates[ 0 ].endpoint.isPointToPoint );
    TEST_ASSERT_EQUAL( 8080,
                       context.pRemoteCandidates[ 0 ].endpoint.transportAddress.port );
    TEST_ASSERT_EQUAL_UINT8_ARRAY( ipAddress,
                                   context.pRemoteCandidates[ 0 ].endpoint.transportAddress.address,
                                   sizeof( ipAddress ) );
    TEST_ASSERT_EQUAL( 0,
                       context.pRemoteCandidates[ 0 ].endpoint.transportAddress.family );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate Ice_AddRemoteCandidate that it doesn't generate
 * any candidate pair because none of them is valid.
 */
void test_iceAddRemoteCandidate_NoValidLocalCandidate( void )
{
    IceContext_t context = { 0 };
    IceRemoteCandidateInfo_t remoteCandidateInfo = { 0 };
    IceEndpoint_t endpoint = { 0 };
    IceResult_t result;

    result = Ice_Init( &( context ),
                       &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       result );

    endpoint.isPointToPoint = 1;
    endpoint.transportAddress.family = 0;
    endpoint.transportAddress.port = 8080;
    memcpy( ( void * ) &( endpoint.transportAddress.address[ 0 ] ),
            ( const void * ) ipAddress,
            sizeof( ipAddress ) );

    /* Set 2 local candidate to trigger adding candidate pair flow. */
    context.numLocalCandidates = 1;
    context.pLocalCandidates[0].state = ICE_CANDIDATE_STATE_ALLOCATING;
    context.pLocalCandidates[0].candidateType = ICE_CANDIDATE_TYPE_RELAY;
    context.numRelayExtensions = 1;
    context.pLocalCandidates[0].pRelayExtension = &( context.pRelayExtensionsArray[0] );

    remoteCandidateInfo.candidateType = ICE_CANDIDATE_TYPE_HOST;
    remoteCandidateInfo.remoteProtocol = ICE_SOCKET_PROTOCOL_UDP;
    remoteCandidateInfo.priority = 1000;
    remoteCandidateInfo.pEndpoint = &( endpoint );

    result = Ice_AddRemoteCandidate( &( context ),
                                     &( remoteCandidateInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       result );
    TEST_ASSERT_EQUAL( 1,
                       context.numRemoteCandidates );
    /* Verify first remote candidate. */
    TEST_ASSERT_EQUAL( ICE_CANDIDATE_TYPE_HOST,
                       context.pRemoteCandidates[ 0 ].candidateType );
    TEST_ASSERT_EQUAL( 1,
                       context.pRemoteCandidates[ 0 ].isRemote );
    TEST_ASSERT_EQUAL( ICE_SOCKET_PROTOCOL_UDP,
                       context.pRemoteCandidates[ 0 ].remoteProtocol );
    TEST_ASSERT_EQUAL( 1000,
                       context.pRemoteCandidates[ 0 ].priority );
    TEST_ASSERT_EQUAL( 1,
                       context.pRemoteCandidates[ 0 ].endpoint.isPointToPoint );
    TEST_ASSERT_EQUAL( 8080,
                       context.pRemoteCandidates[ 0 ].endpoint.transportAddress.port );
    TEST_ASSERT_EQUAL_UINT8_ARRAY( ipAddress,
                                   context.pRemoteCandidates[ 0 ].endpoint.transportAddress.address,
                                   sizeof( ipAddress ) );
    TEST_ASSERT_EQUAL( 0,
                       context.pRemoteCandidates[ 0 ].endpoint.transportAddress.family );
    /* Verify candidate pair. */
    TEST_ASSERT_EQUAL( 0,
                       context.numCandidatePairs );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate ICE Add Remote Candidate functionality.
 */
void test_iceAddCandidatePair( void )
{
    IceContext_t context = { 0 };
    IceRemoteCandidateInfo_t remoteCandidateInfo = { 0 };
    IceEndpoint_t endpoint = { 0 };
    IceResult_t result;
    uint8_t expectedTransactionID[] =
    {
        /* 12 bytes (96 bits) transaction ID as generated by testRandomFxn. */
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
    };
    size_t expectedTransactionIDLength = sizeof( expectedTransactionID );

    result = Ice_Init( &( context ),
                       &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       result );

    endpoint.isPointToPoint = 1;
    endpoint.transportAddress.family = 0;
    endpoint.transportAddress.port = 8080;
    memcpy( ( void * ) &( endpoint.transportAddress.address[ 0 ] ),
            ( const void * ) ipAddress,
            sizeof( ipAddress ) );

    result = Ice_AddHostCandidate( &( context ),
                                   &( endpoint ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       result );

    remoteCandidateInfo.candidateType = ICE_CANDIDATE_TYPE_HOST;
    remoteCandidateInfo.remoteProtocol = ICE_SOCKET_PROTOCOL_UDP;
    remoteCandidateInfo.priority = 1000;
    remoteCandidateInfo.pEndpoint = &( endpoint );

    result = Ice_AddRemoteCandidate( &( context ),
                                     &( remoteCandidateInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       result );

    /* Verify candidate pair Info. */
    TEST_ASSERT_EQUAL( 1,
                       context.numCandidatePairs );
    TEST_ASSERT_EQUAL( 0,
                       context.pCandidatePairs[ 0 ].connectivityCheckFlags );
    TEST_ASSERT_EQUAL( 4299195154943, /* For the given Host Candidate and Remote Candidate this is the generated Priority. */
                       context.pCandidatePairs[ 0 ].priority );
    TEST_ASSERT_EQUAL( ICE_CANDIDATE_PAIR_STATE_WAITING,
                       context.pCandidatePairs[ 0 ].state );
    TEST_ASSERT_EQUAL_UINT8_ARRAY( &( expectedTransactionID[ 0 ] ),
                                   &( context.pCandidatePairs[ 0 ].transactionId[ 0 ] ),
                                   expectedTransactionIDLength );

    /* Verify local candidate Info in the Candidate Pair. */
    TEST_ASSERT_EQUAL( ICE_CANDIDATE_TYPE_HOST,
                       context.pCandidatePairs[ 0 ].pLocalCandidate->candidateType );
    TEST_ASSERT_EQUAL( 0,
                       context.pCandidatePairs[ 0 ].pLocalCandidate->isRemote );
    TEST_ASSERT_EQUAL( HOST_CANDIDATE_PRIORITY,
                       context.pCandidatePairs[ 0 ].pLocalCandidate->priority );
    TEST_ASSERT_EQUAL( ICE_SOCKET_PROTOCOL_NONE,
                       context.pCandidatePairs[ 0 ].pLocalCandidate->remoteProtocol );
    TEST_ASSERT_EQUAL( ICE_CANDIDATE_STATE_VALID,
                       context.pCandidatePairs[ 0 ].pLocalCandidate->state );
    TEST_ASSERT_EQUAL( 1,
                       context.pCandidatePairs[ 0 ].pLocalCandidate->endpoint.isPointToPoint );
    TEST_ASSERT_EQUAL( 0,
                       context.pCandidatePairs[ 0 ].pLocalCandidate->endpoint.transportAddress.family );
    TEST_ASSERT_EQUAL( 8080,
                       context.pCandidatePairs[ 0 ].pLocalCandidate->endpoint.transportAddress.port );
    TEST_ASSERT_EQUAL_UINT8_ARRAY( ipAddress,
                                   context.pCandidatePairs[ 0 ].pLocalCandidate->endpoint.transportAddress.address, sizeof( ipAddress ) );

    /* Verify remote candidate Info in the Candidate Pair. */
    TEST_ASSERT_EQUAL( ICE_CANDIDATE_TYPE_HOST,
                       context.pCandidatePairs[ 0 ].pRemoteCandidate->candidateType );
    TEST_ASSERT_EQUAL( 1,
                       context.pCandidatePairs[ 0 ].pRemoteCandidate->isRemote );
    TEST_ASSERT_EQUAL( ICE_SOCKET_PROTOCOL_UDP,
                       context.pCandidatePairs[ 0 ].pRemoteCandidate->remoteProtocol );
    TEST_ASSERT_EQUAL( 1000,
                       context.pCandidatePairs[ 0 ].pRemoteCandidate->priority );
    TEST_ASSERT_EQUAL( 1,
                       context.pCandidatePairs[ 0 ].pRemoteCandidate->endpoint.isPointToPoint );
    TEST_ASSERT_EQUAL( 8080,
                       context.pCandidatePairs[ 0 ].pRemoteCandidate->endpoint.transportAddress.port );
    TEST_ASSERT_EQUAL_UINT8_ARRAY( ipAddress,
                                   context.pCandidatePairs[ 0 ].pRemoteCandidate->endpoint.transportAddress.address, sizeof( ipAddress ) );
    TEST_ASSERT_EQUAL( 0,
                       context.pCandidatePairs[ 0 ].pRemoteCandidate->endpoint.transportAddress.family );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate ICE Add Remote Candidate functionality for creating multiple Candidate Pairs and their sorting in the array.
 */
void test_iceAddCandidatePair_MultipleCandidatePairs( void )
{
    IceContext_t context = { 0 };
    IceRemoteCandidateInfo_t remoteCandidateInfo = { 0 };
    IceRemoteCandidateInfo_t remoteCandidateInfo2 = { 0 };
    IceEndpoint_t endpoint = { 0 };
    IceResult_t result;
    uint8_t expectedTransactionID[] =
    {
        /* 12 bytes (96 bits) transaction ID as generated by testRandomFxn. */
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
    };
    size_t expectedTransactionIDLength = sizeof( expectedTransactionID );

    result = Ice_Init( &( context ),
                       &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       result );

    endpoint.isPointToPoint = 1;
    endpoint.transportAddress.family = 0x01;
    endpoint.transportAddress.port = 8080;
    memcpy( ( void * ) &( endpoint.transportAddress.address[ 0 ] ),
            ( const void * ) ipAddress,
            sizeof( ipAddress ) );

    result = Ice_AddHostCandidate( &( context ),
                                   &( endpoint ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       result );

    remoteCandidateInfo.candidateType = ICE_CANDIDATE_TYPE_HOST;
    remoteCandidateInfo.remoteProtocol = ICE_SOCKET_PROTOCOL_UDP;
    remoteCandidateInfo.priority = 500;             /* Priority P1 */
    remoteCandidateInfo.pEndpoint = &( endpoint );

    result = Ice_AddRemoteCandidate( &( context ),
                                     &( remoteCandidateInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       result );

    endpoint.transportAddress.family = 0x02;

    remoteCandidateInfo2.candidateType = ICE_CANDIDATE_TYPE_SERVER_REFLEXIVE;
    remoteCandidateInfo2.remoteProtocol = ICE_SOCKET_PROTOCOL_UDP;
    remoteCandidateInfo2.priority = 1000;            /* Priority P2 > P1 */
    remoteCandidateInfo2.pEndpoint = &( endpoint );

    result = Ice_AddRemoteCandidate( &( context ),
                                     &( remoteCandidateInfo2 ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       result );

    endpoint.transportAddress.port = 700;

    remoteCandidateInfo2.candidateType = ICE_CANDIDATE_TYPE_SERVER_REFLEXIVE;
    remoteCandidateInfo2.remoteProtocol = ICE_SOCKET_PROTOCOL_UDP;
    remoteCandidateInfo2.priority = 200;            /* Priority P2 > P1 > P3 */
    remoteCandidateInfo2.pEndpoint = &( endpoint );

    result = Ice_AddRemoteCandidate( &( context ),
                                     &( remoteCandidateInfo2 ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       result );

    /* Verify candidate pair Info. */
    TEST_ASSERT_EQUAL( 3,               /* 1 Local x 3 Remote = 3 Candidate Pairs */
                       context.numCandidatePairs );
    TEST_ASSERT_EQUAL( 1000, context.pCandidatePairs[ 0 ].pRemoteCandidate->priority );
    TEST_ASSERT_EQUAL( 500, context.pCandidatePairs[ 1 ].pRemoteCandidate->priority );
    TEST_ASSERT_EQUAL( 200, context.pCandidatePairs[ 2 ].pRemoteCandidate->priority );
    TEST_ASSERT_EQUAL_UINT8_ARRAY( &( expectedTransactionID[ 0 ] ),
                                   &( context.pCandidatePairs[ 0 ].transactionId[ 0 ] ),
                                   expectedTransactionIDLength );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate ICE Add Remote Candidate functionality when local candidates are added after a remote candidate is added.
 */
void test_iceAddCandidatePair_PostRemoteCandidate( void )
{
    IceContext_t context = { 0 };
    IceRemoteCandidateInfo_t remoteCandidateInfo = { 0 };
    IceEndpoint_t endpoint = { 0 };
    IceResult_t result;

    result = Ice_Init( &( context ),
                       &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       result );

    remoteCandidateInfo.candidateType = ICE_CANDIDATE_TYPE_HOST;
    remoteCandidateInfo.remoteProtocol = ICE_SOCKET_PROTOCOL_UDP;
    remoteCandidateInfo.priority = 1000;
    remoteCandidateInfo.pEndpoint = &( endpoint );

    result = Ice_AddRemoteCandidate( &( context ),
                                     &( remoteCandidateInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       result );

    /* Verify candidate pair Info. */
    TEST_ASSERT_EQUAL( 0,
                       context.numCandidatePairs );

    endpoint.isPointToPoint = 1;
    endpoint.transportAddress.family = 0;
    endpoint.transportAddress.port = 8080;
    memcpy( ( void * ) &( endpoint.transportAddress.address[ 0 ] ),
            ( const void * ) ipAddress,
            sizeof( ipAddress ) );

    result = Ice_AddHostCandidate( &( context ),
                                   &( endpoint ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       result );

    /* Verify candidate pair Info. */
    TEST_ASSERT_EQUAL( 1,
                       context.numCandidatePairs );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate ICE Add Remote Candidate functionality when local candidate
 * has Non-Valid Candidate state.
 */
void test_iceAddCandidatePair_NonValidState( void )
{
    IceContext_t context = { 0 };
    IceRemoteCandidateInfo_t remoteCandidateInfo = { 0 };
    IceEndpoint_t endpoint = { 0 };
    IceResult_t result;

    result = Ice_Init( &( context ),
                       &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       result );

    endpoint.isPointToPoint = 1;
    endpoint.transportAddress.family = 0;
    endpoint.transportAddress.port = 8080;
    memcpy( ( void * ) &( endpoint.transportAddress.address[ 0 ] ),
            ( const void * ) ipAddress,
            sizeof( ipAddress ) );

    /* When a server-reflexive candidate is added, it starts in "New" state
     * and transitions to "Valid" state later when a STUN response is received. */
    result = Ice_AddServerReflexiveCandidate( &( context ),
                                              &( endpoint ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       result );
    TEST_ASSERT_EQUAL( ICE_CANDIDATE_STATE_NEW, /* Non-Valid State. */
                       context.pLocalCandidates[ 0 ].state );

    /* Verify candidate pair Info. */
    TEST_ASSERT_EQUAL( 0,
                       context.numCandidatePairs );

    remoteCandidateInfo.candidateType = ICE_CANDIDATE_TYPE_HOST;
    remoteCandidateInfo.remoteProtocol = ICE_SOCKET_PROTOCOL_UDP;
    remoteCandidateInfo.priority = 1000;
    remoteCandidateInfo.pEndpoint = &( endpoint );

    /* Adding a remote candidate should not result in creation of a candidate
     * pair because the only local candidate (the server reflexive candidate
     * added above) is not in "Valid" state. */
    result = Ice_AddRemoteCandidate( &( context ),
                                     &( remoteCandidateInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       result );

    /* Verify candidate pair Info. */
    TEST_ASSERT_EQUAL( 0,
                       context.numCandidatePairs );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate ICE Create Stun Packet for Response to Stun Binding Packet fail functionality for Bad Parameters.
 */
void test_iceCreateResponseForRequest_BadParams( void )
{
    IceContext_t context = { 0 };
    IceCandidatePair_t candidatePair = { 0 };
    uint8_t transactionId[ STUN_HEADER_TRANSACTION_ID_LENGTH ];
    uint8_t stunMessageBuffer[ 10 ];
    size_t stunMessageBufferLength = sizeof( stunMessageBuffer );
    IceResult_t result;

    result = Ice_CreateResponseForRequest( NULL,
                                           &( candidatePair ),
                                           &( transactionId[ 0 ] ),
                                           &( stunMessageBuffer[ 0 ] ),
                                           &( stunMessageBufferLength ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_BAD_PARAM,
                       result );

    result = Ice_CreateResponseForRequest( &( context ),
                                           NULL,
                                           &( transactionId[ 0 ] ),
                                           &( stunMessageBuffer[ 0 ] ),
                                           &( stunMessageBufferLength ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_BAD_PARAM,
                       result );

    result = Ice_CreateResponseForRequest( &( context ),
                                           &( candidatePair ),
                                           NULL,
                                           &( stunMessageBuffer[ 0 ] ),
                                           &( stunMessageBufferLength ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_BAD_PARAM,
                       result );

    result = Ice_CreateResponseForRequest( &( context ),
                                           &( candidatePair ),
                                           &( transactionId[ 0 ] ),
                                           NULL,
                                           &( stunMessageBufferLength ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_BAD_PARAM,
                       result );

    result = Ice_CreateResponseForRequest( &( context ),
                                           &( candidatePair ),
                                           &( transactionId[ 0 ] ),
                                           &( stunMessageBuffer[ 0 ] ),
                                           NULL );

    TEST_ASSERT_EQUAL( ICE_RESULT_BAD_PARAM,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate ICE Create Stun Packet for Response to Stun Binding Packet fail functionality for Stun Errors.
 */
void test_iceCreateResponseForRequest_StunError( void )
{
    IceContext_t context = { 0 };
    IceEndpoint_t endpoint = { 0 };
    IceRemoteCandidateInfo_t remoteCandidateInfo = { 0 };
    uint8_t stunMessageBuffer[ 8 ] = { 0 }; /* Too small to be able to contain a Stun message. */
    size_t stunMessageBufferLength = sizeof( stunMessageBuffer );
    IceResult_t result;
    uint8_t transactionId[] =
    {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B
    };

    result = Ice_Init( &( context ),
                       &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       result );

    endpoint.isPointToPoint = 1;
    endpoint.transportAddress.family = 0x01;
    endpoint.transportAddress.port = 8080;
    memcpy( ( void * ) &( endpoint.transportAddress.address[ 0 ] ),
            ( const void * ) ipAddress,
            sizeof( ipAddress ) );

    result = Ice_AddHostCandidate( &( context ),
                                   &( endpoint ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       result );

    remoteCandidateInfo.candidateType = ICE_CANDIDATE_TYPE_HOST;
    remoteCandidateInfo.remoteProtocol = ICE_SOCKET_PROTOCOL_UDP;
    remoteCandidateInfo.priority = 1000;
    remoteCandidateInfo.pEndpoint = &( endpoint );

    result = Ice_AddRemoteCandidate( &( context ),
                                     &( remoteCandidateInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       result );

    result = Ice_CreateResponseForRequest( &( context ),
                                           &( context.pCandidatePairs[ 0 ] ),
                                           &( transactionId[ 0 ] ),
                                           &( stunMessageBuffer[ 0 ] ),
                                           &( stunMessageBufferLength ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_STUN_ERROR,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate ICE Create Stun Packet for Response to Stun Binding Packet functionality.
 */
void test_iceCreateResponseForRequest( void )
{
    IceContext_t context = { 0 };
    IceEndpoint_t endpoint = { 0 };
    IceRemoteCandidateInfo_t remoteCandidateInfo = { 0 };
    uint8_t stunMessageBuffer[ 128 ] = { 0 };
    size_t stunMessageBufferLength = sizeof( stunMessageBuffer );
    uint8_t transactionId[] =
    {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B
    };
    uint8_t expectedStunMessage[] =
    {
        /* STUN header: Message Type = BINDING_SUCCESS_RESPONSE (0x0101), Length = 56 bytes (excluding 20 bytes header). */
        0x01, 0x01, 0x00, 0x38,
        /* Magic Cookie (0x2112A442). */
        0x21, 0x12, 0xA4, 0x42,
        /* 12 bytes (96 bits) transaction ID as generated by testRandomFxn. */
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
        /* Attribute type = XOR Mapped Address (0x0020), Length = 8 bytes. */
        0x00, 0x20, 0x00, 0x08,
        /* Address family = IPv4, Port = 0x3E82, IP Address = 0xC0A80164 (192.168.1.100). */
        0x00, 0x01, 0x3E, 0x82, 0xE1, 0xBA, 0xA5, 0x26,
        /* Attribute type = ICE-CONTROLLING ( 0x802A ), Length = 8 bytes. */
        0x80, 0x2A, 0x00, 0x08,
        /* Attribute Value = 0x0706050403020100. */
        0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00,
        /* Attribute type = MESSAGE-INTEGRITY (0x0008), Length = 20 bytes. */
        0x00, 0x08, 0x00, 0x14,
        /* Attribute Value = HMAC value as computed by testHmacFxn. */
        0x6D, 0x6E, 0x63, 0x51,
        0x4D, 0x42, 0xC5, 0x31,
        0x73, 0x76, 0x6D, 0x71,
        0x60, 0x69, 0x69, 0x64,
        0x69, 0x65, 0x5A, 0x6A,
        /* Attribute type = FINGERPRINT (0x8028), Length = 4 bytes. */
        0x80, 0x28, 0x00, 0x04,
        /* Attribute Value: 0x3706803D as calculated by testCrc32Fxn. */
        0x37, 0x06, 0x80, 0x3D
    };
    size_t expectedStunMessageLength = sizeof( expectedStunMessage );
    IceResult_t result;

    result = Ice_Init( &( context ),
                       &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       result );

    endpoint.isPointToPoint = 1;
    endpoint.transportAddress.family = 0x01;
    endpoint.transportAddress.port = 8080;
    memcpy( ( void * ) &( endpoint.transportAddress.address[ 0 ] ),
            ( const void * ) ipAddress,
            sizeof( ipAddress ) );

    result = Ice_AddHostCandidate( &( context ),
                                   &( endpoint ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       result );

    remoteCandidateInfo.candidateType = ICE_CANDIDATE_TYPE_HOST;
    remoteCandidateInfo.remoteProtocol = ICE_SOCKET_PROTOCOL_UDP;
    remoteCandidateInfo.priority = 1000;
    remoteCandidateInfo.pEndpoint = &( endpoint );

    result = Ice_AddRemoteCandidate( &( context ),
                                     &( remoteCandidateInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       result );

    result = Ice_CreateResponseForRequest( &( context ),
                                           &( context.pCandidatePairs[ 0 ] ),
                                           &( transactionId[ 0 ] ),
                                           &( stunMessageBuffer[ 0 ] ),
                                           &( stunMessageBufferLength ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       result );
    TEST_ASSERT_EQUAL( expectedStunMessageLength,
                       stunMessageBufferLength );
    TEST_ASSERT_EQUAL_UINT8_ARRAY( &( expectedStunMessage[ 0 ] ),
                                   &( stunMessageBuffer[ 0 ] ),
                                   expectedStunMessageLength );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate ICE Create Stun Packet for Response to Stun Binding Packet functionality
 * with TURN channel header.
 */
void test_iceCreateResponseForRequest_TurnChannelHeader( void )
{
    IceContext_t context = { 0 };
    IceEndpoint_t endpoint = { 0 };
    IceRemoteCandidateInfo_t remoteCandidateInfo = { 0 };
    uint8_t stunMessageBuffer[ 128 ] = { 0 };
    char * pUsername = "username";
    size_t usernameLength = strlen( pUsername );
    char * pPassword = "password";
    size_t passwordLength = strlen( pPassword );
    size_t stunMessageBufferLength = sizeof( stunMessageBuffer );
    uint8_t transactionId[] =
    {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B
    };
    uint8_t expectedStunMessage[] =
    {
        /* STUN header: Message Type = BINDING_SUCCESS_RESPONSE (0x0101), Length = 56 bytes (excluding 20 bytes header). */
        0x01, 0x01, 0x00, 0x38,
        /* Magic Cookie (0x2112A442). */
        0x21, 0x12, 0xA4, 0x42,
        /* 12 bytes (96 bits) transaction ID as generated by testRandomFxn. */
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
        /* Attribute type = XOR Mapped Address (0x0020), Length = 8 bytes. */
        0x00, 0x20, 0x00, 0x08,
        /* Address family = IPv4, Port = 0x3E82, IP Address = 0xC0A80164 (192.168.1.100). */
        0x00, 0x01, 0x3E, 0x82, 0xE1, 0xBA, 0xA5, 0x26,
        /* Attribute type = ICE-CONTROLLING ( 0x802A ), Length = 8 bytes. */
        0x80, 0x2A, 0x00, 0x08,
        /* Attribute Value = 0x0706050403020100. */
        0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00,
        /* Attribute type = MESSAGE-INTEGRITY (0x0008), Length = 20 bytes. */
        0x00, 0x08, 0x00, 0x14,
        /* Attribute Value = HMAC value as computed by testHmacFxn_FixedFF. */
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        /* Attribute type = FINGERPRINT (0x8028), Length = 4 bytes. */
        0x80, 0x28, 0x00, 0x04,
        /* Attribute Value = 0xB5F5C42F as calculated by testCrc32Fxn_Fixed. */
        0x00, 0x00, 0x00, 0x00
    };
    size_t expectedStunMessageLength = sizeof( expectedStunMessage );
    uint8_t expectedTurnChannelHeader[] =
    {
        /* Channel Number */
        0x40, 0x10,
        /* Content Length = 0x4C ( 0x38 + STUN header 20 bytes ) */
        0x00, 0x4C
    };
    size_t expectedTurnChannelHeaderLength = sizeof( expectedTurnChannelHeader );
    IceResult_t result;

    result = Ice_Init( &( context ),
                       &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       result );

    context.cryptoFunctions.hmacFxn = testHmacFxn_FixedFF;
    context.cryptoFunctions.crc32Fxn = testCrc32Fxn_Fixed;

    endpoint.isPointToPoint = 1;
    endpoint.transportAddress.family = 0x01;
    endpoint.transportAddress.port = 8080;
    memcpy( ( void * ) &( endpoint.transportAddress.address[ 0 ] ),
            ( const void * ) ipAddress,
            sizeof( ipAddress ) );

    result = Ice_AddRelayCandidate( &( context ),
                                    &( endpoint ),
                                    pUsername,
                                    usernameLength,
                                    pPassword,
                                    passwordLength );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       result );
    TEST_ASSERT_EQUAL( 1,
                       context.numLocalCandidates );
    TEST_ASSERT_EQUAL( ICE_CANDIDATE_TYPE_RELAY,
                       context.pLocalCandidates[ 0 ].candidateType );
    TEST_ASSERT_EQUAL( 0,
                       context.pLocalCandidates[ 0 ].isRemote );
    TEST_ASSERT_EQUAL( ICE_CANDIDATE_STATE_ALLOCATING,
                       context.pLocalCandidates[ 0 ].state );
    TEST_ASSERT_NOT_EQUAL( NULL,
                           context.pLocalCandidates[ 0 ].pRelayExtension );

    context.pLocalCandidates[ 0 ].state = ICE_CANDIDATE_STATE_VALID;
    context.pLocalCandidates[ 0 ].pRelayExtension->nextAvailableTurnChannelNumber = TEST_TURN_CHANNEL_NUMBER_START;

    remoteCandidateInfo.candidateType = ICE_CANDIDATE_TYPE_HOST;
    remoteCandidateInfo.remoteProtocol = ICE_SOCKET_PROTOCOL_UDP;
    remoteCandidateInfo.priority = 1000;
    remoteCandidateInfo.pEndpoint = &( endpoint );

    result = Ice_AddRemoteCandidate( &( context ),
                                     &( remoteCandidateInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       result );
    TEST_ASSERT_EQUAL( 1,
                       context.numRemoteCandidates );
    TEST_ASSERT_EQUAL( 1,
                       context.numCandidatePairs );

    context.pCandidatePairs[ 0 ].state = ICE_CANDIDATE_PAIR_STATE_WAITING;

    result = Ice_CreateResponseForRequest( &( context ),
                                           &( context.pCandidatePairs[ 0 ] ),
                                           &( transactionId[ 0 ] ),
                                           &( stunMessageBuffer[ 0 ] ),
                                           &( stunMessageBufferLength ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       result );
    TEST_ASSERT_EQUAL( expectedStunMessageLength + expectedTurnChannelHeaderLength,
                       stunMessageBufferLength );
    TEST_ASSERT_EQUAL_UINT8_ARRAY( &( expectedTurnChannelHeader[ 0 ] ),
                                   &( stunMessageBuffer[ 0 ] ),
                                   expectedTurnChannelHeaderLength );
    TEST_ASSERT_EQUAL_UINT8_ARRAY( &( expectedStunMessage[ 0 ] ),
                                   &( stunMessageBuffer[ expectedTurnChannelHeaderLength ] ),
                                   expectedStunMessageLength );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate ICE Create Stun Packet for Response to Stun Binding Packet functionality.
 */
void test_iceCreateResponseForRequest_Controlled( void )
{
    IceContext_t context = { 0 };
    IceEndpoint_t endpoint = { 0 };
    IceRemoteCandidateInfo_t remoteCandidateInfo = { 0 };
    uint8_t stunMessageBuffer[ 128 ] = { 0 };
    size_t stunMessageBufferLength = sizeof( stunMessageBuffer );
    uint8_t transactionId[] =
    {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B
    };
    uint8_t expectedStunMessage[] =
    {
        /* STUN header: Message Type = BINDING_SUCCESS_RESPONSE (0x0101), Length = 56 bytes (excluding 20 bytes header). */
        0x01, 0x01, 0x00, 0x38,
        /* Magic Cookie (0x2112A442). */
        0x21, 0x12, 0xA4, 0x42,
        /* 12 bytes (96 bits) transaction ID as generated by testRandomFxn. */
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
        /* Attribute type = XOR Mapped Address (0x0020), Length = 8 bytes. */
        0x00, 0x20, 0x00, 0x08,
        /* Address family = IPv4, Port = 0x3E82, IP Address = 0xC0A80164 (192.168.1.100). */
        0x00, 0x01, 0x3E, 0x82, 0xE1, 0xBA, 0xA5, 0x26,
        /* Attribute type = ICE-CONTROLLED (0x8029), Length = 8 bytes. */
        0x80, 0x29, 0x00, 0x08,
        /* Attribute Value = 0x0706050403020100. */
        0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00,
        /* Attribute type = MESSAGE-INTEGRITY (0x0008), Length = 20 bytes. */
        0x00, 0x08, 0x00, 0x14,
        /* Attribute Value = HMAC value as computed by testHmacFxn. */
        0x6D, 0x6E, 0x63, 0x51,
        0x4D, 0x42, 0xC5, 0x31,
        0x73, 0x76, 0x6D, 0x71,
        0x60, 0x69, 0x69, 0x64,
        0x69, 0x65, 0x5A, 0x6A,
        /* Attribute type = FINGERPRINT (0x8028), Length = 4 bytes. */
        0x80, 0x28, 0x00, 0x04,
        /* Attribute Value: 0xBCD5BE24 as calculated by testCrc32Fxn. */
        0xBC, 0xD5, 0xBE, 0x24
    };
    size_t expectedStunMessageLength = sizeof( expectedStunMessage );
    IceResult_t result;

    initInfo.isControlling = 0;
    result = Ice_Init( &( context ),
                       &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       result );

    endpoint.isPointToPoint = 1;
    endpoint.transportAddress.family = 0x01;
    endpoint.transportAddress.port = 8080;
    memcpy( ( void * ) &( endpoint.transportAddress.address[ 0 ] ),
            ( const void * ) ipAddress,
            sizeof( ipAddress ) );

    result = Ice_AddHostCandidate( &( context ),
                                   &( endpoint ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       result );

    remoteCandidateInfo.candidateType = ICE_CANDIDATE_TYPE_HOST;
    remoteCandidateInfo.remoteProtocol = ICE_SOCKET_PROTOCOL_UDP;
    remoteCandidateInfo.priority = 1000;
    remoteCandidateInfo.pEndpoint = &( endpoint );

    result = Ice_AddRemoteCandidate( &( context ),
                                     &( remoteCandidateInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       result );

    result = Ice_CreateResponseForRequest( &( context ),
                                           &( context.pCandidatePairs[ 0 ] ),
                                           &( transactionId[ 0 ] ),
                                           &( stunMessageBuffer[ 0 ] ),
                                           &( stunMessageBufferLength ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       result );
    TEST_ASSERT_EQUAL( expectedStunMessageLength,
                       stunMessageBufferLength );
    TEST_ASSERT_EQUAL_UINT8_ARRAY( &( expectedStunMessage[ 0 ] ),
                                   &( stunMessageBuffer[ 0 ] ),
                                   expectedStunMessageLength );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate ICE Create Next Candidate Reuqest functionality for Bad Parameters.
 */
void test_iceCreateNextCandidateRequest_BadParams( void )
{
    IceContext_t context = { 0 };
    IceCandidate_t localCandidate;
    uint8_t stunMessageBuffer[ 10 ];
    size_t stunMessageBufferLength = sizeof( stunMessageBuffer );
    IceResult_t result;

    result = Ice_CreateNextCandidateRequest( NULL,
                                             &( localCandidate ),
                                             stunMessageBuffer,
                                             &stunMessageBufferLength );

    TEST_ASSERT_EQUAL( ICE_RESULT_BAD_PARAM,
                       result );

    result = Ice_CreateNextCandidateRequest( &( context ),
                                             NULL,
                                             stunMessageBuffer,
                                             &stunMessageBufferLength );

    TEST_ASSERT_EQUAL( ICE_RESULT_BAD_PARAM,
                       result );

    result = Ice_CreateNextCandidateRequest( &( context ),
                                             &( localCandidate ),
                                             NULL,
                                             &stunMessageBufferLength );

    TEST_ASSERT_EQUAL( ICE_RESULT_BAD_PARAM,
                       result );

    result = Ice_CreateNextCandidateRequest( &( context ),
                                             &( localCandidate ),
                                             stunMessageBuffer,
                                             NULL );

    TEST_ASSERT_EQUAL( ICE_RESULT_BAD_PARAM,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Tests that Ice_CreateNextCandidateRequest returns
 * ICE_RESULT_INVALID_CANDIDATE for remote candidate.
 */
void test_iceCreateNextCandidateRequest_IsRemoteCandidate( void )
{
    IceContext_t context = { 0 };
    IceCandidate_t localCandidate;
    uint8_t stunMessageBuffer[ 10 ];
    size_t stunMessageBufferLength = sizeof( stunMessageBuffer );
    IceResult_t result;

    localCandidate.isRemote = 1U;
    result = Ice_CreateNextCandidateRequest( &( context ),
                                             &( localCandidate ),
                                             stunMessageBuffer,
                                             &stunMessageBufferLength );

    TEST_ASSERT_EQUAL( ICE_RESULT_INVALID_CANDIDATE,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Tests that Ice_CreateNextCandidateRequest returns
 * BINDING_REQUEST STUN message to query IP address for new
 * srflx candidate.
 */
void test_iceCreateNextCandidateRequest_NewSrflxCandidate( void )
{
    IceContext_t context = { 0 };
    IceCandidate_t localCandidate;
    IceResult_t result;
    uint8_t stunMessageBuffer[ 32 ];
    size_t stunMessageBufferLength = 32;
    uint8_t expectedStunMessage[] =
    {
        /* STUN header: Message Type = Binding Request (0x0001), Length = 8 bytes (excluding 20 bytes header). */
        0x00, 0x01, 0x00, 0x08,
        /* Magic Cookie (0x2112A442). */
        0x21, 0x12, 0xA4, 0x42,
        /* 12 bytes (96 bits) transaction ID as generated by testRandomFxn. */
        0x00, 0x01, 0x02, 0x03,
        0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B,
        /* Attribute type = FINGERPRINT (0x8028), Length = 4 bytes. */
        0x80, 0x28, 0x00, 0x04,
        /* Attribute Value: 0x54DA6D71 as calculated by testCrc32Fxn. */
        0x54, 0xDA, 0x6D, 0x71,
    };
    size_t expectedStunMessageLength = sizeof( expectedStunMessage );

    result = Ice_Init( &( context ),
                       &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       result );

    memset( &localCandidate, 0, sizeof( IceCandidate_t ) );
    localCandidate.candidateType = ICE_CANDIDATE_TYPE_SERVER_REFLEXIVE;
    localCandidate.state = ICE_CANDIDATE_STATE_NEW;
    result = Ice_CreateNextCandidateRequest( &( context ),
                                             &( localCandidate ),
                                             stunMessageBuffer,
                                             &stunMessageBufferLength );

    TEST_ASSERT_EQUAL( STUN_RESULT_OK,
                       result );
    TEST_ASSERT_EQUAL( expectedStunMessageLength,
                       stunMessageBufferLength );
    TEST_ASSERT_EQUAL_UINT8_ARRAY( &( expectedStunMessage[ 0 ] ),
                                   &( stunMessageBuffer[ 0 ] ),
                                   expectedStunMessageLength );
}

/*-----------------------------------------------------------*/

/**
 * @brief Tests that Ice_CreateNextCandidateRequest get failure while
 * using random function to generate transaction ID.
 */
void test_iceCreateNextCandidateRequest_NewSrflxCandidate_RandomFail( void )
{
    IceContext_t context = { 0 };
    IceCandidate_t localCandidate;
    IceResult_t result;
    uint8_t stunMessageBuffer[ 32 ];
    size_t stunMessageBufferLength = 32;

    result = Ice_Init( &( context ),
                       &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       result );

    /* Ice uses random to generate tie breaker. So we overwrite it after init. */
    context.cryptoFunctions.randomFxn = testRandomFxn_Wrong;

    memset( &localCandidate, 0, sizeof( IceCandidate_t ) );
    localCandidate.candidateType = ICE_CANDIDATE_TYPE_SERVER_REFLEXIVE;
    localCandidate.state = ICE_CANDIDATE_STATE_NEW;
    result = Ice_CreateNextCandidateRequest( &( context ),
                                             &( localCandidate ),
                                             stunMessageBuffer,
                                             &stunMessageBufferLength );

    TEST_ASSERT_EQUAL( ICE_RESULT_RANDOM_GENERATION_ERROR,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Tests that Ice_CreateNextCandidateRequest get failure while
 * inserting transaction ID into transaction ID store.
 */
void test_iceCreateNextCandidateRequest_NewSrflxCandidate_TransactionIdStoreFull( void )
{
    IceContext_t context = { 0 };
    IceCandidate_t localCandidate;
    IceResult_t result;
    uint8_t stunMessageBuffer[ 32 ];
    size_t stunMessageBufferLength = 32;

    result = Ice_Init( &( context ),
                       &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       result );

    /* Make transaction ID store full. */
    for( int i = 0; i < TRANSACTION_ID_SLOTS_ARRAY_ARRAY_SIZE; i++ )
    {
        transactionIdStore.pTransactionIdSlots[ i ].inUse = 1;
    }

    memset( &localCandidate, 0, sizeof( IceCandidate_t ) );
    localCandidate.candidateType = ICE_CANDIDATE_TYPE_SERVER_REFLEXIVE;
    localCandidate.state = ICE_CANDIDATE_STATE_NEW;
    context.cryptoFunctions.randomFxn( localCandidate.transactionId, sizeof( localCandidate.transactionId ) );
    result = Ice_CreateNextCandidateRequest( &( context ),
                                             &( localCandidate ),
                                             stunMessageBuffer,
                                             &stunMessageBufferLength );

    TEST_ASSERT_EQUAL( ICE_RESULT_TRANSACTION_ID_STORE_ERROR,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Tests that Ice_CreateNextCandidateRequest get failure while
 * the buffer is too small to initialize STUN message.
 */
void test_iceCreateNextCandidateRequest_NewSrflxCandidate_StunBufferTooSmallToInit( void )
{
    IceContext_t context = { 0 };
    IceCandidate_t localCandidate;
    IceResult_t result;
    uint8_t stunMessageBuffer[ 10 ];
    size_t stunMessageBufferLength = sizeof( stunMessageBuffer );

    result = Ice_Init( &( context ),
                       &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       result );

    memset( &localCandidate, 0, sizeof( IceCandidate_t ) );
    localCandidate.candidateType = ICE_CANDIDATE_TYPE_SERVER_REFLEXIVE;
    localCandidate.state = ICE_CANDIDATE_STATE_NEW;
    result = Ice_CreateNextCandidateRequest( &( context ),
                                             &( localCandidate ),
                                             stunMessageBuffer,
                                             &stunMessageBufferLength );

    TEST_ASSERT_EQUAL( ICE_RESULT_STUN_ERROR,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Tests that Ice_CreateNextCandidateRequest returns
 * BINDING_REQUEST STUN message to query IP address for new
 * srflx candidate and the transport ID already exists in
 * transaction ID store.
 */
void test_iceCreateNextCandidateRequest_NewSrflxCandidate_ReuseTransactionID( void )
{
    IceContext_t context = { 0 };
    IceCandidate_t localCandidate;
    IceResult_t result;
    uint8_t stunMessageBuffer[ 32 ];
    size_t stunMessageBufferLength = 32;
    uint8_t transactionID[] =
    {
        0xFF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B
    };
    uint8_t expectedStunMessage[] =
    {
        /* STUN header: Message Type = Binding Request (0x0001), Length = 8 bytes (excluding 20 bytes header). */
        0x00, 0x01, 0x00, 0x08,
        /* Magic Cookie (0x2112A442). */
        0x21, 0x12, 0xA4, 0x42,
        /* 12 bytes (96 bits) transaction ID set in transactionID. */
        0xFF, 0x01, 0x02, 0x03,
        0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B,
        /* Attribute type = FINGERPRINT (0x8028), Length = 4 bytes. */
        0x80, 0x28, 0x00, 0x04,
        /* Attribute Value: 0x141CC362 as calculated by testCrc32Fxn. */
        0x62, 0xC3, 0x1C, 0x14,
    };
    size_t expectedStunMessageLength = sizeof( expectedStunMessage );

    result = Ice_Init( &( context ),
                       &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       result );

    transactionIdStore.pTransactionIdSlots[ 0 ].inUse = 1;
    memcpy( &( transactionIdStore.pTransactionIdSlots[ 0 ].transactionId[ 0 ] ),
            &( transactionID[ 0 ] ),
            sizeof( transactionID ) );

    memset( &localCandidate, 0, sizeof( IceCandidate_t ) );
    localCandidate.candidateType = ICE_CANDIDATE_TYPE_SERVER_REFLEXIVE;
    localCandidate.state = ICE_CANDIDATE_STATE_NEW;
    memcpy( &( localCandidate.transactionId[ 0 ] ),
            &( transactionID[ 0 ] ),
            sizeof( transactionID ) );
    result = Ice_CreateNextCandidateRequest( &( context ),
                                             &( localCandidate ),
                                             stunMessageBuffer,
                                             &stunMessageBufferLength );

    TEST_ASSERT_EQUAL( STUN_RESULT_OK,
                       result );
    TEST_ASSERT_EQUAL( expectedStunMessageLength,
                       stunMessageBufferLength );
    TEST_ASSERT_EQUAL_UINT8_ARRAY( &( expectedStunMessage[ 0 ] ),
                                   &( stunMessageBuffer[ 0 ] ),
                                   expectedStunMessageLength );
}

/*-----------------------------------------------------------*/

/**
 * @brief Tests that Ice_CreateNextCandidateRequest returns
 * ICE_RESULT_NO_NEXT_ACTION when a srflx candidate already
 * have the address.
 */
void test_iceCreateNextCandidateRequest_SrflxCandidateAlreadyValid( void )
{
    IceContext_t context = { 0 };
    IceCandidate_t localCandidate;
    IceResult_t result;
    uint8_t stunMessageBuffer[ 32 ];
    size_t stunMessageBufferLength = 32;

    result = Ice_Init( &( context ),
                       &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       result );

    memset( &localCandidate, 0, sizeof( IceCandidate_t ) );
    localCandidate.candidateType = ICE_CANDIDATE_TYPE_SERVER_REFLEXIVE;
    localCandidate.state = ICE_CANDIDATE_STATE_VALID;
    result = Ice_CreateNextCandidateRequest( &( context ),
                                             &( localCandidate ),
                                             stunMessageBuffer,
                                             &stunMessageBufferLength );

    TEST_ASSERT_EQUAL( ICE_RESULT_NO_NEXT_ACTION,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Tests that Ice_CreateNextCandidateRequest returns
 * ICE_RESULT_NO_NEXT_ACTION when it's a host candidate.
 */
void test_iceCreateNextCandidateRequest_HostCandidateNoNextAction( void )
{
    IceContext_t context = { 0 };
    IceCandidate_t localCandidate;
    IceResult_t result;
    uint8_t stunMessageBuffer[ 32 ];
    size_t stunMessageBufferLength = 32;

    result = Ice_Init( &( context ),
                       &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       result );

    memset( &localCandidate, 0, sizeof( IceCandidate_t ) );
    localCandidate.candidateType = ICE_CANDIDATE_TYPE_HOST;
    localCandidate.state = ICE_CANDIDATE_STATE_VALID;
    result = Ice_CreateNextCandidateRequest( &( context ),
                                             &( localCandidate ),
                                             stunMessageBuffer,
                                             &stunMessageBufferLength );

    TEST_ASSERT_EQUAL( ICE_RESULT_NO_NEXT_ACTION,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Tests that Ice_CreateNextCandidateRequest returns
 * ALLOCATE_REQUEST when it's a relay candidate asking for
 * allocation. Note that username, realm, nonce are all set
 * in the candidate.
 */
void test_iceCreateNextCandidateRequest_RelayCandidateAllocating_WithAllInfo_Success( void )
{
    IceContext_t context = { 0 };
    IceCandidate_t localCandidate;
    IceResult_t result;
    char * pUsername = "username";
    size_t usernameLength = strlen( pUsername );
    char * pPassword = "password";
    size_t passwordLength = strlen( pPassword );
    char * pRealm = "realm";
    size_t realmLength = strlen( pRealm );
    char * pNonce = "nonce";
    size_t nonceLength = strlen( pNonce );
    uint8_t stunMessageBuffer[ 104 ];
    size_t stunMessageBufferLength = 104;
    uint8_t expectedStunMessage[] =
    {
        /* STUN header: Message Type = Allocate Request (0x0003), Length = 84 bytes (excluding 20 bytes header). */
        0x00, 0x03, 0x00, 0x54,
        /* Magic Cookie (0x2112A442). */
        0x21, 0x12, 0xA4, 0x42,
        /* 12 bytes (96 bits) transaction ID as generated by testRandomFxn. */
        0x00, 0x01, 0x02, 0x03,
        0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B,
        /* Attribute type = LIFETIME (0x000D), Length = 4 bytes. */
        0x00, 0x0D, 0x00, 0x04,
        /* Attribute Value: 600 as ICE_DEFAULT_TURN_ALLOCATION_LIFETIME_SECONDS. */
        0x00, 0x00, 0x02, 0x58,
        /* Attribute type = REQUESTED_TRANSPORT (0x0019), Length = 4 bytes. */
        0x00, 0x19, 0x00, 0x04,
        /* Attribute Value: 0x11 as UDP. */
        0x11, 0x00, 0x00, 0x00,
        /* Attribute type = USERNAME (0x0006), Length = 8 bytes. */
        0x00, 0x06, 0x00, 0x08,
        /* Attribute Value: "username". */
        0x75, 0x73, 0x65, 0x72,
        0x6E, 0x61, 0x6D, 0x65,
        /* Attribute type = REALM (0x0014), Length = 5 bytes. */
        0x00, 0x14, 0x00, 0x05,
        /* Attribute Value: "realm". */
        0x72, 0x65, 0x61, 0x6C,
        0x6D, 0x00, 0x00, 0x00,
        /* Attribute type = NONCE (0x0015), Length = 5 bytes. */
        0x00, 0x15, 0x00, 0x05,
        /* Attribute Value: "nonce". */
        0x6E, 0x6F, 0x6E, 0x63,
        0x65, 0x00, 0x00, 0x00,
        /* Attribute type = MESSAGE-INTEGRITY (0x0008), Length = 20 bytes. */
        0x00, 0x08, 0x00, 0x14,
        /* Attribute Value = HMAC value as computed by testHmacFxn. */
        0x70, 0x62, 0x73, 0x3F,
        0x56, 0x7D, 0xD6, 0x26,
        0x70, 0x60, 0x71, 0x70,
        0x73, 0x6A, 0x74, 0x63,
        0x78, 0x68, 0x79, 0x78,
        /* Attribute type = FINGERPRINT (0x8028), Length = 4 bytes. */
        0x80, 0x28, 0x00, 0x04,
        /* Attribute Value: 0x6FEDB996 as calculated by testCrc32Fxn. */
        0x96, 0xB9, 0xED, 0x6F,
    };
    size_t expectedStunMessageLength = sizeof( expectedStunMessage );

    result = Ice_Init( &( context ),
                       &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       result );

    memset( &localCandidate, 0, sizeof( IceCandidate_t ) );
    localCandidate.candidateType = ICE_CANDIDATE_TYPE_RELAY;
    localCandidate.state = ICE_CANDIDATE_STATE_ALLOCATING;
    context.numRelayExtensions = 1;
    localCandidate.pRelayExtension = &context.pRelayExtensionsArray[ 0 ];
    memcpy( &localCandidate.pRelayExtension->iceRelayServerInfo.userName, pUsername, usernameLength );
    localCandidate.pRelayExtension->iceRelayServerInfo.userNameLength = usernameLength;
    memcpy( &localCandidate.pRelayExtension->iceRelayServerInfo.longTermPassword, pPassword, passwordLength );
    localCandidate.pRelayExtension->iceRelayServerInfo.longTermPasswordLength = passwordLength;
    memcpy( &localCandidate.pRelayExtension->iceRelayServerInfo.realm, pRealm, realmLength );
    localCandidate.pRelayExtension->iceRelayServerInfo.realmLength = realmLength;
    memcpy( &localCandidate.pRelayExtension->iceRelayServerInfo.nonce, pNonce, nonceLength );
    localCandidate.pRelayExtension->iceRelayServerInfo.nonceLength = nonceLength;
    ( void ) context.cryptoFunctions.randomFxn( &localCandidate.transactionId[ 0 ], STUN_HEADER_TRANSACTION_ID_LENGTH );
    result = Ice_CreateNextCandidateRequest( &( context ),
                                             &( localCandidate ),
                                             stunMessageBuffer,
                                             &stunMessageBufferLength );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       result );
    TEST_ASSERT_EQUAL( expectedStunMessageLength,
                       stunMessageBufferLength );
    TEST_ASSERT_EQUAL_UINT8_ARRAY( &( expectedStunMessage[ 0 ] ),
                                   &( stunMessageBuffer[ 0 ] ),
                                   expectedStunMessageLength );
}

/*-----------------------------------------------------------*/

/**
 * @brief Tests that Ice_CreateNextCandidateRequest returns
 * ALLOCATE_REQUEST when it's a relay candidate asking for
 * allocation. Note that username, realm, nonce are all unset
 * in the candidate.
 */
void test_iceCreateNextCandidateRequest_RelayCandidateAllocating_MissInfo_Success( void )
{
    IceContext_t context = { 0 };
    IceCandidate_t localCandidate;
    IceResult_t result;
    uint8_t stunMessageBuffer[ 44 ];
    size_t stunMessageBufferLength = 44;
    uint8_t expectedStunMessage[] =
    {
        /* STUN header: Message Type = Allocate Request (0x0003), Length = 24 bytes (excluding 20 bytes header). */
        0x00, 0x03, 0x00, 0x18,
        /* Magic Cookie (0x2112A442). */
        0x21, 0x12, 0xA4, 0x42,
        /* 12 bytes (96 bits) transaction ID as generated by testRandomFxn. */
        0x00, 0x01, 0x02, 0x03,
        0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B,
        /* Attribute type = LIFETIME (0x000D), Length = 4 bytes. */
        0x00, 0x0D, 0x00, 0x04,
        /* Attribute Value: 600 as ICE_DEFAULT_TURN_ALLOCATION_LIFETIME_SECONDS. */
        0x00, 0x00, 0x02, 0x58,
        /* Attribute type = REQUESTED_TRANSPORT (0x0019), Length = 4 bytes. */
        0x00, 0x19, 0x00, 0x04,
        /* Attribute Value: 0x11 as UDP. */
        0x11, 0x00, 0x00, 0x00,
        /* Attribute type = FINGERPRINT (0x8028), Length = 4 bytes. */
        0x80, 0x28, 0x00, 0x04,
        /* Attribute Value: 0x76E83E99 as calculated by testCrc32Fxn. */
        0x99, 0x3E, 0xE8, 0x76,
    };
    size_t expectedStunMessageLength = sizeof( expectedStunMessage );

    result = Ice_Init( &( context ),
                       &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       result );

    memset( &localCandidate, 0, sizeof( IceCandidate_t ) );
    localCandidate.candidateType = ICE_CANDIDATE_TYPE_RELAY;
    localCandidate.state = ICE_CANDIDATE_STATE_ALLOCATING;
    context.numRelayExtensions = 1;
    localCandidate.pRelayExtension = &context.pRelayExtensionsArray[ 0 ];
    ( void ) context.cryptoFunctions.randomFxn( &localCandidate.transactionId[ 0 ], STUN_HEADER_TRANSACTION_ID_LENGTH );
    result = Ice_CreateNextCandidateRequest( &( context ),
                                             &( localCandidate ),
                                             stunMessageBuffer,
                                             &stunMessageBufferLength );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       result );
    TEST_ASSERT_EQUAL( expectedStunMessageLength,
                       stunMessageBufferLength );
    TEST_ASSERT_EQUAL_UINT8_ARRAY( &( expectedStunMessage[ 0 ] ),
                                   &( stunMessageBuffer[ 0 ] ),
                                   expectedStunMessageLength );
}

/*-----------------------------------------------------------*/

/**
 * @brief Tests that Ice_CreateNextCandidateRequest returns
 * ICE_RESULT_NULL_RELAY_EXTENSION when it fail to generate allocate request
 * because of missing relay extension buffer.
 */
void test_iceCreateNextCandidateRequest_RelayCandidateAllocating_NoRelayExtension( void )
{
    IceContext_t context = { 0 };
    IceCandidate_t localCandidate;
    IceResult_t result;
    uint8_t stunMessageBuffer[ 2 ];
    size_t stunMessageBufferLength = sizeof( stunMessageBuffer );

    result = Ice_Init( &( context ),
                       &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       result );

    memset( &localCandidate, 0, sizeof( IceCandidate_t ) );
    localCandidate.candidateType = ICE_CANDIDATE_TYPE_RELAY;
    localCandidate.state = ICE_CANDIDATE_STATE_ALLOCATING;
    localCandidate.pRelayExtension = NULL;
    result = Ice_CreateNextCandidateRequest( &( context ),
                                             &( localCandidate ),
                                             stunMessageBuffer,
                                             &stunMessageBufferLength );

    TEST_ASSERT_EQUAL( ICE_RESULT_NULL_RELAY_EXTENSION,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Tests that Ice_CreateNextCandidateRequest returns
 * ICE_RESULT_STUN_ERROR when it fail to generate allocate request
 * because the buffer is too small for STUN header.
 */
void test_iceCreateNextCandidateRequest_RelayCandidateAllocating_StunBufferTooSmallToInit( void )
{
    IceContext_t context = { 0 };
    IceCandidate_t localCandidate;
    IceResult_t result;
    uint8_t stunMessageBuffer[ 2 ];
    size_t stunMessageBufferLength = sizeof( stunMessageBuffer );

    result = Ice_Init( &( context ),
                       &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       result );

    memset( &localCandidate, 0, sizeof( IceCandidate_t ) );
    localCandidate.candidateType = ICE_CANDIDATE_TYPE_RELAY;
    localCandidate.state = ICE_CANDIDATE_STATE_ALLOCATING;
    context.numRelayExtensions = 1;
    localCandidate.pRelayExtension = &context.pRelayExtensionsArray[ 0 ];
    result = Ice_CreateNextCandidateRequest( &( context ),
                                             &( localCandidate ),
                                             stunMessageBuffer,
                                             &stunMessageBufferLength );

    TEST_ASSERT_EQUAL( ICE_RESULT_STUN_ERROR,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Tests that Ice_CreateNextCandidateRequest returns
 * ICE_RESULT_STUN_ERROR when it fail to generate allocate request
 * because the buffer is too small for adding life time.
 */
void test_iceCreateNextCandidateRequest_RelayCandidateAllocating_StunBufferTooSmallToAddLifeTime( void )
{
    IceContext_t context = { 0 };
    IceCandidate_t localCandidate;
    IceResult_t result;
    uint8_t stunMessageBuffer[ 20 ];
    size_t stunMessageBufferLength = sizeof( stunMessageBuffer );

    result = Ice_Init( &( context ),
                       &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       result );

    memset( &localCandidate, 0, sizeof( IceCandidate_t ) );
    localCandidate.candidateType = ICE_CANDIDATE_TYPE_RELAY;
    localCandidate.state = ICE_CANDIDATE_STATE_ALLOCATING;
    context.numRelayExtensions = 1;
    localCandidate.pRelayExtension = &context.pRelayExtensionsArray[ 0 ];
    result = Ice_CreateNextCandidateRequest( &( context ),
                                             &( localCandidate ),
                                             stunMessageBuffer,
                                             &stunMessageBufferLength );

    TEST_ASSERT_EQUAL( ICE_RESULT_STUN_ERROR_ADD_LIFETIME,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Tests that Ice_CreateNextCandidateRequest returns
 * ICE_RESULT_STUN_ERROR when it fail to generate allocate request
 * because the buffer is too small for adding requested transport.
 */
void test_iceCreateNextCandidateRequest_RelayCandidateAllocating_StunBufferTooSmallToAddRequestedTransport( void )
{
    IceContext_t context = { 0 };
    IceCandidate_t localCandidate;
    IceResult_t result;
    uint8_t stunMessageBuffer[ 28 ];
    size_t stunMessageBufferLength = sizeof( stunMessageBuffer );

    result = Ice_Init( &( context ),
                       &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       result );

    memset( &localCandidate, 0, sizeof( IceCandidate_t ) );
    localCandidate.candidateType = ICE_CANDIDATE_TYPE_RELAY;
    localCandidate.state = ICE_CANDIDATE_STATE_ALLOCATING;
    context.numRelayExtensions = 1;
    localCandidate.pRelayExtension = &context.pRelayExtensionsArray[ 0 ];
    ( void ) context.cryptoFunctions.randomFxn( &localCandidate.transactionId[ 0 ], STUN_HEADER_TRANSACTION_ID_LENGTH );
    result = Ice_CreateNextCandidateRequest( &( context ),
                                             &( localCandidate ),
                                             stunMessageBuffer,
                                             &stunMessageBufferLength );

    TEST_ASSERT_EQUAL( ICE_RESULT_STUN_ERROR_ADD_REQUESTED_TRANSPORT,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Tests that Ice_CreateNextCandidateRequest returns
 * ICE_RESULT_STUN_ERROR when it fail to generate allocate request
 * because the buffer is too small for adding username.
 */
void test_iceCreateNextCandidateRequest_RelayCandidateAllocating_StunBufferTooSmallToAddUserName( void )
{
    IceContext_t context = { 0 };
    IceCandidate_t localCandidate;
    IceResult_t result;
    uint8_t stunMessageBuffer[ 36 ];
    size_t stunMessageBufferLength = sizeof( stunMessageBuffer );
    char * pUsername = "username";
    size_t usernameLength = strlen( pUsername );
    char * pPassword = "password";
    size_t passwordLength = strlen( pPassword );
    char * pRealm = "realm";
    size_t realmLength = strlen( pRealm );
    char * pNonce = "nonce";
    size_t nonceLength = strlen( pNonce );

    result = Ice_Init( &( context ),
                       &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       result );

    memset( &localCandidate, 0, sizeof( IceCandidate_t ) );
    localCandidate.candidateType = ICE_CANDIDATE_TYPE_RELAY;
    localCandidate.state = ICE_CANDIDATE_STATE_ALLOCATING;
    context.numRelayExtensions = 1;
    localCandidate.pRelayExtension = &context.pRelayExtensionsArray[ 0 ];
    ( void ) context.cryptoFunctions.randomFxn( &localCandidate.transactionId[ 0 ], STUN_HEADER_TRANSACTION_ID_LENGTH );
    memcpy( &localCandidate.pRelayExtension->iceRelayServerInfo.userName, pUsername, usernameLength );
    localCandidate.pRelayExtension->iceRelayServerInfo.userNameLength = usernameLength;
    memcpy( &localCandidate.pRelayExtension->iceRelayServerInfo.longTermPassword, pPassword, passwordLength );
    localCandidate.pRelayExtension->iceRelayServerInfo.longTermPasswordLength = passwordLength;
    memcpy( &localCandidate.pRelayExtension->iceRelayServerInfo.realm, pRealm, realmLength );
    localCandidate.pRelayExtension->iceRelayServerInfo.realmLength = realmLength;
    memcpy( &localCandidate.pRelayExtension->iceRelayServerInfo.nonce, pNonce, nonceLength );
    localCandidate.pRelayExtension->iceRelayServerInfo.nonceLength = nonceLength;
    result = Ice_CreateNextCandidateRequest( &( context ),
                                             &( localCandidate ),
                                             stunMessageBuffer,
                                             &stunMessageBufferLength );

    TEST_ASSERT_EQUAL( ICE_RESULT_STUN_ERROR_ADD_USERNAME,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Tests that Ice_CreateNextCandidateRequest returns
 * ICE_RESULT_STUN_ERROR when it fail to generate allocate request
 * because the buffer is too small for adding realm.
 */
void test_iceCreateNextCandidateRequest_RelayCandidateAllocating_StunBufferTooSmallToAddRealm( void )
{
    IceContext_t context = { 0 };
    IceCandidate_t localCandidate;
    IceResult_t result;
    uint8_t stunMessageBuffer[ 48 ];
    size_t stunMessageBufferLength = sizeof( stunMessageBuffer );
    char * pUsername = "username";
    size_t usernameLength = strlen( pUsername );
    char * pPassword = "password";
    size_t passwordLength = strlen( pPassword );
    char * pRealm = "realm";
    size_t realmLength = strlen( pRealm );
    char * pNonce = "nonce";
    size_t nonceLength = strlen( pNonce );

    result = Ice_Init( &( context ),
                       &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       result );

    memset( &localCandidate, 0, sizeof( IceCandidate_t ) );
    localCandidate.candidateType = ICE_CANDIDATE_TYPE_RELAY;
    localCandidate.state = ICE_CANDIDATE_STATE_ALLOCATING;
    context.numRelayExtensions = 1;
    localCandidate.pRelayExtension = &context.pRelayExtensionsArray[ 0 ];
    ( void ) context.cryptoFunctions.randomFxn( &localCandidate.transactionId[ 0 ], STUN_HEADER_TRANSACTION_ID_LENGTH );
    memcpy( &localCandidate.pRelayExtension->iceRelayServerInfo.userName, pUsername, usernameLength );
    localCandidate.pRelayExtension->iceRelayServerInfo.userNameLength = usernameLength;
    memcpy( &localCandidate.pRelayExtension->iceRelayServerInfo.longTermPassword, pPassword, passwordLength );
    localCandidate.pRelayExtension->iceRelayServerInfo.longTermPasswordLength = passwordLength;
    memcpy( &localCandidate.pRelayExtension->iceRelayServerInfo.realm, pRealm, realmLength );
    localCandidate.pRelayExtension->iceRelayServerInfo.realmLength = realmLength;
    memcpy( &localCandidate.pRelayExtension->iceRelayServerInfo.nonce, pNonce, nonceLength );
    localCandidate.pRelayExtension->iceRelayServerInfo.nonceLength = nonceLength;
    result = Ice_CreateNextCandidateRequest( &( context ),
                                             &( localCandidate ),
                                             stunMessageBuffer,
                                             &stunMessageBufferLength );

    TEST_ASSERT_EQUAL( ICE_RESULT_STUN_ERROR_ADD_REALM,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Tests that Ice_CreateNextCandidateRequest returns
 * ICE_RESULT_STUN_ERROR when it fail to generate allocate request
 * because the buffer is too small for adding nonce.
 */
void test_iceCreateNextCandidateRequest_RelayCandidateAllocating_StunBufferTooSmallToAddNonce( void )
{
    IceContext_t context = { 0 };
    IceCandidate_t localCandidate;
    IceResult_t result;
    uint8_t stunMessageBuffer[ 60 ];
    size_t stunMessageBufferLength = sizeof( stunMessageBuffer );
    char * pUsername = "username";
    size_t usernameLength = strlen( pUsername );
    char * pPassword = "password";
    size_t passwordLength = strlen( pPassword );
    char * pRealm = "realm";
    size_t realmLength = strlen( pRealm );
    char * pNonce = "nonce";
    size_t nonceLength = strlen( pNonce );

    result = Ice_Init( &( context ),
                       &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       result );

    memset( &localCandidate, 0, sizeof( IceCandidate_t ) );
    localCandidate.candidateType = ICE_CANDIDATE_TYPE_RELAY;
    localCandidate.state = ICE_CANDIDATE_STATE_ALLOCATING;
    context.numRelayExtensions = 1;
    localCandidate.pRelayExtension = &context.pRelayExtensionsArray[ 0 ];
    ( void ) context.cryptoFunctions.randomFxn( &localCandidate.transactionId[ 0 ], STUN_HEADER_TRANSACTION_ID_LENGTH );
    memcpy( &localCandidate.pRelayExtension->iceRelayServerInfo.userName, pUsername, usernameLength );
    localCandidate.pRelayExtension->iceRelayServerInfo.userNameLength = usernameLength;
    memcpy( &localCandidate.pRelayExtension->iceRelayServerInfo.longTermPassword, pPassword, passwordLength );
    localCandidate.pRelayExtension->iceRelayServerInfo.longTermPasswordLength = passwordLength;
    memcpy( &localCandidate.pRelayExtension->iceRelayServerInfo.realm, pRealm, realmLength );
    localCandidate.pRelayExtension->iceRelayServerInfo.realmLength = realmLength;
    memcpy( &localCandidate.pRelayExtension->iceRelayServerInfo.nonce, pNonce, nonceLength );
    localCandidate.pRelayExtension->iceRelayServerInfo.nonceLength = nonceLength;
    result = Ice_CreateNextCandidateRequest( &( context ),
                                             &( localCandidate ),
                                             stunMessageBuffer,
                                             &stunMessageBufferLength );

    TEST_ASSERT_EQUAL( ICE_RESULT_STUN_ERROR_ADD_NONCE,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Tests that Ice_CreateNextCandidateRequest returns
 * ALLOCATE_REQUEST when it's a relay candidate asking for
 * allocation. Note the transaction ID is set in the store,
 * so it reuses same ID this time.
 */
void test_iceCreateNextCandidateRequest_RelayCandidateAllocating_ReuseTransactionID_Success( void )
{
    IceContext_t context = { 0 };
    IceCandidate_t localCandidate;
    IceResult_t result;
    uint8_t stunMessageBuffer[ 44 ];
    size_t stunMessageBufferLength = 44;
    uint8_t transactionID[] =
    {
        0xFF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B
    };
    uint8_t expectedStunMessage[] =
    {
        /* STUN header: Message Type = Allocate Request (0x0003), Length = 24 bytes (excluding 20 bytes header). */
        0x00, 0x03, 0x00, 0x18,
        /* Magic Cookie (0x2112A442). */
        0x21, 0x12, 0xA4, 0x42,
        /* 12 bytes (96 bits) transaction ID as set in transactionID. */
        0xFF, 0x01, 0x02, 0x03,
        0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B,
        /* Attribute type = LIFETIME (0x000D), Length = 4 bytes. */
        0x00, 0x0D, 0x00, 0x04,
        /* Attribute Value: 600 as ICE_DEFAULT_TURN_ALLOCATION_LIFETIME_SECONDS. */
        0x00, 0x00, 0x02, 0x58,
        /* Attribute type = REQUESTED_TRANSPORT (0x0019), Length = 4 bytes. */
        0x00, 0x19, 0x00, 0x04,
        /* Attribute Value: 0x11 as UDP. */
        0x11, 0x00, 0x00, 0x00,
        /* Attribute type = FINGERPRINT (0x8028), Length = 4 bytes. */
        0x80, 0x28, 0x00, 0x04,
        /* Attribute Value: 0x7D48F90A as calculated by testCrc32Fxn. */
        0x0A, 0xF9, 0x48, 0x7D,
    };
    size_t expectedStunMessageLength = sizeof( expectedStunMessage );

    result = Ice_Init( &( context ),
                       &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       result );

    memset( &localCandidate, 0, sizeof( IceCandidate_t ) );
    localCandidate.candidateType = ICE_CANDIDATE_TYPE_RELAY;
    localCandidate.state = ICE_CANDIDATE_STATE_ALLOCATING;
    context.numRelayExtensions = 1;
    localCandidate.pRelayExtension = &context.pRelayExtensionsArray[ 0 ];
    memcpy( localCandidate.transactionId, transactionID, sizeof( transactionID ) );
    result = Ice_CreateNextCandidateRequest( &( context ),
                                             &( localCandidate ),
                                             stunMessageBuffer,
                                             &stunMessageBufferLength );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       result );
    TEST_ASSERT_EQUAL( expectedStunMessageLength,
                       stunMessageBufferLength );
    TEST_ASSERT_EQUAL_UINT8_ARRAY( &( expectedStunMessage[ 0 ] ),
                                   &( stunMessageBuffer[ 0 ] ),
                                   expectedStunMessageLength );
}

/*-----------------------------------------------------------*/

/**
 * @brief Tests that Ice_CreateNextCandidateRequest returns
 * REFRESH_REQUEST when it's a relay candidate asking for
 * relesing. Note that username, realm, nonce are all set
 * in the candidate.
 */
void test_iceCreateNextCandidateRequest_RelayCandidateReleasing_WithAllInfo_Success( void )
{
    IceContext_t context = { 0 };
    IceCandidate_t localCandidate;
    IceResult_t result;
    char * pUsername = "username";
    size_t usernameLength = strlen( pUsername );
    char * pPassword = "password";
    size_t passwordLength = strlen( pPassword );
    char * pRealm = "realm";
    size_t realmLength = strlen( pRealm );
    char * pNonce = "nonce";
    size_t nonceLength = strlen( pNonce );
    uint8_t stunMessageBuffer[ 96 ];
    size_t stunMessageBufferLength = 96;
    uint8_t expectedStunMessage[] =
    {
        /* STUN header: Message Type = Refresh Request (0x0004), Length = 76 bytes (excluding 20 bytes header). */
        0x00, 0x04, 0x00, 0x4C,
        /* Magic Cookie (0x2112A442). */
        0x21, 0x12, 0xA4, 0x42,
        /* 12 bytes (96 bits) transaction ID as generated by testRandomFxn. */
        0x00, 0x01, 0x02, 0x03,
        0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B,
        /* Attribute type = LIFETIME (0x000D), Length = 4 bytes. */
        0x00, 0x0D, 0x00, 0x04,
        /* Attribute Value: 0 when relesing. */
        0x00, 0x00, 0x00, 0x00,
        /* Attribute type = USERNAME (0x0006), Length = 8 bytes. */
        0x00, 0x06, 0x00, 0x08,
        /* Attribute Value: "username". */
        0x75, 0x73, 0x65, 0x72,
        0x6E, 0x61, 0x6D, 0x65,
        /* Attribute type = REALM (0x0014), Length = 5 bytes. */
        0x00, 0x14, 0x00, 0x05,
        /* Attribute Value: "realm". */
        0x72, 0x65, 0x61, 0x6C,
        0x6D, 0x00, 0x00, 0x00,
        /* Attribute type = NONCE (0x0015), Length = 5 bytes. */
        0x00, 0x15, 0x00, 0x05,
        /* Attribute Value: "nonce". */
        0x6E, 0x6F, 0x6E, 0x63,
        0x65, 0x00, 0x00, 0x00,
        /* Attribute type = MESSAGE-INTEGRITY (0x0008), Length = 20 bytes. */
        0x00, 0x08, 0x00, 0x14,
        /* Attribute Value = HMAC value as computed by testHmacFxn. */
        0x70, 0x65, 0x73, 0x37,
        0x56, 0x7D, 0xD6, 0x26,
        0x70, 0x60, 0x71, 0x70,
        0x73, 0x6A, 0x74, 0x63,
        0x78, 0x68, 0x79, 0x78,
        /* Attribute type = FINGERPRINT (0x8028), Length = 4 bytes. */
        0x80, 0x28, 0x00, 0x04,
        /* Attribute Value: 0xC0ACE0bF as calculated by testCrc32Fxn. */
        0xBF, 0xE0, 0xAC, 0xC0,
    };
    size_t expectedStunMessageLength = sizeof( expectedStunMessage );

    result = Ice_Init( &( context ),
                       &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       result );

    memset( &localCandidate, 0, sizeof( IceCandidate_t ) );
    localCandidate.candidateType = ICE_CANDIDATE_TYPE_RELAY;
    localCandidate.state = ICE_CANDIDATE_STATE_RELEASING;
    context.numRelayExtensions = 1;
    localCandidate.pRelayExtension = &context.pRelayExtensionsArray[ 0 ];
    ( void ) context.cryptoFunctions.randomFxn( &localCandidate.transactionId[ 0 ], STUN_HEADER_TRANSACTION_ID_LENGTH );
    memcpy( &localCandidate.pRelayExtension->iceRelayServerInfo.userName, pUsername, usernameLength );
    localCandidate.pRelayExtension->iceRelayServerInfo.userNameLength = usernameLength;
    memcpy( &localCandidate.pRelayExtension->iceRelayServerInfo.longTermPassword, pPassword, passwordLength );
    localCandidate.pRelayExtension->iceRelayServerInfo.longTermPasswordLength = passwordLength;
    memcpy( &localCandidate.pRelayExtension->iceRelayServerInfo.realm, pRealm, realmLength );
    localCandidate.pRelayExtension->iceRelayServerInfo.realmLength = realmLength;
    memcpy( &localCandidate.pRelayExtension->iceRelayServerInfo.nonce, pNonce, nonceLength );
    localCandidate.pRelayExtension->iceRelayServerInfo.nonceLength = nonceLength;
    result = Ice_CreateNextCandidateRequest( &( context ),
                                             &( localCandidate ),
                                             stunMessageBuffer,
                                             &stunMessageBufferLength );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       result );
    TEST_ASSERT_EQUAL( expectedStunMessageLength,
                       stunMessageBufferLength );
    TEST_ASSERT_EQUAL_UINT8_ARRAY( &( expectedStunMessage[ 0 ] ),
                                   &( stunMessageBuffer[ 0 ] ),
                                   expectedStunMessageLength );
}

/*-----------------------------------------------------------*/

/**
 * @brief Tests that Ice_CreateNextCandidateRequest returns
 * REFRESH_REQUEST when it's a relay candidate asking for
 * releasing. Note that username, realm, nonce are all unset
 * in the candidate.
 */
void test_iceCreateNextCandidateRequest_RelayCandidateReleasing_MissInfo_Success( void )
{
    IceContext_t context = { 0 };
    IceCandidate_t localCandidate;
    IceResult_t result;
    uint8_t stunMessageBuffer[ 36 ];
    size_t stunMessageBufferLength = 36;
    uint8_t expectedStunMessage[] =
    {
        /* STUN header: Message Type = Refresh Request (0x0004), Length = 16 bytes (excluding 20 bytes header). */
        0x00, 0x04, 0x00, 0x10,
        /* Magic Cookie (0x2112A442). */
        0x21, 0x12, 0xA4, 0x42,
        /* 12 bytes (96 bits) transaction ID as generated by testRandomFxn. */
        0x00, 0x01, 0x02, 0x03,
        0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B,
        /* Attribute type = LIFETIME (0x000D), Length = 4 bytes. */
        0x00, 0x0D, 0x00, 0x04,
        /* Attribute Value: 0 when relesing. */
        0x00, 0x00, 0x00, 0x00,
        /* Attribute type = FINGERPRINT (0x8028), Length = 4 bytes. */
        0x80, 0x28, 0x00, 0x04,
        /* Attribute Value: 0xCF5529ED as calculated by testCrc32Fxn. */
        0xED, 0x29, 0x55, 0xCF,
    };
    size_t expectedStunMessageLength = sizeof( expectedStunMessage );

    result = Ice_Init( &( context ),
                       &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       result );

    memset( &localCandidate, 0, sizeof( IceCandidate_t ) );
    localCandidate.candidateType = ICE_CANDIDATE_TYPE_RELAY;
    localCandidate.state = ICE_CANDIDATE_STATE_RELEASING;
    context.numRelayExtensions = 1;
    localCandidate.pRelayExtension = &context.pRelayExtensionsArray[ 0 ];
    ( void ) context.cryptoFunctions.randomFxn( &localCandidate.transactionId[ 0 ], STUN_HEADER_TRANSACTION_ID_LENGTH );
    result = Ice_CreateNextCandidateRequest( &( context ),
                                             &( localCandidate ),
                                             stunMessageBuffer,
                                             &stunMessageBufferLength );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       result );
    TEST_ASSERT_EQUAL( expectedStunMessageLength,
                       stunMessageBufferLength );
    TEST_ASSERT_EQUAL_UINT8_ARRAY( &( expectedStunMessage[ 0 ] ),
                                   &( stunMessageBuffer[ 0 ] ),
                                   expectedStunMessageLength );
}

/*-----------------------------------------------------------*/

/**
 * @brief Tests that Ice_CreateNextCandidateRequest returns
 * REFRESH_REQUEST when it's a relay candidate asking for
 * releasing. Note the transaction ID is set in the store,
 * so it reuses same ID this time.
 */
void test_iceCreateNextCandidateRequest_RelayCandidateReleasing_ReuseTransactionID_Success( void )
{
    IceContext_t context = { 0 };
    IceCandidate_t localCandidate;
    IceResult_t result;
    uint8_t stunMessageBuffer[ 36 ];
    size_t stunMessageBufferLength = 36;
    uint8_t transactionID[] =
    {
        0xFF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B
    };
    uint8_t expectedStunMessage[] =
    {
        /* STUN header: Message Type = Refresh Request (0x0004), Length = 16 bytes (excluding 20 bytes header). */
        0x00, 0x04, 0x00, 0x10,
        /* Magic Cookie (0x2112A442). */
        0x21, 0x12, 0xA4, 0x42,
        /* 12 bytes (96 bits) transaction ID as set in transactionID. */
        0xFF, 0x01, 0x02, 0x03,
        0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B,
        /* Attribute type = LIFETIME (0x000D), Length = 4 bytes. */
        0x00, 0x0D, 0x00, 0x04,
        /* Attribute Value: 600 as ICE_DEFAULT_TURN_ALLOCATION_LIFETIME_SECONDS. */
        0x00, 0x00, 0x00, 0x00,
        /* Attribute type = FINGERPRINT (0x8028), Length = 4 bytes. */
        0x80, 0x28, 0x00, 0x04,
        /* Attribute Value: 0xFA3E8535 as calculated by testCrc32Fxn. */
        0x35, 0x85, 0x3E, 0xFA,
    };
    size_t expectedStunMessageLength = sizeof( expectedStunMessage );

    result = Ice_Init( &( context ),
                       &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       result );

    memset( &localCandidate, 0, sizeof( IceCandidate_t ) );
    localCandidate.candidateType = ICE_CANDIDATE_TYPE_RELAY;
    localCandidate.state = ICE_CANDIDATE_STATE_RELEASING;
    context.numRelayExtensions = 1;
    localCandidate.pRelayExtension = &context.pRelayExtensionsArray[ 0 ];
    memcpy( localCandidate.transactionId, transactionID, sizeof( transactionID ) );
    result = Ice_CreateNextCandidateRequest( &( context ),
                                             &( localCandidate ),
                                             stunMessageBuffer,
                                             &stunMessageBufferLength );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       result );
    TEST_ASSERT_EQUAL( expectedStunMessageLength,
                       stunMessageBufferLength );
    TEST_ASSERT_EQUAL_UINT8_ARRAY( &( expectedStunMessage[ 0 ] ),
                                   &( stunMessageBuffer[ 0 ] ),
                                   expectedStunMessageLength );
}

/*-----------------------------------------------------------*/

/**
 * @brief Tests that Ice_CreateNextCandidateRequest returns
 * failure when it's a relay candidate asking for releasing
 * but relay extension is NULL.
 */
void test_iceCreateNextCandidateRequest_RelayCandidateReleasing_NoRelayExtension( void )
{
    IceContext_t context = { 0 };
    IceCandidate_t localCandidate;
    IceResult_t result;
    uint8_t stunMessageBuffer[ 36 ];
    size_t stunMessageBufferLength = 36;

    result = Ice_Init( &( context ),
                       &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       result );

    memset( &localCandidate, 0, sizeof( IceCandidate_t ) );
    localCandidate.candidateType = ICE_CANDIDATE_TYPE_RELAY;
    localCandidate.state = ICE_CANDIDATE_STATE_RELEASING;
    localCandidate.pRelayExtension = NULL;
    result = Ice_CreateNextCandidateRequest( &( context ),
                                             &( localCandidate ),
                                             stunMessageBuffer,
                                             &stunMessageBufferLength );

    TEST_ASSERT_EQUAL( ICE_RESULT_NULL_RELAY_EXTENSION,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Tests that Ice_CreateNextCandidateRequest returns
 * ICE_RESULT_NO_NEXT_ACTION when it's a relay candidate but
 * it's released.
 */
void test_iceCreateNextCandidateRequest_RelayCandidateReleased_NoNextAction( void )
{
    IceContext_t context = { 0 };
    IceCandidate_t localCandidate;
    IceResult_t result;
    uint8_t stunMessageBuffer[ 36 ];
    size_t stunMessageBufferLength = 36;

    result = Ice_Init( &( context ),
                       &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       result );

    memset( &localCandidate, 0, sizeof( IceCandidate_t ) );
    localCandidate.candidateType = ICE_CANDIDATE_TYPE_RELAY;
    localCandidate.state = ICE_CANDIDATE_STATE_RELEASED;
    context.numRelayExtensions = 1;
    localCandidate.pRelayExtension = &context.pRelayExtensionsArray[ 0 ];
    result = Ice_CreateNextCandidateRequest( &( context ),
                                             &( localCandidate ),
                                             stunMessageBuffer,
                                             &stunMessageBufferLength );

    TEST_ASSERT_EQUAL( ICE_RESULT_NO_NEXT_ACTION,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate Ice_CreateNextPairRequest functionality for Bad Parameters.
 */
void test_iceCreateNextPairRequest_BadParams( void )
{
    IceContext_t context = { 0 };
    IceCandidatePair_t candidatePair;
    uint8_t stunMessageBuffer[ 10 ];
    size_t stunMessageBufferLength = sizeof( stunMessageBuffer );
    IceResult_t result;

    result = Ice_CreateNextPairRequest( NULL,
                                        &( candidatePair ),
                                        stunMessageBuffer,
                                        &( stunMessageBufferLength ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_BAD_PARAM,
                       result );

    result = Ice_CreateNextPairRequest( &( context ),
                                        NULL,
                                        stunMessageBuffer,
                                        &( stunMessageBufferLength ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_BAD_PARAM,
                       result );

    result = Ice_CreateNextPairRequest( &( context ),
                                        &( candidatePair ),
                                        NULL,
                                        &( stunMessageBufferLength ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_BAD_PARAM,
                       result );

    result = Ice_CreateNextPairRequest( &( context ),
                                        &( candidatePair ),
                                        stunMessageBuffer,
                                        NULL );

    TEST_ASSERT_EQUAL( ICE_RESULT_BAD_PARAM,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate Ice_CreateNextPairRequest functionality to
 * generate BINDING_REQUEST for connectivity check.
 */
void test_iceCreateNextPairRequest_Waiting_CreateConnectivityCheckBindingRequest( void )
{
    IceContext_t context = { 0 };
    IceCandidate_t localCandidate = { 0 };
    IceCandidatePair_t candidatePair;
    uint8_t stunMessageBuffer[ 92 ];
    size_t stunMessageBufferLength = sizeof( stunMessageBuffer );
    IceResult_t result;
    uint8_t transactionID[] =
    {
        0xFF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B
    };
    uint8_t expectedStunMessage[] =
    {
        /* STUN header: Message Type = Binding Request (0x0001), Length = 0x48 bytes (excluding 20 bytes header). */
        0x00, 0x01, 0x00, 0x48,
        /* Magic Cookie (0x2112A442). */
        0x21, 0x12, 0xA4, 0x42,
        /* 12 bytes (96 bits) transaction ID as generated by testRandomFxn. */
        0xFF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
        /* Attribute type = USERNAME (0x0006), Length = 16 bytes. */
        0x00, 0x06, 0x00, 0x10,
        /* Attribute Value = "combinedUsername". */
        0x63, 0x6F, 0x6D, 0x62, 0x69, 0x6E, 0x65, 0x64,
        0x55, 0x73, 0x65, 0x72, 0x6E, 0x61, 0x6D, 0x65,
        /* Attribute type = PRIORITY (0x0024), Length = 4 bytes. */
        0x00, 0x24, 0x00, 0x04,
        /* Attribute Value = 1000. */
        0x00, 0x00, 0x03, 0xE8,
        /* Attribute type = ICE-CONTROLLING ( 0x802A ), Length = 8 bytes. */
        0x80, 0x2A, 0x00, 0x08,
        /* Attribute Value = 0x0706050403020100. */
        0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00,
        /* Attribute type = MESSAGE-INTEGRITY (0x0008), Length = 20 bytes. */
        0x00, 0x08, 0x00, 0x14,
        /* Attribute Value = HMAC value as computed by testHmacFxn. */
        0x72, 0x64, 0x6D, 0x2F,
        0x55, 0x77, 0xF4, 0x23,
        0x8C, 0x72, 0x75, 0x6C,
        0x76, 0x61, 0x74, 0x62,
        0x65, 0x66, 0x7E, 0x6E,
        /* Attribute type = FINGERPRINT (0x8028), Length = 4 bytes. */
        0x80, 0x28, 0x00, 0x04,
        /* Attribute Value: 0xE18DFEB1 as calculated by testCrc32Fxn. */
        0xB1, 0xFE, 0x8D, 0xE1
    };
    size_t expectedStunMessageLength = sizeof( expectedStunMessage );

    result = Ice_Init( &( context ),
                       &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       result );

    memset( &localCandidate, 0, sizeof( IceCandidate_t ) );
    localCandidate.priority = 1000;

    memset( &candidatePair, 0, sizeof( IceCandidatePair_t ) );
    candidatePair.state = ICE_CANDIDATE_PAIR_STATE_WAITING;
    candidatePair.pLocalCandidate = &( localCandidate );
    memcpy( candidatePair.transactionId, transactionID, sizeof( transactionID ) );

    result = Ice_CreateNextPairRequest( &( context ),
                                        &( candidatePair ),
                                        stunMessageBuffer,
                                        &( stunMessageBufferLength ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       result );
    TEST_ASSERT_EQUAL( expectedStunMessageLength,
                       stunMessageBufferLength );
    TEST_ASSERT_EQUAL_UINT8_ARRAY( &( expectedStunMessage[ 0 ] ),
                                   &( stunMessageBuffer[ 0 ] ),
                                   expectedStunMessageLength );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate Ice_CreateNextPairRequest functionality to
 * generate BINDING_REQUEST for nomination when the candidate pair
 * is nominated.
 */
void test_iceCreateNextPairRequest_Nominated_ControllingSendNominatingRequest( void )
{
    IceContext_t context = { 0 };
    IceCandidate_t localCandidate = { 0 };
    IceCandidatePair_t candidatePair;
    uint8_t stunMessageBuffer[ 96 ];
    size_t stunMessageBufferLength = sizeof( stunMessageBuffer );
    IceResult_t result;
    uint8_t transactionID[] =
    {
        0xFF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B
    };
    uint8_t expectedStunMessage[] =
    {
        /* STUN header: Message Type = Binding Request (0x0001), Length = 0x4C bytes (excluding 20 bytes header). */
        0x00, 0x01, 0x00, 0x4C,
        /* Magic Cookie (0x2112A442). */
        0x21, 0x12, 0xA4, 0x42,
        /* 12 bytes (96 bits) transaction ID as generated by testRandomFxn. */
        0xFF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
        /* Attribute type = USERNAME (0x0006), Length = 16 bytes. */
        0x00, 0x06, 0x00, 0x10,
        /* Attribute Value = "combinedUsername". */
        0x63, 0x6F, 0x6D, 0x62, 0x69, 0x6E, 0x65, 0x64,
        0x55, 0x73, 0x65, 0x72, 0x6E, 0x61, 0x6D, 0x65,
        /* Attribute type = PRIORITY (0x0024), Length = 4 bytes. */
        0x00, 0x24, 0x00, 0x04,
        /* Attribute Value = 1000. */
        0x00, 0x00, 0x03, 0xE8,
        /* Attribute type = ICE-CONTROLLING ( 0x802A ), Length = 8 bytes. */
        0x80, 0x2A, 0x00, 0x08,
        /* Attribute Value = 0x0706050403020100. */
        0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00,
        /* Attribute Type = USE-CANDIDATE (0x0025), Length = 0 bytes. */
        0x00, 0x25, 0x00, 0x00,
        /* Attribute type = MESSAGE-INTEGRITY (0x0008), Length = 20 bytes. */
        0x00, 0x08, 0x00, 0x14,
        /* Attribute Value = HMAC value as computed by testHmacFxn. */
        0x72, 0x64, 0x6D, 0x2B,
        0x55, 0x77, 0xF4, 0x23,
        0x8C, 0x72, 0x75, 0x6C,
        0x76, 0x61, 0x74, 0x62,
        0x65, 0x66, 0x7E, 0x6E,
        /* Attribute type = FINGERPRINT (0x8028), Length = 4 bytes. */
        0x80, 0x28, 0x00, 0x04,
        /* Attribute Value: 0x3A9F86F5 as calculated by testCrc32Fxn. */
        0xF5, 0x86, 0x9F, 0x3A
    };
    size_t expectedStunMessageLength = sizeof( expectedStunMessage );

    result = Ice_Init( &( context ),
                       &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       result );

    memset( &localCandidate, 0, sizeof( IceCandidate_t ) );
    localCandidate.priority = 1000;

    memset( &candidatePair, 0, sizeof( IceCandidatePair_t ) );
    candidatePair.state = ICE_CANDIDATE_PAIR_STATE_NOMINATED;
    candidatePair.pLocalCandidate = &( localCandidate );
    memcpy( candidatePair.transactionId, transactionID, sizeof( transactionID ) );

    result = Ice_CreateNextPairRequest( &( context ),
                                        &( candidatePair ),
                                        stunMessageBuffer,
                                        &( stunMessageBufferLength ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       result );
    TEST_ASSERT_EQUAL( expectedStunMessageLength,
                       stunMessageBufferLength );
    TEST_ASSERT_EQUAL_UINT8_ARRAY( &( expectedStunMessage[ 0 ] ),
                                   &( stunMessageBuffer[ 0 ] ),
                                   expectedStunMessageLength );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate Ice_CreateNextPairRequest functionality return
 * connectivity check request even when the pair is nominated and the ICE
 * context is controlled agent.
 *
 * Note that the controlled agent might receive USE-CANDIDATE even at
 * connectivity check stage. The state of the pair would be changed to
 * nominated. Thus we have to keep sending connectivity check for that
 * case.
 */
void test_iceCreateNextPairRequest_Nominated_ControlledConnectivityCheckRequest( void )
{
    IceContext_t context = { 0 };
    IceCandidate_t localCandidate = { 0 };
    IceCandidatePair_t candidatePair;
    uint8_t stunMessageBuffer[ 128 ];
    size_t stunMessageBufferLength = sizeof( stunMessageBuffer );
    IceResult_t result;
    uint8_t transactionID[] =
    {
        0xFF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B
    };
    uint8_t expectedStunMessage[] =
    {
        /* STUN header: Message Type = Binding Request (0x0001), Length = 72 bytes (excluding 20 bytes header). */
        0x00, 0x01, 0x00, 0x48,
        /* Magic Cookie (0x2112A442). */
        0x21, 0x12, 0xA4, 0x42,
        /* 12 bytes (96 bits) transaction ID which is same as transactionID. */
        0xFF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
        /* Attribute type = USERNAME (0x0006), Length = 16 bytes. */
        0x00, 0x06, 0x00, 0x10,
        /* Attribute Value = "combinedUsername". */
        0x63, 0x6F, 0x6D, 0x62, 0x69, 0x6E, 0x65, 0x64,
        0x55, 0x73, 0x65, 0x72, 0x6E, 0x61, 0x6D, 0x65,
        /* Attribute type = PRIORITY (0x0024), Length = 4 bytes. */
        0x00, 0x24, 0x00, 0x04,
        /* Attribute Value = 1000. */
        0x00, 0x00, 0x03, 0xE8,
        /* Attribute type = ICE-CONTROLLED (0x8029), Length = 8 bytes. */
        0x80, 0x29, 0x00, 0x08,
        /* Attribute Value = 0x0706050403020100. */
        0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00,
        /* Attribute type = MESSAGE-INTEGRITY (0x0008), Length = 20 bytes. */
        0x00, 0x08, 0x00, 0x14,
        /* Attribute Value = HMAC value as computed by testHmacFxn_FixedFF. */
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        /* Attribute type = FINGERPRINT (0x8028), Length = 4 bytes. */
        0x80, 0x28, 0x00, 0x04,
        /* Attribute Value = 0xB5F5C42F as calculated by testCrc32Fxn_Fixed. */
        0x00, 0x00, 0x00, 0x00
    };
    size_t expectedStunMessageLength = sizeof( expectedStunMessage );

    initInfo.isControlling = 0U;
    /* Set CRC32 function to testCrc32Fxn_Fixed to make fingerprint always 0x00000000 */
    initInfo.cryptoFunctions.crc32Fxn = testCrc32Fxn_Fixed;
    /* Set HMAC function to testHmacFxn_FixedFF to make integrity always 0xFF. */
    initInfo.cryptoFunctions.hmacFxn = testHmacFxn_FixedFF;
    result = Ice_Init( &( context ),
                       &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       result );

    memset( &localCandidate, 0, sizeof( IceCandidate_t ) );
    localCandidate.priority = 1000;

    memset( &candidatePair, 0, sizeof( IceCandidatePair_t ) );
    candidatePair.state = ICE_CANDIDATE_PAIR_STATE_NOMINATED;
    candidatePair.pLocalCandidate = &( localCandidate );
    memcpy( candidatePair.transactionId, transactionID, sizeof( transactionID ) );

    result = Ice_CreateNextPairRequest( &( context ),
                                        &( candidatePair ),
                                        stunMessageBuffer,
                                        &( stunMessageBufferLength ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       result );
    TEST_ASSERT_EQUAL( expectedStunMessageLength,
                       stunMessageBufferLength );
    TEST_ASSERT_EQUAL_UINT8_ARRAY( &( expectedStunMessage[ 0 ] ),
                                   &( stunMessageBuffer[ 0 ] ),
                                   expectedStunMessageLength );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate Ice_CreateNextPairRequest functionality return
 * ICE_RESULT_NO_NEXT_ACTION when the pair is under valid state.
 */
void test_iceCreateNextPairRequest_Valid_NoNextAction( void )
{
    IceContext_t context = { 0 };
    IceCandidate_t localCandidate = { 0 };
    IceCandidatePair_t candidatePair;
    uint8_t stunMessageBuffer[ 96 ];
    size_t stunMessageBufferLength = sizeof( stunMessageBuffer );
    IceResult_t result;

    result = Ice_Init( &( context ),
                       &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       result );

    memset( &localCandidate, 0, sizeof( IceCandidate_t ) );
    localCandidate.priority = 1000;

    memset( &candidatePair, 0, sizeof( IceCandidatePair_t ) );
    candidatePair.state = ICE_CANDIDATE_PAIR_STATE_VALID;
    candidatePair.pLocalCandidate = &( localCandidate );

    result = Ice_CreateNextPairRequest( &( context ),
                                        &( candidatePair ),
                                        stunMessageBuffer,
                                        &( stunMessageBufferLength ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_NO_NEXT_ACTION,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate Ice_CreateNextPairRequest functionality return
 * ICE_RESULT_NO_NEXT_ACTION when there is no refresh timeout expired.
 */
void test_iceCreateNextPairRequest_Succeed_NoRefreshNeeded( void )
{
    IceContext_t context = { 0 };
    IceCandidate_t localCandidate = { 0 };
    IceCandidatePair_t candidatePair;
    uint8_t stunMessageBuffer[ 96 ];
    size_t stunMessageBufferLength = sizeof( stunMessageBuffer );
    IceResult_t result;

    result = Ice_Init( &( context ),
                       &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       result );

    memset( &localCandidate, 0, sizeof( IceCandidate_t ) );
    localCandidate.priority = 1000;
    localCandidate.candidateType = ICE_CANDIDATE_TYPE_RELAY;
    localCandidate.state = ICE_CANDIDATE_STATE_VALID;
    context.numRelayExtensions = 1;
    localCandidate.pRelayExtension = &context.pRelayExtensionsArray[ 0 ];
    localCandidate.pRelayExtension->turnAllocationExpirationSeconds = testGetCurrentTime() + 0xFFFF;

    memset( &candidatePair, 0, sizeof( IceCandidatePair_t ) );
    candidatePair.state = ICE_CANDIDATE_PAIR_STATE_SUCCEEDED;
    candidatePair.pLocalCandidate = &( localCandidate );
    candidatePair.turnPermissionExpirationSeconds = testGetCurrentTime() + 0xFFFF;

    result = Ice_CreateNextPairRequest( &( context ),
                                        &( candidatePair ),
                                        stunMessageBuffer,
                                        &( stunMessageBufferLength ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_NO_NEXT_ACTION,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate Ice_CreateNextPairRequest functionality return
 * ICE_RESULT_INVALID_CANDIDATE_PAIR when local candidate pointer is NULL.
 */
void test_iceCreateNextPairRequest_Succeed_NullLocalCandidate( void )
{
    IceContext_t context = { 0 };
    IceCandidatePair_t candidatePair;
    uint8_t stunMessageBuffer[ 96 ];
    size_t stunMessageBufferLength = sizeof( stunMessageBuffer );
    IceResult_t result;

    result = Ice_Init( &( context ),
                       &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       result );

    memset( &candidatePair, 0, sizeof( IceCandidatePair_t ) );
    candidatePair.state = ICE_CANDIDATE_PAIR_STATE_SUCCEEDED;
    candidatePair.pLocalCandidate = NULL;
    candidatePair.turnPermissionExpirationSeconds = testGetCurrentTime() + 0xFFFF;

    result = Ice_CreateNextPairRequest( &( context ),
                                        &( candidatePair ),
                                        stunMessageBuffer,
                                        &( stunMessageBufferLength ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_INVALID_CANDIDATE_PAIR,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate Ice_CreateNextPairRequest functionality return
 * ICE_RESULT_NO_NEXT_ACTION when pair state is succeeded but local
 * candidate is not relay.
 */
void test_iceCreateNextPairRequest_Succeed_NotRelayCandidate( void )
{
    IceContext_t context = { 0 };
    IceCandidate_t localCandidate = { 0 };
    IceCandidatePair_t candidatePair;
    uint8_t stunMessageBuffer[ 96 ];
    size_t stunMessageBufferLength = sizeof( stunMessageBuffer );
    IceResult_t result;

    result = Ice_Init( &( context ),
                       &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       result );

    memset( &localCandidate, 0, sizeof( IceCandidate_t ) );
    localCandidate.priority = 1000;
    localCandidate.candidateType = ICE_CANDIDATE_TYPE_HOST;
    localCandidate.state = ICE_CANDIDATE_STATE_VALID;

    memset( &candidatePair, 0, sizeof( IceCandidatePair_t ) );
    candidatePair.state = ICE_CANDIDATE_PAIR_STATE_SUCCEEDED;
    candidatePair.pLocalCandidate = &localCandidate;
    candidatePair.turnPermissionExpirationSeconds = testGetCurrentTime() + 0xFFFF;

    result = Ice_CreateNextPairRequest( &( context ),
                                        &( candidatePair ),
                                        stunMessageBuffer,
                                        &( stunMessageBufferLength ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_NO_NEXT_ACTION,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate Ice_CreateNextPairRequest functionality return
 * ICE_RESULT_NO_NEXT_ACTION when pair state is succeeded but local
 * candidate doesn't have relay extension.
 */
void test_iceCreateNextPairRequest_Succeed_NullRelayExtension( void )
{
    IceContext_t context = { 0 };
    IceCandidate_t localCandidate = { 0 };
    IceCandidatePair_t candidatePair;
    uint8_t stunMessageBuffer[ 96 ];
    size_t stunMessageBufferLength = sizeof( stunMessageBuffer );
    IceResult_t result;

    result = Ice_Init( &( context ),
                       &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       result );

    memset( &localCandidate, 0, sizeof( IceCandidate_t ) );
    localCandidate.priority = 1000;
    localCandidate.candidateType = ICE_CANDIDATE_TYPE_RELAY;
    localCandidate.state = ICE_CANDIDATE_STATE_VALID;
    localCandidate.pRelayExtension = NULL;

    memset( &candidatePair, 0, sizeof( IceCandidatePair_t ) );
    candidatePair.state = ICE_CANDIDATE_PAIR_STATE_SUCCEEDED;
    candidatePair.pLocalCandidate = &localCandidate;
    candidatePair.turnPermissionExpirationSeconds = testGetCurrentTime() + 0xFFFF;

    result = Ice_CreateNextPairRequest( &( context ),
                                        &( candidatePair ),
                                        stunMessageBuffer,
                                        &( stunMessageBufferLength ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_NULL_RELAY_EXTENSION,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate Ice_CreateNextPairRequest functionality return
 * ICE_RESULT_NO_NEXT_ACTION when the pair is under frozen state.
 */
void test_iceCreateNextPairRequest_Frozen_NoNextAction( void )
{
    IceContext_t context = { 0 };
    IceCandidate_t localCandidate = { 0 };
    IceCandidatePair_t candidatePair;
    uint8_t stunMessageBuffer[ 96 ];
    size_t stunMessageBufferLength = sizeof( stunMessageBuffer );
    IceResult_t result;

    result = Ice_Init( &( context ),
                       &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       result );

    memset( &localCandidate, 0, sizeof( IceCandidate_t ) );
    localCandidate.priority = 1000;

    memset( &candidatePair, 0, sizeof( IceCandidatePair_t ) );
    candidatePair.state = ICE_CANDIDATE_PAIR_STATE_FROZEN;
    candidatePair.pLocalCandidate = &( localCandidate );

    result = Ice_CreateNextPairRequest( &( context ),
                                        &( candidatePair ),
                                        stunMessageBuffer,
                                        &( stunMessageBufferLength ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_NO_NEXT_ACTION,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate Ice_CreateNextPairRequest functionality return
 * ICE_RESULT_NO_NEXT_ACTION when the pair is under invalid state.
 */
void test_iceCreateNextPairRequest_Invalid_NoNextAction( void )
{
    IceContext_t context = { 0 };
    IceCandidate_t localCandidate = { 0 };
    IceCandidatePair_t candidatePair;
    uint8_t stunMessageBuffer[ 96 ];
    size_t stunMessageBufferLength = sizeof( stunMessageBuffer );
    IceResult_t result;

    result = Ice_Init( &( context ),
                       &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       result );

    memset( &localCandidate, 0, sizeof( IceCandidate_t ) );
    localCandidate.priority = 1000;

    memset( &candidatePair, 0, sizeof( IceCandidatePair_t ) );
    candidatePair.state = ICE_CANDIDATE_PAIR_STATE_INVALID;
    candidatePair.pLocalCandidate = &( localCandidate );

    result = Ice_CreateNextPairRequest( &( context ),
                                        &( candidatePair ),
                                        stunMessageBuffer,
                                        &( stunMessageBufferLength ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_NO_NEXT_ACTION,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate Ice_CreateNextPairRequest functionality returns
 * ICE_RESULT_BAD_PARAM when the local candidate pointer is NULL in
 * candidate pair and the state is create permission.
 */
void test_iceCreateNextPairRequest_CreatePermission_NullLocalCandidate( void )
{
    IceContext_t context = { 0 };
    IceCandidate_t localCandidate;
    IceCandidatePair_t candidatePair;
    uint8_t stunMessageBuffer[ 96 ];
    size_t stunMessageBufferLength = sizeof( stunMessageBuffer );
    IceResult_t result;

    result = Ice_Init( &( context ),
                       &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       result );

    memset( &candidatePair, 0, sizeof( IceCandidatePair_t ) );
    candidatePair.state = ICE_CANDIDATE_PAIR_STATE_CREATE_PERMISSION;
    candidatePair.pLocalCandidate = NULL;
    candidatePair.pRemoteCandidate = &localCandidate;

    result = Ice_CreateNextPairRequest( &( context ),
                                        &( candidatePair ),
                                        stunMessageBuffer,
                                        &( stunMessageBufferLength ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_BAD_PARAM,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate Ice_CreateNextPairRequest functionality returns
 * ICE_RESULT_BAD_PARAM when the remote candidate pointer is NULL in
 * candidate pair and the state is create permission.
 */
void test_iceCreateNextPairRequest_CreatePermission_NullRemoteCandidate( void )
{
    IceContext_t context = { 0 };
    IceCandidate_t localCandidate;
    IceCandidatePair_t candidatePair;
    uint8_t stunMessageBuffer[ 96 ];
    size_t stunMessageBufferLength = sizeof( stunMessageBuffer );
    IceResult_t result;

    result = Ice_Init( &( context ),
                       &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       result );

    memset( &candidatePair, 0, sizeof( IceCandidatePair_t ) );
    candidatePair.state = ICE_CANDIDATE_PAIR_STATE_CREATE_PERMISSION;
    candidatePair.pLocalCandidate = &localCandidate;
    candidatePair.pRemoteCandidate = NULL;

    result = Ice_CreateNextPairRequest( &( context ),
                                        &( candidatePair ),
                                        stunMessageBuffer,
                                        &( stunMessageBufferLength ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_BAD_PARAM,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate Ice_CreateNextPairRequest functionality returns
 * ICE_RESULT_INVALID_CANDIDATE_TYPE when the local candidate is not
 * relay type in candidate pair.
 */
void test_iceCreateNextPairRequest_CreatePermission_LocalCandidateNotRelayType( void )
{
    IceContext_t context = { 0 };
    IceCandidate_t localCandidate;
    IceCandidatePair_t candidatePair;
    uint8_t stunMessageBuffer[ 96 ];
    size_t stunMessageBufferLength = sizeof( stunMessageBuffer );
    IceResult_t result;

    result = Ice_Init( &( context ),
                       &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       result );

    memset( &candidatePair, 0, sizeof( IceCandidatePair_t ) );
    candidatePair.state = ICE_CANDIDATE_PAIR_STATE_CREATE_PERMISSION;
    candidatePair.pLocalCandidate = &localCandidate;
    candidatePair.pRemoteCandidate = &localCandidate;

    localCandidate.candidateType = ICE_CANDIDATE_TYPE_HOST;

    result = Ice_CreateNextPairRequest( &( context ),
                                        &( candidatePair ),
                                        stunMessageBuffer,
                                        &( stunMessageBufferLength ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_INVALID_CANDIDATE_TYPE,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate Ice_CreateNextPairRequest functionality returns
 * ICE_RESULT_NULL_RELAY_EXTENSION when local candidate doesn't have
 * relay extension buffer.
 */
void test_iceCreateNextPairRequest_CreatePermission_NoRelayExtension( void )
{
    IceContext_t context = { 0 };
    IceCandidate_t localCandidate;
    IceCandidatePair_t candidatePair;
    uint8_t stunMessageBuffer[ 96 ];
    size_t stunMessageBufferLength = sizeof( stunMessageBuffer );
    IceResult_t result;

    result = Ice_Init( &( context ),
                       &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       result );

    memset( &candidatePair, 0, sizeof( IceCandidatePair_t ) );
    candidatePair.state = ICE_CANDIDATE_PAIR_STATE_CREATE_PERMISSION;
    candidatePair.pLocalCandidate = &localCandidate;
    candidatePair.pRemoteCandidate = &localCandidate;

    localCandidate.candidateType = ICE_CANDIDATE_TYPE_RELAY;
    localCandidate.pRelayExtension = NULL;

    result = Ice_CreateNextPairRequest( &( context ),
                                        &( candidatePair ),
                                        stunMessageBuffer,
                                        &( stunMessageBufferLength ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_NULL_RELAY_EXTENSION,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate Ice_CreateNextPairRequest functionality returns
 * ICE_RESULT_INVALID_CANDIDATE_CREDENTIAL when the long term password
 * in local candidate is invalid and the state is create permission.
 */
void test_iceCreateNextPairRequest_CreatePermission_InValidLongTermPassword( void )
{
    IceContext_t context = { 0 };
    IceCandidate_t localCandidate;
    IceCandidatePair_t candidatePair;
    uint8_t stunMessageBuffer[ 96 ];
    size_t stunMessageBufferLength = sizeof( stunMessageBuffer );
    IceResult_t result;
    char * pUsername = "username";
    size_t usernameLength = strlen( pUsername );
    char * pRealm = "realm";
    size_t realmLength = strlen( pRealm );
    char * pNonce = "nonce";
    size_t nonceLength = strlen( pNonce );

    result = Ice_Init( &( context ),
                       &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       result );

    memset( &candidatePair, 0, sizeof( IceCandidatePair_t ) );
    candidatePair.state = ICE_CANDIDATE_PAIR_STATE_CREATE_PERMISSION;
    candidatePair.pLocalCandidate = &localCandidate;
    candidatePair.pRemoteCandidate = &localCandidate;

    localCandidate.candidateType = ICE_CANDIDATE_TYPE_RELAY;
    context.numRelayExtensions = 1;
    localCandidate.pRelayExtension = &context.pRelayExtensionsArray[ 0 ];
    memcpy( &localCandidate.pRelayExtension->iceRelayServerInfo.userName, pUsername, usernameLength );
    localCandidate.pRelayExtension->iceRelayServerInfo.userNameLength = usernameLength;
    localCandidate.pRelayExtension->iceRelayServerInfo.longTermPasswordLength = 0U;
    memcpy( &localCandidate.pRelayExtension->iceRelayServerInfo.realm, pRealm, realmLength );
    localCandidate.pRelayExtension->iceRelayServerInfo.realmLength = realmLength;
    memcpy( &localCandidate.pRelayExtension->iceRelayServerInfo.nonce, pNonce, nonceLength );
    localCandidate.pRelayExtension->iceRelayServerInfo.nonceLength = nonceLength;

    result = Ice_CreateNextPairRequest( &( context ),
                                        &( candidatePair ),
                                        stunMessageBuffer,
                                        &( stunMessageBufferLength ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_INVALID_CANDIDATE_CREDENTIAL,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate Ice_CreateNextPairRequest functionality returns
 * ICE_RESULT_INVALID_CANDIDATE_CREDENTIAL when the realm
 * in local candidate is invalid and the state is create permission.
 */
void test_iceCreateNextPairRequest_CreatePermission_InValidRealm( void )
{
    IceContext_t context = { 0 };
    IceCandidate_t localCandidate;
    IceCandidatePair_t candidatePair;
    uint8_t stunMessageBuffer[ 96 ];
    size_t stunMessageBufferLength = sizeof( stunMessageBuffer );
    IceResult_t result;
    char * pUsername = "username";
    size_t usernameLength = strlen( pUsername );
    char * pPassword = "password";
    size_t passwordLength = strlen( pPassword );
    char * pNonce = "nonce";
    size_t nonceLength = strlen( pNonce );

    result = Ice_Init( &( context ),
                       &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       result );

    memset( &candidatePair, 0, sizeof( IceCandidatePair_t ) );
    candidatePair.state = ICE_CANDIDATE_PAIR_STATE_CREATE_PERMISSION;
    candidatePair.pLocalCandidate = &localCandidate;
    candidatePair.pRemoteCandidate = &localCandidate;

    localCandidate.candidateType = ICE_CANDIDATE_TYPE_RELAY;
    context.numRelayExtensions = 1;
    localCandidate.pRelayExtension = &context.pRelayExtensionsArray[ 0 ];
    memcpy( &localCandidate.pRelayExtension->iceRelayServerInfo.userName, pUsername, usernameLength );
    localCandidate.pRelayExtension->iceRelayServerInfo.userNameLength = usernameLength;
    memcpy( &localCandidate.pRelayExtension->iceRelayServerInfo.longTermPassword, pPassword, passwordLength );
    localCandidate.pRelayExtension->iceRelayServerInfo.longTermPasswordLength = passwordLength;
    localCandidate.pRelayExtension->iceRelayServerInfo.realmLength = 0U;
    memcpy( &localCandidate.pRelayExtension->iceRelayServerInfo.nonce, pNonce, nonceLength );
    localCandidate.pRelayExtension->iceRelayServerInfo.nonceLength = nonceLength;

    result = Ice_CreateNextPairRequest( &( context ),
                                        &( candidatePair ),
                                        stunMessageBuffer,
                                        &( stunMessageBufferLength ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_INVALID_CANDIDATE_CREDENTIAL,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate Ice_CreateNextPairRequest functionality returns
 * ICE_RESULT_INVALID_CANDIDATE_CREDENTIAL when the nonce
 * in local candidate is invalid and the state is create permission.
 */
void test_iceCreateNextPairRequest_CreatePermission_InValidNonce( void )
{
    IceContext_t context = { 0 };
    IceCandidate_t localCandidate;
    IceCandidatePair_t candidatePair;
    uint8_t stunMessageBuffer[ 96 ];
    size_t stunMessageBufferLength = sizeof( stunMessageBuffer );
    IceResult_t result;
    char * pUsername = "username";
    size_t usernameLength = strlen( pUsername );
    char * pPassword = "password";
    size_t passwordLength = strlen( pPassword );
    char * pRealm = "realm";
    size_t realmLength = strlen( pRealm );

    result = Ice_Init( &( context ),
                       &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       result );

    memset( &candidatePair, 0, sizeof( IceCandidatePair_t ) );
    candidatePair.state = ICE_CANDIDATE_PAIR_STATE_CREATE_PERMISSION;
    candidatePair.pLocalCandidate = &localCandidate;
    candidatePair.pRemoteCandidate = &localCandidate;

    localCandidate.candidateType = ICE_CANDIDATE_TYPE_RELAY;
    context.numRelayExtensions = 1;
    localCandidate.pRelayExtension = &context.pRelayExtensionsArray[ 0 ];
    memcpy( &localCandidate.pRelayExtension->iceRelayServerInfo.userName, pUsername, usernameLength );
    localCandidate.pRelayExtension->iceRelayServerInfo.userNameLength = usernameLength;
    memcpy( &localCandidate.pRelayExtension->iceRelayServerInfo.longTermPassword, pPassword, passwordLength );
    localCandidate.pRelayExtension->iceRelayServerInfo.longTermPasswordLength = passwordLength;
    memcpy( &localCandidate.pRelayExtension->iceRelayServerInfo.realm, pRealm, realmLength );
    localCandidate.pRelayExtension->iceRelayServerInfo.realmLength = realmLength;
    localCandidate.pRelayExtension->iceRelayServerInfo.nonceLength = 0U;

    result = Ice_CreateNextPairRequest( &( context ),
                                        &( candidatePair ),
                                        stunMessageBuffer,
                                        &( stunMessageBufferLength ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_INVALID_CANDIDATE_CREDENTIAL,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate Ice_CreateNextPairRequest functionality returns
 * ICE_RESULT_STUN_ERROR when the input STUN message buffer is too small.
 */
void test_iceCreateNextPairRequest_CreatePermission_StunBufferTooSmall( void )
{
    IceContext_t context = { 0 };
    IceCandidate_t localCandidate;
    IceCandidatePair_t candidatePair;
    uint8_t stunMessageBuffer[ 2 ];
    size_t stunMessageBufferLength = sizeof( stunMessageBuffer );
    IceResult_t result;
    char * pUsername = "username";
    size_t usernameLength = strlen( pUsername );
    char * pPassword = "password";
    size_t passwordLength = strlen( pPassword );
    char * pRealm = "realm";
    size_t realmLength = strlen( pRealm );
    char * pNonce = "nonce";
    size_t nonceLength = strlen( pNonce );
    uint8_t transactionID[] =
    {
        0xFF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B
    };

    result = Ice_Init( &( context ),
                       &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       result );

    memset( &candidatePair, 0, sizeof( IceCandidatePair_t ) );
    candidatePair.state = ICE_CANDIDATE_PAIR_STATE_CREATE_PERMISSION;
    candidatePair.pLocalCandidate = &localCandidate;
    candidatePair.pRemoteCandidate = &localCandidate;
    memcpy( candidatePair.transactionId, transactionID, sizeof( transactionID ) );

    localCandidate.candidateType = ICE_CANDIDATE_TYPE_RELAY;
    context.numRelayExtensions = 1;
    localCandidate.pRelayExtension = &context.pRelayExtensionsArray[ 0 ];
    memcpy( &localCandidate.pRelayExtension->iceRelayServerInfo.userName, pUsername, usernameLength );
    localCandidate.pRelayExtension->iceRelayServerInfo.userNameLength = usernameLength;
    memcpy( &localCandidate.pRelayExtension->iceRelayServerInfo.longTermPassword, pPassword, passwordLength );
    localCandidate.pRelayExtension->iceRelayServerInfo.longTermPasswordLength = passwordLength;
    memcpy( &localCandidate.pRelayExtension->iceRelayServerInfo.realm, pRealm, realmLength );
    localCandidate.pRelayExtension->iceRelayServerInfo.realmLength = realmLength;
    memcpy( &localCandidate.pRelayExtension->iceRelayServerInfo.nonce, pNonce, nonceLength );
    localCandidate.pRelayExtension->iceRelayServerInfo.nonceLength = nonceLength;

    localCandidate.endpoint.isPointToPoint = 0U;
    localCandidate.endpoint.transportAddress.family = STUN_ADDRESS_IPv4;
    localCandidate.endpoint.transportAddress.port = 0x1234;
    memcpy( ( void * ) &( localCandidate.endpoint.transportAddress.address[ 0 ] ),
            ( const void * ) ipAddress,
            sizeof( ipAddress ) );

    result = Ice_CreateNextPairRequest( &( context ),
                                        &( candidatePair ),
                                        stunMessageBuffer,
                                        &( stunMessageBufferLength ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_STUN_ERROR,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate Ice_CreateNextPairRequest functionality returns
 * ICE_RESULT_STUN_ERROR_ADD_XOR_PEER_ADDRESS when the address family is
 * neither IPv4 nor IPv6.
 */
void test_iceCreateNextPairRequest_CreatePermission_UnknownAddressFamily( void )
{
    IceContext_t context = { 0 };
    IceCandidate_t localCandidate;
    IceCandidatePair_t candidatePair;
    uint8_t stunMessageBuffer[ 100 ];
    size_t stunMessageBufferLength = sizeof( stunMessageBuffer );
    IceResult_t result;
    char * pUsername = "username";
    size_t usernameLength = strlen( pUsername );
    char * pPassword = "password";
    size_t passwordLength = strlen( pPassword );
    char * pRealm = "realm";
    size_t realmLength = strlen( pRealm );
    char * pNonce = "nonce";
    size_t nonceLength = strlen( pNonce );
    uint8_t transactionID[] =
    {
        0xFF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B
    };

    result = Ice_Init( &( context ),
                       &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       result );

    memset( &candidatePair, 0, sizeof( IceCandidatePair_t ) );
    candidatePair.state = ICE_CANDIDATE_PAIR_STATE_CREATE_PERMISSION;
    candidatePair.pLocalCandidate = &localCandidate;
    candidatePair.pRemoteCandidate = &localCandidate;
    memcpy( candidatePair.transactionId, transactionID, sizeof( transactionID ) );

    localCandidate.candidateType = ICE_CANDIDATE_TYPE_RELAY;
    context.numRelayExtensions = 1;
    localCandidate.pRelayExtension = &context.pRelayExtensionsArray[ 0 ];
    memcpy( &localCandidate.pRelayExtension->iceRelayServerInfo.userName, pUsername, usernameLength );
    localCandidate.pRelayExtension->iceRelayServerInfo.userNameLength = usernameLength;
    memcpy( &localCandidate.pRelayExtension->iceRelayServerInfo.longTermPassword, pPassword, passwordLength );
    localCandidate.pRelayExtension->iceRelayServerInfo.longTermPasswordLength = passwordLength;
    memcpy( &localCandidate.pRelayExtension->iceRelayServerInfo.realm, pRealm, realmLength );
    localCandidate.pRelayExtension->iceRelayServerInfo.realmLength = realmLength;
    memcpy( &localCandidate.pRelayExtension->iceRelayServerInfo.nonce, pNonce, nonceLength );
    localCandidate.pRelayExtension->iceRelayServerInfo.nonceLength = nonceLength;

    localCandidate.endpoint.isPointToPoint = 0U;
    /* Set family to neither STUN_ADDRESS_IPv4 nor STUN_ADDRESS_IPv6. */
    localCandidate.endpoint.transportAddress.family = 0xFF;
    localCandidate.endpoint.transportAddress.port = 0x1234;
    memcpy( ( void * ) &( localCandidate.endpoint.transportAddress.address[ 0 ] ),
            ( const void * ) ipAddress,
            sizeof( ipAddress ) );

    result = Ice_CreateNextPairRequest( &( context ),
                                        &( candidatePair ),
                                        stunMessageBuffer,
                                        &( stunMessageBufferLength ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_STUN_ERROR_ADD_XOR_PEER_ADDRESS,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Tests error handling when Ice_CreateNextPairRequest fails to append username.
 * This test validates that Ice_CreateNextPairRequest returns ICE_RESULT_STUN_ERROR_ADD_USERNAME
 * when there is insufficient space in the STUN buffer to append the username attribute.
 * The test artificially constrains the STUN buffer size to trigger this error condition.
 */
void test_iceCreateNextPairRequest_CreatePermission_InvalidUsername( void )
{
    IceContext_t context = { 0 };
    IceCandidate_t localCandidate;
    IceCandidatePair_t candidatePair;
    uint8_t stunMessageBuffer[ 32 ];
    size_t stunMessageBufferLength = sizeof( stunMessageBuffer );
    IceResult_t result;
    char * pUsername = "username";
    size_t usernameLength = strlen( pUsername );
    char * pPassword = "password";
    size_t passwordLength = strlen( pPassword );
    char * pRealm = "realm";
    size_t realmLength = strlen( pRealm );
    char * pNonce = "nonce";
    size_t nonceLength = strlen( pNonce );
    uint8_t transactionID[] =
    {
        0xFF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B
    };

    result = Ice_Init( &( context ),
                       &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       result );

    memset( &candidatePair, 0, sizeof( IceCandidatePair_t ) );
    candidatePair.state = ICE_CANDIDATE_PAIR_STATE_CREATE_PERMISSION;
    candidatePair.pLocalCandidate = &localCandidate;
    candidatePair.pRemoteCandidate = &localCandidate;
    memcpy( candidatePair.transactionId, transactionID, sizeof( transactionID ) );

    localCandidate.candidateType = ICE_CANDIDATE_TYPE_RELAY;
    context.numRelayExtensions = 1;
    localCandidate.pRelayExtension = &context.pRelayExtensionsArray[ 0 ];
    memcpy( &localCandidate.pRelayExtension->iceRelayServerInfo.userName, pUsername, usernameLength );
    localCandidate.pRelayExtension->iceRelayServerInfo.userNameLength = usernameLength;
    memcpy( &localCandidate.pRelayExtension->iceRelayServerInfo.longTermPassword, pPassword, passwordLength );
    localCandidate.pRelayExtension->iceRelayServerInfo.longTermPasswordLength = passwordLength;
    memcpy( &localCandidate.pRelayExtension->iceRelayServerInfo.realm, pRealm, realmLength );
    localCandidate.pRelayExtension->iceRelayServerInfo.realmLength = realmLength;
    memcpy( &localCandidate.pRelayExtension->iceRelayServerInfo.nonce, pNonce, nonceLength );
    localCandidate.pRelayExtension->iceRelayServerInfo.nonceLength = nonceLength;

    localCandidate.endpoint.isPointToPoint = 0U;
    localCandidate.endpoint.transportAddress.family = STUN_ADDRESS_IPv4;
    localCandidate.endpoint.transportAddress.port = 0x1234;
    memcpy( ( void * ) &( localCandidate.endpoint.transportAddress.address[ 0 ] ),
            ( const void * ) ipAddress,
            sizeof( ipAddress ) );

    result = Ice_CreateNextPairRequest( &( context ),
                                        &( candidatePair ),
                                        stunMessageBuffer,
                                        &( stunMessageBufferLength ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_STUN_ERROR_ADD_USERNAME,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Tests error handling when Ice_CreateNextPairRequest fails to append realm.
 * This test validates that Ice_CreateNextPairRequest returns ICE_RESULT_STUN_ERROR_ADD_REALM
 * when there is insufficient space in the STUN buffer to append the realm attribute.
 * The test artificially constrains the STUN buffer size to trigger this error condition.
 */
void test_iceCreateNextPairRequest_CreatePermission_InvalidRealm( void )
{
    IceContext_t context = { 0 };
    IceCandidate_t localCandidate;
    IceCandidatePair_t candidatePair;
    uint8_t stunMessageBuffer[ 44 ];
    size_t stunMessageBufferLength = sizeof( stunMessageBuffer );
    IceResult_t result;
    char * pUsername = "username";
    size_t usernameLength = strlen( pUsername );
    char * pPassword = "password";
    size_t passwordLength = strlen( pPassword );
    char * pRealm = "realm";
    size_t realmLength = strlen( pRealm );
    char * pNonce = "nonce";
    size_t nonceLength = strlen( pNonce );
    uint8_t transactionID[] =
    {
        0xFF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B
    };

    result = Ice_Init( &( context ),
                       &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       result );

    memset( &candidatePair, 0, sizeof( IceCandidatePair_t ) );
    candidatePair.state = ICE_CANDIDATE_PAIR_STATE_CREATE_PERMISSION;
    candidatePair.pLocalCandidate = &localCandidate;
    candidatePair.pRemoteCandidate = &localCandidate;
    memcpy( candidatePair.transactionId, transactionID, sizeof( transactionID ) );

    localCandidate.candidateType = ICE_CANDIDATE_TYPE_RELAY;
    context.numRelayExtensions = 1;
    localCandidate.pRelayExtension = &context.pRelayExtensionsArray[ 0 ];
    memcpy( &localCandidate.pRelayExtension->iceRelayServerInfo.userName, pUsername, usernameLength );
    localCandidate.pRelayExtension->iceRelayServerInfo.userNameLength = usernameLength;
    memcpy( &localCandidate.pRelayExtension->iceRelayServerInfo.longTermPassword, pPassword, passwordLength );
    localCandidate.pRelayExtension->iceRelayServerInfo.longTermPasswordLength = passwordLength;
    memcpy( &localCandidate.pRelayExtension->iceRelayServerInfo.realm, pRealm, realmLength );
    localCandidate.pRelayExtension->iceRelayServerInfo.realmLength = realmLength;
    memcpy( &localCandidate.pRelayExtension->iceRelayServerInfo.nonce, pNonce, nonceLength );
    localCandidate.pRelayExtension->iceRelayServerInfo.nonceLength = nonceLength;

    localCandidate.endpoint.isPointToPoint = 0U;
    localCandidate.endpoint.transportAddress.family = STUN_ADDRESS_IPv4;
    localCandidate.endpoint.transportAddress.port = 0x1234;
    memcpy( ( void * ) &( localCandidate.endpoint.transportAddress.address[ 0 ] ),
            ( const void * ) ipAddress,
            sizeof( ipAddress ) );

    result = Ice_CreateNextPairRequest( &( context ),
                                        &( candidatePair ),
                                        stunMessageBuffer,
                                        &( stunMessageBufferLength ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_STUN_ERROR_ADD_REALM,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Tests error handling when Ice_CreateNextPairRequest fails to append nonce.
 * This test validates that Ice_CreateNextPairRequest returns ICE_RESULT_STUN_ERROR_ADD_NONCE
 * when there is insufficient space in the STUN buffer to append the nonce attribute.
 * The test artificially constrains the STUN buffer size to trigger this error condition.
 */
void test_iceCreateNextPairRequest_CreatePermission_InvalidNonce( void )
{
    IceContext_t context = { 0 };
    IceCandidate_t localCandidate;
    IceCandidatePair_t candidatePair;
    uint8_t stunMessageBuffer[ 56 ];
    size_t stunMessageBufferLength = sizeof( stunMessageBuffer );
    IceResult_t result;
    char * pUsername = "username";
    size_t usernameLength = strlen( pUsername );
    char * pPassword = "password";
    size_t passwordLength = strlen( pPassword );
    char * pRealm = "realm";
    size_t realmLength = strlen( pRealm );
    char * pNonce = "nonce";
    size_t nonceLength = strlen( pNonce );
    uint8_t transactionID[] =
    {
        0xFF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B
    };

    result = Ice_Init( &( context ),
                       &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       result );

    memset( &candidatePair, 0, sizeof( IceCandidatePair_t ) );
    candidatePair.state = ICE_CANDIDATE_PAIR_STATE_CREATE_PERMISSION;
    candidatePair.pLocalCandidate = &localCandidate;
    candidatePair.pRemoteCandidate = &localCandidate;
    memcpy( candidatePair.transactionId, transactionID, sizeof( transactionID ) );

    localCandidate.candidateType = ICE_CANDIDATE_TYPE_RELAY;
    context.numRelayExtensions = 1;
    localCandidate.pRelayExtension = &context.pRelayExtensionsArray[ 0 ];
    memcpy( &localCandidate.pRelayExtension->iceRelayServerInfo.userName, pUsername, usernameLength );
    localCandidate.pRelayExtension->iceRelayServerInfo.userNameLength = usernameLength;
    memcpy( &localCandidate.pRelayExtension->iceRelayServerInfo.longTermPassword, pPassword, passwordLength );
    localCandidate.pRelayExtension->iceRelayServerInfo.longTermPasswordLength = passwordLength;
    memcpy( &localCandidate.pRelayExtension->iceRelayServerInfo.realm, pRealm, realmLength );
    localCandidate.pRelayExtension->iceRelayServerInfo.realmLength = realmLength;
    memcpy( &localCandidate.pRelayExtension->iceRelayServerInfo.nonce, pNonce, nonceLength );
    localCandidate.pRelayExtension->iceRelayServerInfo.nonceLength = nonceLength;

    localCandidate.endpoint.isPointToPoint = 0U;
    localCandidate.endpoint.transportAddress.family = STUN_ADDRESS_IPv4;
    localCandidate.endpoint.transportAddress.port = 0x1234;
    memcpy( ( void * ) &( localCandidate.endpoint.transportAddress.address[ 0 ] ),
            ( const void * ) ipAddress,
            sizeof( ipAddress ) );

    result = Ice_CreateNextPairRequest( &( context ),
                                        &( candidatePair ),
                                        stunMessageBuffer,
                                        &( stunMessageBufferLength ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_STUN_ERROR_ADD_NONCE,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate Ice_CreateNextPairRequest functionality returns
 * CreatePermission Request packet for the candidate pair.
 */
void test_iceCreateNextPairRequest_CreatePermission_Success( void )
{
    IceContext_t context = { 0 };
    IceCandidate_t localCandidate;
    IceCandidatePair_t candidatePair;
    uint8_t stunMessageBuffer[ 100 ];
    size_t stunMessageBufferLength = sizeof( stunMessageBuffer );
    IceResult_t result;
    char * pUsername = "username";
    size_t usernameLength = strlen( pUsername );
    char * pPassword = "password";
    size_t passwordLength = strlen( pPassword );
    char * pRealm = "realm";
    size_t realmLength = strlen( pRealm );
    char * pNonce = "nonce";
    size_t nonceLength = strlen( pNonce );
    uint8_t transactionID[] =
    {
        0xFF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B
    };
    uint8_t expectedStunMessage[] =
    {
        /* STUN header: Message Type = Create Permission Request (0x0008), Length = 80 bytes (excluding 20 bytes header). */
        0x00, 0x08, 0x00, 0x50,
        /* Magic Cookie (0x2112A442). */
        0x21, 0x12, 0xA4, 0x42,
        /* 12 bytes (96 bits) transaction ID as generated by testRandomFxn. */
        0xFF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
        /* Attribute type = XOR_PEER_ADDRESS (0x0012), Length = 8 bytes. */
        0x00, 0x12, 0x00, 0x08,
        /* Attribute Value = Family: 0x01, Port: 0x1234 IP: 192.168.1.100. XOR with 0x2112A442. */
        0x00, 0x01, 0x33, 0x26,
        0xE1, 0xBA, 0xA5, 0x26,
        /* Attribute type = USERNAME (0x0006), Length = 8 bytes. */
        0x00, 0x06, 0x00, 0x08,
        /* Attribute Value: "username". */
        0x75, 0x73, 0x65, 0x72,
        0x6E, 0x61, 0x6D, 0x65,
        /* Attribute type = REALM (0x0014), Length = 5 bytes. */
        0x00, 0x14, 0x00, 0x05,
        /* Attribute Value: "realm". */
        0x72, 0x65, 0x61, 0x6C,
        0x6D, 0x00, 0x00, 0x00,
        /* Attribute type = NONCE (0x0015), Length = 5 bytes. */
        0x00, 0x15, 0x00, 0x05,
        /* Attribute Value: "nonce". */
        0x6E, 0x6F, 0x6E, 0x63,
        0x65, 0x00, 0x00, 0x00,
        /* Attribute type = MESSAGE-INTEGRITY (0x0008), Length = 20 bytes. */
        0x00, 0x08, 0x00, 0x14,
        /* Attribute Value = HMAC value as computed by testHmacFxn. */
        0x70, 0x69, 0x73, 0x3B,
        0x56, 0x7D, 0xD6, 0x26,
        0x8F, 0x60, 0x71, 0x70,
        0x73, 0x6A, 0x74, 0x63,
        0x78, 0x68, 0x79, 0x78,
        /* Attribute type = FINGERPRINT (0x8028), Length = 4 bytes. */
        0x80, 0x28, 0x00, 0x04,
        /* Attribute Value = 0xC05DE471 as calculated by testCrc32Fxn. */
        0x71, 0xE4, 0x5D, 0xC0
    };
    size_t expectedStunMessageLength = sizeof( expectedStunMessage );

    result = Ice_Init( &( context ),
                       &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       result );

    memset( &candidatePair, 0, sizeof( IceCandidatePair_t ) );
    candidatePair.state = ICE_CANDIDATE_PAIR_STATE_CREATE_PERMISSION;
    candidatePair.pLocalCandidate = &localCandidate;
    candidatePair.pRemoteCandidate = &localCandidate;
    memcpy( candidatePair.transactionId, transactionID, sizeof( transactionID ) );

    localCandidate.candidateType = ICE_CANDIDATE_TYPE_RELAY;
    context.numRelayExtensions = 1;
    localCandidate.pRelayExtension = &context.pRelayExtensionsArray[ 0 ];
    memcpy( &localCandidate.pRelayExtension->iceRelayServerInfo.userName, pUsername, usernameLength );
    localCandidate.pRelayExtension->iceRelayServerInfo.userNameLength = usernameLength;
    memcpy( &localCandidate.pRelayExtension->iceRelayServerInfo.longTermPassword, pPassword, passwordLength );
    localCandidate.pRelayExtension->iceRelayServerInfo.longTermPasswordLength = passwordLength;
    memcpy( &localCandidate.pRelayExtension->iceRelayServerInfo.realm, pRealm, realmLength );
    localCandidate.pRelayExtension->iceRelayServerInfo.realmLength = realmLength;
    memcpy( &localCandidate.pRelayExtension->iceRelayServerInfo.nonce, pNonce, nonceLength );
    localCandidate.pRelayExtension->iceRelayServerInfo.nonceLength = nonceLength;

    localCandidate.endpoint.isPointToPoint = 0U;
    localCandidate.endpoint.transportAddress.family = STUN_ADDRESS_IPv4;
    localCandidate.endpoint.transportAddress.port = 0x1234;
    memcpy( ( void * ) &( localCandidate.endpoint.transportAddress.address[ 0 ] ),
            ( const void * ) ipAddress,
            sizeof( ipAddress ) );

    result = Ice_CreateNextPairRequest( &( context ),
                                        &( candidatePair ),
                                        stunMessageBuffer,
                                        &( stunMessageBufferLength ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       result );
    TEST_ASSERT_EQUAL( expectedStunMessageLength,
                       stunMessageBufferLength );
    TEST_ASSERT_EQUAL_UINT8_ARRAY( &( expectedStunMessage[ 0 ] ),
                                   &( stunMessageBuffer[ 0 ] ),
                                   expectedStunMessageLength );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate Ice_CreateNextPairRequest functionality returns
 * ICE_RESULT_BAD_PARAM when the local candidate pointer is NULL in
 * candidate pair and the state is channel bind.
 */
void test_iceCreateNextPairRequest_ChannelBind_NullLocalCandidate( void )
{
    IceContext_t context = { 0 };
    IceCandidate_t localCandidate;
    IceCandidatePair_t candidatePair;
    uint8_t stunMessageBuffer[ 96 ];
    size_t stunMessageBufferLength = sizeof( stunMessageBuffer );
    IceResult_t result;

    result = Ice_Init( &( context ),
                       &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       result );

    memset( &candidatePair, 0, sizeof( IceCandidatePair_t ) );
    candidatePair.state = ICE_CANDIDATE_PAIR_STATE_CHANNEL_BIND;
    candidatePair.pLocalCandidate = NULL;
    candidatePair.pRemoteCandidate = &localCandidate;

    result = Ice_CreateNextPairRequest( &( context ),
                                        &( candidatePair ),
                                        stunMessageBuffer,
                                        &( stunMessageBufferLength ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_BAD_PARAM,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate Ice_CreateNextPairRequest functionality returns
 * ICE_RESULT_BAD_PARAM when the remote candidate pointer is NULL in
 * candidate pair and the state is channel bind.
 */
void test_iceCreateNextPairRequest_ChannelBind_NullRemoteCandidate( void )
{
    IceContext_t context = { 0 };
    IceCandidate_t localCandidate;
    IceCandidatePair_t candidatePair;
    uint8_t stunMessageBuffer[ 96 ];
    size_t stunMessageBufferLength = sizeof( stunMessageBuffer );
    IceResult_t result;

    result = Ice_Init( &( context ),
                       &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       result );

    memset( &candidatePair, 0, sizeof( IceCandidatePair_t ) );
    candidatePair.state = ICE_CANDIDATE_PAIR_STATE_CHANNEL_BIND;
    candidatePair.pLocalCandidate = &localCandidate;
    candidatePair.pRemoteCandidate = NULL;

    result = Ice_CreateNextPairRequest( &( context ),
                                        &( candidatePair ),
                                        stunMessageBuffer,
                                        &( stunMessageBufferLength ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_BAD_PARAM,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate Ice_CreateNextPairRequest functionality returns
 * ICE_RESULT_NULL_RELAY_EXTENSION when the local candidate does
 * not have relay extension.
 */
void test_iceCreateNextPairRequest_ChannelBind_NoRelayExtension( void )
{
    IceContext_t context = { 0 };
    IceCandidate_t localCandidate;
    IceCandidatePair_t candidatePair;
    uint8_t stunMessageBuffer[ 96 ];
    size_t stunMessageBufferLength = sizeof( stunMessageBuffer );
    IceResult_t result;

    result = Ice_Init( &( context ),
                       &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       result );

    memset( &candidatePair, 0, sizeof( IceCandidatePair_t ) );
    candidatePair.state = ICE_CANDIDATE_PAIR_STATE_CHANNEL_BIND;
    candidatePair.pLocalCandidate = &localCandidate;
    candidatePair.pRemoteCandidate = &localCandidate;

    localCandidate.candidateType = ICE_CANDIDATE_TYPE_RELAY;
    localCandidate.pRelayExtension = NULL;

    result = Ice_CreateNextPairRequest( &( context ),
                                        &( candidatePair ),
                                        stunMessageBuffer,
                                        &( stunMessageBufferLength ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_NULL_RELAY_EXTENSION,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate Ice_CreateNextPairRequest functionality returns
 * ICE_RESULT_INVALID_CANDIDATE_TYPE when the local candidate is not
 * relay type in candidate pair and the state is channel bind.
 */
void test_iceCreateNextPairRequest_ChannelBind_LocalCandidateNotRelayType( void )
{
    IceContext_t context = { 0 };
    IceCandidate_t localCandidate;
    IceCandidatePair_t candidatePair;
    uint8_t stunMessageBuffer[ 96 ];
    size_t stunMessageBufferLength = sizeof( stunMessageBuffer );
    IceResult_t result;

    result = Ice_Init( &( context ),
                       &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       result );

    memset( &candidatePair, 0, sizeof( IceCandidatePair_t ) );
    candidatePair.state = ICE_CANDIDATE_PAIR_STATE_CHANNEL_BIND;
    candidatePair.pLocalCandidate = &localCandidate;
    candidatePair.pRemoteCandidate = &localCandidate;

    localCandidate.candidateType = ICE_CANDIDATE_TYPE_HOST;

    result = Ice_CreateNextPairRequest( &( context ),
                                        &( candidatePair ),
                                        stunMessageBuffer,
                                        &( stunMessageBufferLength ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_INVALID_CANDIDATE_TYPE,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate Ice_CreateNextPairRequest functionality returns
 * ICE_RESULT_INVALID_CANDIDATE_CREDENTIAL when the long term password
 * in local candidate is invalid and the state is channel bind.
 */
void test_iceCreateNextPairRequest_ChannelBind_InValidLongTermPassword( void )
{
    IceContext_t context = { 0 };
    IceCandidate_t localCandidate;
    IceCandidatePair_t candidatePair;
    uint8_t stunMessageBuffer[ 96 ];
    size_t stunMessageBufferLength = sizeof( stunMessageBuffer );
    IceResult_t result;
    char * pUsername = "username";
    size_t usernameLength = strlen( pUsername );
    char * pRealm = "realm";
    size_t realmLength = strlen( pRealm );
    char * pNonce = "nonce";
    size_t nonceLength = strlen( pNonce );

    result = Ice_Init( &( context ),
                       &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       result );

    memset( &candidatePair, 0, sizeof( IceCandidatePair_t ) );
    candidatePair.state = ICE_CANDIDATE_PAIR_STATE_CHANNEL_BIND;
    candidatePair.pLocalCandidate = &localCandidate;
    candidatePair.pRemoteCandidate = &localCandidate;

    localCandidate.candidateType = ICE_CANDIDATE_TYPE_RELAY;
    context.numRelayExtensions = 1;
    localCandidate.pRelayExtension = &context.pRelayExtensionsArray[ 0 ];
    memcpy( &localCandidate.pRelayExtension->iceRelayServerInfo.userName, pUsername, usernameLength );
    localCandidate.pRelayExtension->iceRelayServerInfo.userNameLength = usernameLength;
    localCandidate.pRelayExtension->iceRelayServerInfo.longTermPasswordLength = 0U;
    memcpy( &localCandidate.pRelayExtension->iceRelayServerInfo.realm, pRealm, realmLength );
    localCandidate.pRelayExtension->iceRelayServerInfo.realmLength = realmLength;
    memcpy( &localCandidate.pRelayExtension->iceRelayServerInfo.nonce, pNonce, nonceLength );
    localCandidate.pRelayExtension->iceRelayServerInfo.nonceLength = nonceLength;

    result = Ice_CreateNextPairRequest( &( context ),
                                        &( candidatePair ),
                                        stunMessageBuffer,
                                        &( stunMessageBufferLength ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_INVALID_CANDIDATE_CREDENTIAL,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate Ice_CreateNextPairRequest functionality returns
 * ICE_RESULT_INVALID_CANDIDATE_CREDENTIAL when the realm
 * in local candidate is invalid and the state is channel bind.
 */
void test_iceCreateNextPairRequest_ChannelBind_InValidRealm( void )
{
    IceContext_t context = { 0 };
    IceCandidate_t localCandidate;
    IceCandidatePair_t candidatePair;
    uint8_t stunMessageBuffer[ 96 ];
    size_t stunMessageBufferLength = sizeof( stunMessageBuffer );
    IceResult_t result;
    char * pUsername = "username";
    size_t usernameLength = strlen( pUsername );
    char * pPassword = "password";
    size_t passwordLength = strlen( pPassword );
    char * pNonce = "nonce";
    size_t nonceLength = strlen( pNonce );

    result = Ice_Init( &( context ),
                       &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       result );

    memset( &candidatePair, 0, sizeof( IceCandidatePair_t ) );
    candidatePair.state = ICE_CANDIDATE_PAIR_STATE_CHANNEL_BIND;
    candidatePair.pLocalCandidate = &localCandidate;
    candidatePair.pRemoteCandidate = &localCandidate;

    localCandidate.candidateType = ICE_CANDIDATE_TYPE_RELAY;
    context.numRelayExtensions = 1;
    localCandidate.pRelayExtension = &context.pRelayExtensionsArray[ 0 ];
    memcpy( &localCandidate.pRelayExtension->iceRelayServerInfo.userName, pUsername, usernameLength );
    localCandidate.pRelayExtension->iceRelayServerInfo.userNameLength = usernameLength;
    memcpy( &localCandidate.pRelayExtension->iceRelayServerInfo.longTermPassword, pPassword, passwordLength );
    localCandidate.pRelayExtension->iceRelayServerInfo.longTermPasswordLength = passwordLength;
    localCandidate.pRelayExtension->iceRelayServerInfo.realmLength = 0U;
    memcpy( &localCandidate.pRelayExtension->iceRelayServerInfo.nonce, pNonce, nonceLength );
    localCandidate.pRelayExtension->iceRelayServerInfo.nonceLength = nonceLength;

    result = Ice_CreateNextPairRequest( &( context ),
                                        &( candidatePair ),
                                        stunMessageBuffer,
                                        &( stunMessageBufferLength ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_INVALID_CANDIDATE_CREDENTIAL,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate Ice_CreateNextPairRequest functionality returns
 * ICE_RESULT_INVALID_CANDIDATE_CREDENTIAL when the nonce
 * in local candidate is invalid and the state is channel bind.
 */
void test_iceCreateNextPairRequest_ChannelBind_InValidNonce( void )
{
    IceContext_t context = { 0 };
    IceCandidate_t localCandidate;
    IceCandidatePair_t candidatePair;
    uint8_t stunMessageBuffer[ 96 ];
    size_t stunMessageBufferLength = sizeof( stunMessageBuffer );
    IceResult_t result;
    char * pUsername = "username";
    size_t usernameLength = strlen( pUsername );
    char * pPassword = "password";
    size_t passwordLength = strlen( pPassword );
    char * pRealm = "realm";
    size_t realmLength = strlen( pRealm );

    result = Ice_Init( &( context ),
                       &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       result );

    memset( &candidatePair, 0, sizeof( IceCandidatePair_t ) );
    candidatePair.state = ICE_CANDIDATE_PAIR_STATE_CHANNEL_BIND;
    candidatePair.pLocalCandidate = &localCandidate;
    candidatePair.pRemoteCandidate = &localCandidate;

    localCandidate.candidateType = ICE_CANDIDATE_TYPE_RELAY;
    context.numRelayExtensions = 1;
    localCandidate.pRelayExtension = &context.pRelayExtensionsArray[ 0 ];
    memcpy( &localCandidate.pRelayExtension->iceRelayServerInfo.userName, pUsername, usernameLength );
    localCandidate.pRelayExtension->iceRelayServerInfo.userNameLength = usernameLength;
    memcpy( &localCandidate.pRelayExtension->iceRelayServerInfo.longTermPassword, pPassword, passwordLength );
    localCandidate.pRelayExtension->iceRelayServerInfo.longTermPasswordLength = passwordLength;
    memcpy( &localCandidate.pRelayExtension->iceRelayServerInfo.realm, pRealm, realmLength );
    localCandidate.pRelayExtension->iceRelayServerInfo.realmLength = realmLength;
    localCandidate.pRelayExtension->iceRelayServerInfo.nonceLength = 0U;

    result = Ice_CreateNextPairRequest( &( context ),
                                        &( candidatePair ),
                                        stunMessageBuffer,
                                        &( stunMessageBufferLength ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_INVALID_CANDIDATE_CREDENTIAL,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate Ice_CreateNextPairRequest functionality returns
 * ICE_RESULT_STUN_ERROR when the input STUN message buffer is too small.
 */
void test_iceCreateNextPairRequest_ChannelBind_StunBufferTooSmall( void )
{
    IceContext_t context = { 0 };
    IceCandidate_t localCandidate;
    IceCandidatePair_t candidatePair;
    uint8_t stunMessageBuffer[ 2 ];
    size_t stunMessageBufferLength = sizeof( stunMessageBuffer );
    IceResult_t result;
    char * pUsername = "username";
    size_t usernameLength = strlen( pUsername );
    char * pPassword = "password";
    size_t passwordLength = strlen( pPassword );
    char * pRealm = "realm";
    size_t realmLength = strlen( pRealm );
    char * pNonce = "nonce";
    size_t nonceLength = strlen( pNonce );
    uint8_t transactionID[] =
    {
        0xFF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B
    };

    result = Ice_Init( &( context ),
                       &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       result );

    memset( &candidatePair, 0, sizeof( IceCandidatePair_t ) );
    candidatePair.state = ICE_CANDIDATE_PAIR_STATE_CHANNEL_BIND;
    candidatePair.pLocalCandidate = &localCandidate;
    candidatePair.pRemoteCandidate = &localCandidate;
    memcpy( candidatePair.transactionId, transactionID, sizeof( transactionID ) );
    candidatePair.turnChannelNumber = 0x4000;

    localCandidate.candidateType = ICE_CANDIDATE_TYPE_RELAY;
    context.numRelayExtensions = 1;
    localCandidate.pRelayExtension = &context.pRelayExtensionsArray[ 0 ];
    memcpy( &localCandidate.pRelayExtension->iceRelayServerInfo.userName, pUsername, usernameLength );
    localCandidate.pRelayExtension->iceRelayServerInfo.userNameLength = usernameLength;
    memcpy( &localCandidate.pRelayExtension->iceRelayServerInfo.longTermPassword, pPassword, passwordLength );
    localCandidate.pRelayExtension->iceRelayServerInfo.longTermPasswordLength = passwordLength;
    memcpy( &localCandidate.pRelayExtension->iceRelayServerInfo.realm, pRealm, realmLength );
    localCandidate.pRelayExtension->iceRelayServerInfo.realmLength = realmLength;
    memcpy( &localCandidate.pRelayExtension->iceRelayServerInfo.nonce, pNonce, nonceLength );
    localCandidate.pRelayExtension->iceRelayServerInfo.nonceLength = nonceLength;

    localCandidate.endpoint.isPointToPoint = 0U;
    localCandidate.endpoint.transportAddress.family = STUN_ADDRESS_IPv4;
    localCandidate.endpoint.transportAddress.port = 0x1234;
    memcpy( ( void * ) &( localCandidate.endpoint.transportAddress.address[ 0 ] ),
            ( const void * ) ipAddress,
            sizeof( ipAddress ) );

    result = Ice_CreateNextPairRequest( &( context ),
                                        &( candidatePair ),
                                        stunMessageBuffer,
                                        &( stunMessageBufferLength ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_STUN_ERROR,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate Ice_CreateNextPairRequest functionality returns
 * ICE_RESULT_STUN_ERROR_ADD_XOR_PEER_ADDRESS when the address family is
 * neither IPv4 nor IPv6.
 */
void test_iceCreateNextPairRequest_ChannelBind_UnknownAddressFamily( void )
{
    IceContext_t context = { 0 };
    IceCandidate_t localCandidate;
    IceCandidatePair_t candidatePair;
    uint8_t stunMessageBuffer[ 100 ];
    size_t stunMessageBufferLength = sizeof( stunMessageBuffer );
    IceResult_t result;
    char * pUsername = "username";
    size_t usernameLength = strlen( pUsername );
    char * pPassword = "password";
    size_t passwordLength = strlen( pPassword );
    char * pRealm = "realm";
    size_t realmLength = strlen( pRealm );
    char * pNonce = "nonce";
    size_t nonceLength = strlen( pNonce );
    uint8_t transactionID[] =
    {
        0xFF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B
    };

    result = Ice_Init( &( context ),
                       &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       result );

    memset( &candidatePair, 0, sizeof( IceCandidatePair_t ) );
    candidatePair.state = ICE_CANDIDATE_PAIR_STATE_CHANNEL_BIND;
    candidatePair.pLocalCandidate = &localCandidate;
    candidatePair.pRemoteCandidate = &localCandidate;
    memcpy( candidatePair.transactionId, transactionID, sizeof( transactionID ) );
    candidatePair.turnChannelNumber = 0x4000;

    localCandidate.candidateType = ICE_CANDIDATE_TYPE_RELAY;
    context.numRelayExtensions = 1;
    localCandidate.pRelayExtension = &context.pRelayExtensionsArray[ 0 ];
    memcpy( &localCandidate.pRelayExtension->iceRelayServerInfo.userName, pUsername, usernameLength );
    localCandidate.pRelayExtension->iceRelayServerInfo.userNameLength = usernameLength;
    memcpy( &localCandidate.pRelayExtension->iceRelayServerInfo.longTermPassword, pPassword, passwordLength );
    localCandidate.pRelayExtension->iceRelayServerInfo.longTermPasswordLength = passwordLength;
    memcpy( &localCandidate.pRelayExtension->iceRelayServerInfo.realm, pRealm, realmLength );
    localCandidate.pRelayExtension->iceRelayServerInfo.realmLength = realmLength;
    memcpy( &localCandidate.pRelayExtension->iceRelayServerInfo.nonce, pNonce, nonceLength );
    localCandidate.pRelayExtension->iceRelayServerInfo.nonceLength = nonceLength;

    localCandidate.endpoint.isPointToPoint = 0U;
    /* Set family to neither STUN_ADDRESS_IPv4 nor STUN_ADDRESS_IPv6. */
    localCandidate.endpoint.transportAddress.family = 0xFF;
    localCandidate.endpoint.transportAddress.port = 0x1234;
    memcpy( ( void * ) &( localCandidate.endpoint.transportAddress.address[ 0 ] ),
            ( const void * ) ipAddress,
            sizeof( ipAddress ) );

    result = Ice_CreateNextPairRequest( &( context ),
                                        &( candidatePair ),
                                        stunMessageBuffer,
                                        &( stunMessageBufferLength ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_STUN_ERROR_ADD_XOR_PEER_ADDRESS,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate Ice_CreateNextPairRequest functionality returns
 * ICE_RESULT_STUN_ERROR_ADD_USERNAME when error happens while adding
 * channel number.
 */
void test_iceCreateNextPairRequest_ChannelBind_InvalidChannelNumber( void )
{
    IceContext_t context = { 0 };
    IceCandidate_t localCandidate;
    IceCandidatePair_t candidatePair;
    uint8_t stunMessageBuffer[ 32 ];
    size_t stunMessageBufferLength = sizeof( stunMessageBuffer );
    IceResult_t result;
    char * pUsername = "username";
    size_t usernameLength = strlen( pUsername );
    char * pPassword = "password";
    size_t passwordLength = strlen( pPassword );
    char * pRealm = "realm";
    size_t realmLength = strlen( pRealm );
    char * pNonce = "nonce";
    size_t nonceLength = strlen( pNonce );
    uint8_t transactionID[] =
    {
        0xFF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B
    };

    result = Ice_Init( &( context ),
                       &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       result );

    memset( &candidatePair, 0, sizeof( IceCandidatePair_t ) );
    candidatePair.state = ICE_CANDIDATE_PAIR_STATE_CHANNEL_BIND;
    candidatePair.pLocalCandidate = &localCandidate;
    candidatePair.pRemoteCandidate = &localCandidate;
    memcpy( candidatePair.transactionId, transactionID, sizeof( transactionID ) );
    candidatePair.turnChannelNumber = 0x4000;

    localCandidate.candidateType = ICE_CANDIDATE_TYPE_RELAY;
    context.numRelayExtensions = 1;
    localCandidate.pRelayExtension = &context.pRelayExtensionsArray[ 0 ];
    memcpy( &localCandidate.pRelayExtension->iceRelayServerInfo.userName, pUsername, usernameLength );
    localCandidate.pRelayExtension->iceRelayServerInfo.userNameLength = usernameLength;
    memcpy( &localCandidate.pRelayExtension->iceRelayServerInfo.longTermPassword, pPassword, passwordLength );
    localCandidate.pRelayExtension->iceRelayServerInfo.longTermPasswordLength = passwordLength;
    memcpy( &localCandidate.pRelayExtension->iceRelayServerInfo.realm, pRealm, realmLength );
    localCandidate.pRelayExtension->iceRelayServerInfo.realmLength = realmLength;
    memcpy( &localCandidate.pRelayExtension->iceRelayServerInfo.nonce, pNonce, nonceLength );
    localCandidate.pRelayExtension->iceRelayServerInfo.nonceLength = nonceLength;

    localCandidate.endpoint.isPointToPoint = 0U;
    localCandidate.endpoint.transportAddress.family = STUN_ADDRESS_IPv4;
    localCandidate.endpoint.transportAddress.port = 0x1234;
    memcpy( ( void * ) &( localCandidate.endpoint.transportAddress.address[ 0 ] ),
            ( const void * ) ipAddress,
            sizeof( ipAddress ) );

    result = Ice_CreateNextPairRequest( &( context ),
                                        &( candidatePair ),
                                        stunMessageBuffer,
                                        &( stunMessageBufferLength ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_STUN_ERROR_ADD_CHANNEL_NUMBER,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Tests error handling when Ice_CreateNextPairRequest fails to append username.
 * This test validates that Ice_CreateNextPairRequest returns ICE_RESULT_STUN_ERROR_ADD_USERNAME
 * when there is insufficient space in the STUN buffer to append the username attribute.
 * The test artificially constrains the STUN buffer size to trigger this error condition.
 */
void test_iceCreateNextPairRequest_ChannelBind_InvalidUsername( void )
{
    IceContext_t context = { 0 };
    IceCandidate_t localCandidate;
    IceCandidatePair_t candidatePair;
    uint8_t stunMessageBuffer[ 40 ];
    size_t stunMessageBufferLength = sizeof( stunMessageBuffer );
    IceResult_t result;
    char * pUsername = "username";
    size_t usernameLength = strlen( pUsername );
    char * pPassword = "password";
    size_t passwordLength = strlen( pPassword );
    char * pRealm = "realm";
    size_t realmLength = strlen( pRealm );
    char * pNonce = "nonce";
    size_t nonceLength = strlen( pNonce );
    uint8_t transactionID[] =
    {
        0xFF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B
    };

    result = Ice_Init( &( context ),
                       &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       result );

    memset( &candidatePair, 0, sizeof( IceCandidatePair_t ) );
    candidatePair.state = ICE_CANDIDATE_PAIR_STATE_CHANNEL_BIND;
    candidatePair.pLocalCandidate = &localCandidate;
    candidatePair.pRemoteCandidate = &localCandidate;
    memcpy( candidatePair.transactionId, transactionID, sizeof( transactionID ) );
    candidatePair.turnChannelNumber = 0x4000;

    localCandidate.candidateType = ICE_CANDIDATE_TYPE_RELAY;
    context.numRelayExtensions = 1;
    localCandidate.pRelayExtension = &context.pRelayExtensionsArray[ 0 ];
    memcpy( &localCandidate.pRelayExtension->iceRelayServerInfo.userName, pUsername, usernameLength );
    localCandidate.pRelayExtension->iceRelayServerInfo.userNameLength = usernameLength;
    memcpy( &localCandidate.pRelayExtension->iceRelayServerInfo.longTermPassword, pPassword, passwordLength );
    localCandidate.pRelayExtension->iceRelayServerInfo.longTermPasswordLength = passwordLength;
    memcpy( &localCandidate.pRelayExtension->iceRelayServerInfo.realm, pRealm, realmLength );
    localCandidate.pRelayExtension->iceRelayServerInfo.realmLength = realmLength;
    memcpy( &localCandidate.pRelayExtension->iceRelayServerInfo.nonce, pNonce, nonceLength );
    localCandidate.pRelayExtension->iceRelayServerInfo.nonceLength = nonceLength;

    localCandidate.endpoint.isPointToPoint = 0U;
    localCandidate.endpoint.transportAddress.family = STUN_ADDRESS_IPv4;
    localCandidate.endpoint.transportAddress.port = 0x1234;
    memcpy( ( void * ) &( localCandidate.endpoint.transportAddress.address[ 0 ] ),
            ( const void * ) ipAddress,
            sizeof( ipAddress ) );

    result = Ice_CreateNextPairRequest( &( context ),
                                        &( candidatePair ),
                                        stunMessageBuffer,
                                        &( stunMessageBufferLength ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_STUN_ERROR_ADD_USERNAME,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Tests error handling when Ice_CreateNextPairRequest fails to append realm.
 * This test validates that Ice_CreateNextPairRequest returns ICE_RESULT_STUN_ERROR_ADD_REALM
 * when there is insufficient space in the STUN buffer to append the realm attribute.
 * The test artificially constrains the STUN buffer size to trigger this error condition.
 */
void test_iceCreateNextPairRequest_ChannelBind_InvalidRealm( void )
{
    IceContext_t context = { 0 };
    IceCandidate_t localCandidate;
    IceCandidatePair_t candidatePair;
    uint8_t stunMessageBuffer[ 52 ];
    size_t stunMessageBufferLength = sizeof( stunMessageBuffer );
    IceResult_t result;
    char * pUsername = "username";
    size_t usernameLength = strlen( pUsername );
    char * pPassword = "password";
    size_t passwordLength = strlen( pPassword );
    char * pRealm = "realm";
    size_t realmLength = strlen( pRealm );
    char * pNonce = "nonce";
    size_t nonceLength = strlen( pNonce );
    uint8_t transactionID[] =
    {
        0xFF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B
    };

    result = Ice_Init( &( context ),
                       &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       result );

    memset( &candidatePair, 0, sizeof( IceCandidatePair_t ) );
    candidatePair.state = ICE_CANDIDATE_PAIR_STATE_CHANNEL_BIND;
    candidatePair.pLocalCandidate = &localCandidate;
    candidatePair.pRemoteCandidate = &localCandidate;
    memcpy( candidatePair.transactionId, transactionID, sizeof( transactionID ) );
    candidatePair.turnChannelNumber = 0x4000;

    localCandidate.candidateType = ICE_CANDIDATE_TYPE_RELAY;
    context.numRelayExtensions = 1;
    localCandidate.pRelayExtension = &context.pRelayExtensionsArray[ 0 ];
    memcpy( &localCandidate.pRelayExtension->iceRelayServerInfo.userName, pUsername, usernameLength );
    localCandidate.pRelayExtension->iceRelayServerInfo.userNameLength = usernameLength;
    memcpy( &localCandidate.pRelayExtension->iceRelayServerInfo.longTermPassword, pPassword, passwordLength );
    localCandidate.pRelayExtension->iceRelayServerInfo.longTermPasswordLength = passwordLength;
    memcpy( &localCandidate.pRelayExtension->iceRelayServerInfo.realm, pRealm, realmLength );
    localCandidate.pRelayExtension->iceRelayServerInfo.realmLength = realmLength;
    memcpy( &localCandidate.pRelayExtension->iceRelayServerInfo.nonce, pNonce, nonceLength );
    localCandidate.pRelayExtension->iceRelayServerInfo.nonceLength = nonceLength;

    localCandidate.endpoint.isPointToPoint = 0U;
    localCandidate.endpoint.transportAddress.family = STUN_ADDRESS_IPv4;
    localCandidate.endpoint.transportAddress.port = 0x1234;
    memcpy( ( void * ) &( localCandidate.endpoint.transportAddress.address[ 0 ] ),
            ( const void * ) ipAddress,
            sizeof( ipAddress ) );

    result = Ice_CreateNextPairRequest( &( context ),
                                        &( candidatePair ),
                                        stunMessageBuffer,
                                        &( stunMessageBufferLength ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_STUN_ERROR_ADD_REALM,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Tests error handling when Ice_CreateNextPairRequest fails to append nonce.
 * This test validates that Ice_CreateNextPairRequest returns ICE_RESULT_STUN_ERROR_ADD_NONCE
 * when there is insufficient space in the STUN buffer to append the nonce attribute.
 * The test artificially constrains the STUN buffer size to trigger this error condition.
 */
void test_iceCreateNextPairRequest_ChannelBind_InvalidNonce( void )
{
    IceContext_t context = { 0 };
    IceCandidate_t localCandidate;
    IceCandidatePair_t candidatePair;
    uint8_t stunMessageBuffer[ 64 ];
    size_t stunMessageBufferLength = sizeof( stunMessageBuffer );
    IceResult_t result;
    char * pUsername = "username";
    size_t usernameLength = strlen( pUsername );
    char * pPassword = "password";
    size_t passwordLength = strlen( pPassword );
    char * pRealm = "realm";
    size_t realmLength = strlen( pRealm );
    char * pNonce = "nonce";
    size_t nonceLength = strlen( pNonce );
    uint8_t transactionID[] =
    {
        0xFF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B
    };

    result = Ice_Init( &( context ),
                       &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       result );

    memset( &candidatePair, 0, sizeof( IceCandidatePair_t ) );
    candidatePair.state = ICE_CANDIDATE_PAIR_STATE_CHANNEL_BIND;
    candidatePair.pLocalCandidate = &localCandidate;
    candidatePair.pRemoteCandidate = &localCandidate;
    memcpy( candidatePair.transactionId, transactionID, sizeof( transactionID ) );
    candidatePair.turnChannelNumber = 0x4000;

    localCandidate.candidateType = ICE_CANDIDATE_TYPE_RELAY;
    context.numRelayExtensions = 1;
    localCandidate.pRelayExtension = &context.pRelayExtensionsArray[ 0 ];
    memcpy( &localCandidate.pRelayExtension->iceRelayServerInfo.userName, pUsername, usernameLength );
    localCandidate.pRelayExtension->iceRelayServerInfo.userNameLength = usernameLength;
    memcpy( &localCandidate.pRelayExtension->iceRelayServerInfo.longTermPassword, pPassword, passwordLength );
    localCandidate.pRelayExtension->iceRelayServerInfo.longTermPasswordLength = passwordLength;
    memcpy( &localCandidate.pRelayExtension->iceRelayServerInfo.realm, pRealm, realmLength );
    localCandidate.pRelayExtension->iceRelayServerInfo.realmLength = realmLength;
    memcpy( &localCandidate.pRelayExtension->iceRelayServerInfo.nonce, pNonce, nonceLength );
    localCandidate.pRelayExtension->iceRelayServerInfo.nonceLength = nonceLength;

    localCandidate.endpoint.isPointToPoint = 0U;
    localCandidate.endpoint.transportAddress.family = STUN_ADDRESS_IPv4;
    localCandidate.endpoint.transportAddress.port = 0x1234;
    memcpy( ( void * ) &( localCandidate.endpoint.transportAddress.address[ 0 ] ),
            ( const void * ) ipAddress,
            sizeof( ipAddress ) );

    result = Ice_CreateNextPairRequest( &( context ),
                                        &( candidatePair ),
                                        stunMessageBuffer,
                                        &( stunMessageBufferLength ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_STUN_ERROR_ADD_NONCE,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate Ice_CreateNextPairRequest functionality returns
 * CreatePermission Request packet for the candidate pair.
 */
void test_iceCreateNextPairRequest_ChannelBind_Success( void )
{
    IceContext_t context = { 0 };
    IceCandidate_t localCandidate;
    IceCandidatePair_t candidatePair;
    uint8_t stunMessageBuffer[ 108 ];
    size_t stunMessageBufferLength = sizeof( stunMessageBuffer );
    IceResult_t result;
    char * pUsername = "username";
    size_t usernameLength = strlen( pUsername );
    char * pPassword = "password";
    size_t passwordLength = strlen( pPassword );
    char * pRealm = "realm";
    size_t realmLength = strlen( pRealm );
    char * pNonce = "nonce";
    size_t nonceLength = strlen( pNonce );
    uint8_t transactionID[] =
    {
        0xFF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B
    };
    uint8_t expectedStunMessage[] =
    {
        /* STUN header: Message Type = Channel Bind Request (0x0009), Length = 88 bytes (excluding 20 bytes header). */
        0x00, 0x09, 0x00, 0x58,
        /* Magic Cookie (0x2112A442). */
        0x21, 0x12, 0xA4, 0x42,
        /* 12 bytes (96 bits) transaction ID as generated by testRandomFxn. */
        0xFF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
        /* Attribute type = XOR_PEER_ADDRESS (0x0012), Length = 8 bytes. */
        0x00, 0x12, 0x00, 0x08,
        /* Attribute Value = Family: 0x01, Port: 0x1234 IP: 192.168.1.100. XOR with 0x2112A442. */
        0x00, 0x01, 0x33, 0x26,
        0xE1, 0xBA, 0xA5, 0x26,
        /* Attribute type = CHANNEL_NUMBER (0x000C), Length = 4 bytes. */
        0x00, 0x0C, 0x00, 0x04,
        /* Attribute Value: 0x4000 and reserved 0x0000. */
        0x40, 0x00, 0x00, 0x00,
        /* Attribute type = USERNAME (0x0006), Length = 8 bytes. */
        0x00, 0x06, 0x00, 0x08,
        /* Attribute Value: "username". */
        0x75, 0x73, 0x65, 0x72,
        0x6E, 0x61, 0x6D, 0x65,
        /* Attribute type = REALM (0x0014), Length = 5 bytes. */
        0x00, 0x14, 0x00, 0x05,
        /* Attribute Value: "realm". */
        0x72, 0x65, 0x61, 0x6C,
        0x6D, 0x00, 0x00, 0x00,
        /* Attribute type = NONCE (0x0015), Length = 5 bytes. */
        0x00, 0x15, 0x00, 0x05,
        /* Attribute Value: "nonce". */
        0x6E, 0x6F, 0x6E, 0x63,
        0x65, 0x00, 0x00, 0x00,
        /* Attribute type = MESSAGE-INTEGRITY (0x0008), Length = 20 bytes. */
        0x00, 0x08, 0x00, 0x14,
        /* Attribute Value = HMAC value as computed by testHmacFxn. */
        0x70, 0x68, 0x73, 0x23,
        0x56, 0x7D, 0xD6, 0x26,
        0x8F, 0x60, 0x71, 0x70,
        0x73, 0x6A, 0x74, 0x63,
        0x78, 0x68, 0x79, 0x78,
        /* Attribute type = FINGERPRINT (0x8028), Length = 4 bytes. */
        0x80, 0x28, 0x00, 0x04,
        /* Attribute Value = 0xAC97A009 as calculated by testCrc32Fxn. */
        0x09, 0xA0, 0x97, 0xAC
    };
    size_t expectedStunMessageLength = sizeof( expectedStunMessage );

    result = Ice_Init( &( context ),
                       &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       result );

    memset( &candidatePair, 0, sizeof( IceCandidatePair_t ) );
    candidatePair.state = ICE_CANDIDATE_PAIR_STATE_CHANNEL_BIND;
    candidatePair.pLocalCandidate = &localCandidate;
    candidatePair.pRemoteCandidate = &localCandidate;
    memcpy( candidatePair.transactionId, transactionID, sizeof( transactionID ) );
    candidatePair.turnChannelNumber = 0x4000;

    localCandidate.candidateType = ICE_CANDIDATE_TYPE_RELAY;
    context.numRelayExtensions = 1;
    localCandidate.pRelayExtension = &context.pRelayExtensionsArray[ 0 ];
    memcpy( &localCandidate.pRelayExtension->iceRelayServerInfo.userName, pUsername, usernameLength );
    localCandidate.pRelayExtension->iceRelayServerInfo.userNameLength = usernameLength;
    memcpy( &localCandidate.pRelayExtension->iceRelayServerInfo.longTermPassword, pPassword, passwordLength );
    localCandidate.pRelayExtension->iceRelayServerInfo.longTermPasswordLength = passwordLength;
    memcpy( &localCandidate.pRelayExtension->iceRelayServerInfo.realm, pRealm, realmLength );
    localCandidate.pRelayExtension->iceRelayServerInfo.realmLength = realmLength;
    memcpy( &localCandidate.pRelayExtension->iceRelayServerInfo.nonce, pNonce, nonceLength );
    localCandidate.pRelayExtension->iceRelayServerInfo.nonceLength = nonceLength;

    localCandidate.endpoint.isPointToPoint = 0U;
    localCandidate.endpoint.transportAddress.family = STUN_ADDRESS_IPv4;
    localCandidate.endpoint.transportAddress.port = 0x1234;
    memcpy( ( void * ) &( localCandidate.endpoint.transportAddress.address[ 0 ] ),
            ( const void * ) ipAddress,
            sizeof( ipAddress ) );

    result = Ice_CreateNextPairRequest( &( context ),
                                        &( candidatePair ),
                                        stunMessageBuffer,
                                        &( stunMessageBufferLength ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       result );
    TEST_ASSERT_EQUAL( expectedStunMessageLength,
                       stunMessageBufferLength );
    TEST_ASSERT_EQUAL_UINT8_ARRAY( &( expectedStunMessage[ 0 ] ),
                                   &( stunMessageBuffer[ 0 ] ),
                                   expectedStunMessageLength );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate Ice_CreateNextPairRequest functionality returns
 * no next action when the state is succeed.
 */
void test_iceCreateNextPairRequest_SucceedRefreshNeeded( void )
{
    IceContext_t context = { 0 };
    IceCandidate_t localCandidate;
    IceCandidatePair_t candidatePair;
    uint8_t stunMessageBuffer[ 108 ];
    size_t stunMessageBufferLength = sizeof( stunMessageBuffer );
    IceResult_t result;
    char * pUsername = "username";
    size_t usernameLength = strlen( pUsername );
    char * pPassword = "password";
    size_t passwordLength = strlen( pPassword );
    char * pRealm = "realm";
    size_t realmLength = strlen( pRealm );
    char * pNonce = "nonce";
    size_t nonceLength = strlen( pNonce );
    uint8_t expectedStunMessage[] =
    {
        /* STUN header: Message Type = Refresh Request (0x0004), Length = 76 bytes (excluding 20 bytes header). */
        0x00, 0x04, 0x00, 0x4C,
        /* Magic Cookie (0x2112A442). */
        0x21, 0x12, 0xA4, 0x42,
        /* 12 bytes (96 bits) transaction ID as generated by testRandomFxn. */
        0x00, 0x01, 0x02, 0x03,
        0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B,
        /* Attribute type = LIFETIME (0x000D), Length = 4 bytes. */
        0x00, 0x0D, 0x00, 0x04,
        /* Attribute Value: 600 as ICE_DEFAULT_TURN_ALLOCATION_LIFETIME_SECONDS. */
        0x00, 0x00, 0x02, 0x58,
        /* Attribute type = USERNAME (0x0006), Length = 8 bytes. */
        0x00, 0x06, 0x00, 0x08,
        /* Attribute Value: "username". */
        0x75, 0x73, 0x65, 0x72,
        0x6E, 0x61, 0x6D, 0x65,
        /* Attribute type = REALM (0x0014), Length = 5 bytes. */
        0x00, 0x14, 0x00, 0x05,
        /* Attribute Value: "realm". */
        0x72, 0x65, 0x61, 0x6C,
        0x6D, 0x00, 0x00, 0x00,
        /* Attribute type = NONCE (0x0015), Length = 5 bytes. */
        0x00, 0x15, 0x00, 0x05,
        /* Attribute Value: "nonce". */
        0x6E, 0x6F, 0x6E, 0x63,
        0x65, 0x00, 0x00, 0x00,
        /* Attribute type = MESSAGE-INTEGRITY (0x0008), Length = 20 bytes. */
        0x00, 0x08, 0x00, 0x14,
        /* Attribute Value = HMAC value as computed by testHmacFxn_FixedFF. */
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        /* Attribute type = FINGERPRINT (0x8028), Length = 4 bytes. */
        0x80, 0x28, 0x00, 0x04,
        /* Attribute Value = 0x00000000 as calculated by testCrc32Fxn_Fixed. */
        0x00, 0x00, 0x00, 0x00
    };
    size_t expectedStunMessageLength = sizeof( expectedStunMessage );

    result = Ice_Init( &( context ),
                       &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       result );

    context.cryptoFunctions.hmacFxn = testHmacFxn_FixedFF;
    context.cryptoFunctions.crc32Fxn = testCrc32Fxn_Fixed;

    memset( &candidatePair, 0, sizeof( IceCandidatePair_t ) );
    candidatePair.state = ICE_CANDIDATE_PAIR_STATE_SUCCEEDED;
    candidatePair.pLocalCandidate = &localCandidate;
    candidatePair.pRemoteCandidate = &localCandidate;
    candidatePair.turnChannelNumber = 0x4000;
    candidatePair.turnPermissionExpirationSeconds = testGetCurrentTime() + 0xFFFF;

    localCandidate.candidateType = ICE_CANDIDATE_TYPE_RELAY;
    localCandidate.state = ICE_CANDIDATE_STATE_VALID;
    context.numRelayExtensions = 1;
    localCandidate.pRelayExtension = &context.pRelayExtensionsArray[ 0 ];
    localCandidate.pRelayExtension->turnAllocationExpirationSeconds = testGetCurrentTime() - 1;
    context.cryptoFunctions.randomFxn( localCandidate.transactionId, sizeof( localCandidate.transactionId ) );
    memcpy( &localCandidate.pRelayExtension->iceRelayServerInfo.userName, pUsername, usernameLength );
    localCandidate.pRelayExtension->iceRelayServerInfo.userNameLength = usernameLength;
    memcpy( &localCandidate.pRelayExtension->iceRelayServerInfo.longTermPassword, pPassword, passwordLength );
    localCandidate.pRelayExtension->iceRelayServerInfo.longTermPasswordLength = passwordLength;
    memcpy( &localCandidate.pRelayExtension->iceRelayServerInfo.realm, pRealm, realmLength );
    localCandidate.pRelayExtension->iceRelayServerInfo.realmLength = realmLength;
    memcpy( &localCandidate.pRelayExtension->iceRelayServerInfo.nonce, pNonce, nonceLength );
    localCandidate.pRelayExtension->iceRelayServerInfo.nonceLength = nonceLength;

    localCandidate.endpoint.isPointToPoint = 0U;
    localCandidate.endpoint.transportAddress.family = STUN_ADDRESS_IPv4;
    localCandidate.endpoint.transportAddress.port = 0x1234;
    memcpy( ( void * ) &( localCandidate.endpoint.transportAddress.address[ 0 ] ),
            ( const void * ) ipAddress,
            sizeof( ipAddress ) );

    result = Ice_CreateNextPairRequest( &( context ),
                                        &( candidatePair ),
                                        stunMessageBuffer,
                                        &( stunMessageBufferLength ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       result );
    TEST_ASSERT_EQUAL( expectedStunMessageLength,
                       stunMessageBufferLength );
    TEST_ASSERT_EQUAL_UINT8_ARRAY( &( expectedStunMessage[ 0 ] ),
                                   &( stunMessageBuffer[ 0 ] ),
                                   expectedStunMessageLength );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate Ice_CreateNextPairRequest functionality returns
 * no next action when the state is succeed.
 */
void test_iceCreateNextPairRequest_SucceedPermissionNeeded( void )
{
    IceContext_t context = { 0 };
    IceCandidate_t localCandidate;
    IceCandidatePair_t candidatePair;
    uint8_t stunMessageBuffer[ 108 ];
    size_t stunMessageBufferLength = sizeof( stunMessageBuffer );
    IceResult_t result;
    char * pUsername = "username";
    size_t usernameLength = strlen( pUsername );
    char * pPassword = "password";
    size_t passwordLength = strlen( pPassword );
    char * pRealm = "realm";
    size_t realmLength = strlen( pRealm );
    char * pNonce = "nonce";
    size_t nonceLength = strlen( pNonce );
    uint8_t expectedStunMessage[] =
    {
        /* STUN header: Message Type = Create Permission Request (0x0008), Length = 80 bytes (excluding 20 bytes header). */
        0x00, 0x08, 0x00, 0x50,
        /* Magic Cookie (0x2112A442). */
        0x21, 0x12, 0xA4, 0x42,
        /* 12 bytes (96 bits) transaction ID as generated by testRandomFxn. */
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
        /* Attribute type = XOR_PEER_ADDRESS (0x0012), Length = 8 bytes. */
        0x00, 0x12, 0x00, 0x08,
        /* Attribute Value = Family: 0x01, Port: 0x1234 IP: 192.168.1.100. XOR with 0x2112A442. */
        0x00, 0x01, 0x33, 0x26,
        0xE1, 0xBA, 0xA5, 0x26,
        /* Attribute type = USERNAME (0x0006), Length = 8 bytes. */
        0x00, 0x06, 0x00, 0x08,
        /* Attribute Value: "username". */
        0x75, 0x73, 0x65, 0x72,
        0x6E, 0x61, 0x6D, 0x65,
        /* Attribute type = REALM (0x0014), Length = 5 bytes. */
        0x00, 0x14, 0x00, 0x05,
        /* Attribute Value: "realm". */
        0x72, 0x65, 0x61, 0x6C,
        0x6D, 0x00, 0x00, 0x00,
        /* Attribute type = NONCE (0x0015), Length = 5 bytes. */
        0x00, 0x15, 0x00, 0x05,
        /* Attribute Value: "nonce". */
        0x6E, 0x6F, 0x6E, 0x63,
        0x65, 0x00, 0x00, 0x00,
        /* Attribute type = MESSAGE-INTEGRITY (0x0008), Length = 20 bytes. */
        0x00, 0x08, 0x00, 0x14,
        /* Attribute Value = HMAC value as computed by testHmacFxn_FixedFF. */
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        /* Attribute type = FINGERPRINT (0x8028), Length = 4 bytes. */
        0x80, 0x28, 0x00, 0x04,
        /* Attribute Value = 0x00000000 as calculated by testCrc32Fxn_Fixed. */
        0x00, 0x00, 0x00, 0x00
    };
    size_t expectedStunMessageLength = sizeof( expectedStunMessage );

    result = Ice_Init( &( context ),
                       &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       result );

    context.cryptoFunctions.hmacFxn = testHmacFxn_FixedFF;
    context.cryptoFunctions.crc32Fxn = testCrc32Fxn_Fixed;

    memset( &candidatePair, 0, sizeof( IceCandidatePair_t ) );
    candidatePair.state = ICE_CANDIDATE_PAIR_STATE_SUCCEEDED;
    candidatePair.pLocalCandidate = &localCandidate;
    candidatePair.pRemoteCandidate = &localCandidate;
    candidatePair.turnChannelNumber = 0x4000;
    candidatePair.turnPermissionExpirationSeconds = testGetCurrentTime() - 1;
    context.cryptoFunctions.randomFxn( candidatePair.transactionId, STUN_HEADER_TRANSACTION_ID_LENGTH );

    localCandidate.candidateType = ICE_CANDIDATE_TYPE_RELAY;
    localCandidate.state = ICE_CANDIDATE_STATE_VALID;
    context.numRelayExtensions = 1;
    localCandidate.pRelayExtension = &context.pRelayExtensionsArray[ 0 ];
    localCandidate.pRelayExtension->turnAllocationExpirationSeconds = testGetCurrentTime() + 0xFFFF;
    memcpy( &localCandidate.pRelayExtension->iceRelayServerInfo.userName, pUsername, usernameLength );
    localCandidate.pRelayExtension->iceRelayServerInfo.userNameLength = usernameLength;
    memcpy( &localCandidate.pRelayExtension->iceRelayServerInfo.longTermPassword, pPassword, passwordLength );
    localCandidate.pRelayExtension->iceRelayServerInfo.longTermPasswordLength = passwordLength;
    memcpy( &localCandidate.pRelayExtension->iceRelayServerInfo.realm, pRealm, realmLength );
    localCandidate.pRelayExtension->iceRelayServerInfo.realmLength = realmLength;
    memcpy( &localCandidate.pRelayExtension->iceRelayServerInfo.nonce, pNonce, nonceLength );
    localCandidate.pRelayExtension->iceRelayServerInfo.nonceLength = nonceLength;

    localCandidate.endpoint.isPointToPoint = 0U;
    localCandidate.endpoint.transportAddress.family = STUN_ADDRESS_IPv4;
    localCandidate.endpoint.transportAddress.port = 0x1234;
    memcpy( ( void * ) &( localCandidate.endpoint.transportAddress.address[ 0 ] ),
            ( const void * ) ipAddress,
            sizeof( ipAddress ) );

    result = Ice_CreateNextPairRequest( &( context ),
                                        &( candidatePair ),
                                        stunMessageBuffer,
                                        &( stunMessageBufferLength ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       result );
    TEST_ASSERT_EQUAL( expectedStunMessageLength,
                       stunMessageBufferLength );
    TEST_ASSERT_EQUAL_UINT8_ARRAY( &( expectedStunMessage[ 0 ] ),
                                   &( stunMessageBuffer[ 0 ] ),
                                   expectedStunMessageLength );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate Ice_CreateNextPairRequest functionality returns
 * no next action when the state is succeed.
 */
void test_iceCreateNextPairRequest_SucceedNoRefreshPermissionNeeded( void )
{
    IceContext_t context = { 0 };
    IceCandidate_t localCandidate;
    IceCandidatePair_t candidatePair;
    uint8_t stunMessageBuffer[ 108 ];
    size_t stunMessageBufferLength = sizeof( stunMessageBuffer );
    IceResult_t result;
    char * pUsername = "username";
    size_t usernameLength = strlen( pUsername );
    char * pPassword = "password";
    size_t passwordLength = strlen( pPassword );
    char * pRealm = "realm";
    size_t realmLength = strlen( pRealm );
    char * pNonce = "nonce";
    size_t nonceLength = strlen( pNonce );

    result = Ice_Init( &( context ),
                       &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       result );

    context.cryptoFunctions.hmacFxn = testHmacFxn_FixedFF;
    context.cryptoFunctions.crc32Fxn = testCrc32Fxn_Fixed;

    memset( &candidatePair, 0, sizeof( IceCandidatePair_t ) );
    candidatePair.state = ICE_CANDIDATE_PAIR_STATE_SUCCEEDED;
    candidatePair.pLocalCandidate = &localCandidate;
    candidatePair.pRemoteCandidate = &localCandidate;
    candidatePair.turnChannelNumber = 0x4000;
    candidatePair.turnPermissionExpirationSeconds = testGetCurrentTime() + 0xFFFF;

    localCandidate.candidateType = ICE_CANDIDATE_TYPE_RELAY;
    context.numRelayExtensions = 1;
    localCandidate.pRelayExtension = &context.pRelayExtensionsArray[ 0 ];
    localCandidate.pRelayExtension->turnAllocationExpirationSeconds = testGetCurrentTime() + 0xFFFF;
    memcpy( &localCandidate.pRelayExtension->iceRelayServerInfo.userName, pUsername, usernameLength );
    localCandidate.pRelayExtension->iceRelayServerInfo.userNameLength = usernameLength;
    memcpy( &localCandidate.pRelayExtension->iceRelayServerInfo.longTermPassword, pPassword, passwordLength );
    localCandidate.pRelayExtension->iceRelayServerInfo.longTermPasswordLength = passwordLength;
    memcpy( &localCandidate.pRelayExtension->iceRelayServerInfo.realm, pRealm, realmLength );
    localCandidate.pRelayExtension->iceRelayServerInfo.realmLength = realmLength;
    memcpy( &localCandidate.pRelayExtension->iceRelayServerInfo.nonce, pNonce, nonceLength );
    localCandidate.pRelayExtension->iceRelayServerInfo.nonceLength = nonceLength;

    localCandidate.endpoint.isPointToPoint = 0U;
    localCandidate.endpoint.transportAddress.family = STUN_ADDRESS_IPv4;
    localCandidate.endpoint.transportAddress.port = 0x1234;
    memcpy( ( void * ) &( localCandidate.endpoint.transportAddress.address[ 0 ] ),
            ( const void * ) ipAddress,
            sizeof( ipAddress ) );

    result = Ice_CreateNextPairRequest( &( context ),
                                        &( candidatePair ),
                                        stunMessageBuffer,
                                        &( stunMessageBufferLength ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_NO_NEXT_ACTION,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate ICE Close Candidate Pair functionality for Bad Parameters.
 */
void test_iceCloseCandidatePair_BadParams( void )
{
    IceContext_t context = { 0 };
    IceResult_t result;
    IceCandidatePair_t iceCandidatePair;

    result = Ice_CloseCandidatePair( NULL,
                                     &( iceCandidatePair ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_BAD_PARAM,
                       result );

    result = Ice_CloseCandidatePair( &( context ),
                                     NULL );

    TEST_ASSERT_EQUAL( ICE_RESULT_BAD_PARAM,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate ICE Close Candidate Pair functionality for invalid candidate pair.
 */
void test_iceCloseCandidatePair_InvalidCandidatePair( void )
{
    IceContext_t context = { 0 };
    IceResult_t result;
    IceCandidatePair_t iceCandidatePair;
    IceEndpoint_t endpoint = { 0 };
    IceRemoteCandidateInfo_t remoteCandidateInfo = { 0 };

    initInfo.isControlling = 0;
    result = Ice_Init( &( context ),
                       &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       result );

    endpoint.isPointToPoint = 1;
    endpoint.transportAddress.family = 0x01;
    endpoint.transportAddress.port = 8080;
    memcpy( ( void * ) &( endpoint.transportAddress.address[ 0 ] ),
            ( const void * ) ipAddress,
            sizeof( ipAddress ) );

    result = Ice_AddHostCandidate( &( context ),
                                   &( endpoint ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       result );

    remoteCandidateInfo.candidateType = ICE_CANDIDATE_TYPE_HOST;
    remoteCandidateInfo.remoteProtocol = ICE_SOCKET_PROTOCOL_UDP;
    remoteCandidateInfo.priority = 1000;
    remoteCandidateInfo.pEndpoint = &( endpoint );

    result = Ice_AddRemoteCandidate( &( context ),
                                     &( remoteCandidateInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       result );

    result = Ice_CloseCandidatePair( &( context ),
                                     &( iceCandidatePair ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_INVALID_CANDIDATE_PAIR,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate ICE Close Candidate Pair functionality.
 */
void test_iceCloseCandidatePair_Success( void )
{
    IceContext_t context = { 0 };
    IceResult_t result;
    IceEndpoint_t endpoint = { 0 };
    IceRemoteCandidateInfo_t remoteCandidateInfo = { 0 };

    initInfo.isControlling = 0;
    result = Ice_Init( &( context ),
                       &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       result );

    endpoint.isPointToPoint = 1;
    endpoint.transportAddress.family = 0x01;
    endpoint.transportAddress.port = 8080;
    memcpy( ( void * ) &( endpoint.transportAddress.address[ 0 ] ),
            ( const void * ) ipAddress,
            sizeof( ipAddress ) );

    result = Ice_AddHostCandidate( &( context ),
                                   &( endpoint ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       result );

    remoteCandidateInfo.candidateType = ICE_CANDIDATE_TYPE_HOST;
    remoteCandidateInfo.remoteProtocol = ICE_SOCKET_PROTOCOL_UDP;
    remoteCandidateInfo.priority = 1000;
    remoteCandidateInfo.pEndpoint = &( endpoint );

    result = Ice_AddRemoteCandidate( &( context ),
                                     &( remoteCandidateInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       result );

    result = Ice_CloseCandidatePair( &( context ),
                                     &( context.pCandidatePairs[0] ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       result );
    TEST_ASSERT_EQUAL( ICE_CANDIDATE_PAIR_STATE_FROZEN,
                       context.pCandidatePairs[0].state );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate ICE Close Candidate functionality for Bad Parameters.
 */
void test_iceCloseCandidate_BadParams( void )
{
    IceContext_t context = { 0 };
    IceResult_t result;
    IceCandidate_t iceCandidate;

    result = Ice_CloseCandidate( NULL,
                                 &( iceCandidate ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_BAD_PARAM,
                       result );

    result = Ice_CloseCandidate( &( context ),
                                 NULL );

    TEST_ASSERT_EQUAL( ICE_RESULT_BAD_PARAM,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate ICE Close Candidate functionality for invalid candidate.
 */
void test_iceCloseCandidate_InvalidCandidate( void )
{
    IceContext_t context = { 0 };
    IceResult_t result;
    IceCandidate_t iceCandidate;
    IceEndpoint_t endpoint = { 0 };

    initInfo.isControlling = 0;
    result = Ice_Init( &( context ),
                       &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       result );

    endpoint.isPointToPoint = 1;
    endpoint.transportAddress.family = 0x01;
    endpoint.transportAddress.port = 8080;
    memcpy( ( void * ) &( endpoint.transportAddress.address[ 0 ] ),
            ( const void * ) ipAddress,
            sizeof( ipAddress ) );

    result = Ice_AddHostCandidate( &( context ),
                                   &( endpoint ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       result );

    result = Ice_CloseCandidate( &( context ),
                                 &( iceCandidate ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_INVALID_CANDIDATE,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate ICE Close Candidate functionality with host candidate.
 */
void test_iceCloseCandidate_HostSuccess( void )
{
    IceContext_t context = { 0 };
    IceResult_t result;
    IceEndpoint_t endpoint = { 0 };

    result = Ice_Init( &( context ),
                       &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       result );

    endpoint.isPointToPoint = 1;
    endpoint.transportAddress.family = 0x01;
    endpoint.transportAddress.port = 8080;
    memcpy( ( void * ) &( endpoint.transportAddress.address[ 0 ] ),
            ( const void * ) ipAddress,
            sizeof( ipAddress ) );

    result = Ice_AddHostCandidate( &( context ),
                                   &( endpoint ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       result );
    TEST_ASSERT_EQUAL( 1,
                       context.numLocalCandidates );

    result = Ice_CloseCandidate( &( context ),
                                 &( context.pLocalCandidates[ 0 ] ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       result );
    TEST_ASSERT_EQUAL( ICE_CANDIDATE_STATE_INVALID,
                       context.pLocalCandidates[ 0 ].state );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate ICE Close Candidate functionality with relay candidate
 * in allocating state.
 */
void test_iceCloseCandidate_RelayAllocatingSuccess( void )
{
    IceContext_t context = { 0 };
    IceResult_t result;
    IceEndpoint_t endpoint = { 0 };
    char * pUsername = "username";
    size_t usernameLength = strlen( pUsername );
    char * pPassword = "password";
    size_t passwordLength = strlen( pPassword );

    result = Ice_Init( &( context ),
                       &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       result );

    endpoint.isPointToPoint = 1;
    endpoint.transportAddress.family = 0x01;
    endpoint.transportAddress.port = 8080;
    memcpy( ( void * ) &( endpoint.transportAddress.address[ 0 ] ),
            ( const void * ) ipAddress,
            sizeof( ipAddress ) );

    result = Ice_AddRelayCandidate( &( context ),
                                    &( endpoint ),
                                    pUsername,
                                    usernameLength,
                                    pPassword,
                                    passwordLength );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       result );
    TEST_ASSERT_EQUAL( 1,
                       context.numLocalCandidates );

    context.pLocalCandidates[ 0 ].state = ICE_CANDIDATE_STATE_ALLOCATING;

    result = Ice_CloseCandidate( &( context ),
                                 &( context.pLocalCandidates[ 0 ] ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       result );
    TEST_ASSERT_EQUAL( ICE_CANDIDATE_STATE_RELEASING,
                       context.pLocalCandidates[ 0 ].state );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate ICE Close Candidate functionality with relay candidate
 * in valid state.
 */
void test_iceCloseCandidate_RelayValidSuccess( void )
{
    IceContext_t context = { 0 };
    IceResult_t result;
    IceEndpoint_t endpoint = { 0 };
    char * pUsername = "username";
    size_t usernameLength = strlen( pUsername );
    char * pPassword = "password";
    size_t passwordLength = strlen( pPassword );

    result = Ice_Init( &( context ),
                       &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       result );

    endpoint.isPointToPoint = 1;
    endpoint.transportAddress.family = 0x01;
    endpoint.transportAddress.port = 8080;
    memcpy( ( void * ) &( endpoint.transportAddress.address[ 0 ] ),
            ( const void * ) ipAddress,
            sizeof( ipAddress ) );

    result = Ice_AddRelayCandidate( &( context ),
                                    &( endpoint ),
                                    pUsername,
                                    usernameLength,
                                    pPassword,
                                    passwordLength );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       result );
    TEST_ASSERT_EQUAL( 1,
                       context.numLocalCandidates );

    context.pLocalCandidates[ 0 ].state = ICE_CANDIDATE_STATE_VALID;

    result = Ice_CloseCandidate( &( context ),
                                 &( context.pLocalCandidates[ 0 ] ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       result );
    TEST_ASSERT_EQUAL( ICE_CANDIDATE_STATE_RELEASING,
                       context.pLocalCandidates[ 0 ].state );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate ICE Close Candidate functionality with relay candidate
 * in released state.
 */
void test_iceCloseCandidate_RelayReleasedSuccess( void )
{
    IceContext_t context = { 0 };
    IceResult_t result;
    IceEndpoint_t endpoint = { 0 };
    char * pUsername = "username";
    size_t usernameLength = strlen( pUsername );
    char * pPassword = "password";
    size_t passwordLength = strlen( pPassword );

    result = Ice_Init( &( context ),
                       &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       result );

    endpoint.isPointToPoint = 1;
    endpoint.transportAddress.family = 0x01;
    endpoint.transportAddress.port = 8080;
    memcpy( ( void * ) &( endpoint.transportAddress.address[ 0 ] ),
            ( const void * ) ipAddress,
            sizeof( ipAddress ) );

    result = Ice_AddRelayCandidate( &( context ),
                                    &( endpoint ),
                                    pUsername,
                                    usernameLength,
                                    pPassword,
                                    passwordLength );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       result );
    TEST_ASSERT_EQUAL( 1,
                       context.numLocalCandidates );

    context.pLocalCandidates[ 0 ].state = ICE_CANDIDATE_STATE_RELEASED;

    result = Ice_CloseCandidate( &( context ),
                                 &( context.pLocalCandidates[ 0 ] ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       result );
    TEST_ASSERT_EQUAL( ICE_CANDIDATE_STATE_RELEASED,
                       context.pLocalCandidates[ 0 ].state );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate ICE Handle TURN Packet fail functionality for Bad Parameters.
 */
void test_iceHandlTurnPacket_BadParams( void )
{
    IceContext_t context = { 0 };
    IceCandidate_t localCandidate = { 0 };
    uint8_t receivedBuffer[ 10 ];
    size_t receivedBufferLength = sizeof( receivedBuffer );
    const uint8_t * pTurnPayloadBuffer;
    uint16_t turnPayloadBufferLength;
    IceCandidatePair_t * pCandidatePair = NULL;
    IceResult_t result;

    result = Ice_HandleTurnPacket( NULL,
                                   &localCandidate,
                                   &( receivedBuffer[ 0 ] ),
                                   receivedBufferLength,
                                   &pTurnPayloadBuffer,
                                   &turnPayloadBufferLength,
                                   &pCandidatePair );

    TEST_ASSERT_EQUAL( ICE_RESULT_BAD_PARAM,
                       result );

    result = Ice_HandleTurnPacket( &context,
                                   NULL,
                                   &( receivedBuffer[ 0 ] ),
                                   receivedBufferLength,
                                   &pTurnPayloadBuffer,
                                   &turnPayloadBufferLength,
                                   &pCandidatePair );

    TEST_ASSERT_EQUAL( ICE_RESULT_BAD_PARAM,
                       result );

    result = Ice_HandleTurnPacket( &context,
                                   &localCandidate,
                                   NULL,
                                   receivedBufferLength,
                                   &pTurnPayloadBuffer,
                                   &turnPayloadBufferLength,
                                   &pCandidatePair );

    TEST_ASSERT_EQUAL( ICE_RESULT_BAD_PARAM,
                       result );

    result = Ice_HandleTurnPacket( &context,
                                   &localCandidate,
                                   &( receivedBuffer[ 0 ] ),
                                   receivedBufferLength,
                                   NULL,
                                   &turnPayloadBufferLength,
                                   &pCandidatePair );

    TEST_ASSERT_EQUAL( ICE_RESULT_BAD_PARAM,
                       result );

    result = Ice_HandleTurnPacket( &context,
                                   &localCandidate,
                                   &( receivedBuffer[ 0 ] ),
                                   receivedBufferLength,
                                   &pTurnPayloadBuffer,
                                   NULL,
                                   &pCandidatePair );

    TEST_ASSERT_EQUAL( ICE_RESULT_BAD_PARAM,
                       result );

    result = Ice_HandleTurnPacket( &context,
                                   &localCandidate,
                                   &( receivedBuffer[ 0 ] ),
                                   receivedBufferLength,
                                   &pTurnPayloadBuffer,
                                   &turnPayloadBufferLength,
                                   NULL );

    TEST_ASSERT_EQUAL( ICE_RESULT_BAD_PARAM,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate ICE Handle TURN Packet fail functionality for less data.
 */
void test_iceHandlTurnPacket_ReceivedLessData( void )
{
    IceContext_t context = { 0 };
    IceCandidate_t localCandidate = { 0 };
    uint8_t receivedBuffer[ 10 ];
    size_t receivedBufferLength = ICE_TURN_CHANNEL_DATA_HEADER_LENGTH - 1;
    const uint8_t * pTurnPayloadBuffer;
    uint16_t turnPayloadBufferLength;
    IceCandidatePair_t * pCandidatePair = NULL;
    IceResult_t result;

    result = Ice_HandleTurnPacket( &context,
                                   &localCandidate,
                                   &( receivedBuffer[ 0 ] ),
                                   receivedBufferLength,
                                   &pTurnPayloadBuffer,
                                   &turnPayloadBufferLength,
                                   &pCandidatePair );

    TEST_ASSERT_EQUAL( ICE_RESULT_DATA_TOO_SMALL,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate ICE Handle TURN Packet fail functionality for
 * not relay candidate.
 */
void test_iceHandlTurnPacket_NotRelayCandidate( void )
{
    IceContext_t context = { 0 };
    IceCandidate_t localCandidate = { 0 };
    uint8_t receivedBuffer[ 10 ];
    size_t receivedBufferLength = sizeof( receivedBuffer );
    const uint8_t * pTurnPayloadBuffer;
    uint16_t turnPayloadBufferLength;
    IceCandidatePair_t * pCandidatePair = NULL;
    IceResult_t result;

    memset( &localCandidate, 0, sizeof( IceCandidate_t ) );
    localCandidate.candidateType = ICE_CANDIDATE_TYPE_HOST;
    result = Ice_HandleTurnPacket( &context,
                                   &localCandidate,
                                   &( receivedBuffer[ 0 ] ),
                                   receivedBufferLength,
                                   &pTurnPayloadBuffer,
                                   &turnPayloadBufferLength,
                                   &pCandidatePair );

    TEST_ASSERT_EQUAL( ICE_RESULT_TURN_PREFIX_NOT_REQUIRED,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validates the failure handling of TURN packets for
 * a relay candidate that is not ready.
 */
void test_iceHandlTurnPacket_CandidateNotReady( void )
{
    IceContext_t context = { 0 };
    IceCandidate_t localCandidate = { 0 };
    uint8_t receivedBuffer[ 10 ];
    size_t receivedBufferLength = sizeof( receivedBuffer );
    const uint8_t * pTurnPayloadBuffer;
    uint16_t turnPayloadBufferLength;
    IceCandidatePair_t * pCandidatePair = NULL;
    IceResult_t result;

    memset( &localCandidate, 0, sizeof( IceCandidate_t ) );
    localCandidate.candidateType = ICE_CANDIDATE_TYPE_RELAY;
    localCandidate.state = ICE_CANDIDATE_STATE_ALLOCATING;
    result = Ice_HandleTurnPacket( &context,
                                   &localCandidate,
                                   &( receivedBuffer[ 0 ] ),
                                   receivedBufferLength,
                                   &pTurnPayloadBuffer,
                                   &turnPayloadBufferLength,
                                   &pCandidatePair );

    TEST_ASSERT_EQUAL( ICE_RESULT_TURN_PREFIX_NOT_REQUIRED,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validates the failure handling of non TURN packets.
 */
void test_iceHandlTurnPacket_NoTurnChannelHeader( void )
{
    IceContext_t context = { 0 };
    IceCandidate_t localCandidate = { 0 };
    const uint8_t * pTurnPayloadBuffer;
    uint16_t turnPayloadBufferLength;
    IceCandidatePair_t * pCandidatePair = NULL;
    IceResult_t result;
    uint8_t receivedBuffer[] = {
        /* Create a packet with the first two bytes outside the range 0x4000 to 0x4FFF. */
        0x00, 0x01,
        0x02, 0x03
    };
    size_t receivedBufferLength = sizeof( receivedBuffer );

    memset( &localCandidate, 0, sizeof( IceCandidate_t ) );
    localCandidate.candidateType = ICE_CANDIDATE_TYPE_RELAY;
    localCandidate.state = ICE_CANDIDATE_STATE_VALID;
    result = Ice_HandleTurnPacket( &context,
                                   &localCandidate,
                                   &( receivedBuffer[ 0 ] ),
                                   receivedBufferLength,
                                   &pTurnPayloadBuffer,
                                   &turnPayloadBufferLength,
                                   &pCandidatePair );

    TEST_ASSERT_EQUAL( ICE_RESULT_TURN_PREFIX_NOT_REQUIRED,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validates the handling of TURN packet failures when the
 * data channel length is larger than the actual packet size.
 */
void test_iceHandlTurnPacket_LargeTurnHeaderLength( void )
{
    IceContext_t context = { 0 };
    IceCandidate_t localCandidate = { 0 };
    const uint8_t * pTurnPayloadBuffer;
    uint16_t turnPayloadBufferLength;
    IceCandidatePair_t * pCandidatePair = NULL;
    IceResult_t result;
    uint8_t receivedBuffer[] = {
        0x40, 0x01,
        /* Create a packet with length 16. */
        0x00, 0x10,
        0x02, 0x03,
    };
    size_t receivedBufferLength = sizeof( receivedBuffer );

    result = Ice_Init( &( context ),
                       &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       result );

    memset( &localCandidate, 0, sizeof( IceCandidate_t ) );
    localCandidate.candidateType = ICE_CANDIDATE_TYPE_RELAY;
    localCandidate.state = ICE_CANDIDATE_STATE_VALID;
    result = Ice_HandleTurnPacket( &context,
                                   &localCandidate,
                                   &( receivedBuffer[ 0 ] ),
                                   receivedBufferLength,
                                   &pTurnPayloadBuffer,
                                   &turnPayloadBufferLength,
                                   &pCandidatePair );

    TEST_ASSERT_EQUAL( ICE_RESULT_TURN_LENGTH_INVALID,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validates the handling of TURN packet failures when the
 * transport address doesn't match any candidate pair.
 */
void test_iceHandlTurnPacket_NoMatchTransportAddress( void )
{
    IceContext_t context = { 0 };
    IceCandidate_t localCandidate1 = { 0 };
    IceCandidate_t localCandidate2 = { 0 };
    IceEndpoint_t endpoint1;
    IceEndpoint_t endpoint2;
    const uint8_t * pTurnPayloadBuffer;
    uint16_t turnPayloadBufferLength;
    IceCandidatePair_t * pCandidatePair = NULL;
    IceResult_t result;
    uint8_t receivedBuffer[] = {
        0x40, 0x01,
        0x00, 0x01,
        0x02, 0x03,
    };
    size_t receivedBufferLength = sizeof( receivedBuffer );

    result = Ice_Init( &( context ),
                       &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       result );

    memset( &endpoint1, 0, sizeof( IceEndpoint_t ) );
    endpoint1.transportAddress.address[ 0 ] = 0x00;
    endpoint1.transportAddress.address[ 1 ] = 0x01;
    endpoint1.transportAddress.address[ 2 ] = 0x02;
    endpoint1.transportAddress.address[ 3 ] = 0x03;
    memset( &endpoint2, 0, sizeof( IceEndpoint_t ) );
    endpoint2.transportAddress.address[ 0 ] = 0x03;
    endpoint2.transportAddress.address[ 1 ] = 0x02;
    endpoint2.transportAddress.address[ 2 ] = 0x01;
    endpoint2.transportAddress.address[ 3 ] = 0x00;

    memset( &localCandidate1, 0, sizeof( IceCandidate_t ) );
    localCandidate1.candidateType = ICE_CANDIDATE_TYPE_RELAY;
    localCandidate1.state = ICE_CANDIDATE_STATE_VALID;
    memcpy( &localCandidate1.endpoint, &endpoint1, sizeof( IceEndpoint_t ) );
    memset( &localCandidate2, 0, sizeof( IceCandidate_t ) );
    localCandidate2.candidateType = ICE_CANDIDATE_TYPE_RELAY;
    localCandidate2.state = ICE_CANDIDATE_STATE_VALID;
    memcpy( &localCandidate2.endpoint, &endpoint2, sizeof( IceEndpoint_t ) );

    context.numCandidatePairs = 1;
    context.pCandidatePairs[ 0 ].pLocalCandidate = &localCandidate1;
    result = Ice_HandleTurnPacket( &context,
                                   &localCandidate2,
                                   &( receivedBuffer[ 0 ] ),
                                   receivedBufferLength,
                                   &pTurnPayloadBuffer,
                                   &turnPayloadBufferLength,
                                   &pCandidatePair );

    TEST_ASSERT_EQUAL( ICE_RESULT_TURN_CANDIDATE_PAIR_NOT_FOUND,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validates the handling of TURN packet failures when the
 * TURN channel number doesn't match any candidate pair.
 */
void test_iceHandlTurnPacket_NoMatchTurnChannelNumber( void )
{
    IceContext_t context = { 0 };
    IceCandidate_t localCandidate1 = { 0 };
    IceEndpoint_t endpoint1;
    const uint8_t * pTurnPayloadBuffer;
    uint16_t turnPayloadBufferLength;
    IceCandidatePair_t * pCandidatePair = NULL;
    IceResult_t result;
    uint8_t receivedBuffer[] = {
        0x40, 0x01,
        0x00, 0x01,
        0x02, 0x03,
    };
    size_t receivedBufferLength = sizeof( receivedBuffer );

    result = Ice_Init( &( context ),
                       &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       result );

    memset( &endpoint1, 0, sizeof( IceEndpoint_t ) );
    endpoint1.transportAddress.address[ 0 ] = 0x00;
    endpoint1.transportAddress.address[ 1 ] = 0x01;
    endpoint1.transportAddress.address[ 2 ] = 0x02;
    endpoint1.transportAddress.address[ 3 ] = 0x03;

    memset( &localCandidate1, 0, sizeof( IceCandidate_t ) );
    localCandidate1.candidateType = ICE_CANDIDATE_TYPE_RELAY;
    localCandidate1.state = ICE_CANDIDATE_STATE_VALID;
    memcpy( &localCandidate1.endpoint, &endpoint1, sizeof( IceEndpoint_t ) );

    context.numCandidatePairs = 1;
    context.pCandidatePairs[ 0 ].pLocalCandidate = &localCandidate1;
    context.pCandidatePairs[ 0 ].turnChannelNumber = 0x40FF;
    result = Ice_HandleTurnPacket( &context,
                                   &localCandidate1,
                                   &( receivedBuffer[ 0 ] ),
                                   receivedBufferLength,
                                   &pTurnPayloadBuffer,
                                   &turnPayloadBufferLength,
                                   &pCandidatePair );

    TEST_ASSERT_EQUAL( ICE_RESULT_TURN_CANDIDATE_PAIR_NOT_FOUND,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validates TURN packet handling when a matching candidate
 * pair is found.
 */
void test_iceHandlTurnPacket_Success( void )
{
    IceContext_t context = { 0 };
    IceCandidate_t localCandidate1 = { 0 };
    IceEndpoint_t endpoint1;
    const uint8_t * pTurnPayloadBuffer;
    uint16_t turnPayloadBufferLength;
    IceCandidatePair_t * pCandidatePair = NULL;
    IceResult_t result;
    uint8_t receivedBuffer[] = {
        0x40, 0x01,
        0x00, 0x02,
        0x02, 0x03,
    };
    size_t receivedBufferLength = sizeof( receivedBuffer );

    result = Ice_Init( &( context ),
                       &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       result );

    memset( &endpoint1, 0, sizeof( IceEndpoint_t ) );
    endpoint1.transportAddress.address[ 0 ] = 0x00;
    endpoint1.transportAddress.address[ 1 ] = 0x01;
    endpoint1.transportAddress.address[ 2 ] = 0x02;
    endpoint1.transportAddress.address[ 3 ] = 0x03;

    memset( &localCandidate1, 0, sizeof( IceCandidate_t ) );
    localCandidate1.candidateType = ICE_CANDIDATE_TYPE_RELAY;
    localCandidate1.state = ICE_CANDIDATE_STATE_VALID;
    memcpy( &localCandidate1.endpoint, &endpoint1, sizeof( IceEndpoint_t ) );

    context.numCandidatePairs = 1;
    context.pCandidatePairs[ 0 ].pLocalCandidate = &localCandidate1;
    context.pCandidatePairs[ 0 ].turnChannelNumber = 0x4001;
    result = Ice_HandleTurnPacket( &context,
                                   &localCandidate1,
                                   &( receivedBuffer[ 0 ] ),
                                   receivedBufferLength,
                                   &pTurnPayloadBuffer,
                                   &turnPayloadBufferLength,
                                   &pCandidatePair );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       result );
    TEST_ASSERT_EQUAL_PTR( &( receivedBuffer[ ICE_TURN_CHANNEL_DATA_HEADER_LENGTH ] ),
                           pTurnPayloadBuffer );
    TEST_ASSERT_EQUAL( 2,
                       turnPayloadBufferLength );
    TEST_ASSERT_EQUAL_PTR( &( context.pCandidatePairs[ 0 ] ),
                           pCandidatePair );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate ICE Handle Stun Packet fail functionality for Bad Parameters.
 */
void test_iceHandleStunPacket_BadParams( void )
{
    IceContext_t context = { 0 };
    uint8_t stunMessage[ 10 ];
    size_t stunMessageLength = sizeof( stunMessage );
    IceCandidate_t localCandidate = { 0 };
    IceEndpoint_t endpoint = { 0 };
    uint8_t * transactionId[ STUN_HEADER_TRANSACTION_ID_LENGTH ];
    IceCandidatePair_t * pCandidatePair = NULL;
    IceHandleStunPacketResult_t result;

    result = Ice_HandleStunPacket( NULL,
                                   &( stunMessage[ 0 ] ),
                                   stunMessageLength,
                                   &( localCandidate ),
                                   &( endpoint ),
                                   &( transactionId[ 0 ] ),
                                   &( pCandidatePair ) );

    TEST_ASSERT_EQUAL( ICE_HANDLE_STUN_PACKET_RESULT_BAD_PARAM,
                       result );

    result = Ice_HandleStunPacket( &( context ),
                                   NULL,
                                   0,
                                   &( localCandidate ),
                                   &( endpoint ),
                                   &( transactionId[ 0 ] ),
                                   &( pCandidatePair ) );

    TEST_ASSERT_EQUAL( ICE_HANDLE_STUN_PACKET_RESULT_BAD_PARAM,
                       result );

    result = Ice_HandleStunPacket( &( context ),
                                   &( stunMessage[ 0 ] ),
                                   stunMessageLength,
                                   NULL,
                                   &( endpoint ),
                                   &( transactionId[ 0 ] ),
                                   &( pCandidatePair ) );

    TEST_ASSERT_EQUAL( ICE_HANDLE_STUN_PACKET_RESULT_BAD_PARAM,
                       result );

    result = Ice_HandleStunPacket( &( context ),
                                   &( stunMessage[ 0 ] ),
                                   stunMessageLength,
                                   &( localCandidate ),
                                   NULL,
                                   &( transactionId[ 0 ] ),
                                   &( pCandidatePair ) );

    TEST_ASSERT_EQUAL( ICE_HANDLE_STUN_PACKET_RESULT_BAD_PARAM,
                       result );

    result = Ice_HandleStunPacket( &( context ),
                                   &( stunMessage[ 0 ] ),
                                   stunMessageLength,
                                   &( localCandidate ),
                                   &( endpoint ),
                                   NULL,
                                   &( pCandidatePair ) );

    TEST_ASSERT_EQUAL( ICE_HANDLE_STUN_PACKET_RESULT_BAD_PARAM,
                       result );

    result = Ice_HandleStunPacket( &( context ),
                                   &( stunMessage[ 0 ] ),
                                   stunMessageLength,
                                   &( localCandidate ),
                                   &( endpoint ),
                                   &( transactionId[ 0 ] ),
                                   NULL );

    TEST_ASSERT_EQUAL( ICE_HANDLE_STUN_PACKET_RESULT_BAD_PARAM,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate ICE Handle Stun Packet fail functionality for Deserialize Errors.
 */
void test_iceHandleStunPacket_DeserializeError( void )
{
    IceContext_t context = { 0 };
    uint8_t stunMessage[ 10 ]; /* Too small to be able to contain a Stun message. */
    size_t stunMessageLength = sizeof( stunMessage );
    IceEndpoint_t endpoint = { 0 };
    uint8_t * transactionId[ STUN_HEADER_TRANSACTION_ID_LENGTH ];
    IceCandidatePair_t * pCandidatePair = NULL;
    IceHandleStunPacketResult_t result;
    IceCandidate_t localCandidate = { 0 };

    result = Ice_HandleStunPacket( &( context ),
                                   &( stunMessage[ 0 ] ),
                                   stunMessageLength,
                                   &( localCandidate ),
                                   &( endpoint ),
                                   &( transactionId[ 0 ] ),
                                   &( pCandidatePair ) );

    TEST_ASSERT_EQUAL( ICE_HANDLE_STUN_PACKET_RESULT_NOT_STUN_PACKET,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate ICE Handle Stun Packet functionality for Binding Request Type for Unknown Attribute.
 */
void test_iceHandleStunPacket_BindingRequest_Invalid( void )
{
    IceContext_t context = { 0 };
    IceCandidate_t localCandidate = { 0 };
    IceEndpoint_t remoteEndpoint = { 0 };
    IceRemoteCandidateInfo_t remoteCandidateInfo = { 0 };
    uint8_t * pTransactionId;
    IceCandidatePair_t * pCandidatePair = NULL;
    IceResult_t iceResult;
    IceHandleStunPacketResult_t result;
    uint8_t stunMessage[] =
    {
        /* STUN header: Message Type = Binding Request (0x0001), Length = 84 bytes (excluding 20 bytes header). */
        0x00, 0x01, 0x00, 0x54,
        /* Magic Cookie (0x2112A442). */
        0x21, 0x12, 0xA4, 0x42,
        /* 12 bytes (96 bits) transaction ID as generated by testRandomFxn. */
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
        /* Attribute type = USERNAME (0x0006), Length = 16 bytes. */
        0x00, 0x06, 0x00, 0x10,
        /* Attribute Value = "combinedUsername". */
        0x63, 0x6F, 0x6D, 0x62, 0x69, 0x6E, 0x65, 0x64,
        0x55, 0x73, 0x65, 0x72, 0x6E, 0x61, 0x6D, 0x65,
        /* Attribute type = PRIORITY (0x0024), Length = 4 bytes. */
        0x00, 0x24, 0x00, 0x04,
        /* Attribute Value = 0x7E0000FF. */
        0x7E, 0x00, 0x00, 0xFF,
        /* Attribute type = ICE-CONTROLLING (0x802A), Length = 8 bytes. */
        0x80, 0x2A, 0x00, 0x08,
        /* Attribute Value = 0x0706050403020100. */
        0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00,
        /* Attribute Type = USE-CANDIDATE (0x0025), Length = 0 bytes. */
        0x00, 0x25, 0x00, 0x00,
        /* Attribute type = MESSAGE-INTEGRITY (0x0008), Length = 20 bytes. */
        0x00, 0x08, 0x00, 0x14,
        /* Attribute Value = HMAC value as computed by testHmacFxn. */
        0x6C, 0x6E, 0x63, 0x25,
        0x4D, 0x42, 0xC5, 0x31,
        0x73, 0x76, 0x6D, 0x71,
        0x60, 0x69, 0x69, 0x64,
        0x69, 0x65, 0x5A, 0x6A,
        /* Attribute type = FINGERPRINT (0x8028), Length = 4 bytes. */
        0x80, 0x28, 0x00, 0x04,
        /* Attribute Value: 0x9A8841E2 as calculated by testCrc32Fxn. */
        0x9A, 0x88, 0x41, 0xE2,
        /* Attribute type = UNKNOWN , Length = 4 bytes. */                      /* This Unknown Attribute results in Deserialization Error */
        0x40, 0x28, 0x00, 0x04,
        /* Attribute Value: 0x010267E8. */
        0x01, 0x02, 0x67, 0xE8,
    };
    size_t stunMessageLength = sizeof( stunMessage );

    iceResult = Ice_Init( &( context ),
                          &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       iceResult );

    localCandidate.endpoint.isPointToPoint = 1;
    localCandidate.endpoint.transportAddress.family = 0x01;
    localCandidate.endpoint.transportAddress.port = 8080;
    memcpy( ( void * ) &( localCandidate.endpoint.transportAddress.address[ 0 ] ),
            ( const void * ) ipAddress,
            sizeof( ipAddress ) );

    remoteEndpoint = localCandidate.endpoint; /* For simplicity, use the same endpoint for remote. */

    iceResult = Ice_AddHostCandidate( &( context ),
                                      &( localCandidate.endpoint ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       iceResult );

    remoteCandidateInfo.candidateType = ICE_CANDIDATE_TYPE_HOST;
    remoteCandidateInfo.remoteProtocol = ICE_SOCKET_PROTOCOL_UDP;
    remoteCandidateInfo.priority = 1000;
    remoteCandidateInfo.pEndpoint = &( remoteEndpoint );

    iceResult = Ice_AddRemoteCandidate( &( context ),
                                        &( remoteCandidateInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       iceResult );

    result = Ice_HandleStunPacket( &( context ),
                                   &( stunMessage[ 0 ] ),
                                   stunMessageLength,
                                   &( localCandidate ),
                                   &( remoteEndpoint ),
                                   &( pTransactionId ),
                                   &( pCandidatePair ) );

    TEST_ASSERT_EQUAL( ICE_HANDLE_STUN_PACKET_RESULT_DESERIALIZE_ERROR,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate ICE Handle Stun Packet functionality for Binding Request Type for No Candidate Pair.
 */
void test_iceHandleStunPacket_BindingRequest_NoCandidatePair( void )
{
    IceContext_t context = { 0 };
    IceCandidate_t localCandidate = { 0 };
    IceEndpoint_t remoteEndpoint = { 0 };
    IceRemoteCandidateInfo_t remoteCandidateInfo = { 0 };
    uint8_t * pTransactionId;
    IceCandidatePair_t * pCandidatePair = NULL;
    IceResult_t iceResult;
    IceHandleStunPacketResult_t result;
    uint8_t stunMessage[] =
    {
        /* STUN header: Message Type = Binding Request (0x0001), Length = 76 bytes (excluding 20 bytes header). */
        0x00, 0x01, 0x00, 0x4C,
        /* Magic Cookie (0x2112A442). */
        0x21, 0x12, 0xA4, 0x42,
        /* 12 bytes (96 bits) transaction ID as generated by testRandomFxn. */
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
        /* Attribute type = USERNAME (0x0006), Length = 16 bytes. */
        0x00, 0x06, 0x00, 0x10,
        /* Attribute Value = "combinedUsername". */
        0x63, 0x6F, 0x6D, 0x62, 0x69, 0x6E, 0x65, 0x64,
        0x55, 0x73, 0x65, 0x72, 0x6E, 0x61, 0x6D, 0x65,
        /* Attribute type = PRIORITY (0x0024), Length = 4 bytes. */
        0x00, 0x24, 0x00, 0x04,
        /* Attribute Value = 0x7E0000FF. */
        0x7E, 0x00, 0x00, 0xFF,
        /* Attribute type = ICE-CONTROLLING (0x802A), Length = 8 bytes. */
        0x80, 0x2A, 0x00, 0x08,
        /* Attribute Value = 0x0706050403020100. */
        0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00,
        /* Attribute Type = USE-CANDIDATE (0x0025), Length = 0 bytes. */
        0x00, 0x25, 0x00, 0x00,
        /* Attribute type = MESSAGE-INTEGRITY (0x0008), Length = 20 bytes. */
        0x00, 0x08, 0x00, 0x14,
        /* Attribute Value = HMAC value as computed by testHmacFxn. */
        0x6C, 0x6E, 0x63, 0x25,
        0x4D, 0x42, 0xC5, 0x31,
        0x73, 0x76, 0x6D, 0x71,
        0x60, 0x69, 0x69, 0x64,
        0x69, 0x65, 0x5A, 0x6A,
        /* Attribute type = FINGERPRINT (0x8028), Length = 4 bytes. */
        0x80, 0x28, 0x00, 0x04,
        /* Attribute Value: 0x9A8841E2 as calculated by testCrc32Fxn. */
        0x9A, 0x88, 0x41, 0xE2,
    };
    size_t stunMessageLength = sizeof( stunMessage );

    iceResult = Ice_Init( &( context ),
                          &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       iceResult );

    localCandidate.endpoint.isPointToPoint = 1;
    localCandidate.endpoint.transportAddress.family = 0x01;
    localCandidate.endpoint.transportAddress.port = 8080;
    memcpy( ( void * ) &( localCandidate.endpoint.transportAddress.address[ 0 ] ),
            ( const void * ) ipAddress,
            sizeof( ipAddress ) );

    remoteEndpoint = localCandidate.endpoint; /* For simplicity, use the same endpoint for remote. */

    remoteCandidateInfo.candidateType = ICE_CANDIDATE_TYPE_HOST;
    remoteCandidateInfo.remoteProtocol = ICE_SOCKET_PROTOCOL_UDP;
    remoteCandidateInfo.priority = 1000;
    remoteCandidateInfo.pEndpoint = &( remoteEndpoint );

    iceResult = Ice_AddRemoteCandidate( &( context ),
                                        &( remoteCandidateInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       iceResult );

    result = Ice_HandleStunPacket( &( context ),
                                   &( stunMessage[ 0 ] ),
                                   stunMessageLength,
                                   &( localCandidate ),
                                   &( remoteEndpoint ),
                                   &( pTransactionId ),
                                   &( pCandidatePair ) );

    TEST_ASSERT_EQUAL( ICE_HANDLE_STUN_PACKET_RESULT_CANDIDATE_PAIR_NOT_FOUND,
                       result );
    TEST_ASSERT_EQUAL_PTR( &( stunMessage[ 8 ] ),
                           pTransactionId );
    TEST_ASSERT_EQUAL( 0, context.numCandidatePairs );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate ICE Handle Stun Packet functionality for Binding Request Type where no connectivity check request has been sent.
 */
void test_iceHandleStunPacket_BindingRequest_TriggeredCheck( void )
{
    IceContext_t context = { 0 };
    IceCandidate_t localCandidate = { 0 };
    IceEndpoint_t remoteEndpoint = { 0 };
    IceRemoteCandidateInfo_t remoteCandidateInfo = { 0 };
    uint8_t * pTransactionId;
    IceCandidatePair_t * pCandidatePair = NULL;
    IceResult_t iceResult;
    IceHandleStunPacketResult_t result;
    uint8_t stunMessage[] =
    {
        /* STUN header: Message Type = Binding Request (0x0001), Length = 76 bytes (excluding 20 bytes header). */
        0x00, 0x01, 0x00, 0x4C,
        /* Magic Cookie (0x2112A442). */
        0x21, 0x12, 0xA4, 0x42,
        /* 12 bytes (96 bits) transaction ID as generated by testRandomFxn. */
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
        /* Attribute type = USERNAME (0x0006), Length = 16 bytes. */
        0x00, 0x06, 0x00, 0x10,
        /* Attribute Value = "combinedUsername". */
        0x63, 0x6F, 0x6D, 0x62, 0x69, 0x6E, 0x65, 0x64,
        0x55, 0x73, 0x65, 0x72, 0x6E, 0x61, 0x6D, 0x65,
        /* Attribute type = PRIORITY (0x0024), Length = 4 bytes. */
        0x00, 0x24, 0x00, 0x04,
        /* Attribute Value = 0x7E0000FF. */
        0x7E, 0x00, 0x00, 0xFF,
        /* Attribute type = ICE-CONTROLLING (0x802A), Length = 8 bytes. */
        0x80, 0x2A, 0x00, 0x08,
        /* Attribute Value = 0x0706050403020100. */
        0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00,
        /* Attribute Type = USE-CANDIDATE (0x0025), Length = 0 bytes. */
        0x00, 0x25, 0x00, 0x00,
        /* Attribute type = MESSAGE-INTEGRITY (0x0008), Length = 20 bytes. */
        0x00, 0x08, 0x00, 0x14,
        /* Attribute Value = HMAC value as computed by testHmacFxn. */
        0x6C, 0x6E, 0x63, 0x25,
        0x4D, 0x42, 0xC5, 0x31,
        0x73, 0x76, 0x6D, 0x71,
        0x60, 0x69, 0x69, 0x64,
        0x69, 0x65, 0x5A, 0x6A,
        /* Attribute type = FINGERPRINT (0x8028), Length = 4 bytes. */
        0x80, 0x28, 0x00, 0x04,
        /* Attribute Value: 0x9A8841E2 as calculated by testCrc32Fxn. */
        0x9A, 0x88, 0x41, 0xE2,
    };
    size_t stunMessageLength = sizeof( stunMessage );

    iceResult = Ice_Init( &( context ),
                          &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       iceResult );

    localCandidate.endpoint.isPointToPoint = 1;
    localCandidate.endpoint.transportAddress.family = 0x01;
    localCandidate.endpoint.transportAddress.port = 8080;
    memcpy( ( void * ) &( localCandidate.endpoint.transportAddress.address[ 0 ] ),
            ( const void * ) ipAddress,
            sizeof( ipAddress ) );

    remoteEndpoint = localCandidate.endpoint; /* For simplicity, use the same endpoint for remote. */

    iceResult = Ice_AddHostCandidate( &( context ),
                                      &( localCandidate.endpoint ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       iceResult );

    remoteCandidateInfo.candidateType = ICE_CANDIDATE_TYPE_HOST;
    remoteCandidateInfo.remoteProtocol = ICE_SOCKET_PROTOCOL_UDP;
    remoteCandidateInfo.priority = 1000;
    remoteCandidateInfo.pEndpoint = &( remoteEndpoint );

    iceResult = Ice_AddRemoteCandidate( &( context ),
                                        &( remoteCandidateInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       iceResult );

    result = Ice_HandleStunPacket( &( context ),
                                   &( stunMessage[ 0 ] ),
                                   stunMessageLength,
                                   &( localCandidate ),
                                   &( remoteEndpoint ),
                                   &( pTransactionId ),
                                   &( pCandidatePair ) );

    TEST_ASSERT_EQUAL( ICE_HANDLE_STUN_PACKET_RESULT_SEND_TRIGGERED_CHECK,
                       result );
    TEST_ASSERT_EQUAL_PTR( &( stunMessage[ 8 ] ),
                           pTransactionId );
    TEST_ASSERT_EQUAL_PTR( ICE_STUN_REQUEST_SENT_FLAG | ICE_STUN_REQUEST_RECEIVED_FLAG | ICE_STUN_RESPONSE_SENT_FLAG,
                           pCandidatePair->connectivityCheckFlags );

    /* Verify local candidate Info in the Candidate Pair. */
    TEST_ASSERT_EQUAL( ICE_CANDIDATE_TYPE_HOST,
                       pCandidatePair->pLocalCandidate->candidateType );
    TEST_ASSERT_EQUAL( 0,
                       pCandidatePair->pLocalCandidate->isRemote );
    TEST_ASSERT_EQUAL( HOST_CANDIDATE_PRIORITY,
                       pCandidatePair->pLocalCandidate->priority );
    TEST_ASSERT_EQUAL( ICE_SOCKET_PROTOCOL_NONE,
                       pCandidatePair->pLocalCandidate->remoteProtocol );
    TEST_ASSERT_EQUAL( ICE_CANDIDATE_STATE_VALID,
                       pCandidatePair->pLocalCandidate->state );
    TEST_ASSERT_EQUAL( 1,
                       pCandidatePair->pLocalCandidate->endpoint.isPointToPoint );
    TEST_ASSERT_EQUAL( 1,
                       pCandidatePair->pLocalCandidate->endpoint.transportAddress.family );
    TEST_ASSERT_EQUAL( 8080,
                       pCandidatePair->pLocalCandidate->endpoint.transportAddress.port );
    TEST_ASSERT_EQUAL_UINT8_ARRAY( ipAddress,
                                   pCandidatePair->pLocalCandidate->endpoint.transportAddress.address, sizeof( ipAddress ) );

    /* Verify remote candidate Info in the Candidate Pair. */
    TEST_ASSERT_EQUAL( ICE_CANDIDATE_TYPE_HOST,
                       pCandidatePair->pRemoteCandidate->candidateType );
    TEST_ASSERT_EQUAL( 1,
                       pCandidatePair->pRemoteCandidate->isRemote );
    TEST_ASSERT_EQUAL( ICE_SOCKET_PROTOCOL_UDP,
                       pCandidatePair->pRemoteCandidate->remoteProtocol );
    TEST_ASSERT_EQUAL( 1000,
                       pCandidatePair->pRemoteCandidate->priority );
    TEST_ASSERT_EQUAL( 1,
                       pCandidatePair->pRemoteCandidate->endpoint.isPointToPoint );
    TEST_ASSERT_EQUAL( 8080,
                       pCandidatePair->pRemoteCandidate->endpoint.transportAddress.port );
    TEST_ASSERT_EQUAL_UINT8_ARRAY( ipAddress,
                                   pCandidatePair->pRemoteCandidate->endpoint.transportAddress.address, sizeof( ipAddress ) );
    TEST_ASSERT_EQUAL( 1,
                       pCandidatePair->pRemoteCandidate->endpoint.transportAddress.family );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate ICE Handle Stun Packet functionality for Binding Request Type for New Remote Candidate being found.
 */
void test_iceHandleStunPacket_BindingRequest_NewRemoteCandidate( void )
{
    IceContext_t context = { 0 };
    IceCandidate_t localCandidate = { 0 };
    IceEndpoint_t remoteEndpoint = { 0 };
    IceRemoteCandidateInfo_t remoteCandidateInfo = { 0 };
    uint8_t * pTransactionId;
    IceCandidatePair_t * pCandidatePair = NULL;
    IceResult_t iceResult;
    IceHandleStunPacketResult_t result;
    uint8_t stunMessageBuffer[] =
    {
        /* STUN header: Message Type = Binding Request (0x0001), Length = 76 bytes (excluding 20 bytes header). */
        0x00, 0x01, 0x00, 0x4C,
        /* Magic Cookie (0x2112A442). */
        0x21, 0x12, 0xA4, 0x42,
        /* 12 bytes (96 bits) transaction ID as generated by testRandomFxn. */
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
        /* Attribute type = USERNAME (0x0006), Length = 16 bytes. */
        0x00, 0x06, 0x00, 0x10,
        /* Attribute Value = "combinedUsername". */
        0x63, 0x6F, 0x6D, 0x62, 0x69, 0x6E, 0x65, 0x64,
        0x55, 0x73, 0x65, 0x72, 0x6E, 0x61, 0x6D, 0x65,
        /* Attribute type = PRIORITY (0x0024), Length = 4 bytes. */
        0x00, 0x24, 0x00, 0x04,
        /* Attribute Value = 0x7E0000FF. */
        0x7E, 0x00, 0x00, 0xFF,
        /* Attribute type = ICE-CONTROLLING (0x802A), Length = 8 bytes. */
        0x80, 0x2A, 0x00, 0x08,
        /* Attribute Value = 0x0706050403020100. */
        0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00,
        /* Attribute Type = USE-CANDIDATE (0x0025), Length = 0 bytes. */
        0x00, 0x25, 0x00, 0x00,
        /* Attribute type = MESSAGE-INTEGRITY (0x0008), Length = 20 bytes. */
        0x00, 0x08, 0x00, 0x14,
        /* Attribute Value = HMAC value as computed by testHmacFxn. */
        0x6C, 0x6E, 0x63, 0x25,
        0x4D, 0x42, 0xC5, 0x31,
        0x73, 0x76, 0x6D, 0x71,
        0x60, 0x69, 0x69, 0x64,
        0x69, 0x65, 0x5A, 0x6A,
        /* Attribute type = FINGERPRINT (0x8028), Length = 4 bytes. */
        0x80, 0x28, 0x00, 0x04,
        /* Attribute Value: 0x9A8841E2 as calculated by testCrc32Fxn. */
        0x9A, 0x88, 0x41, 0xE2,
    };
    size_t stunMessageBufferLength = sizeof( stunMessageBuffer );

    iceResult = Ice_Init( &( context ),
                          &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       iceResult );

    localCandidate.endpoint.isPointToPoint = 1;
    localCandidate.endpoint.transportAddress.family = 0x01;
    localCandidate.endpoint.transportAddress.port = 8080;
    memcpy( ( void * ) &( localCandidate.endpoint.transportAddress.address[ 0 ] ),
            ( const void * ) ipAddress,
            sizeof( ipAddress ) );

    remoteEndpoint = localCandidate.endpoint; /* For simplicity, use the same endpoint for remote. */

    iceResult = Ice_AddHostCandidate( &( context ),
                                      &( localCandidate.endpoint ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       iceResult );

    remoteCandidateInfo.candidateType = ICE_CANDIDATE_TYPE_HOST;
    remoteCandidateInfo.remoteProtocol = ICE_SOCKET_PROTOCOL_UDP;
    remoteCandidateInfo.priority = 1000;
    remoteCandidateInfo.pEndpoint = &( remoteEndpoint );

    iceResult = Ice_AddRemoteCandidate( &( context ),
                                        &( remoteCandidateInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       iceResult );

    remoteEndpoint.transportAddress.port = 6000;

    result = Ice_HandleStunPacket( &( context ),
                                   &( stunMessageBuffer[ 0 ] ),
                                   stunMessageBufferLength,
                                   &( localCandidate ),
                                   &( remoteEndpoint ),
                                   &( pTransactionId ),
                                   &( pCandidatePair ) );

    TEST_ASSERT_EQUAL( ICE_HANDLE_STUN_PACKET_RESULT_SEND_TRIGGERED_CHECK,
                       result );
    TEST_ASSERT_EQUAL_PTR( &( stunMessageBuffer[ 8 ] ),
                           pTransactionId );
    TEST_ASSERT_EQUAL( 2, context.numRemoteCandidates );
    TEST_ASSERT_EQUAL( 2, context.numCandidatePairs );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate ICE Handle Stun Packet functionality for Binding Request Type for Remote Request i.e. 2nd step of 4-Way Handshake.
 */
void test_iceHandleStunPacket_BindingRequest_ForRemoteRequest( void )
{
    IceContext_t context = { 0 };
    IceCandidate_t localCandidate = { 0 };
    IceEndpoint_t remoteEndpoint = { 0 };
    IceRemoteCandidateInfo_t remoteCandidateInfo = { 0 };
    uint8_t * pTransactionId;
    IceCandidatePair_t * pCandidatePair = NULL;
    IceResult_t iceResult;
    IceHandleStunPacketResult_t result;
    uint8_t stunMessageBuffer[] =
    {
        /* STUN header: Message Type = Binding Request (0x0001), Length = 76 bytes (excluding 20 bytes header). */
        0x00, 0x01, 0x00, 0x4C,
        /* Magic Cookie (0x2112A442). */
        0x21, 0x12, 0xA4, 0x42,
        /* 12 bytes (96 bits) transaction ID as generated by testRandomFxn. */
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
        /* Attribute type = USERNAME (0x0006), Length = 16 bytes. */
        0x00, 0x06, 0x00, 0x10,
        /* Attribute Value = "combinedUsername". */
        0x63, 0x6F, 0x6D, 0x62, 0x69, 0x6E, 0x65, 0x64,
        0x55, 0x73, 0x65, 0x72, 0x6E, 0x61, 0x6D, 0x65,
        /* Attribute type = PRIORITY (0x0024), Length = 4 bytes. */
        0x00, 0x24, 0x00, 0x04,
        /* Attribute Value = 0x7E0000FF. */
        0x7E, 0x00, 0x00, 0xFF,
        /* Attribute type = ICE-CONTROLLING (0x802A), Length = 8 bytes. */
        0x80, 0x2A, 0x00, 0x08,
        /* Attribute Value = 0x0706050403020100. */
        0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00,
        /* Attribute Type = USE-CANDIDATE (0x0025), Length = 0 bytes. */
        0x00, 0x25, 0x00, 0x00,
        /* Attribute type = MESSAGE-INTEGRITY (0x0008), Length = 20 bytes. */
        0x00, 0x08, 0x00, 0x14,
        /* Attribute Value = HMAC value as computed by testHmacFxn. */
        0x6C, 0x6E, 0x63, 0x25,
        0x4D, 0x42, 0xC5, 0x31,
        0x73, 0x76, 0x6D, 0x71,
        0x60, 0x69, 0x69, 0x64,
        0x69, 0x65, 0x5A, 0x6A,
        /* Attribute type = FINGERPRINT (0x8028), Length = 4 bytes. */
        0x80, 0x28, 0x00, 0x04,
        /* Attribute Value: 0x9A8841E2 as calculated by testCrc32Fxn. */
        0x9A, 0x88, 0x41, 0xE2,
    };
    size_t stunMessageBufferLength = sizeof( stunMessageBuffer );

    iceResult = Ice_Init( &( context ),
                          &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       iceResult );

    localCandidate.endpoint.isPointToPoint = 1;
    localCandidate.endpoint.transportAddress.family = 0x01;
    localCandidate.endpoint.transportAddress.port = 8080;
    memcpy( ( void * ) &( localCandidate.endpoint.transportAddress.address[ 0 ] ),
            ( const void * ) ipAddress,
            sizeof( ipAddress ) );

    remoteEndpoint = localCandidate.endpoint; /* For simplicity, use the same endpoint for remote. */

    iceResult = Ice_AddHostCandidate( &( context ),
                                      &( localCandidate.endpoint ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       iceResult );

    remoteCandidateInfo.candidateType = ICE_CANDIDATE_TYPE_HOST;
    remoteCandidateInfo.remoteProtocol = ICE_SOCKET_PROTOCOL_UDP;
    remoteCandidateInfo.priority = 1000;
    remoteCandidateInfo.pEndpoint = &( remoteEndpoint );

    iceResult = Ice_AddRemoteCandidate( &( context ),
                                        &( remoteCandidateInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       iceResult );

    /* 1st step of 4-Way Handshake is done */
    context.pCandidatePairs[ 0 ].connectivityCheckFlags = ICE_STUN_REQUEST_SENT_FLAG;

    /* Here we are assuming for the 4-Way Hanshake process,
     *  Binding Request has been sent and then we have received a Response for it. */

    result = Ice_HandleStunPacket( &( context ),
                                   &( stunMessageBuffer[ 0 ] ),
                                   stunMessageBufferLength,
                                   &( localCandidate ),
                                   &( remoteEndpoint ),
                                   &( pTransactionId ),
                                   &( pCandidatePair ) );

    TEST_ASSERT_EQUAL( ICE_HANDLE_STUN_PACKET_RESULT_SEND_RESPONSE_FOR_REMOTE_REQUEST,
                       result );
    TEST_ASSERT_EQUAL_PTR( &( stunMessageBuffer[ 8 ] ),
                           pTransactionId );
    TEST_ASSERT_EQUAL( ICE_STUN_REQUEST_SENT_FLAG | ICE_STUN_REQUEST_RECEIVED_FLAG | ICE_STUN_RESPONSE_SENT_FLAG, pCandidatePair->connectivityCheckFlags );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate ICE Handle Stun Packet functionality for Binding Request Type for Nomination.
 */
void test_iceHandleStunPacket_BindingRequest_ForNomination( void )
{
    IceContext_t context = { 0 };
    IceCandidate_t localCandidate = { 0 };
    IceEndpoint_t remoteEndpoint = { 0 };
    IceRemoteCandidateInfo_t remoteCandidateInfo = { 0 };
    uint8_t * pTransactionId;
    IceCandidatePair_t * pCandidatePair = NULL;
    IceResult_t iceResult;
    IceHandleStunPacketResult_t result;
    uint8_t stunMessage[] =
    {
        /* STUN header: Message Type = Binding Request (0x0001), Length = 76 bytes (excluding 20 bytes header). */
        0x00, 0x01, 0x00, 0x4C,
        /* Magic Cookie (0x2112A442). */
        0x21, 0x12, 0xA4, 0x42,
        /* 12 bytes (96 bits) transaction ID as generated by testRandomFxn. */
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
        /* Attribute type = USERNAME (0x0006), Length = 16 bytes. */
        0x00, 0x06, 0x00, 0x10,
        /* Attribute Value = "combinedUsername". */
        0x63, 0x6F, 0x6D, 0x62, 0x69, 0x6E, 0x65, 0x64,
        0x55, 0x73, 0x65, 0x72, 0x6E, 0x61, 0x6D, 0x65,
        /* Attribute type = PRIORITY (0x0024), Length = 4 bytes. */
        0x00, 0x24, 0x00, 0x04,
        /* Attribute Value = 0x7E0000FF. */
        0x7E, 0x00, 0x00, 0xFF,
        /* Attribute type = ICE-CONTROLLING (0x802A), Length = 8 bytes. */
        0x80, 0x2A, 0x00, 0x08,
        /* Attribute Value = 0x0706050403020100. */
        0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00,
        /* Attribute Type = USE-CANDIDATE (0x0025), Length = 0 bytes. */
        0x00, 0x25, 0x00, 0x00,
        /* Attribute type = MESSAGE-INTEGRITY (0x0008), Length = 20 bytes. */
        0x00, 0x08, 0x00, 0x14,
        /* Attribute Value = HMAC value as computed by testHmacFxn. */
        0x6C, 0x6E, 0x63, 0x25,
        0x4D, 0x42, 0xC5, 0x31,
        0x73, 0x76, 0x6D, 0x71,
        0x60, 0x69, 0x69, 0x64,
        0x69, 0x65, 0x5A, 0x6A,
        /* Attribute type = FINGERPRINT (0x8028), Length = 4 bytes. */
        0x80, 0x28, 0x00, 0x04,
        /* Attribute Value: 0x9A8841E2 as calculated by testCrc32Fxn. */
        0x9A, 0x88, 0x41, 0xE2,
    };
    size_t stunMessageLength = sizeof( stunMessage );

    initInfo.isControlling = 0;
    iceResult = Ice_Init( &( context ),
                          &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       iceResult );

    localCandidate.endpoint.isPointToPoint = 1;
    localCandidate.endpoint.transportAddress.family = 0x01;
    localCandidate.endpoint.transportAddress.port = 8080;
    memcpy( ( void * ) &( localCandidate.endpoint.transportAddress.address[ 0 ] ),
            ( const void * ) ipAddress,
            sizeof( ipAddress ) );

    remoteEndpoint = localCandidate.endpoint; /* For simplicity, use the same endpoint for remote. */

    iceResult = Ice_AddHostCandidate( &( context ),
                                      &( localCandidate.endpoint ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       iceResult );

    remoteCandidateInfo.candidateType = ICE_CANDIDATE_TYPE_HOST;
    remoteCandidateInfo.remoteProtocol = ICE_SOCKET_PROTOCOL_UDP;
    remoteCandidateInfo.priority = 1000;
    remoteCandidateInfo.pEndpoint = &( remoteEndpoint );

    iceResult = Ice_AddRemoteCandidate( &( context ),
                                        &( remoteCandidateInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       iceResult );

    /* All 4 steps of 4-Way Handshake are done */
    context.pCandidatePairs[ 0 ].state = ICE_CANDIDATE_PAIR_STATE_WAITING;
    context.pCandidatePairs[ 0 ].connectivityCheckFlags = ICE_STUN_REQUEST_SENT_FLAG | ICE_STUN_RESPONSE_RECEIVED_FLAG | ICE_STUN_REQUEST_RECEIVED_FLAG | ICE_STUN_RESPONSE_SENT_FLAG;

    /* The tests covers that all 4 steps are done and for the
     * chosen candidate Pair the state has been modified to Nominated. */
    result = Ice_HandleStunPacket( &( context ),
                                   &( stunMessage[ 0 ] ),
                                   stunMessageLength,
                                   &( localCandidate ),
                                   &( remoteEndpoint ),
                                   &( pTransactionId ),
                                   &( pCandidatePair ) );

    TEST_ASSERT_EQUAL( ICE_HANDLE_STUN_PACKET_RESULT_SEND_RESPONSE_FOR_NOMINATION,
                       result );
    TEST_ASSERT_EQUAL_PTR( &( stunMessage[ 8 ] ),
                           pTransactionId );
    TEST_ASSERT_EQUAL( 1, context.numRemoteCandidates );
    TEST_ASSERT_EQUAL( ICE_CANDIDATE_PAIR_STATE_SUCCEEDED, pCandidatePair->state );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate ICE Handle Stun Packet functionality to start nomination
 * when it's controlling agent and achieve connectivity for the first pair.
 */
void test_iceHandleStunPacket_BindingRequest_StartNomination( void )
{
    IceContext_t context = { 0 };
    IceCandidate_t localCandidate = { 0 };
    IceEndpoint_t remoteEndpoint = { 0 };
    IceRemoteCandidateInfo_t remoteCandidateInfo = { 0 };
    uint8_t * pTransactionId;
    IceCandidatePair_t * pCandidatePair = NULL;
    IceResult_t iceResult;
    IceHandleStunPacketResult_t result;
    uint8_t stunMessage[] =
    {
        /* STUN header: Message Type = Binding Request (0x0001), Length = 72 bytes (excluding 20 bytes header). */
        0x00, 0x01, 0x00, 0x48,
        /* Magic Cookie (0x2112A442). */
        0x21, 0x12, 0xA4, 0x42,
        /* 12 bytes (96 bits) transaction ID as generated by testRandomFxn. */
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
        /* Attribute type = USERNAME (0x0006), Length = 16 bytes. */
        0x00, 0x06, 0x00, 0x10,
        /* Attribute Value = "combinedUsername". */
        0x63, 0x6F, 0x6D, 0x62, 0x69, 0x6E, 0x65, 0x64,
        0x55, 0x73, 0x65, 0x72, 0x6E, 0x61, 0x6D, 0x65,
        /* Attribute type = PRIORITY (0x0024), Length = 4 bytes. */
        0x00, 0x24, 0x00, 0x04,
        /* Attribute Value = 0x7E0000FF. */
        0x7E, 0x00, 0x00, 0xFF,
        /* Attribute type = ICE-CONTROLLED (0x8029), Length = 8 bytes. */
        0x80, 0x29, 0x00, 0x08,
        /* Attribute Value = 0x0706050403020100. */
        0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00,
        /* Attribute type = MESSAGE-INTEGRITY (0x0008), Length = 20 bytes. */
        0x00, 0x08, 0x00, 0x14,
        /* Attribute Value = HMAC value as computed by testHmacFxn_FixedFF. */
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        /* Attribute type = FINGERPRINT (0x8028), Length = 4 bytes. */
        0x80, 0x28, 0x00, 0x04,
        /* Attribute Value: 0x00 as calculated by testCrc32Fxn_Fixed. */
        0x00, 0x00, 0x00, 0x00,
    };
    size_t stunMessageLength = sizeof( stunMessage );

    initInfo.isControlling = 1;
    /* Set CRC32 function to testCrc32Fxn_Fixed to make fingerprint always 0x00000000 */
    initInfo.cryptoFunctions.crc32Fxn = testCrc32Fxn_Fixed;
    /* Set CRC32 function to testHmacFxn_FixedFF to make integrity always 0xFF. */
    initInfo.cryptoFunctions.hmacFxn = testHmacFxn_FixedFF;
    iceResult = Ice_Init( &( context ),
                          &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       iceResult );

    localCandidate.endpoint.isPointToPoint = 1;
    localCandidate.endpoint.transportAddress.family = 0x01;
    localCandidate.endpoint.transportAddress.port = 8080;
    memcpy( ( void * ) &( localCandidate.endpoint.transportAddress.address[ 0 ] ),
            ( const void * ) ipAddress,
            sizeof( ipAddress ) );

    remoteEndpoint = localCandidate.endpoint; /* For simplicity, use the same endpoint for remote. */

    iceResult = Ice_AddHostCandidate( &( context ),
                                      &( localCandidate.endpoint ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       iceResult );

    remoteCandidateInfo.candidateType = ICE_CANDIDATE_TYPE_HOST;
    remoteCandidateInfo.remoteProtocol = ICE_SOCKET_PROTOCOL_UDP;
    remoteCandidateInfo.priority = 1000;
    remoteCandidateInfo.pEndpoint = &( remoteEndpoint );

    iceResult = Ice_AddRemoteCandidate( &( context ),
                                        &( remoteCandidateInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       iceResult );

    /* All 4 steps of 4-Way Handshake are done */
    context.pCandidatePairs[ 0 ].state = ICE_CANDIDATE_PAIR_STATE_WAITING;
    context.pCandidatePairs[ 0 ].connectivityCheckFlags = ICE_STUN_REQUEST_SENT_FLAG | ICE_STUN_RESPONSE_RECEIVED_FLAG | ICE_STUN_REQUEST_RECEIVED_FLAG | ICE_STUN_RESPONSE_SENT_FLAG;

    /* The tests covers that all 4 steps are done and for the
     * chosen candidate Pair the state has been modified to Nominated. */
    result = Ice_HandleStunPacket( &( context ),
                                   &( stunMessage[ 0 ] ),
                                   stunMessageLength,
                                   &( localCandidate ),
                                   &( remoteEndpoint ),
                                   &( pTransactionId ),
                                   &( pCandidatePair ) );

    TEST_ASSERT_EQUAL( ICE_HANDLE_STUN_PACKET_RESULT_START_NOMINATION,
                       result );
    TEST_ASSERT_EQUAL( ICE_CANDIDATE_PAIR_STATE_NOMINATED,
                       pCandidatePair->state );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate ICE Handle Stun Packet functionality to start nomination
 * when it's controlling agent but it already have nominated pair.
 */
void test_iceHandleStunPacket_BindingRequest_AlreadyHaveNominatedPair( void )
{
    IceContext_t context = { 0 };
    IceCandidate_t localCandidate = { 0 };
    IceEndpoint_t remoteEndpoint = { 0 };
    IceRemoteCandidateInfo_t remoteCandidateInfo = { 0 };
    uint8_t * pTransactionId;
    IceCandidatePair_t * pCandidatePair = NULL;
    IceResult_t iceResult;
    IceHandleStunPacketResult_t result;
    uint8_t stunMessage[] =
    {
        /* STUN header: Message Type = Binding Request (0x0001), Length = 72 bytes (excluding 20 bytes header). */
        0x00, 0x01, 0x00, 0x48,
        /* Magic Cookie (0x2112A442). */
        0x21, 0x12, 0xA4, 0x42,
        /* 12 bytes (96 bits) transaction ID as generated by testRandomFxn. */
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
        /* Attribute type = USERNAME (0x0006), Length = 16 bytes. */
        0x00, 0x06, 0x00, 0x10,
        /* Attribute Value = "combinedUsername". */
        0x63, 0x6F, 0x6D, 0x62, 0x69, 0x6E, 0x65, 0x64,
        0x55, 0x73, 0x65, 0x72, 0x6E, 0x61, 0x6D, 0x65,
        /* Attribute type = PRIORITY (0x0024), Length = 4 bytes. */
        0x00, 0x24, 0x00, 0x04,
        /* Attribute Value = 0x7E0000FF. */
        0x7E, 0x00, 0x00, 0xFF,
        /* Attribute type = ICE-CONTROLLED (0x8029), Length = 8 bytes. */
        0x80, 0x29, 0x00, 0x08,
        /* Attribute Value = 0x0706050403020100. */
        0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00,
        /* Attribute type = MESSAGE-INTEGRITY (0x0008), Length = 20 bytes. */
        0x00, 0x08, 0x00, 0x14,
        /* Attribute Value = HMAC value as computed by testHmacFxn_FixedFF. */
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        /* Attribute type = FINGERPRINT (0x8028), Length = 4 bytes. */
        0x80, 0x28, 0x00, 0x04,
        /* Attribute Value: 0x00 as calculated by testCrc32Fxn_Fixed. */
        0x00, 0x00, 0x00, 0x00,
    };
    size_t stunMessageLength = sizeof( stunMessage );

    initInfo.isControlling = 1;
    /* Set CRC32 function to testCrc32Fxn_Fixed to make fingerprint always 0x00000000 */
    initInfo.cryptoFunctions.crc32Fxn = testCrc32Fxn_Fixed;
    /* Set CRC32 function to testHmacFxn_FixedFF to make integrity always 0xFF. */
    initInfo.cryptoFunctions.hmacFxn = testHmacFxn_FixedFF;
    iceResult = Ice_Init( &( context ),
                          &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       iceResult );

    localCandidate.endpoint.isPointToPoint = 1;
    localCandidate.endpoint.transportAddress.family = 0x01;
    localCandidate.endpoint.transportAddress.port = 8080;
    memcpy( ( void * ) &( localCandidate.endpoint.transportAddress.address[ 0 ] ),
            ( const void * ) ipAddress,
            sizeof( ipAddress ) );

    remoteEndpoint = localCandidate.endpoint; /* For simplicity, use the same endpoint for remote. */

    iceResult = Ice_AddHostCandidate( &( context ),
                                      &( localCandidate.endpoint ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       iceResult );

    remoteCandidateInfo.candidateType = ICE_CANDIDATE_TYPE_HOST;
    remoteCandidateInfo.remoteProtocol = ICE_SOCKET_PROTOCOL_UDP;
    remoteCandidateInfo.priority = 1000;
    remoteCandidateInfo.pEndpoint = &( remoteEndpoint );

    iceResult = Ice_AddRemoteCandidate( &( context ),
                                        &( remoteCandidateInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       iceResult );

    /* All 4 steps of 4-Way Handshake are done */
    context.numCandidatePairs = 2;
    context.pCandidatePairs[ 0 ].state = ICE_CANDIDATE_PAIR_STATE_WAITING;
    context.pCandidatePairs[ 0 ].connectivityCheckFlags = ICE_STUN_REQUEST_SENT_FLAG | ICE_STUN_RESPONSE_RECEIVED_FLAG | ICE_STUN_REQUEST_RECEIVED_FLAG | ICE_STUN_RESPONSE_SENT_FLAG;

    /* Set nominated pair as it's nominated. */
    context.pCandidatePairs[ 1 ].state = ICE_CANDIDATE_PAIR_STATE_NOMINATED;
    context.pCandidatePairs[ 1 ].connectivityCheckFlags = ICE_STUN_REQUEST_SENT_FLAG | ICE_STUN_RESPONSE_RECEIVED_FLAG | ICE_STUN_REQUEST_RECEIVED_FLAG | ICE_STUN_RESPONSE_SENT_FLAG;
    context.pNominatePairs = &context.pCandidatePairs[ 1 ];

    /* The tests covers that all 4 steps are done and for the
     * chosen candidate Pair the state has been modified to Nominated. */
    result = Ice_HandleStunPacket( &( context ),
                                   &( stunMessage[ 0 ] ),
                                   stunMessageLength,
                                   &( localCandidate ),
                                   &( remoteEndpoint ),
                                   &( pTransactionId ),
                                   &( pCandidatePair ) );

    TEST_ASSERT_EQUAL( ICE_HANDLE_STUN_PACKET_RESULT_SEND_RESPONSE_FOR_REMOTE_REQUEST,
                       result );
    TEST_ASSERT_EQUAL_UINT8_ARRAY( &( stunMessage[ 8 ] ),
                                   pTransactionId,
                                   STUN_HEADER_TRANSACTION_ID_LENGTH );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate ICE Handle Stun Packet functionality for Binding Request Type for Nomination.
 * Note that there are other local candidates needed to be freed.
 */
void test_iceHandleStunPacket_BindingRequest_Nomination_ReleaseOtherCandidates( void )
{
    IceContext_t context = { 0 };
    uint8_t * pTransactionId;
    IceCandidatePair_t * pCandidatePair = NULL;
    IceResult_t iceResult;
    IceHandleStunPacketResult_t result;
    uint8_t transactionID[] = {
        0xFF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
    };
    uint8_t stunMessage[] =
    {
        /* STUN header: Message Type = Binding Request (0x0001), Length = 76 bytes (excluding 20 bytes header). */
        0x00, 0x01, 0x00, 0x4C,
        /* Magic Cookie (0x2112A442). */
        0x21, 0x12, 0xA4, 0x42,
        /* 12 bytes (96 bits) transaction ID as generated by testRandomFxn. */
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
        /* Attribute type = USERNAME (0x0006), Length = 16 bytes. */
        0x00, 0x06, 0x00, 0x10,
        /* Attribute Value = "combinedUsername". */
        0x63, 0x6F, 0x6D, 0x62, 0x69, 0x6E, 0x65, 0x64,
        0x55, 0x73, 0x65, 0x72, 0x6E, 0x61, 0x6D, 0x65,
        /* Attribute type = PRIORITY (0x0024), Length = 4 bytes. */
        0x00, 0x24, 0x00, 0x04,
        /* Attribute Value = 0x7E0000FF. */
        0x7E, 0x00, 0x00, 0xFF,
        /* Attribute type = ICE-CONTROLLING (0x802A), Length = 8 bytes. */
        0x80, 0x2A, 0x00, 0x08,
        /* Attribute Value = 0x0706050403020100. */
        0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00,
        /* Attribute Type = USE-CANDIDATE (0x0025), Length = 0 bytes. */
        0x00, 0x25, 0x00, 0x00,
        /* Attribute type = MESSAGE-INTEGRITY (0x0008), Length = 20 bytes. */
        0x00, 0x08, 0x00, 0x14,
        /* Attribute Value = HMAC value as computed by testHmacFxn. */
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        /* Attribute type = FINGERPRINT (0x8028), Length = 4 bytes. */
        0x80, 0x28, 0x00, 0x04,
        /* Attribute Value: 0x00 as calculated by testCrc32Fxn_Fixed. */
        0x00, 0x00, 0x00, 0x00,
    };
    size_t stunMessageLength = sizeof( stunMessage );
    IceCandidate_t candidate;
    uint8_t ipAddress2[] = { 0xC0, 0xA8, 0x01, 0x65 }; /* "192.168.1.101". */
    uint8_t transactionIDInStore[] = {
        0xFF, 0xFF, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
    };

    /* Set CRC32 function to testCrc32Fxn_Fixed to make fingerprint always 0x00000000 */
    initInfo.cryptoFunctions.crc32Fxn = testCrc32Fxn_Fixed;
    /* Set CRC32 function to testHmacFxn_FixedFF to make integrity always 0xFF. */
    initInfo.cryptoFunctions.hmacFxn = testHmacFxn_FixedFF;
    initInfo.isControlling = 0U;
    iceResult = Ice_Init( &( context ),
                          &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       iceResult );

    memset( &candidate, 0, sizeof( IceCandidate_t ) );
    candidate.endpoint.isPointToPoint = 0U;
    candidate.endpoint.transportAddress.family = STUN_ADDRESS_IPv4;
    candidate.endpoint.transportAddress.port = 8080;
    memcpy( ( void * ) &( candidate.endpoint.transportAddress.address[ 0 ] ),
            ( const void * ) ipAddress2,
            sizeof( ipAddress2 ) );

    context.numLocalCandidates = 6;
    memset( &context.pLocalCandidates[ 0 ], 0, sizeof( IceCandidate_t ) );
    context.pLocalCandidates[ 0 ].candidateType = ICE_CANDIDATE_TYPE_HOST;
    context.pLocalCandidates[ 0 ].endpoint.isPointToPoint = 0U;
    context.pLocalCandidates[ 0 ].endpoint.transportAddress.family = STUN_ADDRESS_IPv4;
    context.pLocalCandidates[ 0 ].endpoint.transportAddress.port = 8080;
    memcpy( ( void * ) &( context.pLocalCandidates[ 0 ].endpoint.transportAddress.address[ 0 ] ),
            ( const void * ) ipAddress,
            sizeof( ipAddress ) );
    memset( &context.pLocalCandidates[ 0 ], 0, sizeof( IceCandidate_t ) );

    /* Add a relay candidate to be freed to release TURN server allocation. */
    context.pLocalCandidates[ 1 ].candidateType = ICE_CANDIDATE_TYPE_RELAY;
    context.pLocalCandidates[ 1 ].state = ICE_CANDIDATE_STATE_VALID;
    context.pLocalCandidates[ 1 ].endpoint.isPointToPoint = 0U;
    context.pLocalCandidates[ 1 ].endpoint.transportAddress.family = STUN_ADDRESS_IPv4;
    context.pLocalCandidates[ 1 ].endpoint.transportAddress.port = 8080;
    memcpy( ( void * ) &( context.pLocalCandidates[ 1 ].endpoint.transportAddress.address[ 1 ] ),
            ( const void * ) ipAddress,
            sizeof( ipAddress ) );

    /* Add a host candidate to be freed by setting state to invalid. */
    context.pLocalCandidates[ 2 ].candidateType = ICE_CANDIDATE_TYPE_HOST;
    context.pLocalCandidates[ 2 ].state = ICE_CANDIDATE_STATE_VALID;
    context.pLocalCandidates[ 2 ].endpoint.isPointToPoint = 0U;
    context.pLocalCandidates[ 2 ].endpoint.transportAddress.family = STUN_ADDRESS_IPv4;
    context.pLocalCandidates[ 2 ].endpoint.transportAddress.port = 8080;
    memcpy( ( void * ) &( context.pLocalCandidates[ 2 ].endpoint.transportAddress.address[ 2 ] ),
            ( const void * ) ipAddress,
            sizeof( ipAddress ) );

    /* Add a relay candidate that is allocating, storing transaction ID in the store. */
    context.pLocalCandidates[ 3 ].candidateType = ICE_CANDIDATE_TYPE_RELAY;
    context.pLocalCandidates[ 3 ].state = ICE_CANDIDATE_STATE_VALID;
    context.pLocalCandidates[ 3 ].endpoint.isPointToPoint = 0U;
    context.pLocalCandidates[ 3 ].endpoint.transportAddress.family = STUN_ADDRESS_IPv4;
    context.pLocalCandidates[ 3 ].endpoint.transportAddress.port = 8080;
    memcpy( ( void * ) &( context.pLocalCandidates[ 3 ].endpoint.transportAddress.address[ 3 ] ),
            ( const void * ) ipAddress,
            sizeof( ipAddress ) );
    memcpy( ( void * ) &( context.pLocalCandidates[ 3 ].transactionId ),
            ( const void * ) transactionIDInStore,
            STUN_HEADER_TRANSACTION_ID_LENGTH );

    /* Add a relay candidate that is already terminated. */
    context.pLocalCandidates[ 4 ].candidateType = ICE_CANDIDATE_TYPE_RELAY;
    context.pLocalCandidates[ 4 ].state = ICE_CANDIDATE_STATE_RELEASED;
    context.pLocalCandidates[ 4 ].endpoint.isPointToPoint = 0U;
    context.pLocalCandidates[ 4 ].endpoint.transportAddress.family = STUN_ADDRESS_IPv4;
    context.pLocalCandidates[ 4 ].endpoint.transportAddress.port = 8080;
    memcpy( ( void * ) &( context.pLocalCandidates[ 4 ].endpoint.transportAddress.address[ 4 ] ),
            ( const void * ) ipAddress,
            sizeof( ipAddress ) );

    /* Add a relay candidate to be freed to release TURN server allocation. */
    context.pLocalCandidates[ 1 ].candidateType = ICE_CANDIDATE_TYPE_RELAY;
    context.pLocalCandidates[ 1 ].state = ICE_CANDIDATE_STATE_ALLOCATING;
    context.pLocalCandidates[ 1 ].endpoint.isPointToPoint = 0U;
    context.pLocalCandidates[ 1 ].endpoint.transportAddress.family = STUN_ADDRESS_IPv4;
    context.pLocalCandidates[ 1 ].endpoint.transportAddress.port = 8080;
    memcpy( ( void * ) &( context.pLocalCandidates[ 1 ].endpoint.transportAddress.address[ 1 ] ),
            ( const void * ) ipAddress,
            sizeof( ipAddress ) );

    /* To simplify, set remote candidate with same endpoint of local candidate. */
    context.numRemoteCandidates = 1;
    memset( &context.pRemoteCandidates[ 0 ], 0, sizeof( IceCandidate_t ) );
    context.pRemoteCandidates[ 0 ].candidateType = ICE_CANDIDATE_TYPE_RELAY;
    context.pRemoteCandidates[ 0 ].endpoint.isPointToPoint = 0U;
    context.pRemoteCandidates[ 0 ].endpoint.transportAddress.family = STUN_ADDRESS_IPv4;
    context.pRemoteCandidates[ 0 ].endpoint.transportAddress.port = 8080;
    memcpy( ( void * ) &( context.pRemoteCandidates[ 0 ].endpoint.transportAddress.address[ 0 ] ),
            ( const void * ) ipAddress,
            sizeof( ipAddress ) );

    context.numCandidatePairs = 1;
    context.pCandidatePairs[ 0 ].pLocalCandidate = &( context.pLocalCandidates[ 0 ] );
    context.pCandidatePairs[ 0 ].pRemoteCandidate = &( context.pRemoteCandidates[ 0 ] );
    context.pCandidatePairs[ 0 ].state = ICE_CANDIDATE_PAIR_STATE_WAITING;
    memcpy( context.pCandidatePairs[ 0 ].transactionId, transactionID, STUN_HEADER_TRANSACTION_ID_LENGTH );
    pCandidatePair = &context.pCandidatePairs[ 0 ];

    /* All 4 steps of 4-Way Handshake are done */
    context.pCandidatePairs[ 0 ].state = ICE_CANDIDATE_PAIR_STATE_NOMINATED;
    context.pCandidatePairs[ 0 ].connectivityCheckFlags = ICE_STUN_REQUEST_SENT_FLAG | ICE_STUN_RESPONSE_RECEIVED_FLAG | ICE_STUN_REQUEST_RECEIVED_FLAG | ICE_STUN_RESPONSE_SENT_FLAG;

    /* The tests covers that all 4 steps are done and for the
     * chosen candidate Pair the state has been modified to Nominated. */
    result = Ice_HandleStunPacket( &( context ),
                                   &( stunMessage[ 0 ] ),
                                   stunMessageLength,
                                   &( context.pLocalCandidates[ 0 ] ),
                                   &( context.pRemoteCandidates[ 0 ].endpoint ),
                                   &( pTransactionId ),
                                   &( pCandidatePair ) );

    TEST_ASSERT_EQUAL( ICE_HANDLE_STUN_PACKET_RESULT_SEND_RESPONSE_FOR_NOMINATION,
                       result );
    TEST_ASSERT_EQUAL_PTR( &( stunMessage[ 8 ] ),
                           pTransactionId );
    TEST_ASSERT_EQUAL( 1, context.numRemoteCandidates );
    TEST_ASSERT_EQUAL( ICE_CANDIDATE_PAIR_STATE_SUCCEEDED, pCandidatePair->state );
    TEST_ASSERT_EQUAL( ICE_CANDIDATE_STATE_RELEASING, context.pLocalCandidates[ 1 ].state );
    TEST_ASSERT_EQUAL( ICE_CANDIDATE_STATE_INVALID, context.pLocalCandidates[ 2 ].state );
    TEST_ASSERT_EQUAL( ICE_CANDIDATE_STATE_RELEASING, context.pLocalCandidates[ 3 ].state );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate ICE Handle Stun Packet functionality for Binding Request Type.
 */
void test_iceHandleStunPacket_BindingRequest_DeserializationError( void )
{
    IceContext_t context = { 0 };
    IceCandidate_t localCandidate = { 0 };
    IceEndpoint_t remoteEndpoint = { 0 };
    uint8_t * pTransactionId;
    IceCandidatePair_t * pCandidatePair = NULL;
    IceResult_t iceResult;
    IceHandleStunPacketResult_t result;
    uint8_t stunMessage[] =
    {
        /* STUN header: Message Type = Binding Request (0x0001), Length = 76 bytes (excluding 20 bytes header). */
        0x00, 0x01, 0x00, 0x4C,
        /* Magic Cookie (0x2112A442). */
        0x21, 0x12, 0xA4, 0x42,
        /* 12 bytes (96 bits) transaction ID as generated by testRandomFxn. */
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
        /* Attribute type = USERNAME (0x0006), Length = 16 bytes. */
        0x00, 0x06, 0x00, 0x10,
        /* Attribute Value = "combinedUsername". */
        0x63, 0x6F, 0x6D, 0x62,0x69, 0x6E, 0x65, 0x64,
        0x55, 0x73, 0x65, 0x72, 0x6E, 0x61, 0x6D, 0x65,
        /* Attribute type = PRIORITY (0x0024), Length = 4 bytes. */
        0x00, 0x24, 0x00, 0x04,
        /* Attribute Value = 0x7E0000FF. */
        0x7E, 0x00, 0x00, 0xFF,
        /* Attribute type = ICE-CONTROLLING (0x802A), Length = 8 bytes. */
        0x80, 0x2A, 0x00, 0x08,
        /* Attribute Value = 0x0706050403020100. */
        0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00,
        /* Attribute Type = USE-CANDIDATE (0x0025), Length = 0 bytes. */
        0x00, 0x25, 0x00, 0x00,
        /* Attribute type = MESSAGE-INTEGRITY (0x0008), Length = 20 bytes. */
        0x00, 0x08, 0x00, 0x14,
        /* Attribute Value = HMAC value as computed by testHmacFxn. */
        0x6C, 0x6E, 0x63, 0x25,
        0x4D, 0x42, 0xC5, 0x31,
        0x73, 0x76, 0x6D, 0x71,
        0x60, 0x69, 0x69, 0x64,
        0x69, 0x65, 0x5A, 0x6A,
        /* Attribute type = FINGERPRINT (0x8028), Length = 4 bytes. */
        0x80, 0x28, 0x00, 0x04,
        /* Attribute Value = 0x9A8841E2 as calculated by testCrc32Fxn. */
        0x9A, 0x88, 0x41, 0xE2,
    };
    size_t stunMessageLength = sizeof( stunMessage );

    /* The Local Password Length is set 0 so that the ICE library cannot compute
     * the message integrity and thereby fails to deserialize the STUN message.
     */
    initInfo.creds.localPasswordLength = 0;
    iceResult = Ice_Init( &( context ),
                          &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       iceResult );

    result = Ice_HandleStunPacket( &( context ),
                                   &( stunMessage[ 0 ] ),
                                   stunMessageLength,
                                   &( localCandidate ),
                                   &( remoteEndpoint ),
                                   &( pTransactionId ),
                                   &( pCandidatePair ) );

    TEST_ASSERT_EQUAL( ICE_HANDLE_STUN_PACKET_RESULT_DESERIALIZE_ERROR,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate ICE Handle Stun Packet functionality.
 */
void test_iceHandleStunPacket_IntegrityMismatch( void )
{
    IceContext_t context = { 0 };
    IceCandidate_t localCandidate = { 0 };
    IceEndpoint_t remoteEndpoint = { 0 };
    uint8_t * pTransactionId;
    IceCandidatePair_t * pCandidatePair = NULL;
    IceResult_t iceResult;
    IceHandleStunPacketResult_t result;
    uint8_t stunMessage[] =
    {
        /* STUN header: Message Type = Binding Request (0x0001), Length = 76 bytes (excluding 20 bytes header). */
        0x00, 0x01, 0x00, 0x4C,
        /* Magic Cookie (0x2112A442). */
        0x21, 0x12, 0xA4, 0x42,
        /* 12 bytes (96 bits) transaction ID as generated by testRandomFxn. */
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
        /* Attribute type = USERNAME (0x0006), Length = 16 bytes. */
        0x00, 0x06, 0x00, 0x10,
        /* Attribute Value = "combinedUsername". */
        0x63, 0x6F, 0x6D, 0x62, 0x69, 0x6E, 0x65, 0x64,
        0x55, 0x73, 0x65, 0x72, 0x6E, 0x61, 0x6D, 0x65,
        /* Attribute type = PRIORITY (0x0024), Length = 4 bytes. */
        0x00, 0x24, 0x00, 0x04,
        /* Attribute Value = 0x7E0000FF. */
        0x7E, 0x00, 0x00, 0xFF,
        /* Attribute type = ICE-CONTROLLING (0x802A), Length = 8 bytes. */
        0x80, 0x2A, 0x00, 0x08,
        /* Attribute Value = 0x0706050403020100. */
        0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00,
        /* Attribute Type = USE-CANDIDATE (0x0025), Length = 0 bytes. */
        0x00, 0x25, 0x00, 0x00,
        /* Attribute type = MESSAGE-INTEGRITY (0x0008), Length = 20 bytes. */
        0x00, 0x08, 0x00, 0x14,
        /* Attribute Value = HMAC value as computed by testHmacFxn. */
        0x6C, 0x00, 0x63, 0x25, /* 2nd Byte should be 0x6E not 0x00. */
        0x4D, 0x42, 0xC5, 0x31,
        0x73, 0x76, 0x6D, 0x71,
        0x60, 0x69, 0x69, 0x64,
        0x69, 0x65, 0x5A, 0x6A,
        /* Attribute type = FINGERPRINT (0x8028), Length = 4 bytes. */
        0x80, 0x28, 0x00, 0x04,
        /* Attribute Value: 0x9A8841E2 as calculated by testCrc32Fxn. */
        0x9A, 0x88, 0x41, 0xE2,
    };
    size_t stunMessageLength = sizeof( stunMessage );

    iceResult = Ice_Init( &( context ),
                          &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       iceResult );

    result = Ice_HandleStunPacket( &( context ),
                                   &( stunMessage[ 0 ] ),
                                   stunMessageLength,
                                   &( localCandidate ),
                                   &( remoteEndpoint ),
                                   &( pTransactionId ),
                                   &( pCandidatePair ) );

    TEST_ASSERT_EQUAL( ICE_HANDLE_STUN_PACKET_RESULT_INTEGRITY_MISMATCH,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate ICE Handle Stun Packet functionality.
 */
void test_iceHandleStunPacket_FingerPrintMismatch( void )
{
    IceContext_t context = { 0 };
    IceCandidate_t localCandidate = { 0 };
    IceEndpoint_t remoteEndpoint = { 0 };
    uint8_t * pTransactionId;
    IceCandidatePair_t * pCandidatePair = NULL;
    IceResult_t iceResult;
    IceHandleStunPacketResult_t result;
    uint8_t stunMessage[] =
    {
        /* STUN header: Message Type = BINDING_SUCCESS_RESPONSE (0x0101), Length = 56 bytes (excluding 20 bytes header). */
        0x01, 0x01, 0x00, 0x38,
        /* Magic Cookie (0x2112A442). */
        0x21, 0x12, 0xA4, 0x42,
        /* 12 bytes (96 bits) transaction ID as generated by testRandomFxn. */
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
        /* Attribute type = XOR Mapped Address (0x0020), Length = 8 bytes. */
        0x00, 0x20, 0x00, 0x08,
        /* Address family = IPv4, Port = 0x3E82, IP Address = 0xC0A80164 (192.168.1.100). */
        0x00, 0x01, 0x3E, 0x82, 0xE1, 0xBA, 0xA5, 0x26,
        /* Attribute type = ICE-CONTROLLED (0x8029), Length = 8 bytes. */
        0x80, 0x29, 0x00, 0x08,
        /* Attribute Value = 0x0706050403020100. */
        0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00,
        /* Attribute type = MESSAGE-INTEGRITY (0x0008), Length = 20 bytes. */
        0x00, 0x08, 0x00, 0x14,
        /* Attribute Value = HMAC value as computed by testHmacFxn. */
        0x73, 0x64, 0x6D, 0x5F,
        0x55, 0x77, 0xF4, 0X23,
        0x73, 0x72, 0x75, 0x6C,
        0x76, 0x61, 0x74, 0X62,
        0x65, 0x66, 0x7E, 0x6E,
        /* Attribute type = FINGERPRINT (0x8028), Length = 4 bytes. */
        0x80, 0x28, 0x00, 0x04,
        /* Attribute Actual Value: 0xBCD5BE24 as calculated by testCrc32Fxn whereas Attribute Value being Passed: 0xB1D5BE24. */
        0xB1, 0xD5, 0xBE, 0x24
    };
    size_t stunMessageLength = sizeof( stunMessage );

    iceResult = Ice_Init( &( context ),
                          &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       iceResult );

    localCandidate.endpoint.isPointToPoint = 1;
    localCandidate.endpoint.transportAddress.family = 0x01;
    localCandidate.endpoint.transportAddress.port = 8080;
    memcpy( ( void * ) &( localCandidate.endpoint.transportAddress.address[ 0 ] ),
            ( const void * ) ipAddress,
            sizeof( ipAddress ) );

    remoteEndpoint = localCandidate.endpoint; /* For simplicity, use the same endpoint for remote. */

    result = Ice_HandleStunPacket( &( context ),
                                   &( stunMessage[ 0 ] ),
                                   stunMessageLength,
                                   &( localCandidate ),
                                   &( remoteEndpoint ),
                                   &( pTransactionId ),
                                   &( pCandidatePair ) );

    TEST_ASSERT_EQUAL( ICE_HANDLE_STUN_PACKET_RESULT_FINGERPRINT_MISMATCH,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate ICE Handle Stun Packet functionality.
 */
void test_iceHandleStunPacket_BindingResponseSuccess( void )
{
    IceContext_t context = { 0 };
    IceCandidate_t localCandidate = { 0 };
    IceEndpoint_t remoteEndpoint = { 0 };
    IceRemoteCandidateInfo_t remoteCandidateInfo = { 0 };
    uint8_t * pTransactionId;
    IceCandidatePair_t * pCandidatePair = NULL;
    IceResult_t iceResult;
    IceHandleStunPacketResult_t result;
    uint8_t stunMessage[] =
    {
        /* STUN header: Message Type = BINDING_SUCCESS_RESPONSE (0x0101), Length = 56 bytes (excluding 20 bytes header). */
        0x01, 0x01, 0x00, 0x38,
        /* Magic Cookie (0x2112A442). */
        0x21, 0x12, 0xA4, 0x42,
        /* 12 bytes (96 bits) transaction ID as generated by testRandomFxn. */
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
        /* Attribute type = XOR Mapped Address (0x0020), Length = 8 bytes. */
        0x00, 0x20, 0x00, 0x08,
        /* Address family = IPv4, Port = 0x3E82, IP Address = 0xC0A80164 (192.168.1.100). */
        0x00, 0x01, 0x3E, 0x82, 0xE1, 0xBA, 0xA5, 0x26,
        /* Attribute type = ICE-CONTROLLED (0x8029), Length = 8 bytes. */
        0x80, 0x29, 0x00, 0x08,
        /* Attribute Value = 0x0706050403020100. */
        0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00,
        /* Attribute type = MESSAGE-INTEGRITY (0x0008), Length = 20 bytes. */
        0x00, 0x08, 0x00, 0x14,
        /* Attribute Value = HMAC value as Sent by testHmacFxn. */
        0x73, 0x64, 0x6D, 0x5F,
        0x55, 0x77, 0xF4, 0X23,
        0x73, 0x72, 0x75, 0x6C,
        0x76, 0x61, 0x74, 0X62,
        0x65, 0x66, 0x7E, 0x6E,
        /* Attribute type = FINGERPRINT (0x8028), Length = 4 bytes. */
        0x80, 0x28, 0x00, 0x04,
        /* Attribute Actual Value: 0x3668061D as calculated by testCrc32Fxn of the sender's ICE Agent. */
        0x36, 0x68, 0x06, 0x1D
    };
    size_t stunMessageLength = sizeof( stunMessage );

    iceResult = Ice_Init( &( context ),
                          &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       iceResult );

    localCandidate.endpoint.isPointToPoint = 1;
    localCandidate.endpoint.transportAddress.family = 0x01;
    localCandidate.endpoint.transportAddress.port = 8080;
    memcpy( ( void * ) &( localCandidate.endpoint.transportAddress.address[ 0 ] ),
            ( const void * ) ipAddress,
            sizeof( ipAddress ) );

    remoteEndpoint = localCandidate.endpoint; /* For simplicity, use the same endpoint for remote. */

    iceResult = Ice_AddHostCandidate( &( context ),
                                      &( localCandidate.endpoint ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       iceResult );

    remoteCandidateInfo.candidateType = ICE_CANDIDATE_TYPE_HOST;
    remoteCandidateInfo.remoteProtocol = ICE_SOCKET_PROTOCOL_UDP;
    remoteCandidateInfo.priority = 1000;
    remoteCandidateInfo.pEndpoint = &( remoteEndpoint );

    iceResult = Ice_AddRemoteCandidate( &( context ),
                                        &( remoteCandidateInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       iceResult );

    result = Ice_HandleStunPacket( &( context ),
                                   &( stunMessage[ 0 ] ),
                                   stunMessageLength,
                                   &( localCandidate ),
                                   &( remoteEndpoint ),
                                   &( pTransactionId ),
                                   &( pCandidatePair ) );

    TEST_ASSERT_EQUAL( ICE_HANDLE_STUN_PACKET_RESULT_OK,
                       result );
    TEST_ASSERT_EQUAL_PTR( &( stunMessage[ 8 ] ),
                           pTransactionId );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate ICE Handle Stun Packet functionality.
 */
void test_iceHandleStunPacket_BindingResponseSuccess_StartNomination( void )
{
    IceContext_t context = { 0 };
    IceCandidate_t localCandidate = { 0 };
    IceEndpoint_t remoteEndpoint = { 0 };
    IceRemoteCandidateInfo_t remoteCandidateInfo = { 0 };
    uint8_t * pTransactionId;
    IceCandidatePair_t * pCandidatePair = NULL;
    IceResult_t iceResult;
    IceHandleStunPacketResult_t result;
    uint8_t stunMessage[] =
    {
        /* STUN header: Message Type = BINDING_SUCCESS_RESPONSE (0x0101), Length = 56 bytes (excluding 20 bytes header). */
        0x01, 0x01, 0x00, 0x38,
        /* Magic Cookie (0x2112A442). */
        0x21, 0x12, 0xA4, 0x42,
        /* 12 bytes (96 bits) transaction ID as generated by testRandomFxn. */
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
        /* Attribute type = XOR Mapped Address (0x0020), Length = 8 bytes. */
        0x00, 0x20, 0x00, 0x08,
        /* Address family = IPv4, Port = 0x3E82, IP Address = 0xC0A80164 (192.168.1.100). */
        0x00, 0x01, 0x3E, 0x82, 0xE1, 0xBA, 0xA5, 0x26,
        /* Attribute type = ICE-CONTROLLED (0x8029), Length = 8 bytes. */
        0x80, 0x29, 0x00, 0x08,
        /* Attribute Value = 0x0706050403020100. */
        0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00,
        /* Attribute type = MESSAGE-INTEGRITY (0x0008), Length = 20 bytes. */
        0x00, 0x08, 0x00, 0x14,
        /* Attribute Value = HMAC value as computed by testHmacFxn. */
        0x73, 0x64, 0x6D, 0x5F,
        0x55, 0x77, 0xF4, 0X23,
        0x73, 0x72, 0x75, 0x6C,
        0x76, 0x61, 0x74, 0X62,
        0x65, 0x66, 0x7E, 0x6E,
        /* Attribute type = FINGERPRINT (0x8028), Length = 4 bytes. */
        0x80, 0x28, 0x00, 0x04,
        /* Attribute Actual Value: 0x3668061D as calculated by testCrc32Fxn of the sender's ICE Agent. */
        0x36, 0x68, 0x06, 0x1D
    };
    size_t stunMessageLength = sizeof( stunMessage );

    iceResult = Ice_Init( &( context ),
                          &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       iceResult );

    localCandidate.endpoint.isPointToPoint = 1;
    localCandidate.endpoint.transportAddress.family = 0x01;
    localCandidate.endpoint.transportAddress.port = 8080;
    memcpy( ( void * ) &( localCandidate.endpoint.transportAddress.address[ 0 ] ),
            ( const void * ) ipAddress,
            sizeof( ipAddress ) );

    remoteEndpoint = localCandidate.endpoint; /* For simplicity, use the same endpoint for remote. */

    iceResult = Ice_AddHostCandidate( &( context ),
                                      &( localCandidate.endpoint ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       iceResult );

    remoteCandidateInfo.candidateType = ICE_CANDIDATE_TYPE_HOST;
    remoteCandidateInfo.remoteProtocol = ICE_SOCKET_PROTOCOL_UDP;
    remoteCandidateInfo.priority = 1000;
    remoteCandidateInfo.pEndpoint = &( remoteEndpoint );

    iceResult = Ice_AddRemoteCandidate( &( context ),
                                        &( remoteCandidateInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       iceResult );

    /* We are in the following state -
     * 1. We have sent a STUN request to the peer.
     * 2. The peer has sent us a STUN request.
     * 3. We have sent STUN response to the peer's STUN request.
     *
     * We are simulating receiving the STUN response for our STUN request from
     * the peer. This will conclude the 4-way handshake. As the controlling
     * agent, the ICE library should ask us to start the nomination process. */
    context.pCandidatePairs[ 0 ].connectivityCheckFlags = ICE_STUN_REQUEST_SENT_FLAG |
                                                          ICE_STUN_REQUEST_RECEIVED_FLAG |
                                                          ICE_STUN_RESPONSE_SENT_FLAG;

    result = Ice_HandleStunPacket( &( context ),
                                   &( stunMessage[ 0 ] ),
                                   stunMessageLength,
                                   &( localCandidate ),
                                   &( remoteEndpoint ),
                                   &( pTransactionId ),
                                   &( pCandidatePair ) );

    TEST_ASSERT_EQUAL( ICE_HANDLE_STUN_PACKET_RESULT_START_NOMINATION,
                       result );
    TEST_ASSERT_EQUAL_PTR( &( stunMessage[ 8 ] ),
                           pTransactionId );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate ICE Handle Stun Packet functionality.
 */
void test_iceHandleStunPacket_BindingResponseSuccess_ValidCandidatePair( void )
{
    IceContext_t context = { 0 };
    IceCandidate_t localCandidate = { 0 };
    IceEndpoint_t remoteEndpoint = { 0 };
    IceRemoteCandidateInfo_t remoteCandidateInfo = { 0 };
    uint8_t * pTransactionId;
    IceCandidatePair_t * pCandidatePair = NULL;
    IceResult_t iceResult;
    IceHandleStunPacketResult_t result;
    uint8_t stunMessage[] =
    {
        /* STUN header: Message Type = BINDING_SUCCESS_RESPONSE (0x0101), Length = 56 bytes (excluding 20 bytes header). */
        0x01, 0x01, 0x00, 0x38,
        /* Magic Cookie (0x2112A442). */
        0x21, 0x12, 0xA4, 0x42,
        /* 12 bytes (96 bits) transaction ID as generated by testRandomFxn. */
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
        /* Attribute type = XOR Mapped Address (0x0020), Length = 8 bytes. */
        0x00, 0x20, 0x00, 0x08,
        /* Address family = IPv4, Port = 0x3E82, IP Address = 0xC0A80164 (192.168.1.100). */
        0x00, 0x01, 0x3E, 0x82, 0xE1, 0xBA, 0xA5, 0x26,
        /* Attribute type = ICE-CONTROLLED (0x8029), Length = 8 bytes. */
        0x80, 0x29, 0x00, 0x08,
        /* Attribute Value = 0x0706050403020100. */
        0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00,
        /* Attribute type = MESSAGE-INTEGRITY (0x0008), Length = 20 bytes. */
        0x00, 0x08, 0x00, 0x14,
        /* Attribute Value = HMAC value as computed by testHmacFxn. */
        0x73, 0x64, 0x6D, 0x5F,
        0x55, 0x77, 0xF4, 0X23,
        0x73, 0x72, 0x75, 0x6C,
        0x76, 0x61, 0x74, 0X62,
        0x65, 0x66, 0x7E, 0x6E,
        /* Attribute type = FINGERPRINT (0x8028), Length = 4 bytes. */
        0x80, 0x28, 0x00, 0x04,
        /* Attribute Actual Value: 0x3668061D as calculated by testCrc32Fxn of the sender's ICE Agent. */
        0x36, 0x68, 0x06, 0x1D
    };
    size_t stunMessageLength = sizeof( stunMessage );

    /* We are not the controlling agent. */
    initInfo.isControlling = 0;
    iceResult = Ice_Init( &( context ),
                          &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       iceResult );

    localCandidate.endpoint.isPointToPoint = 1;
    localCandidate.endpoint.transportAddress.family = 0x01;
    localCandidate.endpoint.transportAddress.port = 8080;
    memcpy( ( void * ) &( localCandidate.endpoint.transportAddress.address[ 0 ] ),
            ( const void * ) ipAddress,
            sizeof( ipAddress ) );

    remoteEndpoint = localCandidate.endpoint; /* For simplicity, use the same endpoint for remote. */

    iceResult = Ice_AddHostCandidate( &( context ),
                                      &( localCandidate.endpoint ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       iceResult );

    remoteCandidateInfo.candidateType = ICE_CANDIDATE_TYPE_HOST;
    remoteCandidateInfo.remoteProtocol = ICE_SOCKET_PROTOCOL_UDP;
    remoteCandidateInfo.priority = 1000;
    remoteCandidateInfo.pEndpoint = &( remoteEndpoint );

    iceResult = Ice_AddRemoteCandidate( &( context ),
                                        &( remoteCandidateInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       iceResult );

    /* We are in the following state -
     * 1. We have sent a STUN request to the peer.
     * 2. The peer has sent us a STUN request.
     * 3. We have sent STUN response to the peer's STUN request.
     *
     * We are simulating receiving the STUN response for our STUN request from
     * the peer. This will conclude the 4-way handshake. As the non-controlling
     * agent, the ICE library should just inform us that a valid candidate pair
     * is found and must not ask us to start the nomination process. */
    context.pCandidatePairs[ 0 ].connectivityCheckFlags = ICE_STUN_REQUEST_SENT_FLAG |
                                                          ICE_STUN_REQUEST_RECEIVED_FLAG |
                                                          ICE_STUN_RESPONSE_SENT_FLAG;

    result = Ice_HandleStunPacket( &( context ),
                                   &( stunMessage[ 0 ] ),
                                   stunMessageLength,
                                   &( localCandidate ),
                                   &( remoteEndpoint ),
                                   &( pTransactionId ),
                                   &( pCandidatePair ) );

    TEST_ASSERT_EQUAL( ICE_HANDLE_STUN_PACKET_RESULT_VALID_CANDIDATE_PAIR,
                       result );
    TEST_ASSERT_EQUAL_PTR( &( stunMessage[ 8 ] ),
                           pTransactionId );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate ICE Handle Stun Packet functionality when No Candidate is Found.
 */
void test_iceHandleStunPacket_BindingResponseSuccess_NoCandidatePair( void )
{
    IceContext_t context = { 0 };
    IceCandidate_t localCandidate = { 0 };
    IceEndpoint_t remoteEndpoint = { 0 };
    uint8_t * pTransactionId;
    IceCandidatePair_t * pCandidatePair = NULL;
    IceResult_t iceResult;
    IceHandleStunPacketResult_t result;
    uint8_t stunMessageReceived[] =
    {
        /* STUN header: Message Type = BINDING_SUCCESS_RESPONSE (0x0101), Length = 48 bytes (excluding 20 bytes header). */
        0x01, 0x01, 0x00, 0x38,
        /* Magic Cookie (0x2112A442). */
        0x21, 0x12, 0xA4, 0x42,
        /* 12 bytes (96 bits) transaction ID as generated by testRandomFxn. */
        0x00, 0x01, 0x02, 0x03,0x04,  0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
        /* Attribute type = XOR Mapped Address (0x0020), Length = 8 bytes. */
        0x00, 0x20, 0x00, 0x08,
        /* Address family = IPv4, Port = 0x3E82, IP Address = 0xC0A80164 (192.168.1.100). */
        0x00, 0x01, 0x3E, 0x82,0xE1,  0xBA, 0xA5, 0x26,
        /* Attribute type = ICE-CONTROLLED  ( 0x8029 ), Length = 8 bytes. */
        0x80, 0x29, 0x00, 0x08,
        /* Attribute Value = 0x0706050403020100. */
        0x07, 0x06, 0x05, 0x04,0x03,  0x02, 0x01, 0x00,
        /* Attribute type = MESSAGE-INTEGRITY (0x0008), Length = 20 bytes. */
        0x00, 0x08, 0x00, 0x14,
        /* Attribute Value = HMAC value as Sent by testHmacFxn. */
        0x73, 0x64, 0x6D, 0x5F,
        0x55, 0x77, 0xF4, 0X23,
        0x73, 0x72, 0x75, 0x6C,
        0x76, 0x61, 0x74, 0X62,
        0x65, 0x66, 0x7E, 0x6E,
        /* Attribute type = FINGERPRINT (0x8028), Length = 4 bytes. */
        0x80, 0x28, 0x00, 0x04,
        /* Attribute Actual Value: 0x3668061D as calculated by testCrc32Fxn of the sender's ICE Agent. */
        0x36, 0x68, 0x06, 0x1D
    };
    size_t stunMessageReceivedLength = sizeof( stunMessageReceived );

    iceResult = Ice_Init( &( context ),
                          &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       iceResult );

    localCandidate.endpoint.isPointToPoint = 1;
    localCandidate.endpoint.transportAddress.family = 0x01;
    localCandidate.endpoint.transportAddress.port = 8080;
    memcpy( ( void * ) &( localCandidate.endpoint.transportAddress.address[ 0 ] ),
            ( const void * ) ipAddress,
            sizeof( ipAddress ) );

    remoteEndpoint = localCandidate.endpoint; /* For simplicity, use the same endpoint for remote */

    iceResult = Ice_AddHostCandidate( &( context ),
                                      &( localCandidate.endpoint ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       iceResult );

    TEST_ASSERT_EQUAL( 0,
                       context.numCandidatePairs );

    result = Ice_HandleStunPacket( &( context ),
                                   &( stunMessageReceived[ 0 ] ),
                                   stunMessageReceivedLength,
                                   &( localCandidate ),
                                   &( remoteEndpoint ),
                                   &( pTransactionId ),
                                   &( pCandidatePair ) );

    TEST_ASSERT_EQUAL( ICE_HANDLE_STUN_PACKET_RESULT_CANDIDATE_PAIR_NOT_FOUND,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate ICE Handle Stun Packet functionality.
 */
void test_iceHandleStunPacket_BindingResponseSuccess_FoundPeerReflexiveCandidate( void )
{
    IceContext_t context = { 0 };
    IceCandidate_t localCandidate = { 0 };
    IceEndpoint_t remoteEndpoint = { 0 };
    IceRemoteCandidateInfo_t remoteCandidateInfo = { 0 };
    uint8_t * pTransactionId;
    IceCandidatePair_t * pCandidatePair = NULL;
    IceResult_t iceResult;
    IceHandleStunPacketResult_t result;
    uint8_t stunMessageReceived[] =
    {
        /* STUN header: Message Type = BINDING_SUCCESS_RESPONSE (0x0101), Length = 36 bytes (excluding 20 bytes header). */
        0x01, 0x01, 0x00, 0x24,
        /* Magic Cookie (0x2112A442). */
        0x21, 0x12, 0xA4, 0x42,
        /* 12 bytes (96 bits) transaction ID as generated by testRandomFxn. */
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
        /* Attribute type = XOR-MAPPED-ADDRESS (0x0020), Attribute Length = 20. */
        0x00, 0x20, 0x00, 0x14,
        /* Address family = IPv6, Port = 0x3326 (0x1234 XOR'd with 2 msb of cookie),
         * IP Address = 2001:0DB8:85A3:0000:0000:8A2E:0370:7334 (0113:A9FA:9797:5678:9ABC:54DE:A8BD:9C91
         * XOR'd with cookie and transaction ID). */
        0x00, 0x02, 0x33, 0x26,
        0x20, 0x01, 0x0D, 0xB8,
        0x85, 0xA3, 0x00, 0x00,
        0x00, 0x00, 0x8A, 0x2E,
        0x03, 0x70, 0x73, 0x34,
        /* Attribute type = ICE-CONTROLLED  ( 0x8029 ), Length = 8 bytes. */
        0x80, 0x29, 0x00, 0x08,
        /* Attribute Value = 0x0706050403020100. */
        0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00,
    };
    size_t stunMessageReceivedLength = sizeof( stunMessageReceived );

    iceResult = Ice_Init( &( context ),
                          &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       iceResult );

    localCandidate.endpoint.isPointToPoint = 1;
    localCandidate.endpoint.transportAddress.family = 0x01;
    localCandidate.endpoint.transportAddress.port = 8080;
    memcpy( ( void * ) &( localCandidate.endpoint.transportAddress.address[ 0 ] ),
            ( const void * ) ipAddress,
            sizeof( ipAddress ) );

    remoteEndpoint = localCandidate.endpoint; /* For simplicity, use the same endpoint for remote */

    iceResult = Ice_AddServerReflexiveCandidate( &( context ),
                                                 &( localCandidate.endpoint ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       iceResult );

    context.pLocalCandidates[ 0 ].state = ICE_CANDIDATE_STATE_VALID;  /* [ Imitating the Ice_HandleServerReflexiveResponse() functionality */
    context.pLocalCandidates[ 0 ].endpoint.isPointToPoint = 0;

    transactionIdStore.pTransactionIdSlots[ 0 ].inUse = 0;
    memset( &( transactionIdStore ),
            0,
            sizeof( TransactionIdStore_t ) );      /* Imitating the Ice_HandleServerReflexiveResponse() functionality ] */

    /* Here a valid state Server Reflexive Local Candidate is created by this process. */

    remoteCandidateInfo.candidateType = ICE_CANDIDATE_TYPE_SERVER_REFLEXIVE;
    remoteCandidateInfo.remoteProtocol = ICE_SOCKET_PROTOCOL_UDP;
    remoteCandidateInfo.priority = 1000;
    remoteCandidateInfo.pEndpoint = &( remoteEndpoint );

    iceResult = Ice_AddRemoteCandidate( &( context ),
                                        &( remoteCandidateInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       iceResult );

    context.pCandidatePairs[ 0 ].connectivityCheckFlags = ICE_STUN_REQUEST_SENT_FLAG; /* Wait for local response. */

    result = Ice_HandleStunPacket( &( context ),
                                   &( stunMessageReceived[ 0 ] ),
                                   stunMessageReceivedLength,
                                   &( localCandidate ),
                                   &( remoteEndpoint ),
                                   &( pTransactionId ),
                                   &( pCandidatePair ) );

    TEST_ASSERT_EQUAL( ICE_HANDLE_STUN_PACKET_RESULT_FOUND_PEER_REFLEXIVE_CANDIDATE,
                       result );
    TEST_ASSERT_EQUAL( ICE_CANDIDATE_TYPE_PEER_REFLEXIVE,
                       pCandidatePair->pLocalCandidate->candidateType );
    TEST_ASSERT_EQUAL( 0,
                       pCandidatePair->pLocalCandidate->endpoint.isPointToPoint );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate ICE Handle Stun Packet functionality when
 * the message has message-integrity unexpectly.
 */
void test_iceHandleStunPacket_BindingResponseSuccess_HaveUnexpectedIntegrity( void )
{
    IceContext_t context = { 0 };
    IceCandidate_t localCandidate = { 0 };
    IceEndpoint_t remoteEndpoint = { 0 };
    IceRemoteCandidateInfo_t remoteCandidateInfo = { 0 };
    uint8_t * pTransactionId;
    IceCandidatePair_t * pCandidatePair = NULL;
    IceResult_t iceResult;
    IceHandleStunPacketResult_t result;
    uint8_t transactionID[] = {
        0xFF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
    };
    uint8_t stunMessageReceived[] =
    {
        /* STUN header: Message Type = BINDING_SUCCESS_RESPONSE (0x0101), Length = 60 bytes (excluding 20 bytes header). */
        0x01, 0x01, 0x00, 0x3C,
        /* Magic Cookie (0x2112A442). */
        0x21, 0x12, 0xA4, 0x42,
        /* 12 bytes (96 bits) transaction ID same as transactionID. */
        0xFF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
        /* Attribute type = XOR-MAPPED-ADDRESS (0x0020), Attribute Length = 20. */
        0x00, 0x20, 0x00, 0x14,
        /* Address family = IPv6, Port = 0x3326 (0x1234 XOR'd with 2 msb of cookie),
         * IP Address = 2001:0DB8:85A3:0000:0000:8A2E:0370:7334 (0113:A9FA:9797:5678:9ABC:54DE:A8BD:9C91
         * XOR'd with cookie and transaction ID). */
        0x00, 0x02, 0x33, 0x26,
        0x20, 0x01, 0x0D, 0xB8,
        0x85, 0xA3, 0x00, 0x00,
        0x00, 0x00, 0x8A, 0x2E,
        0x03, 0x70, 0x73, 0x34,
        /* Attribute type = ICE-CONTROLLED  ( 0x8029 ), Length = 8 bytes. */
        0x80, 0x29, 0x00, 0x08,
        /* Attribute Value = 0x0706050403020100. */
        0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00,
        /* Attribute type = MESSAGE-INTEGRITY (0x0008), Length = 20 bytes. */
        0x00, 0x08, 0x00, 0x14,
        /* Attribute Value = HMAC value (unexpected). */
        0x73, 0x64, 0x6D, 0x5F,
        0x55, 0x77, 0xF4, 0X23,
        0x73, 0x72, 0x75, 0x6C,
        0x76, 0x61, 0x74, 0X62,
        0x65, 0x66, 0x7E, 0x6E,
    };
    size_t stunMessageReceivedLength = sizeof( stunMessageReceived );

    iceResult = Ice_Init( &( context ),
                          &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       iceResult );

    localCandidate.endpoint.isPointToPoint = 1;
    localCandidate.endpoint.transportAddress.family = 0x01;
    localCandidate.endpoint.transportAddress.port = 8080;
    memcpy( ( void * ) &( localCandidate.endpoint.transportAddress.address[ 0 ] ),
            ( const void * ) ipAddress,
            sizeof( ipAddress ) );

    remoteEndpoint = localCandidate.endpoint; /* For simplicity, use the same endpoint for remote */

    iceResult = Ice_AddServerReflexiveCandidate( &( context ),
                                                 &( localCandidate.endpoint ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       iceResult );

    context.pLocalCandidates[ 0 ].state = ICE_CANDIDATE_STATE_VALID;  /* [ Imitating the Ice_HandleServerReflexiveResponse() functionality */
    context.pLocalCandidates[ 0 ].endpoint.isPointToPoint = 0;

    transactionIdStore.pTransactionIdSlots[ 0 ].inUse = 1;
    memcpy( &( transactionIdStore.pTransactionIdSlots[ 0 ].transactionId ),
            transactionID,
            STUN_HEADER_TRANSACTION_ID_LENGTH );

    /* Here a valid state Server Reflexive Local Candidate is created by this process. */

    remoteCandidateInfo.candidateType = ICE_CANDIDATE_TYPE_SERVER_REFLEXIVE;
    remoteCandidateInfo.remoteProtocol = ICE_SOCKET_PROTOCOL_UDP;
    remoteCandidateInfo.priority = 1000;
    remoteCandidateInfo.pEndpoint = &( remoteEndpoint );

    iceResult = Ice_AddRemoteCandidate( &( context ),
                                        &( remoteCandidateInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       iceResult );

    context.pCandidatePairs[ 0 ].connectivityCheckFlags = ICE_STUN_REQUEST_SENT_FLAG; /* Wait for local response. */

    result = Ice_HandleStunPacket( &( context ),
                                   &( stunMessageReceived[ 0 ] ),
                                   stunMessageReceivedLength,
                                   &( localCandidate ),
                                   &( remoteEndpoint ),
                                   &( pTransactionId ),
                                   &( pCandidatePair ) );

    TEST_ASSERT_EQUAL( ICE_HANDLE_STUN_PACKET_RESULT_DESERIALIZE_ERROR,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate ICE Handle Stun Packet functionality when No Address is Found. (Address Family is neither IPV4 nor IPV6)
 */
void test_iceHandleStunPacket_BindingResponseSuccess_NoAddressFound( void )
{
    IceContext_t context = { 0 };
    IceCandidate_t localCandidate = { 0 };
    IceEndpoint_t remoteEndpoint = { 0 };
    IceRemoteCandidateInfo_t remoteCandidateInfo = { 0 };
    uint8_t * pTransactionId;
    IceCandidatePair_t * pCandidatePair = NULL;
    IceResult_t iceResult;
    IceHandleStunPacketResult_t result;
    uint8_t stunMessageReceived[] =
    {
        /* STUN header: Message Type = BINDING_SUCCESS_RESPONSE (0x0101), Length = 24 bytes (excluding 20 bytes header). */
        0x01, 0x01, 0x00, 0x18,
        /* Magic Cookie (0x2112A442). */
        0x21, 0x12, 0xA4, 0x42,
        /* 12 bytes (96 bits) transaction ID as generated by testRandomFxn. */
        0x00, 0x01, 0x02, 0x03,0x04,  0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
        /* Attribute type = XOR Mapped Address (0x0020), Length = 8 bytes. */
        0x00, 0x20, 0x00, 0x08,
        /* Address family = 0, Port = 0x3E82, IP Address = 0xC0A80164 (192.168.1.100). */
        0x00, 0x00, 0x3E, 0x82,0xE1,  0xBA, 0xA5, 0x26,
        /* Attribute type = ICE-CONTROLLED  ( 0x8029 ), Length = 8 bytes. */
        0x80, 0x29, 0x00, 0x08,
        /* Attribute Value = 0x0706050403020100. */
        0x07, 0x06, 0x05, 0x04,0x03,  0x02, 0x01, 0x00,
    };
    size_t stunMessageReceivedLength = sizeof( stunMessageReceived );

    iceResult = Ice_Init( &( context ),
                          &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       iceResult );

    localCandidate.endpoint.isPointToPoint = 1;
    localCandidate.endpoint.transportAddress.family = 0x01;
    localCandidate.endpoint.transportAddress.port = 8080;
    memcpy( ( void * ) &( localCandidate.endpoint.transportAddress.address[ 0 ] ),
            ( const void * ) ipAddress,
            sizeof( ipAddress ) );

    remoteEndpoint = localCandidate.endpoint; /* For simplicity, use the same endpoint for remote */

    iceResult = Ice_AddHostCandidate( &( context ),
                                      &( localCandidate.endpoint ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       iceResult );

    remoteCandidateInfo.candidateType = ICE_CANDIDATE_TYPE_HOST;
    remoteCandidateInfo.remoteProtocol = ICE_SOCKET_PROTOCOL_UDP;
    remoteCandidateInfo.priority = 1000;
    remoteCandidateInfo.pEndpoint = &( remoteEndpoint );

    iceResult = Ice_AddRemoteCandidate( &( context ),
                                        &( remoteCandidateInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       iceResult );

    TEST_ASSERT_EQUAL( 1,
                       context.numCandidatePairs );

    result = Ice_HandleStunPacket( &( context ),
                                   &( stunMessageReceived[ 0 ] ),
                                   stunMessageReceivedLength,
                                   &( localCandidate ),
                                   &( remoteEndpoint ),
                                   &( pTransactionId ),
                                   &( pCandidatePair ) );

    TEST_ASSERT_EQUAL( ICE_HANDLE_STUN_PACKET_RESULT_ADDRESS_ATTRIBUTE_NOT_FOUND,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate ICE Handle Stun Packet functionality for Second-Handshake in 4-Way Handshake.
 */
void test_iceHandleStunPacket_BindingResponseSuccess_SuccessLocalResponse( void )
{
    IceContext_t context = { 0 };
    IceCandidate_t localCandidate = { 0 };
    IceEndpoint_t remoteEndpoint = { 0 };
    IceRemoteCandidateInfo_t remoteCandidateInfo = { 0 };
    uint8_t * pTransactionId;
    IceCandidatePair_t * pCandidatePair = NULL;
    IceResult_t iceResult;
    IceHandleStunPacketResult_t result;

    uint8_t stunMessageReceived[] =
    {
        /* STUN header: Message Type = BINDING_SUCCESS_RESPONSE (0x0101), Length = 48 bytes (excluding 20 bytes header). */
        0x01, 0x01, 0x00, 0x38,
        /* Magic Cookie (0x2112A442). */
        0x21, 0x12, 0xA4, 0x42,
        /* 12 bytes (96 bits) transaction ID as generated by testRandomFxn. */
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
        /* Attribute type = XOR Mapped Address (0x0020), Length = 8 bytes. */
        0x00, 0x20, 0x00, 0x08,
        /* Address family = IPv4, Port = 0x3E82, IP Address = 0xC0A80164 (192.168.1.100). */
        0x00, 0x01, 0x3E, 0x82, 0xE1, 0xBA, 0xA5, 0x26,
        /* Attribute type = ICE-CONTROLLED  ( 0x8029 ), Length = 8 bytes. */
        0x80, 0x29, 0x00, 0x08,
        /* Attribute Value = 0x0706050403020100. */
        0x07, 0x06, 0x05, 0x04,0x03,  0x02, 0x01, 0x00,
        /* Attribute type = MESSAGE-INTEGRITY (0x0008), Length = 20 bytes. */
        0x00, 0x08, 0x00, 0x14,
        /* Attribute Value = HMAC value as Sent by testHmacFxn. */
        0x73, 0x64, 0x6D, 0x5F,
        0x55, 0x77, 0xF4, 0X23,
        0x73, 0x72, 0x75, 0x6C,
        0x76, 0x61, 0x74, 0X62,
        0x65, 0x66, 0x7E, 0x6E,
        /* Attribute type = FINGERPRINT (0x8028), Length = 4 bytes. */
        0x80, 0x28, 0x00, 0x04,
        /* Attribute Actual Value: 0x3668061D as calculated by testCrc32Fxn of the sender's ICE Agent. */
        0x36, 0x68, 0x06, 0x1D
    };
    size_t stunMessageReceivedLength = sizeof( stunMessageReceived );

    iceResult = Ice_Init( &( context ),
                          &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       iceResult );

    localCandidate.endpoint.isPointToPoint = 1;
    localCandidate.endpoint.transportAddress.family = 0x01;
    localCandidate.endpoint.transportAddress.port = 8080;
    memcpy( ( void * ) &( localCandidate.endpoint.transportAddress.address[ 0 ] ),
            ( const void * ) ipAddress,
            sizeof( ipAddress ) );

    remoteEndpoint = localCandidate.endpoint; /* For simplicity, use the same endpoint for remote */

    iceResult = Ice_AddServerReflexiveCandidate( &( context ),
                                                 &( localCandidate.endpoint ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       iceResult );

    context.pLocalCandidates[ 0 ].state = ICE_CANDIDATE_STATE_VALID;        /* [ Imitating the Ice_HandleServerReflexiveResponse() functionality */
    context.pLocalCandidates[ 0 ].endpoint.isPointToPoint = 0;

    transactionIdStore.pTransactionIdSlots[ 0 ].inUse = 0;
    memset( &( transactionIdStore ),
            0,
            sizeof( TransactionIdStore_t ) );      /* Imitating the Ice_HandleServerReflexiveResponse() functionality  ] */

    remoteCandidateInfo.candidateType = ICE_CANDIDATE_TYPE_SERVER_REFLEXIVE;
    remoteCandidateInfo.remoteProtocol = ICE_SOCKET_PROTOCOL_UDP;
    remoteCandidateInfo.priority = 1000;
    remoteCandidateInfo.pEndpoint = &( remoteEndpoint );

    iceResult = Ice_AddRemoteCandidate( &( context ),
                                        &( remoteCandidateInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       iceResult );
    TEST_ASSERT_EQUAL( 1,
                       context.numCandidatePairs );

    context.pCandidatePairs[ 0 ].connectivityCheckFlags = ICE_STUN_REQUEST_SENT_FLAG; /* Wait for local response. */

    result = Ice_HandleStunPacket( &( context ),
                                   &( stunMessageReceived[ 0 ] ),
                                   stunMessageReceivedLength,
                                   &( localCandidate ),
                                   &( remoteEndpoint ),
                                   &( pTransactionId ),
                                   &( pCandidatePair ) );

    TEST_ASSERT_EQUAL( ICE_HANDLE_STUN_PACKET_RESULT_OK,
                       result );
    TEST_ASSERT_EQUAL( ICE_CANDIDATE_PAIR_STATE_WAITING,
                       pCandidatePair->state );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate ICE Handle Stun Packet functionality.
 */
void test_iceHandleStunPacket_BindingResponseSuccess_CandidatePairReady( void )
{
    IceContext_t context = { 0 };
    IceCandidate_t localCandidate = { 0 };
    IceEndpoint_t remoteEndpoint = { 0 };
    IceRemoteCandidateInfo_t remoteCandidateInfo = { 0 };
    uint8_t * pTransactionId;
    IceCandidatePair_t * pCandidatePair = NULL;
    IceResult_t iceResult;
    IceHandleStunPacketResult_t result;
    uint8_t stunMessage[] =
    {
        /* STUN header: Message Type = BINDING_SUCCESS_RESPONSE (0x0101), Length = 56 bytes (excluding 20 bytes header). */
        0x01, 0x01, 0x00, 0x38,
        /* Magic Cookie (0x2112A442). */
        0x21, 0x12, 0xA4, 0x42,
        /* 12 bytes (96 bits) transaction ID as generated by testRandomFxn. */
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
        /* Attribute type = XOR Mapped Address (0x0020), Length = 8 bytes. */
        0x00, 0x20, 0x00, 0x08,
        /* Address family = IPv4, Port = 0x3E82, IP Address = 0xC0A80164 (192.168.1.100). */
        0x00, 0x01, 0x3E, 0x82, 0xE1, 0xBA, 0xA5, 0x26,
        /* Attribute type = ICE-CONTROLLED (0x8029), Length = 8 bytes. */
        0x80, 0x29, 0x00, 0x08,
        /* Attribute Value = 0x0706050403020100. */
        0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00,
        /* Attribute type = MESSAGE-INTEGRITY (0x0008), Length = 20 bytes. */
        0x00, 0x08, 0x00, 0x14,
        /* Attribute Value = HMAC value as computed by testHmacFxn. */
        0x73, 0x64, 0x6D, 0x5F,
        0x55, 0x77, 0xF4, 0X23,
        0x73, 0x72, 0x75, 0x6C,
        0x76, 0x61, 0x74, 0X62,
        0x65, 0x66, 0x7E, 0x6E,
        /* Attribute type = FINGERPRINT (0x8028), Length = 4 bytes. */
        0x80, 0x28, 0x00, 0x04,
        /* Attribute Actual Value: 0x3668061D as calculated by testCrc32Fxn of the sender's ICE Agent. */
        0x36, 0x68, 0x06, 0x1D
    };
    size_t stunMessageLength = sizeof( stunMessage );

    iceResult = Ice_Init( &( context ),
                          &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       iceResult );

    localCandidate.endpoint.isPointToPoint = 1;
    localCandidate.endpoint.transportAddress.family = 0x01;
    localCandidate.endpoint.transportAddress.port = 8080;
    memcpy( ( void * ) &( localCandidate.endpoint.transportAddress.address[ 0 ] ),
            ( const void * ) ipAddress,
            sizeof( ipAddress ) );

    remoteEndpoint = localCandidate.endpoint; /* For simplicity, use the same endpoint for remote. */

    iceResult = Ice_AddHostCandidate( &( context ),
                                      &( localCandidate.endpoint ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       iceResult );

    remoteCandidateInfo.candidateType = ICE_CANDIDATE_TYPE_HOST;
    remoteCandidateInfo.remoteProtocol = ICE_SOCKET_PROTOCOL_UDP;
    remoteCandidateInfo.priority = 1000;
    remoteCandidateInfo.pEndpoint = &( remoteEndpoint );

    iceResult = Ice_AddRemoteCandidate( &( context ),
                                        &( remoteCandidateInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       iceResult );

    /* We have nominated a candidate pair and we are in the following state -
     * 1. We have sent a STUN request to the peer.
     * 2. The peer has sent us a STUN request.
     * 3. We have sent STUN response to the peer's STUN request.
     *
     * We are simulating receiving the STUN response for our STUN request from
     * the peer. This will conclude the 4-way handshake for nomination. The ICE
     * library should inform us that a candidate pair is ready for media
     * exchange. */
    context.pCandidatePairs[ 0 ].connectivityCheckFlags = ICE_STUN_REQUEST_SENT_FLAG |
                                                          ICE_STUN_REQUEST_RECEIVED_FLAG |
                                                          ICE_STUN_RESPONSE_SENT_FLAG;
    context.pCandidatePairs[ 0 ].state = ICE_CANDIDATE_PAIR_STATE_NOMINATED;

    result = Ice_HandleStunPacket( &( context ),
                                   &( stunMessage[ 0 ] ),
                                   stunMessageLength,
                                   &( localCandidate ),
                                   &( remoteEndpoint ),
                                   &( pTransactionId ),
                                   &( pCandidatePair ) );

    TEST_ASSERT_EQUAL( ICE_HANDLE_STUN_PACKET_RESULT_CANDIDATE_PAIR_READY,
                       result );
    TEST_ASSERT_EQUAL_PTR( &( stunMessage[ 8 ] ),
                           pTransactionId );
    TEST_ASSERT_EQUAL( ICE_CANDIDATE_PAIR_STATE_SUCCEEDED,
                       pCandidatePair->state );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate ICE Handle Stun Packet functionality.
 */
void test_iceHandleStunPacket_BindingResponseSuccess_TransactionID_NoMatch( void )
{
    IceContext_t context = { 0 };
    IceCandidate_t localCandidate = { 0 };
    IceEndpoint_t remoteEndpoint = { 0 };
    IceRemoteCandidateInfo_t remoteCandidateInfo = { 0 };
    uint8_t * pTransactionId;
    IceCandidatePair_t * pCandidatePair = NULL;
    IceResult_t iceResult;
    IceHandleStunPacketResult_t result;
    uint8_t stunMessage[] =
    {
        /* STUN header: Message Type = BINDING_SUCCESS_RESPONSE (0x0101), Length = 24 bytes (excluding 20 bytes header). */
        0x01, 0x01, 0x00, 0x18,
        /* Magic Cookie (0x2112A442). */
        0x21, 0x12, 0xA4, 0x42,
        /* 12 bytes (96 bits) transaction ID as received . */
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0C, /* Last byte is different. */
        /* Attribute type = XOR Mapped Address (0x0020), Length = 8 bytes. */
        0x00, 0x20, 0x00, 0x08,
        /* Address family = IPv4, Port = 0x3E82, IP Address = 0xC0A80164 (192.168.1.100). */
        0x00, 0x01, 0x3E, 0x82, 0xE1, 0xBA, 0xA5, 0x26,
        /* Attribute type = ICE-CONTROLLED (0x8029), Length = 8 bytes. */
        0x80, 0x29, 0x00, 0x08,
        /* Attribute Value = 0x0706050403020100. */
        0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00,
    };
    size_t stunMessageLength = sizeof( stunMessage );

    iceResult = Ice_Init( &( context ),
                          &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       iceResult );

    localCandidate.endpoint.isPointToPoint = 1;
    localCandidate.endpoint.transportAddress.family = 0x01;
    localCandidate.endpoint.transportAddress.port = 16002;
    memcpy( ( void * ) &( localCandidate.endpoint.transportAddress.address[ 0 ] ),
            ( const void * ) ipAddress,
            sizeof( ipAddress ) );

    iceResult = Ice_AddServerReflexiveCandidate( &( context ),
                                                 &( localCandidate.endpoint ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       iceResult );

    /* Mark the above added server reflexive candidate as valid. */
    context.pLocalCandidates[ 0 ].state = ICE_CANDIDATE_STATE_VALID;

    remoteEndpoint.isPointToPoint = 1;
    remoteEndpoint.transportAddress.family = 0x01;
    remoteEndpoint.transportAddress.port = 7000;

    remoteCandidateInfo.candidateType = ICE_CANDIDATE_TYPE_SERVER_REFLEXIVE;
    remoteCandidateInfo.remoteProtocol = ICE_SOCKET_PROTOCOL_UDP;
    remoteCandidateInfo.priority = 1000;
    remoteCandidateInfo.pEndpoint = &( remoteEndpoint );

    /* Adding a remote candidate should result in creation of candidate pair
     * as the local candidate is valid. */
    iceResult = Ice_AddRemoteCandidate( &( context ),
                                        &( remoteCandidateInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       iceResult );
    TEST_ASSERT_EQUAL( 1,
                       context.numCandidatePairs );

    /* We are simulating receiving a STUN response from our peer with a
     * mis-matching transaction ID. */
    result = Ice_HandleStunPacket( &( context ),
                                   &( stunMessage[ 0 ] ),
                                   stunMessageLength,
                                   &( localCandidate ),
                                   &( remoteEndpoint ),
                                   &( pTransactionId ),
                                   &( pCandidatePair ) );

    TEST_ASSERT_EQUAL( ICE_HANDLE_STUN_PACKET_RESULT_MATCHING_TRANSACTION_ID_NOT_FOUND,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate ICE Handle Stun Packet functionality.
 */
void test_iceHandleStunPacket_ErrorCode( void )
{
    IceContext_t context = { 0 };
    IceCandidate_t localCandidate = { 0 };
    IceEndpoint_t remoteEndpoint = { 0 };
    IceRemoteCandidateInfo_t remoteCandidateInfo = { 0 };
    uint8_t * pTransactionId;
    IceCandidatePair_t * pCandidatePair = NULL;
    IceResult_t iceResult;
    IceHandleStunPacketResult_t result;
    uint8_t stunMessage[] =
    {
        /* STUN header: Message Type = BINDING_SUCCESS_RESPONSE (0x0101), Length = 44 bytes (excluding 20 bytes header). */
        0x01, 0x01, 0x00, 0x2C,
        /* Magic Cookie (0x2112A442). */
        0x21, 0x12, 0xA4, 0x42,
        /* 12 bytes (96 bits) transaction ID as generated by testRandomFxn. */
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
        /* Attribute type = XOR Mapped Address (0x0020), Length = 8 bytes. */
        0x00, 0x20, 0x00, 0x08,
        /* Address family = IPv4, Port = 0x3E82, IP Address = 0xC0A80164 (192.168.1.100). */
        0x00, 0x01, 0x3E, 0x82, 0xE1, 0xBA, 0xA5, 0x26,
        /* Attribute type = ICE-CONTROLLED (0x8029), Length = 8 bytes. */
        0x80, 0x29, 0x00, 0x08,
        /* Attribute Value = 0x0706050403020100. */
        0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00,
        /* Attribute Type = Error Code (0x0009), Attribute Length = 16 (2 reserved bytes, 2 byte error code and 12 byte error phrase). */
        0x00, 0x09, 0x00, 0x10,
        /* Reserved = 0x0000, Error Class = 6, Error Number = 0 (Error Code = 600). */
        0x00, 0x00, 0x06, 0x00,
        /* Error Phrase = "Error Phrase". */
        0x45, 0x72, 0x72, 0x6F,
        0x72, 0x20, 0x50, 0x68,
        0x72, 0x61, 0x73, 0x65
    };
    size_t stunMessageLength = sizeof( stunMessage );

    iceResult = Ice_Init( &( context ),
                          &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       iceResult );

    localCandidate.endpoint.isPointToPoint = 1;
    localCandidate.endpoint.transportAddress.family = 0x01;
    localCandidate.endpoint.transportAddress.port = 8080;
    memcpy( ( void * ) &( localCandidate.endpoint.transportAddress.address[ 0 ] ),
            ( const void * ) ipAddress,
            sizeof( ipAddress ) );

    remoteEndpoint = localCandidate.endpoint; /* For simplicity, use the same endpoint for remote. */

    iceResult = Ice_AddHostCandidate( &( context ),
                                      &( localCandidate.endpoint ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       iceResult );

    remoteCandidateInfo.candidateType = ICE_CANDIDATE_TYPE_HOST;
    remoteCandidateInfo.remoteProtocol = ICE_SOCKET_PROTOCOL_UDP;
    remoteCandidateInfo.priority = 1000;
    remoteCandidateInfo.pEndpoint = &( remoteEndpoint );

    iceResult = Ice_AddRemoteCandidate( &( context ),
                                        &( remoteCandidateInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       iceResult );

    /* We are simulating receiving a STUN message with non-zero error code. */
    result = Ice_HandleStunPacket( &( context ),
                                   &( stunMessage[ 0 ] ),
                                   stunMessageLength,
                                   &( localCandidate ),
                                   &( remoteEndpoint ),
                                   &( pTransactionId ),
                                   &( pCandidatePair ) );

    TEST_ASSERT_EQUAL( ICE_HANDLE_STUN_PACKET_RESULT_NON_ZERO_ERROR_CODE,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate ICE Handle Stun Packet functionality for Binding Successful
 * Response when Transaction ID is in the Store but Local Candidate type is
 * wrong.
 */
void test_iceHandleStunPacket_BindingResponseSuccess_InvalidCandidateType( void )
{
    IceContext_t context = { 0 };
    IceCandidate_t localCandidate = { 0 };
    IceEndpoint_t remoteEndpoint = { 0 };
    uint8_t * pTransactionId;
    IceCandidatePair_t * pCandidatePair = NULL;
    IceResult_t iceResult;
    IceHandleStunPacketResult_t result;
    uint8_t stunMessage[] =
    {
        /* STUN header: Message Type = BINDING_SUCCESS_RESPONSE (0x0101), Length = 24 bytes (excluding 20 bytes header). */
        0x01, 0x01, 0x00, 0x18,
        /* Magic Cookie (0x2112A442). */
        0x21, 0x12, 0xA4, 0x42,
        /* 12 bytes (96 bits) transaction ID as received . */
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
        /* Attribute type = XOR Mapped Address (0x0020), Length = 8 bytes. */
        0x00, 0x20, 0x00, 0x08,
        /* Address family = IPv4, Port = 0x3E82, IP Address = 0xC0A80164 (192.168.1.100). */
        0x00, 0x01, 0x3E, 0x82, 0xE1, 0xBA, 0xA5, 0x26,
        /* Attribute type = ICE-CONTROLLED (0x8029), Length = 8 bytes. */
        0x80, 0x29, 0x00, 0x08,
        /* Attribute Value = 0x0706050403020100. */
        0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00,
    };
    size_t stunMessageLength = sizeof( stunMessage );
    uint8_t transactionID[] =
    {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B
    };

    transactionIdStore.pTransactionIdSlots[ 0 ].inUse = 1;
    memcpy( &( transactionIdStore.pTransactionIdSlots[ 0 ].transactionId[ 0 ] ),
            &( transactionID[ 0 ] ),
            sizeof( transactionID ) );

    iceResult = Ice_Init( &( context ),
                          &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       iceResult );

    localCandidate.candidateType = ICE_CANDIDATE_TYPE_HOST;
    localCandidate.endpoint.isPointToPoint = 1;
    localCandidate.endpoint.transportAddress.family = 0x01;
    localCandidate.endpoint.transportAddress.port = 8080;
    memcpy( ( void * ) &( localCandidate.endpoint.transportAddress.address[ 0 ] ),
            ( const void * ) ipAddress,
            sizeof( ipAddress ) );

    remoteEndpoint.isPointToPoint = 1;
    remoteEndpoint.transportAddress.family = 0x01;
    remoteEndpoint.transportAddress.port = 7000;

    /* No candidate. */
    TEST_ASSERT_EQUAL( 0,
                       context.numLocalCandidates );
    TEST_ASSERT_EQUAL( 0,
                       context.numRemoteCandidates );
    TEST_ASSERT_EQUAL( 0,
                       context.numCandidatePairs );

    result = Ice_HandleStunPacket( &( context ),
                                   &( stunMessage[ 0 ] ),
                                   stunMessageLength,
                                   &( localCandidate ),
                                   &( remoteEndpoint ),
                                   &( pTransactionId ),
                                   &( pCandidatePair ) );

    TEST_ASSERT_EQUAL( ICE_HANDLE_STUN_PACKET_RESULT_INVALID_CANDIDATE_TYPE,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate ICE Handle Stun Packet functionality for Binding Successful
 * Response when Transaction ID is in the Store.
 */
void test_iceHandleStunPacket_BindingResponseSuccess_TransactionIDStore( void )
{
    IceContext_t context = { 0 };
    IceCandidate_t localCandidate = { 0 };
    IceEndpoint_t remoteEndpoint = { 0 };
    IceRemoteCandidateInfo_t remoteCandidateInfo = { 0 };
    uint8_t * pTransactionId;
    IceCandidatePair_t * pCandidatePair = NULL;
    IceResult_t iceResult;
    IceHandleStunPacketResult_t result;
    uint8_t stunMessage[] =
    {
        /* STUN header: Message Type = BINDING_SUCCESS_RESPONSE (0x0101), Length = 24 bytes (excluding 20 bytes header). */
        0x01, 0x01, 0x00, 0x18,
        /* Magic Cookie (0x2112A442). */
        0x21, 0x12, 0xA4, 0x42,
        /* 12 bytes (96 bits) transaction ID as received . */
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
        /* Attribute type = XOR Mapped Address (0x0020), Length = 8 bytes. */
        0x00, 0x20, 0x00, 0x08,
        /* Address family = IPv4, Port = 0x3E82, IP Address = 0xC0A80164 (192.168.1.100). */
        0x00, 0x01, 0x3E, 0x82, 0xE1, 0xBA, 0xA5, 0x26,
        /* Attribute type = ICE-CONTROLLED (0x8029), Length = 8 bytes. */
        0x80, 0x29, 0x00, 0x08,
        /* Attribute Value = 0x0706050403020100. */
        0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00,
    };
    size_t stunMessageLength = sizeof( stunMessage );
    uint8_t transactionID[] =
    {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B
    };

    transactionIdStore.pTransactionIdSlots[ 0 ].inUse = 1;
    memcpy( &( transactionIdStore.pTransactionIdSlots[ 0 ].transactionId[ 0 ] ),
            &( transactionID[ 0 ] ),
            sizeof( transactionID ) );

    iceResult = Ice_Init( &( context ),
                          &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       iceResult );

    localCandidate.candidateType = ICE_CANDIDATE_TYPE_SERVER_REFLEXIVE;
    localCandidate.endpoint.isPointToPoint = 1;
    localCandidate.endpoint.transportAddress.family = 0x01;
    localCandidate.endpoint.transportAddress.port = 8080;
    memcpy( ( void * ) &( localCandidate.endpoint.transportAddress.address[ 0 ] ),
            ( const void * ) ipAddress,
            sizeof( ipAddress ) );

    /* When a server-reflexive candidate is added, it starts in "New" state
     * and transitions to "Valid" state later when a STUN response is received. */
    iceResult = Ice_AddServerReflexiveCandidate( &( context ),
                                                 &( localCandidate.endpoint ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       iceResult );

    remoteEndpoint.isPointToPoint = 1;
    remoteEndpoint.transportAddress.family = 0x01;
    remoteEndpoint.transportAddress.port = 7000;

    remoteCandidateInfo.candidateType = ICE_CANDIDATE_TYPE_SERVER_REFLEXIVE;
    remoteCandidateInfo.remoteProtocol = ICE_SOCKET_PROTOCOL_UDP;
    remoteCandidateInfo.priority = 1000;
    remoteCandidateInfo.pEndpoint = &( remoteEndpoint );

    iceResult = Ice_AddRemoteCandidate( &( context ),
                                        &( remoteCandidateInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       iceResult );

    /* Adding a remote candidate should not result in creation of a candidate
     * pair as the local candidate (the server reflexive candidate) is in
     * "New" state and not in "Valid" state. */
    TEST_ASSERT_EQUAL( 0,
                       context.numCandidatePairs );

    /* We are simulating receiving a Binding Success response. This should
     * transition the server reflexive candidate to "Valid" state and candidate
     * pair with the remote candidate should get created. */
    result = Ice_HandleStunPacket( &( context ),
                                   &( stunMessage[ 0 ] ),
                                   stunMessageLength,
                                   &( localCandidate ),
                                   &( remoteEndpoint ),
                                   &( pTransactionId ),
                                   &( pCandidatePair ) );

    TEST_ASSERT_EQUAL( ICE_HANDLE_STUN_PACKET_RESULT_UPDATED_SERVER_REFLEXIVE_CANDIDATE_ADDRESS,
                       result );
    TEST_ASSERT_EQUAL_PTR( &( stunMessage[ 8 ] ),
                           pTransactionId );
    TEST_ASSERT_EQUAL( ICE_CANDIDATE_STATE_VALID,
                       context.pCandidatePairs[ 0 ].pLocalCandidate->state );
    TEST_ASSERT_EQUAL( 1,
                       context.numCandidatePairs );
}

/*-----------------------------------------------------------*/

/**
 * @brief Receiving binding request on TURN connection. And local candidate
 * is not matching.
 */
void test_iceHandleStunPacket_BindingResponseSuccess_HostCandidateEndpointNotMatching( void )
{
    IceContext_t context = { 0 };
    uint8_t * pTransactionId;
    IceCandidatePair_t * pCandidatePair = NULL;
    IceResult_t iceResult;
    IceHandleStunPacketResult_t result;
    uint8_t transactionID[] = {
        0xFF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
    };
    uint8_t stunMessage[] =
    {
        /* STUN header: Message Type = BINDING_REQUEST (0x0001), Length = 56 bytes (excluding 20 bytes header). */
        0x00, 0x01, 0x00, 0x38,
        /* Magic Cookie (0x2112A442). */
        0x21, 0x12, 0xA4, 0x42,
        /* 12 bytes (96 bits) transaction ID which is same as transactionID. */
        0xFF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
        /* Attribute type = XOR Mapped Address (0x0020), Length = 8 bytes. */
        0x00, 0x20, 0x00, 0x08,
        /* Address family = IPv4, Port = 0x3E82, IP Address = 0xC0A80164 (192.168.1.100). */
        0x00, 0x01, 0x3E, 0x82, 0xE1, 0xBA, 0xA5, 0x26,
        /* Attribute type = ICE-CONTROLLED (0x8029), Length = 8 bytes. */
        0x80, 0x29, 0x00, 0x08,
        /* Attribute Value = 0x0706050403020100. */
        0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00,
        /* Attribute type = MESSAGE-INTEGRITY (0x0008), Length = 20 bytes. */
        0x00, 0x08, 0x00, 0x14,
        /* Attribute Value = HMAC value as computed by testHmacFxn_FixedFF. */
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        /* Attribute type = FINGERPRINT (0x8028), Length = 4 bytes. */
        0x80, 0x28, 0x00, 0x04,
        /* Attribute Value: 0x00000000 as calculated by testCrc32Fxn_Fixed. */
        0x00, 0x00, 0x00, 0x00
    };
    size_t stunMessageLength = sizeof( stunMessage );
    IceCandidate_t candidate;
    uint8_t ipAddress2[] = { 0xC0, 0xA8, 0x01, 0x65 }; /* "192.168.1.101". */

    /* Set CRC32 function to testCrc32Fxn_Fixed to make fingerprint always 0x00000000 */
    initInfo.cryptoFunctions.crc32Fxn = testCrc32Fxn_Fixed;
    /* Set CRC32 function to testHmacFxn_FixedFF to make integrity always 0xFF. */
    initInfo.cryptoFunctions.hmacFxn = testHmacFxn_FixedFF;
    iceResult = Ice_Init( &( context ),
                          &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       iceResult );

    memset( &candidate, 0, sizeof( IceCandidate_t ) );
    candidate.endpoint.isPointToPoint = 0U;
    candidate.endpoint.transportAddress.family = STUN_ADDRESS_IPv4;
    candidate.endpoint.transportAddress.port = 8080;
    memcpy( ( void * ) &( candidate.endpoint.transportAddress.address[ 0 ] ),
            ( const void * ) ipAddress2,
            sizeof( ipAddress2 ) );

    context.numLocalCandidates = 1;
    memset( &context.pLocalCandidates[ 0 ], 0, sizeof( IceCandidate_t ) );
    context.pLocalCandidates[ 0 ].candidateType = ICE_CANDIDATE_TYPE_HOST;
    context.pLocalCandidates[ 0 ].endpoint.isPointToPoint = 0U;
    context.pLocalCandidates[ 0 ].endpoint.transportAddress.family = STUN_ADDRESS_IPv4;
    context.pLocalCandidates[ 0 ].endpoint.transportAddress.port = 8080;
    memcpy( ( void * ) &( context.pLocalCandidates[ 0 ].endpoint.transportAddress.address[ 0 ] ),
            ( const void * ) ipAddress,
            sizeof( ipAddress ) );

    /* To simplify, set remote candidate with same endpoint of local candidate. */
    context.numRemoteCandidates = 1;
    memset( &context.pRemoteCandidates[ 0 ], 0, sizeof( IceCandidate_t ) );
    context.pRemoteCandidates[ 0 ].candidateType = ICE_CANDIDATE_TYPE_RELAY;
    context.pRemoteCandidates[ 0 ].endpoint.isPointToPoint = 0U;
    context.pRemoteCandidates[ 0 ].endpoint.transportAddress.family = STUN_ADDRESS_IPv4;
    context.pRemoteCandidates[ 0 ].endpoint.transportAddress.port = 8080;
    memcpy( ( void * ) &( context.pRemoteCandidates[ 0 ].endpoint.transportAddress.address[ 0 ] ),
            ( const void * ) ipAddress,
            sizeof( ipAddress ) );

    context.numCandidatePairs = 1;
    context.pCandidatePairs[ 0 ].pLocalCandidate = &( context.pLocalCandidates[ 0 ] );
    context.pCandidatePairs[ 0 ].pRemoteCandidate = &( context.pRemoteCandidates[ 0 ] );
    context.pCandidatePairs[ 0 ].state = ICE_CANDIDATE_PAIR_STATE_WAITING;
    memcpy( context.pCandidatePairs[ 0 ].transactionId, transactionID, STUN_HEADER_TRANSACTION_ID_LENGTH );
    pCandidatePair = &context.pCandidatePairs[ 0 ];

    result = Ice_HandleStunPacket( &( context ),
                                   &( stunMessage[ 0 ] ),
                                   stunMessageLength,
                                   &( candidate ),
                                   &( context.pRemoteCandidates[ 0 ].endpoint ),
                                   &( pTransactionId ),
                                   &( pCandidatePair ) );

    TEST_ASSERT_EQUAL( ICE_HANDLE_STUN_PACKET_RESULT_CANDIDATE_PAIR_NOT_FOUND,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Receiving binding request on TURN connection. And local candidate
 * is not matching.
 */
void test_iceHandleStunPacket_BindingRequest_ErrorInBindingRequest( void )
{
    IceContext_t context = { 0 };
    uint8_t * pTransactionId;
    IceCandidatePair_t * pCandidatePair = NULL;
    IceResult_t iceResult;
    IceHandleStunPacketResult_t result;
    uint8_t transactionID[] = {
        0xFF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
    };
    uint8_t stunMessage[] =
    {
        /* STUN header: Message Type = BINDING_REQUEST (0x0001), Length = 2C bytes (excluding 20 bytes header). */
        0x00, 0x01, 0x00, 0x2C,
        /* Magic Cookie (0x2112A442). */
        0x21, 0x12, 0xA4, 0x42,
        /* 12 bytes (96 bits) transaction ID which is same as transactionID. */
        0xFF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
        /* Attribute type = XOR Mapped Address (0x0020), Length = 8 bytes. */
        0x00, 0x20, 0x00, 0x08,
        /* Address family = IPv4, Port = 0x3E82, IP Address = 0xC0A80164 (192.168.1.100). */
        0x00, 0x01, 0x3E, 0x82, 0xE1, 0xBA, 0xA5, 0x26,
        /* Attribute type = ICE-CONTROLLED (0x8029), Length = 8 bytes. */
        0x80, 0x29, 0x00, 0x08,
        /* Attribute Value = 0x0706050403020100. */
        0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00,
        /* Attribute Type = Error Code (0x0009), Attribute Length = 16 (2 reserved bytes, 2 byte error code and 12 byte error phrase). */
        0x00, 0x09, 0x00, 0x10,
        /* Reserved = 0x0000, Error Class = 6, Error Number = 0 (Error Code = 600). */
        0x00, 0x00, 0x06, 0x00,
        /* Error Phrase = "Error Phrase". */
        0x45, 0x72, 0x72, 0x6F,
        0x72, 0x20, 0x50, 0x68,
        0x72, 0x61, 0x73, 0x65
    };
    size_t stunMessageLength = sizeof( stunMessage );
    IceCandidate_t candidate;
    uint8_t ipAddress2[] = { 0xC0, 0xA8, 0x01, 0x65 }; /* "192.168.1.101". */

    /* Set CRC32 function to testCrc32Fxn_Fixed to make fingerprint always 0x00000000 */
    initInfo.cryptoFunctions.crc32Fxn = testCrc32Fxn_Fixed;
    /* Set CRC32 function to testHmacFxn_FixedFF to make integrity always 0xFF. */
    initInfo.cryptoFunctions.hmacFxn = testHmacFxn_FixedFF;
    iceResult = Ice_Init( &( context ),
                          &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       iceResult );

    memset( &candidate, 0, sizeof( IceCandidate_t ) );
    candidate.endpoint.isPointToPoint = 0U;
    candidate.endpoint.transportAddress.family = STUN_ADDRESS_IPv4;
    candidate.endpoint.transportAddress.port = 8080;
    memcpy( ( void * ) &( candidate.endpoint.transportAddress.address[ 0 ] ),
            ( const void * ) ipAddress2,
            sizeof( ipAddress2 ) );

    context.numLocalCandidates = 1;
    memset( &context.pLocalCandidates[ 0 ], 0, sizeof( IceCandidate_t ) );
    context.pLocalCandidates[ 0 ].candidateType = ICE_CANDIDATE_TYPE_HOST;
    context.pLocalCandidates[ 0 ].endpoint.isPointToPoint = 0U;
    context.pLocalCandidates[ 0 ].endpoint.transportAddress.family = STUN_ADDRESS_IPv4;
    context.pLocalCandidates[ 0 ].endpoint.transportAddress.port = 8080;
    memcpy( ( void * ) &( context.pLocalCandidates[ 0 ].endpoint.transportAddress.address[ 0 ] ),
            ( const void * ) ipAddress,
            sizeof( ipAddress ) );

    /* To simplify, set remote candidate with same endpoint of local candidate. */
    context.numRemoteCandidates = 1;
    memset( &context.pRemoteCandidates[ 0 ], 0, sizeof( IceCandidate_t ) );
    context.pRemoteCandidates[ 0 ].candidateType = ICE_CANDIDATE_TYPE_RELAY;
    context.pRemoteCandidates[ 0 ].endpoint.isPointToPoint = 0U;
    context.pRemoteCandidates[ 0 ].endpoint.transportAddress.family = STUN_ADDRESS_IPv4;
    context.pRemoteCandidates[ 0 ].endpoint.transportAddress.port = 8080;
    memcpy( ( void * ) &( context.pRemoteCandidates[ 0 ].endpoint.transportAddress.address[ 0 ] ),
            ( const void * ) ipAddress,
            sizeof( ipAddress ) );

    context.numCandidatePairs = 1;
    context.pCandidatePairs[ 0 ].pLocalCandidate = &( context.pLocalCandidates[ 0 ] );
    context.pCandidatePairs[ 0 ].pRemoteCandidate = &( context.pRemoteCandidates[ 0 ] );
    context.pCandidatePairs[ 0 ].state = ICE_CANDIDATE_PAIR_STATE_WAITING;
    memcpy( context.pCandidatePairs[ 0 ].transactionId, transactionID, STUN_HEADER_TRANSACTION_ID_LENGTH );
    pCandidatePair = &context.pCandidatePairs[ 0 ];

    result = Ice_HandleStunPacket( &( context ),
                                   &( stunMessage[ 0 ] ),
                                   stunMessageLength,
                                   &( candidate ),
                                   &( context.pRemoteCandidates[ 0 ].endpoint ),
                                   &( pTransactionId ),
                                   &( pCandidatePair ) );

    TEST_ASSERT_EQUAL( ICE_HANDLE_STUN_PACKET_RESULT_NON_ZERO_ERROR_CODE,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Receiving binding request on TURN connection. And remote endpoint
 * is not matching.
 */
void test_iceHandleStunPacket_BindingResponseSuccess_RemoteEndpointNotMatching( void )
{
    IceContext_t context = { 0 };
    uint8_t * pTransactionId;
    IceCandidatePair_t * pCandidatePair = NULL;
    IceResult_t iceResult;
    IceHandleStunPacketResult_t result;
    uint8_t transactionID[] = {
        0xFF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
    };
    uint8_t stunMessage[] =
    {
        /* STUN header: Message Type = BINDING_REQUEST (0x0001), Length = 56 bytes (excluding 20 bytes header). */
        0x00, 0x01, 0x00, 0x38,
        /* Magic Cookie (0x2112A442). */
        0x21, 0x12, 0xA4, 0x42,
        /* 12 bytes (96 bits) transaction ID which is same as transactionID. */
        0xFF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
        /* Attribute type = XOR Mapped Address (0x0020), Length = 8 bytes. */
        0x00, 0x20, 0x00, 0x08,
        /* Address family = IPv4, Port = 0x3E82, IP Address = 0xC0A80164 (192.168.1.100). */
        0x00, 0x01, 0x3E, 0x82, 0xE1, 0xBA, 0xA5, 0x26,
        /* Attribute type = ICE-CONTROLLED (0x8029), Length = 8 bytes. */
        0x80, 0x29, 0x00, 0x08,
        /* Attribute Value = 0x0706050403020100. */
        0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00,
        /* Attribute type = MESSAGE-INTEGRITY (0x0008), Length = 20 bytes. */
        0x00, 0x08, 0x00, 0x14,
        /* Attribute Value = HMAC value as computed by testHmacFxn_FixedFF. */
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        /* Attribute type = FINGERPRINT (0x8028), Length = 4 bytes. */
        0x80, 0x28, 0x00, 0x04,
        /* Attribute Value: 0x00000000 as calculated by testCrc32Fxn_Fixed. */
        0x00, 0x00, 0x00, 0x00
    };
    size_t stunMessageLength = sizeof( stunMessage );
    IceCandidate_t candidate;
    uint8_t ipAddress2[] = { 0xC0, 0xA8, 0x01, 0x65 }; /* "192.168.1.101". */

    /* Set CRC32 function to testCrc32Fxn_Fixed to make fingerprint always 0x00000000 */
    initInfo.cryptoFunctions.crc32Fxn = testCrc32Fxn_Fixed;
    /* Set CRC32 function to testHmacFxn_FixedFF to make integrity always 0xFF. */
    initInfo.cryptoFunctions.hmacFxn = testHmacFxn_FixedFF;
    iceResult = Ice_Init( &( context ),
                          &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       iceResult );

    memset( &candidate, 0, sizeof( IceCandidate_t ) );
    candidate.endpoint.isPointToPoint = 0U;
    candidate.endpoint.transportAddress.family = STUN_ADDRESS_IPv4;
    candidate.endpoint.transportAddress.port = 8080;
    memcpy( ( void * ) &( candidate.endpoint.transportAddress.address[ 0 ] ),
            ( const void * ) ipAddress2,
            sizeof( ipAddress2 ) );

    context.numLocalCandidates = 1;
    memset( &context.pLocalCandidates[ 0 ], 0, sizeof( IceCandidate_t ) );
    context.pLocalCandidates[ 0 ].candidateType = ICE_CANDIDATE_TYPE_HOST;
    context.pLocalCandidates[ 0 ].endpoint.isPointToPoint = 0U;
    context.pLocalCandidates[ 0 ].endpoint.transportAddress.family = STUN_ADDRESS_IPv4;
    context.pLocalCandidates[ 0 ].endpoint.transportAddress.port = 8080;
    memcpy( ( void * ) &( context.pLocalCandidates[ 0 ].endpoint.transportAddress.address[ 0 ] ),
            ( const void * ) ipAddress,
            sizeof( ipAddress ) );

    /* To simplify, set remote candidate with same endpoint of local candidate. */
    context.numRemoteCandidates = 1;
    memset( &context.pRemoteCandidates[ 0 ], 0, sizeof( IceCandidate_t ) );
    context.pRemoteCandidates[ 0 ].candidateType = ICE_CANDIDATE_TYPE_RELAY;
    context.pRemoteCandidates[ 0 ].endpoint.isPointToPoint = 0U;
    context.pRemoteCandidates[ 0 ].endpoint.transportAddress.family = STUN_ADDRESS_IPv4;
    context.pRemoteCandidates[ 0 ].endpoint.transportAddress.port = 8080;
    memcpy( ( void * ) &( context.pRemoteCandidates[ 0 ].endpoint.transportAddress.address[ 0 ] ),
            ( const void * ) ipAddress,
            sizeof( ipAddress ) );

    context.numCandidatePairs = 1;
    context.pCandidatePairs[ 0 ].pLocalCandidate = &( context.pLocalCandidates[ 0 ] );
    context.pCandidatePairs[ 0 ].pRemoteCandidate = &( context.pRemoteCandidates[ 0 ] );
    context.pCandidatePairs[ 0 ].state = ICE_CANDIDATE_PAIR_STATE_WAITING;
    memcpy( context.pCandidatePairs[ 0 ].transactionId, transactionID, STUN_HEADER_TRANSACTION_ID_LENGTH );
    pCandidatePair = &context.pCandidatePairs[ 0 ];

    result = Ice_HandleStunPacket( &( context ),
                                   &( stunMessage[ 0 ] ),
                                   stunMessageLength,
                                   &( context.pLocalCandidates[ 0 ] ),
                                   &( candidate.endpoint ),
                                   &( pTransactionId ),
                                   &( pCandidatePair ) );

    TEST_ASSERT_EQUAL( ICE_HANDLE_STUN_PACKET_RESULT_CANDIDATE_PAIR_NOT_FOUND,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Receiving binding request on TURN connection. And the pair
 * has empty connectivity check flags.
 */
void test_iceHandleStunPacket_BindingResponseSuccess_RelayCandidate( void )
{
    IceContext_t context = { 0 };
    uint8_t * pTransactionId;
    IceCandidatePair_t * pCandidatePair = NULL;
    IceResult_t iceResult;
    IceHandleStunPacketResult_t result;
    uint8_t transactionID[] = {
        0xFF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
    };
    uint8_t stunMessage[] =
    {
        /* STUN header: Message Type = BINDING_REQUEST (0x0001), Length = 56 bytes (excluding 20 bytes header). */
        0x00, 0x01, 0x00, 0x38,
        /* Magic Cookie (0x2112A442). */
        0x21, 0x12, 0xA4, 0x42,
        /* 12 bytes (96 bits) transaction ID which is same as transactionID. */
        0xFF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
        /* Attribute type = XOR Mapped Address (0x0020), Length = 8 bytes. */
        0x00, 0x20, 0x00, 0x08,
        /* Address family = IPv4, Port = 0x3E82, IP Address = 0xC0A80164 (192.168.1.100). */
        0x00, 0x01, 0x3E, 0x82, 0xE1, 0xBA, 0xA5, 0x26,
        /* Attribute type = ICE-CONTROLLED (0x8029), Length = 8 bytes. */
        0x80, 0x29, 0x00, 0x08,
        /* Attribute Value = 0x0706050403020100. */
        0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00,
        /* Attribute type = MESSAGE-INTEGRITY (0x0008), Length = 20 bytes. */
        0x00, 0x08, 0x00, 0x14,
        /* Attribute Value = HMAC value as computed by testHmacFxn_FixedFF. */
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        /* Attribute type = FINGERPRINT (0x8028), Length = 4 bytes. */
        0x80, 0x28, 0x00, 0x04,
        /* Attribute Value: 0x00000000 as calculated by testCrc32Fxn_Fixed. */
        0x00, 0x00, 0x00, 0x00
    };
    size_t stunMessageLength = sizeof( stunMessage );

    /* Set CRC32 function to testCrc32Fxn_Fixed to make fingerprint always 0x00000000 */
    initInfo.cryptoFunctions.crc32Fxn = testCrc32Fxn_Fixed;
    /* Set CRC32 function to testHmacFxn_FixedFF to make integrity always 0xFF. */
    initInfo.cryptoFunctions.hmacFxn = testHmacFxn_FixedFF;
    iceResult = Ice_Init( &( context ),
                          &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       iceResult );

    context.numLocalCandidates = 1;
    memset( &context.pLocalCandidates[ 0 ], 0, sizeof( IceCandidate_t ) );
    context.pLocalCandidates[ 0 ].candidateType = ICE_CANDIDATE_TYPE_RELAY;
    context.pLocalCandidates[ 0 ].endpoint.isPointToPoint = 0U;
    context.pLocalCandidates[ 0 ].endpoint.transportAddress.family = STUN_ADDRESS_IPv4;
    context.pLocalCandidates[ 0 ].endpoint.transportAddress.port = 8080;
    memcpy( ( void * ) &( context.pLocalCandidates[ 0 ].endpoint.transportAddress.address[ 0 ] ),
            ( const void * ) ipAddress,
            sizeof( ipAddress ) );

    /* To simplify, set remote candidate with same endpoint of local candidate. */
    context.numRemoteCandidates = 1;
    memset( &context.pRemoteCandidates[ 0 ], 0, sizeof( IceCandidate_t ) );
    context.pRemoteCandidates[ 0 ].candidateType = ICE_CANDIDATE_TYPE_RELAY;
    context.pRemoteCandidates[ 0 ].endpoint.isPointToPoint = 0U;
    context.pRemoteCandidates[ 0 ].endpoint.transportAddress.family = STUN_ADDRESS_IPv4;
    context.pRemoteCandidates[ 0 ].endpoint.transportAddress.port = 8080;
    memcpy( ( void * ) &( context.pRemoteCandidates[ 0 ].endpoint.transportAddress.address[ 0 ] ),
            ( const void * ) ipAddress,
            sizeof( ipAddress ) );

    context.numCandidatePairs = 1;
    context.pCandidatePairs[ 0 ].pLocalCandidate = &( context.pLocalCandidates[ 0 ] );
    context.pCandidatePairs[ 0 ].pRemoteCandidate = &( context.pRemoteCandidates[ 0 ] );
    context.pCandidatePairs[ 0 ].state = ICE_CANDIDATE_PAIR_STATE_WAITING;
    memcpy( context.pCandidatePairs[ 0 ].transactionId, transactionID, STUN_HEADER_TRANSACTION_ID_LENGTH );
    pCandidatePair = &context.pCandidatePairs[ 0 ];

    result = Ice_HandleStunPacket( &( context ),
                                   &( stunMessage[ 0 ] ),
                                   stunMessageLength,
                                   &( context.pLocalCandidates[ 0 ] ),
                                   &( context.pRemoteCandidates[ 0 ].endpoint ),
                                   &( pTransactionId ),
                                   &( pCandidatePair ) );

    TEST_ASSERT_EQUAL( ICE_HANDLE_STUN_PACKET_RESULT_SEND_TRIGGERED_CHECK,
                       result );
    TEST_ASSERT_EQUAL( ICE_STUN_REQUEST_RECEIVED_FLAG | ICE_STUN_REQUEST_SENT_FLAG | ICE_STUN_RESPONSE_SENT_FLAG,
                       pCandidatePair->connectivityCheckFlags );
}

/*-----------------------------------------------------------*/

/**
 * @brief Receiving binding request on TURN connection. And input candidate pair
 * is NULL.
 */
void test_iceHandleStunPacket_BindingResponseSuccess_RelayCandidate_NoInputCandidatePair( void )
{
    IceContext_t context = { 0 };
    uint8_t * pTransactionId;
    IceCandidatePair_t * pCandidatePair = NULL;
    IceResult_t iceResult;
    IceHandleStunPacketResult_t result;
    uint8_t stunMessage[] =
    {
        /* STUN header: Message Type = BINDING_REQUEST (0x0001), Length = 56 bytes (excluding 20 bytes header). */
        0x00, 0x01, 0x00, 0x38,
        /* Magic Cookie (0x2112A442). */
        0x21, 0x12, 0xA4, 0x42,
        /* 12 bytes (96 bits) transaction ID which is same as transactionID. */
        0xFF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
        /* Attribute type = XOR Mapped Address (0x0020), Length = 8 bytes. */
        0x00, 0x20, 0x00, 0x08,
        /* Address family = IPv4, Port = 0x3E82, IP Address = 0xC0A80164 (192.168.1.100). */
        0x00, 0x01, 0x3E, 0x82, 0xE1, 0xBA, 0xA5, 0x26,
        /* Attribute type = ICE-CONTROLLED (0x8029), Length = 8 bytes. */
        0x80, 0x29, 0x00, 0x08,
        /* Attribute Value = 0x0706050403020100. */
        0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00,
        /* Attribute type = MESSAGE-INTEGRITY (0x0008), Length = 20 bytes. */
        0x00, 0x08, 0x00, 0x14,
        /* Attribute Value = HMAC value as computed by testHmacFxn_FixedFF. */
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        /* Attribute type = FINGERPRINT (0x8028), Length = 4 bytes. */
        0x80, 0x28, 0x00, 0x04,
        /* Attribute Value: 0x00000000 as calculated by testCrc32Fxn_Fixed. */
        0x00, 0x00, 0x00, 0x00
    };
    size_t stunMessageLength = sizeof( stunMessage );

    /* Set CRC32 function to testCrc32Fxn_Fixed to make fingerprint always 0x00000000 */
    initInfo.cryptoFunctions.crc32Fxn = testCrc32Fxn_Fixed;
    /* Set CRC32 function to testHmacFxn_FixedFF to make integrity always 0xFF. */
    initInfo.cryptoFunctions.hmacFxn = testHmacFxn_FixedFF;
    iceResult = Ice_Init( &( context ),
                          &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       iceResult );

    context.numLocalCandidates = 1;
    memset( &context.pLocalCandidates[ 0 ], 0, sizeof( IceCandidate_t ) );
    context.pLocalCandidates[ 0 ].candidateType = ICE_CANDIDATE_TYPE_RELAY;
    context.pLocalCandidates[ 0 ].endpoint.isPointToPoint = 0U;
    context.pLocalCandidates[ 0 ].endpoint.transportAddress.family = STUN_ADDRESS_IPv4;
    context.pLocalCandidates[ 0 ].endpoint.transportAddress.port = 8080;
    memcpy( ( void * ) &( context.pLocalCandidates[ 0 ].endpoint.transportAddress.address[ 0 ] ),
            ( const void * ) ipAddress,
            sizeof( ipAddress ) );

    /* To simplify, set remote candidate with same endpoint of local candidate. */
    context.numRemoteCandidates = 1;
    memset( &context.pRemoteCandidates[ 0 ], 0, sizeof( IceCandidate_t ) );
    context.pRemoteCandidates[ 0 ].candidateType = ICE_CANDIDATE_TYPE_RELAY;
    context.pRemoteCandidates[ 0 ].endpoint.isPointToPoint = 0U;
    context.pRemoteCandidates[ 0 ].endpoint.transportAddress.family = STUN_ADDRESS_IPv4;
    context.pRemoteCandidates[ 0 ].endpoint.transportAddress.port = 8080;
    memcpy( ( void * ) &( context.pRemoteCandidates[ 0 ].endpoint.transportAddress.address[ 0 ] ),
            ( const void * ) ipAddress,
            sizeof( ipAddress ) );

    result = Ice_HandleStunPacket( &( context ),
                                   &( stunMessage[ 0 ] ),
                                   stunMessageLength,
                                   &( context.pLocalCandidates[ 0 ] ),
                                   &( context.pRemoteCandidates[ 0 ].endpoint ),
                                   &( pTransactionId ),
                                   &( pCandidatePair ) );

    TEST_ASSERT_EQUAL( ICE_HANDLE_STUN_PACKET_RESULT_CANDIDATE_PAIR_NOT_FOUND,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate ICE Handle Stun Packet functionality for Invalid Packets.
 */
void test_iceHandleStunPacket_InvalidPacket( void )
{
    IceContext_t context = { 0 };
    IceCandidate_t localCandidate = { 0 };
    IceEndpoint_t remoteEndpoint = { 0 };
    uint8_t * pTransactionId;
    IceCandidatePair_t * pCandidatePair = NULL;
    IceResult_t iceResult;
    IceHandleStunPacketResult_t result;
    uint8_t stunMessage[] =
    {
        /* STUN header: Message Type = UNKOWN (0x1111), Length = 56 bytes (excluding 20 bytes header). */
        0x11, 0x11, 0x00, 0x38,
        /* Magic Cookie (0x2112A442). */
        0x21, 0x12, 0xA4, 0x42,
        /* 12 bytes (96 bits) transaction ID as generated by testRandomFxn. */
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
        /* Attribute type = XOR Mapped Address (0x0020), Length = 8 bytes. */
        0x00, 0x20, 0x00, 0x08,
        /* Address family = IPv4, Port = 0x3E82, IP Address = 0xC0A80164 (192.168.1.100). */
        0x00, 0x01, 0x3E, 0x82, 0xE1, 0xBA, 0xA5, 0x26,
        /* Attribute type = ICE-CONTROLLED (0x8029), Length = 8 bytes. */
        0x80, 0x29, 0x00, 0x08,
        /* Attribute Value = 0x0706050403020100. */
        0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00,
        /* Attribute type = MESSAGE-INTEGRITY (0x0008), Length = 20 bytes. */
        0x00, 0x08, 0x00, 0x14,
        /* Attribute Value = HMAC value as computed by testHmacFxn. */
        0x6D, 0x6E, 0x63, 0x51,
        0x4D, 0x42, 0xC5, 0x31,
        0x73, 0x76, 0x6D, 0x71,
        0x60, 0x69, 0x69, 0x64,
        0x69, 0x65, 0x5A, 0x6A,
        /* Attribute type = FINGERPRINT (0x8028), Length = 4 bytes. */
        0x80, 0x28, 0x00, 0x04,
        /* Attribute Value: 0xBCD5BE24 as calculated by testCrc32Fxn. */
        0xBC, 0xD5, 0xBE, 0x24
    };
    size_t stunMessageLength = sizeof( stunMessage );

    iceResult = Ice_Init( &( context ),
                          &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       iceResult );

    result = Ice_HandleStunPacket( &( context ),
                                   &( stunMessage[ 0 ] ),
                                   stunMessageLength,
                                   &( localCandidate ),
                                   &( remoteEndpoint ),
                                   &( pTransactionId ),
                                   &( pCandidatePair ) );

    TEST_ASSERT_EQUAL( ICE_HANDLE_STUN_PACKET_RESULT_INVALID_PACKET_TYPE,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate ICE Handle Stun Packet functionality.
 */
void test_iceHandleStunPacket_BindingIndication( void )
{
    IceContext_t context = { 0 };
    IceCandidate_t localCandidate = { 0 };
    IceEndpoint_t remoteEndpoint = { 0 };
    uint8_t * pTransactionId;
    IceCandidatePair_t * pCandidatePair = NULL;
    IceResult_t iceResult;
    IceHandleStunPacketResult_t result;
    uint8_t stunMessage[] =
    {
        /* STUN header: Message Type = BINDING_INDICATION (0x0011), Length = 56 bytes (excluding 20 bytes header). */
        0x00, 0x11, 0x00, 0x38,
        /* Magic Cookie (0x2112A442). */
        0x21, 0x12, 0xA4, 0x42,
        /* 12 bytes (96 bits) transaction ID as generated by testRandomFxn. */
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
        /* Attribute type = XOR Mapped Address (0x0020), Length = 8 bytes. */
        0x00, 0x20, 0x00, 0x08,
        /* Address family = IPv4, Port = 0x3E82, IP Address = 0xC0A80164 (192.168.1.100). */
        0x00, 0x01, 0x3E, 0x82, 0xE1, 0xBA, 0xA5, 0x26,
        /* Attribute type = ICE-CONTROLLED (0x8029), Length = 8 bytes. */
        0x80, 0x29, 0x00, 0x08,
        /* Attribute Value = 0x0706050403020100. */
        0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00,
        /* Attribute type = MESSAGE-INTEGRITY (0x0008), Length = 20 bytes. */
        0x00, 0x08, 0x00, 0x14,
        /* Attribute Value = HMAC value as computed by testHmacFxn. */
        0x6D, 0x6E, 0x63, 0x51,
        0x4D, 0x42, 0xC5, 0x31,
        0x73, 0x76, 0x6D, 0x71,
        0x60, 0x69, 0x69, 0x64,
        0x69, 0x65, 0x5A, 0x6A,
        /* Attribute type = FINGERPRINT (0x8028), Length = 4 bytes. */
        0x80, 0x28, 0x00, 0x04,
        /* Attribute Value: 0xBCD5BE24 as calculated by testCrc32Fxn. */
        0xBC, 0xD5, 0xBE, 0x24
    };
    size_t stunMessageLength = sizeof( stunMessage );

    iceResult = Ice_Init( &( context ),
                          &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       iceResult );

    result = Ice_HandleStunPacket( &( context ),
                                   &( stunMessage[ 0 ] ),
                                   stunMessageLength,
                                   &( localCandidate ),
                                   &( remoteEndpoint ),
                                   &( pTransactionId ),
                                   &( pCandidatePair ) );

    TEST_ASSERT_EQUAL( ICE_HANDLE_STUN_PACKET_RESULT_STUN_BINDING_INDICATION,
                       result );
    TEST_ASSERT_EQUAL_PTR( &( stunMessage[ 8 ] ),
                           pTransactionId );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate Ice_HandleStunPacket droping the packet when transaction ID associated
 * on the packet is not found in the transaction ID store.
 */
void test_iceHandleStunPacket_AllocateErrorResponse_TransactionIDNotFound( void )
{
    IceContext_t context = { 0 };
    IceCandidate_t localCandidate = { 0 };
    IceEndpoint_t remoteEndpoint = { 0 };
    uint8_t * pTransactionId;
    IceCandidatePair_t * pCandidatePair = NULL;
    IceResult_t iceResult;
    IceHandleStunPacketResult_t result;
    uint8_t stunMessage[] =
    {
        /* STUN header: Message Type = ALLOCATE_ERROR_RESPONSE (0x0113), Length = 64 bytes (excluding 20 bytes header). */
        0x01, 0x13, 0x00, 0x40,
        /* Magic Cookie (0x2112A442). */
        0x21, 0x12, 0xA4, 0x42,
        /* 12 bytes (96 bits) invalid transaction ID. */
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
        /* Attribute Type = Error Code (0x0009), Attribute Length = 16 (2 reserved bytes, 2 byte error code and 12 byte error phrase). */
        0x00, 0x09, 0x00, 0x10,
        /* Reserved = 0x0000, Error Class = 4, Error Number = 01 (Error Code = 401 unauthorized). */
        0x00, 0x00, 0x04, 0x01,
        /* Attribute type = REALM (0x0014), Length = 5 bytes. */
        0x00, 0x14, 0x00, 0x05,
        /* Attribute Value: "realm". */
        0x72, 0x65, 0x61, 0x6C,
        0x6D, 0x00, 0x00, 0x00,
        /* Attribute type = NONCE (0x0015), Length = 5 bytes. */
        0x00, 0x15, 0x00, 0x05,
        /* Attribute Value: "nonce". */
        0x6E, 0x6F, 0x6E, 0x63,
        0x65, 0x00, 0x00, 0x00,
        /* Attribute type = MESSAGE-INTEGRITY (0x0008), Length = 20 bytes. */
        0x00, 0x08, 0x00, 0x14,
        /* Attribute Value = HMAC value as computed by testHmacFxn. */
        0x6D, 0x6E, 0x63, 0x51,
        0x4D, 0x42, 0xC5, 0x31,
        0x73, 0x76, 0x6D, 0x71,
        0x60, 0x69, 0x69, 0x64,
        0x69, 0x65, 0x5A, 0x6A,
        /* Attribute type = FINGERPRINT (0x8028), Length = 4 bytes. */
        0x80, 0x28, 0x00, 0x04,
        /* Attribute Value: 0xBCD5BE24 as calculated by testCrc32Fxn. */
        0xBC, 0xD5, 0xBE, 0x24
    };
    size_t stunMessageLength = sizeof( stunMessage );

    iceResult = Ice_Init( &( context ),
                          &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       iceResult );

    result = Ice_HandleStunPacket( &( context ),
                                   &( stunMessage[ 0 ] ),
                                   stunMessageLength,
                                   &( localCandidate ),
                                   &( remoteEndpoint ),
                                   &( pTransactionId ),
                                   &( pCandidatePair ) );

    TEST_ASSERT_EQUAL( ICE_HANDLE_STUN_PACKET_RESULT_DROP_PACKET,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate Ice_HandleStunPacket update realm, nonce, and long term key
 * in the local candidate.
 */
void test_iceHandleStunPacket_AllocateErrorResponse_Unautorized_UpdateServerInfo( void )
{
    IceContext_t context = { 0 };
    IceCandidate_t localCandidate = { 0 };
    IceEndpoint_t remoteEndpoint = { 0 };
    uint8_t * pTransactionId;
    IceCandidatePair_t * pCandidatePair = NULL;
    IceResult_t iceResult;
    IceHandleStunPacketResult_t result;
    uint8_t transactionID[] =
    {
        0xFF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B
    };
    uint8_t stunMessage[] =
    {
        /* STUN header: Message Type = ALLOCATE_ERROR_RESPONSE (0x0113), Length = 52 bytes (excluding 20 bytes header). */
        0x01, 0x13, 0x00, 0x34,
        /* Magic Cookie (0x2112A442). */
        0x21, 0x12, 0xA4, 0x42,
        /* 12 bytes (96 bits) transaction ID which is same as transactionID. */
        0xFF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
        /* Attribute Type = Error Code (0x0009), Attribute Length = 16 (2 reserved bytes, 2 byte error code and 12 byte error phrase). */
        0x00, 0x09, 0x00, 0x10,
        /* Reserved = 0x0000, Error Class = 4, Error Number = 01 (Error Code = 401 unauthorized). */
        0x00, 0x00, 0x04, 0x01,
        /* Error Phrase = "Error Phrase". */
        0x45, 0x72, 0x72, 0x6F,
        0x72, 0x20, 0x50, 0x68,
        0x72, 0x61, 0x73, 0x65,
        /* Attribute type = REALM (0x0014), Length = 5 bytes. */
        0x00, 0x14, 0x00, 0x05,
        /* Attribute Value: "realm". */
        0x72, 0x65, 0x61, 0x6C,
        0x6D, 0x00, 0x00, 0x00,
        /* Attribute type = NONCE (0x0015), Length = 5 bytes. */
        0x00, 0x15, 0x00, 0x05,
        /* Attribute Value: "nonce". */
        0x6E, 0x6F, 0x6E, 0x63,
        0x65, 0x00, 0x00, 0x00,
        /* Attribute type = FINGERPRINT (0x8028), Length = 4 bytes. */
        0x80, 0x28, 0x00, 0x04,
        /* Attribute Value: 0x32868620 as calculated by testCrc32Fxn. */
        0x32, 0x86, 0x86, 0x20
    };
    size_t stunMessageLength = sizeof( stunMessage );
    char * pUsername = "username";
    size_t usernameLength = strlen( pUsername );
    char * pPassword = "password";
    size_t passwordLength = strlen( pPassword );
    char * pExpectedRealm = "realm";
    size_t expectedRealmLength = strlen( pExpectedRealm );
    char * pExpectedNonce = "nonce";
    size_t expectedNonceLength = strlen( pExpectedNonce );
    char * pPreLongTermPassword = "username:realm:password"; /* Follow https://datatracker.ietf.org/doc/html/rfc5389#section-15.4. */
    size_t preLongTermPasswordLength = strlen( pPreLongTermPassword );
    uint16_t expectedLongTermPasswordLength = 16; /* It's always 16 bytes as MD5 result. */
    uint8_t pExpectedLongTermPassword[ expectedLongTermPasswordLength ];

    iceResult = Ice_Init( &( context ),
                          &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       iceResult );

    memset( &( localCandidate ),
            0,
            sizeof( IceCandidate_t ) );
    context.numRelayExtensions = 1;
    localCandidate.pRelayExtension = &( context.pRelayExtensionsArray[ 0 ] );
    memcpy( &localCandidate.pRelayExtension->iceRelayServerInfo.userName, pUsername, usernameLength );
    localCandidate.pRelayExtension->iceRelayServerInfo.userNameLength = usernameLength;
    memcpy( &localCandidate.pRelayExtension->iceRelayServerInfo.password, pPassword, passwordLength );
    localCandidate.pRelayExtension->iceRelayServerInfo.passwordLength = passwordLength;
    localCandidate.candidateType = ICE_CANDIDATE_TYPE_RELAY;
    localCandidate.state = ICE_CANDIDATE_STATE_ALLOCATING;

    memcpy( &( localCandidate.transactionId[ 0 ] ),
            &( transactionID[ 0 ] ),
            sizeof( transactionID ) );

    /* Prepare expected long term password by calling testMd5 API. */
    ( void ) testMd5Fxn( ( const uint8_t * ) pPreLongTermPassword,
                         preLongTermPasswordLength,
                         pExpectedLongTermPassword,
                         &expectedLongTermPasswordLength );

    result = Ice_HandleStunPacket( &( context ),
                                   &( stunMessage[ 0 ] ),
                                   stunMessageLength,
                                   &( localCandidate ),
                                   &( remoteEndpoint ),
                                   &( pTransactionId ),
                                   &( pCandidatePair ) );

    TEST_ASSERT_EQUAL( ICE_HANDLE_STUN_PACKET_RESULT_SEND_ALLOCATION_REQUEST,
                       result );
    TEST_ASSERT_EQUAL( expectedRealmLength,
                       localCandidate.pRelayExtension->iceRelayServerInfo.realmLength );
    TEST_ASSERT_EQUAL_UINT8_ARRAY( pExpectedRealm,
                                   localCandidate.pRelayExtension->iceRelayServerInfo.realm,
                                   expectedRealmLength );
    TEST_ASSERT_EQUAL( expectedNonceLength,
                       localCandidate.pRelayExtension->iceRelayServerInfo.nonceLength );
    TEST_ASSERT_EQUAL_UINT8_ARRAY( pExpectedNonce,
                                   localCandidate.pRelayExtension->iceRelayServerInfo.nonce,
                                   expectedNonceLength );
    TEST_ASSERT_EQUAL( expectedLongTermPasswordLength,
                       localCandidate.pRelayExtension->iceRelayServerInfo.longTermPasswordLength );
    TEST_ASSERT_EQUAL_UINT8_ARRAY( pExpectedLongTermPassword,
                                   localCandidate.pRelayExtension->iceRelayServerInfo.longTermPassword,
                                   expectedLongTermPasswordLength );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate Ice_HandleStunPacket update nonce when receiving stale nonce.
 */
void test_iceHandleStunPacket_AllocateErrorResponse_StaleNonce_UpdateServerInfo( void )
{
    IceContext_t context = { 0 };
    IceCandidate_t localCandidate = { 0 };
    IceEndpoint_t remoteEndpoint = { 0 };
    uint8_t * pTransactionId;
    IceCandidatePair_t * pCandidatePair = NULL;
    IceResult_t iceResult;
    IceHandleStunPacketResult_t result;
    uint8_t transactionID[] =
    {
        0xFF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B
    };
    uint8_t stunMessage[] =
    {
        /* STUN header: Message Type = ALLOCATE_ERROR_RESPONSE (0x0113), Length = 40 bytes (excluding 20 bytes header). */
        0x01, 0x13, 0x00, 0x28,
        /* Magic Cookie (0x2112A442). */
        0x21, 0x12, 0xA4, 0x42,
        /* 12 bytes (96 bits) transaction ID which is same as transactionID. */
        0xFF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
        /* Attribute Type = Error Code (0x0009), Attribute Length = 16 (2 reserved bytes, 2 byte error code and 12 byte error phrase). */
        0x00, 0x09, 0x00, 0x10,
        /* Reserved = 0x0000, Error Class = 4, Error Number = 22 (Error Code = 438 stale nonce). */
        0x00, 0x00, 0x04, 0x01,
        /* Error Phrase = "Error Phrase". */
        0x45, 0x72, 0x72, 0x6F,
        0x72, 0x20, 0x50, 0x68,
        0x72, 0x61, 0x73, 0x65,
        /* Attribute type = NONCE (0x0015), Length = 5 bytes. */
        0x00, 0x15, 0x00, 0x05,
        /* Attribute Value: "nonce". */
        0x6E, 0x6F, 0x6E, 0x63,
        0x65, 0x00, 0x00, 0x00,
        /* Attribute type = FINGERPRINT (0x8028), Length = 4 bytes. */
        0x80, 0x28, 0x00, 0x04,
        /* Attribute Value: 0xFEEF5290 as calculated by testCrc32Fxn. */
        0xFE, 0xEF, 0x52, 0x90
    };
    size_t stunMessageLength = sizeof( stunMessage );
    char * pUsername = "username";
    size_t usernameLength = strlen( pUsername );
    char * pPassword = "password";
    size_t passwordLength = strlen( pPassword );
    char * pExpectedNonce = "nonce";
    size_t expectedNonceLength = strlen( pExpectedNonce );

    iceResult = Ice_Init( &( context ),
                          &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       iceResult );

    memset( &( localCandidate ),
            0,
            sizeof( IceCandidate_t ) );
    context.numRelayExtensions = 1;
    localCandidate.pRelayExtension = &( context.pRelayExtensionsArray[ 0 ] );
    memcpy( &localCandidate.pRelayExtension->iceRelayServerInfo.userName, pUsername, usernameLength );
    localCandidate.pRelayExtension->iceRelayServerInfo.userNameLength = usernameLength;
    memcpy( &localCandidate.pRelayExtension->iceRelayServerInfo.password, pPassword, passwordLength );
    localCandidate.pRelayExtension->iceRelayServerInfo.passwordLength = passwordLength;
    localCandidate.candidateType = ICE_CANDIDATE_TYPE_RELAY;
    localCandidate.state = ICE_CANDIDATE_STATE_ALLOCATING;

    memcpy( &( localCandidate.transactionId[ 0 ] ),
            &( transactionID[ 0 ] ),
            sizeof( transactionID ) );

    result = Ice_HandleStunPacket( &( context ),
                                   &( stunMessage[ 0 ] ),
                                   stunMessageLength,
                                   &( localCandidate ),
                                   &( remoteEndpoint ),
                                   &( pTransactionId ),
                                   &( pCandidatePair ) );

    TEST_ASSERT_EQUAL( ICE_HANDLE_STUN_PACKET_RESULT_SEND_ALLOCATION_REQUEST,
                       result );
    TEST_ASSERT_EQUAL( expectedNonceLength,
                       localCandidate.pRelayExtension->iceRelayServerInfo.nonceLength );
    TEST_ASSERT_EQUAL_UINT8_ARRAY( pExpectedNonce,
                                   localCandidate.pRelayExtension->iceRelayServerInfo.nonce,
                                   expectedNonceLength );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate Ice_HandleStunPacket with Allocate Error Response but the
 * local candidate is not allocating resource.
 */
void test_iceHandleStunPacket_AllocateErrorResponse_CandidateNotAllocating( void )
{
    IceContext_t context = { 0 };
    IceCandidate_t localCandidate = { 0 };
    IceEndpoint_t remoteEndpoint = { 0 };
    uint8_t * pTransactionId;
    IceCandidatePair_t * pCandidatePair = NULL;
    IceResult_t iceResult;
    IceHandleStunPacketResult_t result;
    uint8_t transactionID[] =
    {
        0xFF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B
    };
    uint8_t stunMessage[] =
    {
        /* STUN header: Message Type = ALLOCATE_ERROR_RESPONSE (0x0113), Length = 40 bytes (excluding 20 bytes header). */
        0x01, 0x13, 0x00, 0x28,
        /* Magic Cookie (0x2112A442). */
        0x21, 0x12, 0xA4, 0x42,
        /* 12 bytes (96 bits) transaction ID which is same as transactionID. */
        0xFF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
        /* Attribute Type = Error Code (0x0009), Attribute Length = 16 (2 reserved bytes, 2 byte error code and 12 byte error phrase). */
        0x00, 0x09, 0x00, 0x10,
        /* Reserved = 0x0000, Error Class = 4, Error Number = 22 (Error Code = 438 stale nonce). */
        0x00, 0x00, 0x04, 0x01,
        /* Error Phrase = "Error Phrase". */
        0x45, 0x72, 0x72, 0x6F,
        0x72, 0x20, 0x50, 0x68,
        0x72, 0x61, 0x73, 0x65,
        /* Attribute type = NONCE (0x0015), Length = 5 bytes. */
        0x00, 0x15, 0x00, 0x05,
        /* Attribute Value: "nonce". */
        0x6E, 0x6F, 0x6E, 0x63,
        0x65, 0x00, 0x00, 0x00,
        /* Attribute type = FINGERPRINT (0x8028), Length = 4 bytes. */
        0x80, 0x28, 0x00, 0x04,
        /* Attribute Value: 0xFEEF5290 as calculated by testCrc32Fxn. */
        0xFE, 0xEF, 0x52, 0x90
    };
    size_t stunMessageLength = sizeof( stunMessage );
    char * pUsername = "username";
    size_t usernameLength = strlen( pUsername );
    char * pPassword = "password";
    size_t passwordLength = strlen( pPassword );

    iceResult = Ice_Init( &( context ),
                          &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       iceResult );

    memset( &( localCandidate ),
            0,
            sizeof( IceCandidate_t ) );
    context.numRelayExtensions = 1;
    localCandidate.pRelayExtension = &( context.pRelayExtensionsArray[ 0 ] );
    memcpy( &localCandidate.pRelayExtension->iceRelayServerInfo.userName, pUsername, usernameLength );
    localCandidate.pRelayExtension->iceRelayServerInfo.userNameLength = usernameLength;
    memcpy( &localCandidate.pRelayExtension->iceRelayServerInfo.password, pPassword, passwordLength );
    localCandidate.pRelayExtension->iceRelayServerInfo.passwordLength = passwordLength;
    localCandidate.candidateType = ICE_CANDIDATE_TYPE_RELAY;
    localCandidate.state = ICE_CANDIDATE_STATE_VALID;

    memcpy( &( localCandidate.transactionId[ 0 ] ),
            &( transactionID[ 0 ] ),
            sizeof( transactionID ) );

    result = Ice_HandleStunPacket( &( context ),
                                   &( stunMessage[ 0 ] ),
                                   stunMessageLength,
                                   &( localCandidate ),
                                   &( remoteEndpoint ),
                                   &( pTransactionId ),
                                   &( pCandidatePair ) );

    TEST_ASSERT_EQUAL( ICE_HANDLE_STUN_PACKET_RESULT_RELAY_CANDIDATE_NOT_ALLOCATING,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Receive a ALLOCATE_ERROR_RESPONSE and the nonce inside is longer than default
 * buffer size ( 128 ).
 */
void test_iceHandleStunPacket_AllocateErrorResponse_Unautorized_NonceTooLong( void )
{
    IceContext_t context = { 0 };
    IceCandidate_t localCandidate = { 0 };
    IceEndpoint_t remoteEndpoint = { 0 };
    uint8_t * pTransactionId;
    IceCandidatePair_t * pCandidatePair = NULL;
    IceResult_t iceResult;
    IceHandleStunPacketResult_t result;
    uint8_t transactionID[] =
    {
        0xFF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B
    };
    uint8_t stunMessage[] =
    {
        /* STUN header: Message Type = ALLOCATE_ERROR_RESPONSE (0x0113), Length = 176 bytes (excluding 20 bytes header). */
        0x01, 0x13, 0x00, 0xB0,
        /* Magic Cookie (0x2112A442). */
        0x21, 0x12, 0xA4, 0x42,
        /* 12 bytes (96 bits) transaction ID which is same as transactionID. */
        0xFF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
        /* Attribute Type = Error Code (0x0009), Attribute Length = 16 (2 reserved bytes, 2 byte error code and 12 byte error phrase). */
        0x00, 0x09, 0x00, 0x10,
        /* Reserved = 0x0000, Error Class = 4, Error Number = 01 (Error Code = 401 unauthorized). */
        0x00, 0x00, 0x04, 0x01,
        /* Error Phrase = "Error Phrase". */
        0x45, 0x72, 0x72, 0x6F,
        0x72, 0x20, 0x50, 0x68,
        0x72, 0x61, 0x73, 0x65,
        /* Attribute type = REALM (0x0014), Length = 5 bytes. */
        0x00, 0x14, 0x00, 0x05,
        /* Attribute Value: "realm". */
        0x72, 0x65, 0x61, 0x6C,
        0x6D, 0x00, 0x00, 0x00,
        /* Attribute type = NONCE (0x0015), Length = 129 bytes, which is larger than ICE_SERVER_CONFIG_MAX_NONCE_LENGTH(128). */
        0x00, 0x15, 0x00, 0x81,
        /* Attribute Value: 0x00~0x80. */
        0x00, 0x01, 0x02, 0x03,
        0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B,
        0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13,
        0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1A, 0x1B,
        0x1C, 0x1D, 0x1E, 0x1F,
        0x20, 0x21, 0x22, 0x23,
        0x24, 0x25, 0x26, 0x27,
        0x28, 0x29, 0x2A, 0x2B,
        0x2C, 0x2D, 0x2E, 0x2F,
        0x30, 0x31, 0x32, 0x33,
        0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x3A, 0x3B,
        0x3C, 0x3D, 0x3E, 0x3F,
        0x40, 0x41, 0x42, 0x43,
        0x44, 0x45, 0x46, 0x47,
        0x48, 0x49, 0x4A, 0x4B,
        0x4C, 0x4D, 0x4E, 0x4F,
        0x50, 0x51, 0x52, 0x53,
        0x54, 0x55, 0x56, 0x57,
        0x58, 0x59, 0x5A, 0x5B,
        0x5C, 0x5D, 0x5E, 0x5F,
        0x60, 0x61, 0x62, 0x63,
        0x64, 0x65, 0x66, 0x67,
        0x68, 0x69, 0x6A, 0x6B,
        0x6C, 0x6D, 0x6E, 0x6F,
        0x70, 0x71, 0x72, 0x73,
        0x74, 0x75, 0x76, 0x77,
        0x78, 0x79, 0x7A, 0x7B,
        0x7C, 0x7D, 0x7E, 0x7F,
        0x80, 0x00, 0x00, 0x00,
        /* Attribute type = FINGERPRINT (0x8028), Length = 4 bytes. */
        0x80, 0x28, 0x00, 0x04,
        /* Attribute Value: 0xDCEAECB9 as calculated by testCrc32Fxn. */
        0xDC, 0xEA, 0xEC, 0xB9
    };
    size_t stunMessageLength = sizeof( stunMessage );

    iceResult = Ice_Init( &( context ),
                          &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       iceResult );

    memset( &( localCandidate ),
            0,
            sizeof( IceCandidate_t ) );
    localCandidate.candidateType = ICE_CANDIDATE_TYPE_RELAY;
    localCandidate.state = ICE_CANDIDATE_STATE_ALLOCATING;
    context.numRelayExtensions = 1;
    localCandidate.pRelayExtension = &( context.pRelayExtensionsArray[ 0 ] );

    memcpy( &( localCandidate.transactionId[ 0 ] ),
            &( transactionID[ 0 ] ),
            sizeof( transactionID ) );

    result = Ice_HandleStunPacket( &( context ),
                                   &( stunMessage[ 0 ] ),
                                   stunMessageLength,
                                   &( localCandidate ),
                                   &( remoteEndpoint ),
                                   &( pTransactionId ),
                                   &( pCandidatePair ) );

    TEST_ASSERT_EQUAL( ICE_HANDLE_STUN_PACKET_RESULT_NONCE_LENGTH_EXCEEDED,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Receive a ALLOCATE_ERROR_RESPONSE and the realm inside is longer than default
 * buffer size ( 128 ).
 */
void test_iceHandleStunPacket_AllocateErrorResponse_Unautorized_RealmTooLong( void )
{
    IceContext_t context = { 0 };
    IceCandidate_t localCandidate = { 0 };
    IceEndpoint_t remoteEndpoint = { 0 };
    uint8_t * pTransactionId;
    IceCandidatePair_t * pCandidatePair = NULL;
    IceResult_t iceResult;
    IceHandleStunPacketResult_t result;
    uint8_t transactionID[] =
    {
        0xFF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B
    };
    uint8_t stunMessage[] =
    {
        /* STUN header: Message Type = ALLOCATE_ERROR_RESPONSE (0x0113), Length = 176 bytes (excluding 20 bytes header). */
        0x01, 0x13, 0x00, 0xB0,
        /* Magic Cookie (0x2112A442). */
        0x21, 0x12, 0xA4, 0x42,
        /* 12 bytes (96 bits) transaction ID which is same as transactionID. */
        0xFF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
        /* Attribute Type = Error Code (0x0009), Attribute Length = 16 (2 reserved bytes, 2 byte error code and 12 byte error phrase). */
        0x00, 0x09, 0x00, 0x10,
        /* Reserved = 0x0000, Error Class = 4, Error Number = 01 (Error Code = 401 unauthorized). */
        0x00, 0x00, 0x04, 0x01,
        /* Error Phrase = "Error Phrase". */
        0x45, 0x72, 0x72, 0x6F,
        0x72, 0x20, 0x50, 0x68,
        0x72, 0x61, 0x73, 0x65,
        /* Attribute type = REALM (0x0014), Length = 129 bytes, which is larger than ICE_SERVER_CONFIG_MAX_REALM_LENGTH(128). */
        0x00, 0x14, 0x00, 0x81,
        /* Attribute Value: 0x00~0x80. */
        0x00, 0x01, 0x02, 0x03,
        0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B,
        0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13,
        0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1A, 0x1B,
        0x1C, 0x1D, 0x1E, 0x1F,
        0x20, 0x21, 0x22, 0x23,
        0x24, 0x25, 0x26, 0x27,
        0x28, 0x29, 0x2A, 0x2B,
        0x2C, 0x2D, 0x2E, 0x2F,
        0x30, 0x31, 0x32, 0x33,
        0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x3A, 0x3B,
        0x3C, 0x3D, 0x3E, 0x3F,
        0x40, 0x41, 0x42, 0x43,
        0x44, 0x45, 0x46, 0x47,
        0x48, 0x49, 0x4A, 0x4B,
        0x4C, 0x4D, 0x4E, 0x4F,
        0x50, 0x51, 0x52, 0x53,
        0x54, 0x55, 0x56, 0x57,
        0x58, 0x59, 0x5A, 0x5B,
        0x5C, 0x5D, 0x5E, 0x5F,
        0x60, 0x61, 0x62, 0x63,
        0x64, 0x65, 0x66, 0x67,
        0x68, 0x69, 0x6A, 0x6B,
        0x6C, 0x6D, 0x6E, 0x6F,
        0x70, 0x71, 0x72, 0x73,
        0x74, 0x75, 0x76, 0x77,
        0x78, 0x79, 0x7A, 0x7B,
        0x7C, 0x7D, 0x7E, 0x7F,
        0x80, 0x00, 0x00, 0x00,
        /* Attribute type = NONCE (0x0015), Length = 5 bytes. */
        0x00, 0x15, 0x00, 0x05,
        /* Attribute Value: "nonce". */
        0x6E, 0x6F, 0x6E, 0x63,
        0x65, 0x00, 0x00, 0x00,
        /* Attribute type = FINGERPRINT (0x8028), Length = 4 bytes. */
        0x80, 0x28, 0x00, 0x04,
        /* Attribute Value: 0xB7DCACB2 as calculated by testCrc32Fxn. */
        0xB7, 0xDC, 0xAC, 0xB2
    };
    size_t stunMessageLength = sizeof( stunMessage );

    iceResult = Ice_Init( &( context ),
                          &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       iceResult );

    memset( &( localCandidate ),
            0,
            sizeof( IceCandidate_t ) );
    localCandidate.candidateType = ICE_CANDIDATE_TYPE_RELAY;
    localCandidate.state = ICE_CANDIDATE_STATE_ALLOCATING;
    context.numRelayExtensions = 1;
    localCandidate.pRelayExtension = &( context.pRelayExtensionsArray[ 0 ] );


    memcpy( &( localCandidate.transactionId[ 0 ] ),
            &( transactionID[ 0 ] ),
            sizeof( transactionID ) );

    result = Ice_HandleStunPacket( &( context ),
                                   &( stunMessage[ 0 ] ),
                                   stunMessageLength,
                                   &( localCandidate ),
                                   &( remoteEndpoint ),
                                   &( pTransactionId ),
                                   &( pCandidatePair ) );

    TEST_ASSERT_EQUAL( ICE_HANDLE_STUN_PACKET_RESULT_REALM_LENGTH_EXCEEDED,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Ice_HandleStunPacket recieves a ALLOCATE_ERROR_RESPONSE with
 * no nonce inside.
 */
void test_iceHandleStunPacket_AllocateErrorResponse_Unautorized_NoNonce( void )
{
    IceContext_t context = { 0 };
    IceCandidate_t localCandidate = { 0 };
    IceEndpoint_t remoteEndpoint = { 0 };
    uint8_t * pTransactionId;
    IceCandidatePair_t * pCandidatePair = NULL;
    IceResult_t iceResult;
    IceHandleStunPacketResult_t result;
    uint8_t transactionID[] =
    {
        0xFF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B
    };
    uint8_t stunMessage[] =
    {
        /* STUN header: Message Type = ALLOCATE_ERROR_RESPONSE (0x0113), Length = 40 bytes (excluding 20 bytes header). */
        0x01, 0x13, 0x00, 0x28,
        /* Magic Cookie (0x2112A442). */
        0x21, 0x12, 0xA4, 0x42,
        /* 12 bytes (96 bits) transaction ID which is same as transactionID. */
        0xFF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
        /* Attribute Type = Error Code (0x0009), Attribute Length = 16 (2 reserved bytes, 2 byte error code and 12 byte error phrase). */
        0x00, 0x09, 0x00, 0x10,
        /* Reserved = 0x0000, Error Class = 4, Error Number = 01 (Error Code = 401 unauthorized). */
        0x00, 0x00, 0x04, 0x01,
        /* Error Phrase = "Error Phrase". */
        0x45, 0x72, 0x72, 0x6F,
        0x72, 0x20, 0x50, 0x68,
        0x72, 0x61, 0x73, 0x65,
        /* Attribute type = REALM (0x0014), Length = 5 bytes. */
        0x00, 0x14, 0x00, 0x05,
        /* Attribute Value: "realm". */
        0x72, 0x65, 0x61, 0x6C,
        0x6D, 0x00, 0x00, 0x00,
        /* Attribute type = FINGERPRINT (0x8028), Length = 4 bytes. */
        0x80, 0x28, 0x00, 0x04,
        /* Attribute Value: 0x00000000 as calculated by testCrc32Fxn_Fixed. */
        0x00, 0x00, 0x00, 0x00
    };
    size_t stunMessageLength = sizeof( stunMessage );
    char * pUsername = "username";
    size_t usernameLength = strlen( pUsername );
    char * pPassword = "password";
    size_t passwordLength = strlen( pPassword );
    char * pExpectedRealm = "realm";
    size_t expectedRealmLength = strlen( pExpectedRealm );
    size_t expectedNonceLength = 0;
    char * pPreLongTermPassword = "username:realm:password"; /* Follow https://datatracker.ietf.org/doc/html/rfc5389#section-15.4. */
    size_t preLongTermPasswordLength = strlen( pPreLongTermPassword );
    uint16_t expectedLongTermPasswordLength = 16; /* It's always 16 bytes as MD5 result. */
    uint8_t pExpectedLongTermPassword[ expectedLongTermPasswordLength ];

    /* Set CRC32 function to testCrc32Fxn_Fixed to make fingerprint always 0x00000000 */
    initInfo.cryptoFunctions.crc32Fxn = testCrc32Fxn_Fixed;

    iceResult = Ice_Init( &( context ),
                          &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       iceResult );

    memset( &( localCandidate ),
            0,
            sizeof( IceCandidate_t ) );
    context.numRelayExtensions = 1;
    localCandidate.pRelayExtension = &( context.pRelayExtensionsArray[ 0 ] );
    memcpy( &localCandidate.pRelayExtension->iceRelayServerInfo.userName, pUsername, usernameLength );
    localCandidate.pRelayExtension->iceRelayServerInfo.userNameLength = usernameLength;
    memcpy( &localCandidate.pRelayExtension->iceRelayServerInfo.password, pPassword, passwordLength );
    localCandidate.pRelayExtension->iceRelayServerInfo.passwordLength = passwordLength;
    localCandidate.candidateType = ICE_CANDIDATE_TYPE_RELAY;
    localCandidate.state = ICE_CANDIDATE_STATE_ALLOCATING;

    memcpy( &( localCandidate.transactionId[ 0 ] ),
            &( transactionID[ 0 ] ),
            sizeof( transactionID ) );

    /* Prepare expected long term password by calling testMd5 API. */
    ( void ) testMd5Fxn( ( const uint8_t * ) pPreLongTermPassword,
                         preLongTermPasswordLength,
                         pExpectedLongTermPassword,
                         &expectedLongTermPasswordLength );

    result = Ice_HandleStunPacket( &( context ),
                                   &( stunMessage[ 0 ] ),
                                   stunMessageLength,
                                   &( localCandidate ),
                                   &( remoteEndpoint ),
                                   &( pTransactionId ),
                                   &( pCandidatePair ) );

    TEST_ASSERT_EQUAL( ICE_HANDLE_STUN_PACKET_RESULT_SEND_ALLOCATION_REQUEST,
                       result );
    TEST_ASSERT_EQUAL( expectedRealmLength,
                       localCandidate.pRelayExtension->iceRelayServerInfo.realmLength );
    TEST_ASSERT_EQUAL_UINT8_ARRAY( pExpectedRealm,
                                   localCandidate.pRelayExtension->iceRelayServerInfo.realm,
                                   expectedRealmLength );
    TEST_ASSERT_EQUAL( expectedNonceLength,
                       localCandidate.pRelayExtension->iceRelayServerInfo.nonceLength );
    TEST_ASSERT_EQUAL( expectedLongTermPasswordLength,
                       localCandidate.pRelayExtension->iceRelayServerInfo.longTermPasswordLength );
    TEST_ASSERT_EQUAL_UINT8_ARRAY( pExpectedLongTermPassword,
                                   localCandidate.pRelayExtension->iceRelayServerInfo.longTermPassword,
                                   expectedLongTermPasswordLength );
}

/*-----------------------------------------------------------*/

/**
 * @brief Ice_HandleStunPacket recieves a ALLOCATE_ERROR_RESPONSE with
 * no realm inside.
 */
void test_iceHandleStunPacket_AllocateErrorResponse_Unautorized_NoRealm( void )
{
    IceContext_t context = { 0 };
    IceCandidate_t localCandidate = { 0 };
    IceEndpoint_t remoteEndpoint = { 0 };
    uint8_t * pTransactionId;
    IceCandidatePair_t * pCandidatePair = NULL;
    IceResult_t iceResult;
    IceHandleStunPacketResult_t result;
    uint8_t transactionID[] =
    {
        0xFF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B
    };
    uint8_t stunMessage[] =
    {
        /* STUN header: Message Type = ALLOCATE_ERROR_RESPONSE (0x0113), Length = 40 bytes (excluding 20 bytes header). */
        0x01, 0x13, 0x00, 0x28,
        /* Magic Cookie (0x2112A442). */
        0x21, 0x12, 0xA4, 0x42,
        /* 12 bytes (96 bits) transaction ID which is same as transactionID. */
        0xFF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
        /* Attribute Type = Error Code (0x0009), Attribute Length = 16 (2 reserved bytes, 2 byte error code and 12 byte error phrase). */
        0x00, 0x09, 0x00, 0x10,
        /* Reserved = 0x0000, Error Class = 4, Error Number = 01 (Error Code = 401 unauthorized). */
        0x00, 0x00, 0x04, 0x01,
        /* Error Phrase = "Error Phrase". */
        0x45, 0x72, 0x72, 0x6F,
        0x72, 0x20, 0x50, 0x68,
        0x72, 0x61, 0x73, 0x65,
        /* Attribute type = NONCE (0x0015), Length = 5 bytes. */
        0x00, 0x15, 0x00, 0x05,
        /* Attribute Value: "nonce". */
        0x6E, 0x6F, 0x6E, 0x63,
        0x65, 0x00, 0x00, 0x00,
        /* Attribute type = FINGERPRINT (0x8028), Length = 4 bytes. */
        0x80, 0x28, 0x00, 0x04,
        /* Attribute Value: 0x00000000 as calculated by testCrc32Fxn_Fixed. */
        0x00, 0x00, 0x00, 0x00
    };
    size_t stunMessageLength = sizeof( stunMessage );
    char * pUsername = "username";
    size_t usernameLength = strlen( pUsername );
    char * pPassword = "password";
    size_t passwordLength = strlen( pPassword );
    size_t expectedRealmLength = 0U;
    char * pExpectedNonce = "nonce";
    size_t expectedNonceLength = strlen( pExpectedNonce );

    /* Set CRC32 function to testCrc32Fxn_Fixed to make fingerprint always 0x00000000 */
    initInfo.cryptoFunctions.crc32Fxn = testCrc32Fxn_Fixed;

    iceResult = Ice_Init( &( context ),
                          &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       iceResult );

    memset( &( localCandidate ),
            0,
            sizeof( IceCandidate_t ) );
    context.numRelayExtensions = 1;
    localCandidate.pRelayExtension = &( context.pRelayExtensionsArray[ 0 ] );
    memcpy( &localCandidate.pRelayExtension->iceRelayServerInfo.userName, pUsername, usernameLength );
    localCandidate.pRelayExtension->iceRelayServerInfo.userNameLength = usernameLength;
    memcpy( &localCandidate.pRelayExtension->iceRelayServerInfo.password, pPassword, passwordLength );
    localCandidate.pRelayExtension->iceRelayServerInfo.passwordLength = passwordLength;
    localCandidate.candidateType = ICE_CANDIDATE_TYPE_RELAY;
    localCandidate.state = ICE_CANDIDATE_STATE_ALLOCATING;

    memcpy( &( localCandidate.transactionId[ 0 ] ),
            &( transactionID[ 0 ] ),
            sizeof( transactionID ) );

    result = Ice_HandleStunPacket( &( context ),
                                   &( stunMessage[ 0 ] ),
                                   stunMessageLength,
                                   &( localCandidate ),
                                   &( remoteEndpoint ),
                                   &( pTransactionId ),
                                   &( pCandidatePair ) );

    TEST_ASSERT_EQUAL( ICE_HANDLE_STUN_PACKET_RESULT_SEND_ALLOCATION_REQUEST,
                       result );
    TEST_ASSERT_EQUAL( expectedRealmLength,
                       localCandidate.pRelayExtension->iceRelayServerInfo.realmLength );
    TEST_ASSERT_EQUAL( expectedNonceLength,
                       localCandidate.pRelayExtension->iceRelayServerInfo.nonceLength );
    TEST_ASSERT_EQUAL_UINT8_ARRAY( pExpectedNonce,
                                   localCandidate.pRelayExtension->iceRelayServerInfo.nonce,
                                   expectedNonceLength );
}

/*-----------------------------------------------------------*/

/**
 * @brief Ice_HandleStunPacket recieves a ALLOCATE_ERROR_RESPONSE but
 * the username is too long to generate long term password.
 */
void test_iceHandleStunPacket_AllocateErrorResponse_Unautorized_UsernameTooLong( void )
{
    IceContext_t context = { 0 };
    IceCandidate_t localCandidate = { 0 };
    IceEndpoint_t remoteEndpoint = { 0 };
    uint8_t * pTransactionId;
    IceCandidatePair_t * pCandidatePair = NULL;
    IceResult_t iceResult;
    IceHandleStunPacketResult_t result;
    uint8_t transactionID[] =
    {
        0xFF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B
    };
    uint8_t stunMessage[] =
    {
        /* STUN header: Message Type = ALLOCATE_ERROR_RESPONSE (0x0113), Length = 52 bytes (excluding 20 bytes header). */
        0x01, 0x13, 0x00, 0x34,
        /* Magic Cookie (0x2112A442). */
        0x21, 0x12, 0xA4, 0x42,
        /* 12 bytes (96 bits) transaction ID which is same as transactionID. */
        0xFF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
        /* Attribute Type = Error Code (0x0009), Attribute Length = 16 (2 reserved bytes, 2 byte error code and 12 byte error phrase). */
        0x00, 0x09, 0x00, 0x10,
        /* Reserved = 0x0000, Error Class = 4, Error Number = 01 (Error Code = 401 unauthorized). */
        0x00, 0x00, 0x04, 0x01,
        /* Error Phrase = "Error Phrase". */
        0x45, 0x72, 0x72, 0x6F,
        0x72, 0x20, 0x50, 0x68,
        0x72, 0x61, 0x73, 0x65,
        /* Attribute type = REALM (0x0014), Length = 5 bytes. */
        0x00, 0x14, 0x00, 0x05,
        /* Attribute Value: "realm". */
        0x72, 0x65, 0x61, 0x6C,
        0x6D, 0x00, 0x00, 0x00,
        /* Attribute type = NONCE (0x0015), Length = 5 bytes. */
        0x00, 0x15, 0x00, 0x05,
        /* Attribute Value: "nonce". */
        0x6E, 0x6F, 0x6E, 0x63,
        0x65, 0x00, 0x00, 0x00,
        /* Attribute type = FINGERPRINT (0x8028), Length = 4 bytes. */
        0x80, 0x28, 0x00, 0x04,
        /* Attribute Value: 0x00000000 as calculated by testCrc32Fxn_Fixed. */
        0x00, 0x00, 0x00, 0x00
    };
    size_t stunMessageLength = sizeof( stunMessage );

    // 513 bytes, longer than ICE_SERVER_CONFIG_MAX_USER_NAME_LENGTH
    char * pUsername = "12345678901234567890123456789012345678901234567890"\
                       "12345678901234567890123456789012345678901234567890"\
                       "12345678901234567890123456789012345678901234567890"\
                       "12345678901234567890123456789012345678901234567890"\
                       "12345678901234567890123456789012345678901234567890"\
                       "12345678901234567890123456789012345678901234567890"\
                       "12345678901234567890123456789012345678901234567890"\
                       "12345678901234567890123456789012345678901234567890"\
                       "12345678901234567890123456789012345678901234567890"\
                       "12345678901234567890123456789012345678901234567890"\
                       "1234567890123";

    size_t usernameLength = strlen( pUsername );
    char * pPassword = "password";
    size_t passwordLength = strlen( pPassword );

    /* Set CRC32 function to testCrc32Fxn_Fixed to make fingerprint always 0x00000000 */
    initInfo.cryptoFunctions.crc32Fxn = testCrc32Fxn_Fixed;

    iceResult = Ice_Init( &( context ),
                          &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       iceResult );

    memset( &( localCandidate ),
            0,
            sizeof( IceCandidate_t ) );
    context.numRelayExtensions = 1;
    localCandidate.pRelayExtension = &( context.pRelayExtensionsArray[ 0 ] );
    /* The buffer of userName is not able to store data longer than ICE_SERVER_CONFIG_MAX_USER_NAME_LENGTH. */
    // memcpy( &localCandidate.pRelayExtension->iceRelayServerInfo.userName, pUsername, usernameLength );
    localCandidate.pRelayExtension->iceRelayServerInfo.userNameLength = usernameLength;
    memcpy( &localCandidate.pRelayExtension->iceRelayServerInfo.password, pPassword, passwordLength );
    localCandidate.pRelayExtension->iceRelayServerInfo.passwordLength = passwordLength;
    localCandidate.candidateType = ICE_CANDIDATE_TYPE_RELAY;
    localCandidate.state = ICE_CANDIDATE_STATE_ALLOCATING;

    memcpy( &( localCandidate.transactionId[ 0 ] ),
            &( transactionID[ 0 ] ),
            sizeof( transactionID ) );

    result = Ice_HandleStunPacket( &( context ),
                                   &( stunMessage[ 0 ] ),
                                   stunMessageLength,
                                   &( localCandidate ),
                                   &( remoteEndpoint ),
                                   &( pTransactionId ),
                                   &( pCandidatePair ) );

    TEST_ASSERT_EQUAL( ICE_HANDLE_STUN_PACKET_RESULT_LONG_TERM_CREDENTIAL_CALCULATION_ERROR,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Ice_HandleStunPacket recieves a ALLOCATE_ERROR_RESPONSE but
 * the password is too long to generate long term password.
 */
void test_iceHandleStunPacket_AllocateErrorResponse_Unautorized_PasswordTooLong( void )
{
    IceContext_t context = { 0 };
    IceCandidate_t localCandidate = { 0 };
    IceEndpoint_t remoteEndpoint = { 0 };
    uint8_t * pTransactionId;
    IceCandidatePair_t * pCandidatePair = NULL;
    IceResult_t iceResult;
    IceHandleStunPacketResult_t result;
    uint8_t transactionID[] =
    {
        0xFF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B
    };
    uint8_t stunMessage[] =
    {
        /* STUN header: Message Type = ALLOCATE_ERROR_RESPONSE (0x0113), Length = 52 bytes (excluding 20 bytes header). */
        0x01, 0x13, 0x00, 0x34,
        /* Magic Cookie (0x2112A442). */
        0x21, 0x12, 0xA4, 0x42,
        /* 12 bytes (96 bits) transaction ID which is same as transactionID. */
        0xFF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
        /* Attribute Type = Error Code (0x0009), Attribute Length = 16 (2 reserved bytes, 2 byte error code and 12 byte error phrase). */
        0x00, 0x09, 0x00, 0x10,
        /* Reserved = 0x0000, Error Class = 4, Error Number = 01 (Error Code = 401 unauthorized). */
        0x00, 0x00, 0x04, 0x01,
        /* Error Phrase = "Error Phrase". */
        0x45, 0x72, 0x72, 0x6F,
        0x72, 0x20, 0x50, 0x68,
        0x72, 0x61, 0x73, 0x65,
        /* Attribute type = REALM (0x0014), Length = 5 bytes. */
        0x00, 0x14, 0x00, 0x05,
        /* Attribute Value: "realm". */
        0x72, 0x65, 0x61, 0x6C,
        0x6D, 0x00, 0x00, 0x00,
        /* Attribute type = NONCE (0x0015), Length = 5 bytes. */
        0x00, 0x15, 0x00, 0x05,
        /* Attribute Value: "nonce". */
        0x6E, 0x6F, 0x6E, 0x63,
        0x65, 0x00, 0x00, 0x00,
        /* Attribute type = FINGERPRINT (0x8028), Length = 4 bytes. */
        0x80, 0x28, 0x00, 0x04,
        /* Attribute Value: 0x00000000 as calculated by testCrc32Fxn_Fixed. */
        0x00, 0x00, 0x00, 0x00
    };
    size_t stunMessageLength = sizeof( stunMessage );
    char * pUsername = "username";
    size_t usernameLength = strlen( pUsername );
    // 257 bytes, longer than ICE_SERVER_CONFIG_MAX_PASSWORD_LENGTH
    char * pPassword = "12345678901234567890123456789012345678901234567890"\
                       "12345678901234567890123456789012345678901234567890"\
                       "12345678901234567890123456789012345678901234567890"\
                       "12345678901234567890123456789012345678901234567890"\
                       "12345678901234567890123456789012345678901234567890"\
                       "1234567";

    size_t passwordLength = strlen( pPassword );

    /* Set CRC32 function to testCrc32Fxn_Fixed to make fingerprint always 0x00000000 */
    initInfo.cryptoFunctions.crc32Fxn = testCrc32Fxn_Fixed;

    iceResult = Ice_Init( &( context ),
                          &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       iceResult );

    memset( &( localCandidate ),
            0,
            sizeof( IceCandidate_t ) );
    context.numRelayExtensions = 1;
    localCandidate.pRelayExtension = &( context.pRelayExtensionsArray[ 0 ] );
    memcpy( &localCandidate.pRelayExtension->iceRelayServerInfo.userName, pUsername, usernameLength );
    localCandidate.pRelayExtension->iceRelayServerInfo.userNameLength = usernameLength;
    /* The buffer of password is not able to store data longer than ICE_SERVER_CONFIG_MAX_PASSWORD_LENGTH. */
    // memcpy( &localCandidate.pRelayExtension->iceRelayServerInfo.password, pPassword, passwordLength );
    localCandidate.pRelayExtension->iceRelayServerInfo.passwordLength = passwordLength;
    localCandidate.candidateType = ICE_CANDIDATE_TYPE_RELAY;
    localCandidate.state = ICE_CANDIDATE_STATE_ALLOCATING;

    memcpy( &( localCandidate.transactionId[ 0 ] ),
            &( transactionID[ 0 ] ),
            sizeof( transactionID ) );

    result = Ice_HandleStunPacket( &( context ),
                                   &( stunMessage[ 0 ] ),
                                   stunMessageLength,
                                   &( localCandidate ),
                                   &( remoteEndpoint ),
                                   &( pTransactionId ),
                                   &( pCandidatePair ) );

    TEST_ASSERT_EQUAL( ICE_HANDLE_STUN_PACKET_RESULT_LONG_TERM_CREDENTIAL_CALCULATION_ERROR,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Ice_HandleStunPacket recieves a ALLOCATE_ERROR_RESPONSE but
 * the error code is 0.
 */
void test_iceHandleStunPacket_AllocateErrorResponse_ZeroError( void )
{
    IceContext_t context = { 0 };
    IceCandidate_t localCandidate = { 0 };
    IceEndpoint_t remoteEndpoint = { 0 };
    uint8_t * pTransactionId;
    IceCandidatePair_t * pCandidatePair = NULL;
    IceResult_t iceResult;
    IceHandleStunPacketResult_t result;
    uint8_t transactionID[] =
    {
        0xFF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B
    };
    uint8_t stunMessage[] =
    {
        /* STUN header: Message Type = ALLOCATE_ERROR_RESPONSE (0x0113), Length = 52 bytes (excluding 20 bytes header). */
        0x01, 0x13, 0x00, 0x34,
        /* Magic Cookie (0x2112A442). */
        0x21, 0x12, 0xA4, 0x42,
        /* 12 bytes (96 bits) transaction ID which is same as transactionID. */
        0xFF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
        /* Attribute Type = Error Code (0x0009), Attribute Length = 16 (2 reserved bytes, 2 byte error code and 12 byte error phrase). */
        0x00, 0x09, 0x00, 0x10,
        /* Reserved = 0x0000, Error Class = 0, Error Number = 00 (Error Code = Success). */
        0x00, 0x00, 0x00, 0x00,
        /* Error Phrase = "Error Phrase". */
        0x45, 0x72, 0x72, 0x6F,
        0x72, 0x20, 0x50, 0x68,
        0x72, 0x61, 0x73, 0x65,
        /* Attribute type = REALM (0x0014), Length = 5 bytes. */
        0x00, 0x14, 0x00, 0x05,
        /* Attribute Value: "realm". */
        0x72, 0x65, 0x61, 0x6C,
        0x6D, 0x00, 0x00, 0x00,
        /* Attribute type = NONCE (0x0015), Length = 5 bytes. */
        0x00, 0x15, 0x00, 0x05,
        /* Attribute Value: "nonce". */
        0x6E, 0x6F, 0x6E, 0x63,
        0x65, 0x00, 0x00, 0x00,
        /* Attribute type = FINGERPRINT (0x8028), Length = 4 bytes. */
        0x80, 0x28, 0x00, 0x04,
        /* Attribute Value: 0x00000000 as calculated by testCrc32Fxn_Fixed. */
        0x00, 0x00, 0x00, 0x00
    };
    size_t stunMessageLength = sizeof( stunMessage );
    char * pUsername = "username";
    size_t usernameLength = strlen( pUsername );
    char * pPassword = "password";
    size_t passwordLength = strlen( pPassword );

    /* Set CRC32 function to testCrc32Fxn_Fixed to make fingerprint always 0x00000000 */
    initInfo.cryptoFunctions.crc32Fxn = testCrc32Fxn_Fixed;

    iceResult = Ice_Init( &( context ),
                          &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       iceResult );

    memset( &( localCandidate ),
            0,
            sizeof( IceCandidate_t ) );
    context.numRelayExtensions = 1;
    localCandidate.pRelayExtension = &( context.pRelayExtensionsArray[ 0 ] );
    memcpy( &localCandidate.pRelayExtension->iceRelayServerInfo.userName, pUsername, usernameLength );
    localCandidate.pRelayExtension->iceRelayServerInfo.userNameLength = usernameLength;
    memcpy( &localCandidate.pRelayExtension->iceRelayServerInfo.password, pPassword, passwordLength );
    localCandidate.pRelayExtension->iceRelayServerInfo.passwordLength = passwordLength;
    localCandidate.candidateType = ICE_CANDIDATE_TYPE_RELAY;
    localCandidate.state = ICE_CANDIDATE_STATE_ALLOCATING;

    memcpy( &( localCandidate.transactionId[ 0 ] ),
            &( transactionID[ 0 ] ),
            sizeof( transactionID ) );

    result = Ice_HandleStunPacket( &( context ),
                                   &( stunMessage[ 0 ] ),
                                   stunMessageLength,
                                   &( localCandidate ),
                                   &( remoteEndpoint ),
                                   &( pTransactionId ),
                                   &( pCandidatePair ) );

    TEST_ASSERT_EQUAL( ICE_HANDLE_STUN_PACKET_RESULT_ALLOCATION_UNEXPECTED_COMPLETE,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Ice_HandleStunPacket recieves a ALLOCATE_ERROR_RESPONSE and
 * the error code is unknown.
 */
void test_iceHandleStunPacket_AllocateErrorResponse_UnknownError( void )
{
    IceContext_t context = { 0 };
    IceCandidate_t localCandidate = { 0 };
    IceEndpoint_t remoteEndpoint = { 0 };
    uint8_t * pTransactionId;
    IceCandidatePair_t * pCandidatePair = NULL;
    IceResult_t iceResult;
    IceHandleStunPacketResult_t result;
    uint8_t transactionID[] =
    {
        0xFF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B
    };
    uint8_t stunMessage[] =
    {
        /* STUN header: Message Type = ALLOCATE_ERROR_RESPONSE (0x0113), Length = 52 bytes (excluding 20 bytes header). */
        0x01, 0x13, 0x00, 0x34,
        /* Magic Cookie (0x2112A442). */
        0x21, 0x12, 0xA4, 0x42,
        /* 12 bytes (96 bits) transaction ID which is same as transactionID. */
        0xFF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
        /* Attribute Type = Error Code (0x0009), Attribute Length = 16 (2 reserved bytes, 2 byte error code and 12 byte error phrase). */
        0x00, 0x09, 0x00, 0x10,
        /* Reserved = 0x0000, Error Class = 4, Error Number = 00 (Error Code = 400 Unknown). */
        0x00, 0x00, 0x04, 0x00,
        /* Error Phrase = "Error Phrase". */
        0x45, 0x72, 0x72, 0x6F,
        0x72, 0x20, 0x50, 0x68,
        0x72, 0x61, 0x73, 0x65,
        /* Attribute type = REALM (0x0014), Length = 5 bytes. */
        0x00, 0x14, 0x00, 0x05,
        /* Attribute Value: "realm". */
        0x72, 0x65, 0x61, 0x6C,
        0x6D, 0x00, 0x00, 0x00,
        /* Attribute type = NONCE (0x0015), Length = 5 bytes. */
        0x00, 0x15, 0x00, 0x05,
        /* Attribute Value: "nonce". */
        0x6E, 0x6F, 0x6E, 0x63,
        0x65, 0x00, 0x00, 0x00,
        /* Attribute type = FINGERPRINT (0x8028), Length = 4 bytes. */
        0x80, 0x28, 0x00, 0x04,
        /* Attribute Value: 0x00000000 as calculated by testCrc32Fxn_Fixed. */
        0x00, 0x00, 0x00, 0x00
    };
    size_t stunMessageLength = sizeof( stunMessage );
    char * pUsername = "username";
    size_t usernameLength = strlen( pUsername );
    char * pPassword = "password";
    size_t passwordLength = strlen( pPassword );

    /* Set CRC32 function to testCrc32Fxn_Fixed to make fingerprint always 0x00000000 */
    initInfo.cryptoFunctions.crc32Fxn = testCrc32Fxn_Fixed;

    iceResult = Ice_Init( &( context ),
                          &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       iceResult );

    memset( &( localCandidate ),
            0,
            sizeof( IceCandidate_t ) );
    context.numRelayExtensions = 1;
    localCandidate.pRelayExtension = &( context.pRelayExtensionsArray[ 0 ] );
    memcpy( &localCandidate.pRelayExtension->iceRelayServerInfo.userName, pUsername, usernameLength );
    localCandidate.pRelayExtension->iceRelayServerInfo.userNameLength = usernameLength;
    memcpy( &localCandidate.pRelayExtension->iceRelayServerInfo.password, pPassword, passwordLength );
    localCandidate.pRelayExtension->iceRelayServerInfo.passwordLength = passwordLength;
    localCandidate.candidateType = ICE_CANDIDATE_TYPE_RELAY;
    localCandidate.state = ICE_CANDIDATE_STATE_ALLOCATING;

    memcpy( &( localCandidate.transactionId[ 0 ] ),
            &( transactionID[ 0 ] ),
            sizeof( transactionID ) );

    result = Ice_HandleStunPacket( &( context ),
                                   &( stunMessage[ 0 ] ),
                                   stunMessageLength,
                                   &( localCandidate ),
                                   &( remoteEndpoint ),
                                   &( pTransactionId ),
                                   &( pCandidatePair ) );

    TEST_ASSERT_EQUAL( ICE_HANDLE_STUN_PACKET_RESULT_ALLOCATE_UNKNOWN_ERROR,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Ice_HandleStunPacket recieves a ALLOCATE_SUCCESS_RESPONSE but
 * the transaction ID is not found in store.
 */
void test_iceHandleStunPacket_AllocateSuccessResponse_TransactionIDNotFound( void )
{
    IceContext_t context = { 0 };
    IceCandidate_t localCandidate = { 0 };
    IceEndpoint_t remoteEndpoint = { 0 };
    uint8_t * pTransactionId;
    IceCandidatePair_t * pCandidatePair = NULL;
    IceResult_t iceResult;
    IceHandleStunPacketResult_t result;
    uint8_t stunMessage[] =
    {
        /* STUN header: Message Type = ALLOCATE_SUCCESS_RESPONSE (0x0103), Length = 72 bytes (excluding 20 bytes header). */
        0x01, 0x03, 0x00, 0x48,
        /* Magic Cookie (0x2112A442). */
        0x21, 0x12, 0xA4, 0x42,
        /* 12 bytes (96 bits) invalid transaction ID. */
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
        /* Attribute Type = Error Code (0x0009), Attribute Length = 16 (2 reserved bytes, 2 byte error code and 12 byte error phrase). */
        0x00, 0x09, 0x00, 0x10,
        /* Reserved = 0x0000, Error Class = 0, Error Number = 00 (Error Code = 0 Success). */
        0x00, 0x00, 0x04, 0x01,
        /* Error Phrase = "Error Phrase". */
        0x45, 0x72, 0x72, 0x6F,
        0x72, 0x20, 0x50, 0x68,
        0x72, 0x61, 0x73, 0x65,
        /* Attribute type = Relay Transport Address (0x0016), Length = 8 bytes. */
        0x00, 0x16, 0x00, 0x08,
        /* Attribute Value = Family: 0x01, Port: 0x1234 IP: 192.168.1.100. XOR with 0x2112A442. */
        0x00, 0x01, 0x33, 0x26,
        0xE1, 0xBA, 0xA5, 0x26,
        /* Attribute type = LIFETIME (0x000D), Length = 4 bytes. */
        0x00, 0x0D, 0x00, 0x04,
        /* Attribute Value: 600 as ICE_DEFAULT_TURN_ALLOCATION_LIFETIME_SECONDS. */
        0x00, 0x00, 0x02, 0x58,
        /* Attribute type = MESSAGE-INTEGRITY (0x0008), Length = 20 bytes. */
        0x00, 0x08, 0x00, 0x14,
        /* Attribute Value = HMAC value as computed by testHmacFxn. */
        0x6D, 0x6E, 0x63, 0x51,
        0x4D, 0x42, 0xC5, 0x31,
        0x73, 0x76, 0x6D, 0x71,
        0x60, 0x69, 0x69, 0x64,
        0x69, 0x65, 0x5A, 0x6A,
        /* Attribute type = FINGERPRINT (0x8028), Length = 4 bytes. */
        0x80, 0x28, 0x00, 0x04,
        /* Attribute Value: 0x00000000 as calculated by testCrc32Fxn_Fixed. */
        0x00, 0x00, 0x00, 0x00
    };
    size_t stunMessageLength = sizeof( stunMessage );

    /* Set CRC32 function to testCrc32Fxn_Fixed to make fingerprint always 0x00000000 */
    initInfo.cryptoFunctions.crc32Fxn = testCrc32Fxn_Fixed;
    initInfo.getCurrentTimeSecondsFxn = testGetCurrentTime_FixedZero;

    iceResult = Ice_Init( &( context ),
                          &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       iceResult );

    result = Ice_HandleStunPacket( &( context ),
                                   &( stunMessage[ 0 ] ),
                                   stunMessageLength,
                                   &( localCandidate ),
                                   &( remoteEndpoint ),
                                   &( pTransactionId ),
                                   &( pCandidatePair ) );

    TEST_ASSERT_EQUAL( ICE_HANDLE_STUN_PACKET_RESULT_DROP_PACKET,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Ice_HandleStunPacket recieves a ALLOCATE_SUCCESS_RESPONSE but
 * the local candidate is not allocating.
 */
void test_iceHandleStunPacket_AllocateSuccessResponse_NotAllocating( void )
{
    IceContext_t context = { 0 };
    IceCandidate_t localCandidate = { 0 };
    IceEndpoint_t remoteEndpoint = { 0 };
    uint8_t * pTransactionId;
    IceCandidatePair_t * pCandidatePair = NULL;
    IceResult_t iceResult;
    IceHandleStunPacketResult_t result;
    uint8_t transactionID[] =
    {
        0xFF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B
    };
    uint8_t stunMessage[] =
    {
        /* STUN header: Message Type = ALLOCATE_SUCCESS_RESPONSE (0x0103), Length = 72 bytes (excluding 20 bytes header). */
        0x01, 0x03, 0x00, 0x48,
        /* Magic Cookie (0x2112A442). */
        0x21, 0x12, 0xA4, 0x42,
        /* 12 bytes (96 bits) transaction ID which is same as transactionID above. */
        0xFF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
        /* Attribute Type = Error Code (0x0009), Attribute Length = 16 (2 reserved bytes, 2 byte error code and 12 byte error phrase). */
        0x00, 0x09, 0x00, 0x10,
        /* Reserved = 0x0000, Error Class = 0, Error Number = 00 (Error Code = 0 Success). */
        0x00, 0x00, 0x04, 0x01,
        /* Error Phrase = "Error Phrase". */
        0x45, 0x72, 0x72, 0x6F,
        0x72, 0x20, 0x50, 0x68,
        0x72, 0x61, 0x73, 0x65,
        /* Attribute type = Relay Transport Address (0x0016), Length = 8 bytes. */
        0x00, 0x16, 0x00, 0x08,
        /* Attribute Value = Family: 0x01, Port: 0x1234 IP: 192.168.1.100. XOR with 0x2112A442. */
        0x00, 0x01, 0x33, 0x26,
        0xE1, 0xBA, 0xA5, 0x26,
        /* Attribute type = LIFETIME (0x000D), Length = 4 bytes. */
        0x00, 0x0D, 0x00, 0x04,
        /* Attribute Value: 600 as ICE_DEFAULT_TURN_ALLOCATION_LIFETIME_SECONDS. */
        0x00, 0x00, 0x02, 0x58,
        /* Attribute type = MESSAGE-INTEGRITY (0x0008), Length = 20 bytes. */
        0x00, 0x08, 0x00, 0x14,
        /* Attribute Value = HMAC value as computed by testHmacFxn. */
        0x6D, 0x6E, 0x63, 0x51,
        0x4D, 0x42, 0xC5, 0x31,
        0x73, 0x76, 0x6D, 0x71,
        0x60, 0x69, 0x69, 0x64,
        0x69, 0x65, 0x5A, 0x6A,
        /* Attribute type = FINGERPRINT (0x8028), Length = 4 bytes. */
        0x80, 0x28, 0x00, 0x04,
        /* Attribute Value: 0x00000000 as calculated by testCrc32Fxn_Fixed. */
        0x00, 0x00, 0x00, 0x00
    };
    size_t stunMessageLength = sizeof( stunMessage );

    /* Set CRC32 function to testCrc32Fxn_Fixed to make fingerprint always 0x00000000 */
    initInfo.cryptoFunctions.crc32Fxn = testCrc32Fxn_Fixed;
    initInfo.getCurrentTimeSecondsFxn = testGetCurrentTime_FixedZero;

    iceResult = Ice_Init( &( context ),
                          &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       iceResult );

    memset( &( localCandidate ),
            0,
            sizeof( IceCandidate_t ) );
    localCandidate.candidateType = ICE_CANDIDATE_TYPE_RELAY;
    localCandidate.state = ICE_CANDIDATE_STATE_VALID;
    context.numRelayExtensions = 1;
    localCandidate.pRelayExtension = &( context.pRelayExtensionsArray[ 0 ] );


    memcpy( &( localCandidate.transactionId[ 0 ] ),
            &( transactionID[ 0 ] ),
            sizeof( transactionID ) );

    result = Ice_HandleStunPacket( &( context ),
                                   &( stunMessage[ 0 ] ),
                                   stunMessageLength,
                                   &( localCandidate ),
                                   &( remoteEndpoint ),
                                   &( pTransactionId ),
                                   &( pCandidatePair ) );

    TEST_ASSERT_EQUAL( ICE_HANDLE_STUN_PACKET_RESULT_RELAY_CANDIDATE_NOT_ALLOCATING,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Ice_HandleStunPacket recieves a ALLOCATE_SUCCESS_RESPONSE in pass.
 */
void test_iceHandleStunPacket_AllocateSuccessResponse_Success( void )
{
    IceContext_t context = { 0 };
    IceCandidate_t localCandidate = { 0 };
    IceEndpoint_t remoteEndpoint = { 0 };
    uint8_t * pTransactionId;
    IceCandidatePair_t * pCandidatePair = NULL;
    IceResult_t iceResult;
    IceHandleStunPacketResult_t result;
    uint8_t transactionID[] =
    {
        0xFF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B
    };
    uint8_t stunMessage[] =
    {
        /* STUN header: Message Type = ALLOCATE_SUCCESS_RESPONSE (0x0103), Length = 72 bytes (excluding 20 bytes header). */
        0x01, 0x03, 0x00, 0x48,
        /* Magic Cookie (0x2112A442). */
        0x21, 0x12, 0xA4, 0x42,
        /* 12 bytes (96 bits) transaction ID which is same as transactionID above. */
        0xFF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
        /* Attribute Type = Error Code (0x0009), Attribute Length = 16 (2 reserved bytes, 2 byte error code and 12 byte error phrase). */
        0x00, 0x09, 0x00, 0x10,
        /* Reserved = 0x0000, Error Class = 0, Error Number = 00 (Error Code = 0 Success). */
        0x00, 0x00, 0x00, 0x00,
        /* Error Phrase = "Error Phrase". */
        0x45, 0x72, 0x72, 0x6F,
        0x72, 0x20, 0x50, 0x68,
        0x72, 0x61, 0x73, 0x65,
        /* Attribute type = Relay Transport Address (0x0016), Length = 8 bytes. */
        0x00, 0x16, 0x00, 0x08,
        /* Attribute Value = Family: 0x01, Port: 0x1234 IP: 192.168.1.100. XOR with 0x2112A442. */
        0x00, 0x01, 0x33, 0x26,
        0xE1, 0xBA, 0xA5, 0x26,
        /* Attribute type = LIFETIME (0x000D), Length = 4 bytes. */
        0x00, 0x0D, 0x00, 0x04,
        /* Attribute Value: 600 as ICE_DEFAULT_TURN_ALLOCATION_LIFETIME_SECONDS. */
        0x00, 0x00, 0x02, 0x58,
        /* Attribute type = MESSAGE-INTEGRITY (0x0008), Length = 20 bytes. */
        0x00, 0x08, 0x00, 0x14,
        /* Attribute Value = HMAC value as computed by testHmacFxn_FixedFF. */
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        /* Attribute type = FINGERPRINT (0x8028), Length = 4 bytes. */
        0x80, 0x28, 0x00, 0x04,
        /* Attribute Value: 0x00000000 as calculated by testCrc32Fxn_Fixed. */
        0x00, 0x00, 0x00, 0x00
    };
    size_t stunMessageLength = sizeof( stunMessage );
    char longTermPassword[] = "LongTermPassword";
    size_t longTermPasswordLength = strlen( longTermPassword );
    uint16_t expectEndpointFamily = STUN_ADDRESS_IPv4;
    uint16_t expectEndpointPort = 0x1234;
    uint8_t * pExpectIpAddress = ipAddress;
    size_t expectIpAddressLength = sizeof( ipAddress );

    /* Set CRC32 function to testCrc32Fxn_Fixed to make fingerprint always 0x00000000 */
    initInfo.cryptoFunctions.crc32Fxn = testCrc32Fxn_Fixed;
    /* Set CRC32 function to testHmacFxn_FixedFF to make integrity always 0xFF. */
    initInfo.cryptoFunctions.hmacFxn = testHmacFxn_FixedFF;
    initInfo.getCurrentTimeSecondsFxn = testGetCurrentTime_FixedZero;

    iceResult = Ice_Init( &( context ),
                          &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       iceResult );

    memset( &( localCandidate ),
            0,
            sizeof( IceCandidate_t ) );
    localCandidate.candidateType = ICE_CANDIDATE_TYPE_RELAY;
    localCandidate.state = ICE_CANDIDATE_STATE_ALLOCATING;
    context.numRelayExtensions = 1;
    localCandidate.pRelayExtension = &( context.pRelayExtensionsArray[ 0 ] );
    memcpy( localCandidate.pRelayExtension->iceRelayServerInfo.longTermPassword,
            longTermPassword,
            longTermPasswordLength );
    localCandidate.pRelayExtension->iceRelayServerInfo.longTermPasswordLength = longTermPasswordLength;

    memcpy( &( localCandidate.transactionId[ 0 ] ),
            &( transactionID[ 0 ] ),
            sizeof( transactionID ) );

    result = Ice_HandleStunPacket( &( context ),
                                   &( stunMessage[ 0 ] ),
                                   stunMessageLength,
                                   &( localCandidate ),
                                   &( remoteEndpoint ),
                                   &( pTransactionId ),
                                   &( pCandidatePair ) );

    TEST_ASSERT_EQUAL( ICE_HANDLE_STUN_PACKET_RESULT_UPDATED_RELAY_CANDIDATE_ADDRESS,
                       result );
    TEST_ASSERT_EQUAL( ICE_CANDIDATE_STATE_VALID,
                       localCandidate.state );
    TEST_ASSERT_EQUAL( ICE_DEFAULT_TURN_CHANNEL_NUMBER_MIN,
                       localCandidate.pRelayExtension->nextAvailableTurnChannelNumber );
    TEST_ASSERT_EQUAL( expectEndpointFamily,
                       localCandidate.endpoint.transportAddress.family );
    TEST_ASSERT_EQUAL( expectEndpointPort,
                       localCandidate.endpoint.transportAddress.port );
    TEST_ASSERT_EQUAL_UINT8_ARRAY( pExpectIpAddress,
                                   localCandidate.endpoint.transportAddress.address,
                                   expectIpAddressLength );
}

/*-----------------------------------------------------------*/

/**
 * @brief Ice_HandleStunPacket recieves a ALLOCATE_SUCCESS_RESPONSE but
 * the error code is not zero.
 */
void test_iceHandleStunPacket_AllocateSuccessResponse_NonZeroError( void )
{
    IceContext_t context = { 0 };
    IceCandidate_t localCandidate = { 0 };
    IceEndpoint_t remoteEndpoint = { 0 };
    uint8_t * pTransactionId;
    IceCandidatePair_t * pCandidatePair = NULL;
    IceResult_t iceResult;
    IceHandleStunPacketResult_t result;
    uint8_t transactionID[] =
    {
        0xFF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B
    };
    uint8_t stunMessage[] =
    {
        /* STUN header: Message Type = ALLOCATE_SUCCESS_RESPONSE (0x0103), Length = 72 bytes (excluding 20 bytes header). */
        0x01, 0x03, 0x00, 0x48,
        /* Magic Cookie (0x2112A442). */
        0x21, 0x12, 0xA4, 0x42,
        /* 12 bytes (96 bits) transaction ID which is same as transactionID above. */
        0xFF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
        /* Attribute Type = Error Code (0x0009), Attribute Length = 16 (2 reserved bytes, 2 byte error code and 12 byte error phrase). */
        0x00, 0x09, 0x00, 0x10,
        /* Reserved = 0x0000, Error Class = 4, Error Number = 01 (Error Code = 401 Unautorized). */
        0x00, 0x00, 0x04, 0x01,
        /* Error Phrase = "Error Phrase". */
        0x45, 0x72, 0x72, 0x6F,
        0x72, 0x20, 0x50, 0x68,
        0x72, 0x61, 0x73, 0x65,
        /* Attribute type = Relay Transport Address (0x0016), Length = 8 bytes. */
        0x00, 0x16, 0x00, 0x08,
        /* Attribute Value = Family: 0x01, Port: 0x1234 IP: 192.168.1.100. XOR with 0x2112A442. */
        0x00, 0x01, 0x33, 0x26,
        0xE1, 0xBA, 0xA5, 0x26,
        /* Attribute type = LIFETIME (0x000D), Length = 4 bytes. */
        0x00, 0x0D, 0x00, 0x04,
        /* Attribute Value: 600 as ICE_DEFAULT_TURN_ALLOCATION_LIFETIME_SECONDS. */
        0x00, 0x00, 0x02, 0x58,
        /* Attribute type = MESSAGE-INTEGRITY (0x0008), Length = 20 bytes. */
        0x00, 0x08, 0x00, 0x14,
        /* Attribute Value = HMAC value as computed by testHmacFxn_FixedFF. */
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        /* Attribute type = FINGERPRINT (0x8028), Length = 4 bytes. */
        0x80, 0x28, 0x00, 0x04,
        /* Attribute Value: 0x00000000 as calculated by testCrc32Fxn_Fixed. */
        0x00, 0x00, 0x00, 0x00
    };
    size_t stunMessageLength = sizeof( stunMessage );
    char longTermPassword[] = "LongTermPassword";
    size_t longTermPasswordLength = strlen( longTermPassword );

    /* Set CRC32 function to testCrc32Fxn_Fixed to make fingerprint always 0x00000000 */
    initInfo.cryptoFunctions.crc32Fxn = testCrc32Fxn_Fixed;
    /* Set CRC32 function to testHmacFxn_FixedFF to make integrity always 0xFF. */
    initInfo.cryptoFunctions.hmacFxn = testHmacFxn_FixedFF;
    initInfo.getCurrentTimeSecondsFxn = testGetCurrentTime_FixedZero;

    iceResult = Ice_Init( &( context ),
                          &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       iceResult );

    memset( &( localCandidate ),
            0,
            sizeof( IceCandidate_t ) );
    localCandidate.candidateType = ICE_CANDIDATE_TYPE_RELAY;
    localCandidate.state = ICE_CANDIDATE_STATE_ALLOCATING;
    context.numRelayExtensions = 1;
    localCandidate.pRelayExtension = &( context.pRelayExtensionsArray[ 0 ] );
    memcpy( localCandidate.pRelayExtension->iceRelayServerInfo.longTermPassword,
            longTermPassword,
            longTermPasswordLength );
    localCandidate.pRelayExtension->iceRelayServerInfo.longTermPasswordLength = longTermPasswordLength;

    memcpy( &( localCandidate.transactionId[ 0 ] ),
            &( transactionID[ 0 ] ),
            sizeof( transactionID ) );

    result = Ice_HandleStunPacket( &( context ),
                                   &( stunMessage[ 0 ] ),
                                   stunMessageLength,
                                   &( localCandidate ),
                                   &( remoteEndpoint ),
                                   &( pTransactionId ),
                                   &( pCandidatePair ) );

    TEST_ASSERT_EQUAL( ICE_HANDLE_STUN_PACKET_RESULT_NON_ZERO_ERROR_CODE,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Ice_HandleStunPacket recieves a ALLOCATE_SUCCESS_RESPONSE and add
 * two candidate pairs by pre-adding two remote candidates.
 */
void test_iceHandleStunPacket_AllocateSuccessResponse_Success_AddTwoCandidatePair( void )
{
    IceContext_t context = { 0 };
    IceCandidate_t localCandidate = { 0 };
    IceEndpoint_t remoteEndpoint = { 0 };
    uint8_t * pTransactionId;
    IceCandidatePair_t * pCandidatePair = NULL;
    IceResult_t iceResult;
    IceHandleStunPacketResult_t result;
    uint8_t transactionID[] =
    {
        0xFF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B
    };
    uint8_t stunMessage[] =
    {
        /* STUN header: Message Type = ALLOCATE_SUCCESS_RESPONSE (0x0103), Length = 72 bytes (excluding 20 bytes header). */
        0x01, 0x03, 0x00, 0x48,
        /* Magic Cookie (0x2112A442). */
        0x21, 0x12, 0xA4, 0x42,
        /* 12 bytes (96 bits) transaction ID which is same as transactionID above. */
        0xFF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
        /* Attribute Type = Error Code (0x0009), Attribute Length = 16 (2 reserved bytes, 2 byte error code and 12 byte error phrase). */
        0x00, 0x09, 0x00, 0x10,
        /* Reserved = 0x0000, Error Class = 0, Error Number = 00 (Error Code = 0 Success). */
        0x00, 0x00, 0x00, 0x00,
        /* Error Phrase = "Error Phrase". */
        0x45, 0x72, 0x72, 0x6F,
        0x72, 0x20, 0x50, 0x68,
        0x72, 0x61, 0x73, 0x65,
        /* Attribute type = Relay Transport Address (0x0016), Length = 8 bytes. */
        0x00, 0x16, 0x00, 0x08,
        /* Attribute Value = Family: 0x01, Port: 0x1234 IP: 192.168.1.100. XOR with 0x2112A442. */
        0x00, 0x01, 0x33, 0x26,
        0xE1, 0xBA, 0xA5, 0x26,
        /* Attribute type = LIFETIME (0x000D), Length = 4 bytes. */
        0x00, 0x0D, 0x00, 0x04,
        /* Attribute Value: 600 as ICE_DEFAULT_TURN_ALLOCATION_LIFETIME_SECONDS. */
        0x00, 0x00, 0x02, 0x58,
        /* Attribute type = MESSAGE-INTEGRITY (0x0008), Length = 20 bytes. */
        0x00, 0x08, 0x00, 0x14,
        /* Attribute Value = HMAC value as computed by testHmacFxn_FixedFF. */
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        /* Attribute type = FINGERPRINT (0x8028), Length = 4 bytes. */
        0x80, 0x28, 0x00, 0x04,
        /* Attribute Value: 0x00000000 as calculated by testCrc32Fxn_Fixed. */
        0x00, 0x00, 0x00, 0x00
    };
    size_t stunMessageLength = sizeof( stunMessage );
    char longTermPassword[] = "LongTermPassword";
    size_t longTermPasswordLength = strlen( longTermPassword );
    uint16_t expectEndpointFamily = STUN_ADDRESS_IPv4;
    uint16_t expectEndpointPort = 0x1234;
    uint8_t * pExpectIpAddress = ipAddress;
    size_t expectIpAddressLength = sizeof( ipAddress );

    /* Set CRC32 function to testCrc32Fxn_Fixed to make fingerprint always 0x00000000 */
    initInfo.cryptoFunctions.crc32Fxn = testCrc32Fxn_Fixed;
    /* Set CRC32 function to testHmacFxn_FixedFF to make integrity always 0xFF. */
    initInfo.cryptoFunctions.hmacFxn = testHmacFxn_FixedFF;
    initInfo.getCurrentTimeSecondsFxn = testGetCurrentTime_FixedZero;

    iceResult = Ice_Init( &( context ),
                          &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       iceResult );

    memset( &( localCandidate ),
            0,
            sizeof( IceCandidate_t ) );
    localCandidate.candidateType = ICE_CANDIDATE_TYPE_RELAY;
    localCandidate.state = ICE_CANDIDATE_STATE_ALLOCATING;
    context.numRelayExtensions = 1;
    localCandidate.pRelayExtension = &( context.pRelayExtensionsArray[ 0 ] );
    memcpy( localCandidate.pRelayExtension->iceRelayServerInfo.longTermPassword,
            longTermPassword,
            longTermPasswordLength );
    localCandidate.pRelayExtension->iceRelayServerInfo.longTermPasswordLength = longTermPasswordLength;

    /* Enable two remote candidates. */
    context.numRemoteCandidates = 2;

    memcpy( &( localCandidate.transactionId[ 0 ] ),
            &( transactionID[ 0 ] ),
            sizeof( transactionID ) );

    result = Ice_HandleStunPacket( &( context ),
                                   &( stunMessage[ 0 ] ),
                                   stunMessageLength,
                                   &( localCandidate ),
                                   &( remoteEndpoint ),
                                   &( pTransactionId ),
                                   &( pCandidatePair ) );

    TEST_ASSERT_EQUAL( ICE_HANDLE_STUN_PACKET_RESULT_UPDATED_RELAY_CANDIDATE_ADDRESS,
                       result );
    TEST_ASSERT_EQUAL( ICE_CANDIDATE_STATE_VALID,
                       localCandidate.state );
    TEST_ASSERT_EQUAL( ICE_DEFAULT_TURN_CHANNEL_NUMBER_MIN + 2,
                       localCandidate.pRelayExtension->nextAvailableTurnChannelNumber );
    TEST_ASSERT_EQUAL( expectEndpointFamily,
                       localCandidate.endpoint.transportAddress.family );
    TEST_ASSERT_EQUAL( expectEndpointPort,
                       localCandidate.endpoint.transportAddress.port );
    TEST_ASSERT_EQUAL_UINT8_ARRAY( pExpectIpAddress,
                                   localCandidate.endpoint.transportAddress.address,
                                   expectIpAddressLength );
    TEST_ASSERT_EQUAL( 2,
                       context.numCandidatePairs );
}

/*-----------------------------------------------------------*/

/**
 * @brief Ice_HandleStunPacket recieves a ALLOCATE_SUCCESS_RESPONSE but
 * hitting max channel ID by adding 4097 remote candidates.
 */
void test_iceHandleStunPacket_AllocateSuccessResponse_ChannelNumberExceed( void )
{
    IceContext_t context = { 0 };
    IceCandidate_t localCandidate = { 0 };
    IceEndpoint_t remoteEndpoint = { 0 };
    uint8_t * pTransactionId;
    IceCandidatePair_t * pCandidatePair = NULL;
    IceResult_t iceResult;
    IceHandleStunPacketResult_t result;
    uint8_t transactionID[] =
    {
        0xFF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B
    };
    uint8_t stunMessage[] =
    {
        /* STUN header: Message Type = ALLOCATE_SUCCESS_RESPONSE (0x0103), Length = 72 bytes (excluding 20 bytes header). */
        0x01, 0x03, 0x00, 0x48,
        /* Magic Cookie (0x2112A442). */
        0x21, 0x12, 0xA4, 0x42,
        /* 12 bytes (96 bits) transaction ID which is same as transactionID above. */
        0xFF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
        /* Attribute Type = Error Code (0x0009), Attribute Length = 16 (2 reserved bytes, 2 byte error code and 12 byte error phrase). */
        0x00, 0x09, 0x00, 0x10,
        /* Reserved = 0x0000, Error Class = 0, Error Number = 00 (Error Code = 0 Success). */
        0x00, 0x00, 0x00, 0x00,
        /* Error Phrase = "Error Phrase". */
        0x45, 0x72, 0x72, 0x6F,
        0x72, 0x20, 0x50, 0x68,
        0x72, 0x61, 0x73, 0x65,
        /* Attribute type = Relay Transport Address (0x0016), Length = 8 bytes. */
        0x00, 0x16, 0x00, 0x08,
        /* Attribute Value = Family: 0x01, Port: 0x1234 IP: 192.168.1.100. XOR with 0x2112A442. */
        0x00, 0x01, 0x33, 0x26,
        0xE1, 0xBA, 0xA5, 0x26,
        /* Attribute type = LIFETIME (0x000D), Length = 4 bytes. */
        0x00, 0x0D, 0x00, 0x04,
        /* Attribute Value: 600 as ICE_DEFAULT_TURN_ALLOCATION_LIFETIME_SECONDS. */
        0x00, 0x00, 0x02, 0x58,
        /* Attribute type = MESSAGE-INTEGRITY (0x0008), Length = 20 bytes. */
        0x00, 0x08, 0x00, 0x14,
        /* Attribute Value = HMAC value as computed by testHmacFxn_FixedFF. */
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        /* Attribute type = FINGERPRINT (0x8028), Length = 4 bytes. */
        0x80, 0x28, 0x00, 0x04,
        /* Attribute Value: 0x00000000 as calculated by testCrc32Fxn_Fixed. */
        0x00, 0x00, 0x00, 0x00
    };
    size_t stunMessageLength = sizeof( stunMessage );
    char longTermPassword[] = "LongTermPassword";
    size_t longTermPasswordLength = strlen( longTermPassword );
    size_t localRemoteCandidateArrayLength = ICE_DEFAULT_TURN_CHANNEL_NUMBER_MAX - ICE_DEFAULT_TURN_CHANNEL_NUMBER_MIN + 2;
    size_t localCandidatePairArrayLength = localRemoteCandidateArrayLength;
    IceCandidate_t localRemoteCandidateArray[ localRemoteCandidateArrayLength ];
    IceCandidatePair_t localCandidatePairArray[ localCandidatePairArrayLength ];

    /* Set CRC32 function to testCrc32Fxn_Fixed to make fingerprint always 0x00000000 */
    initInfo.cryptoFunctions.crc32Fxn = testCrc32Fxn_Fixed;
    /* Set CRC32 function to testHmacFxn_FixedFF to make integrity always 0xFF. */
    initInfo.cryptoFunctions.hmacFxn = testHmacFxn_FixedFF;
    initInfo.getCurrentTimeSecondsFxn = testGetCurrentTime_FixedZero;

    memset( localRemoteCandidateArray, 0, sizeof( localRemoteCandidateArray ) );
    memset( localCandidatePairArray, 0, sizeof( localCandidatePairArray ) );
    initInfo.pRemoteCandidatesArray = localRemoteCandidateArray;
    initInfo.remoteCandidatesArrayLength = localRemoteCandidateArrayLength;
    initInfo.pCandidatePairsArray = localCandidatePairArray;
    initInfo.candidatePairsArrayLength = localCandidatePairArrayLength;
    iceResult = Ice_Init( &( context ),
                          &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       iceResult );

    memset( &( localCandidate ),
            0,
            sizeof( IceCandidate_t ) );
    localCandidate.candidateType = ICE_CANDIDATE_TYPE_RELAY;
    localCandidate.state = ICE_CANDIDATE_STATE_ALLOCATING;
    context.numRelayExtensions = 1;
    localCandidate.pRelayExtension = &( context.pRelayExtensionsArray[ 0 ] );
    memcpy( localCandidate.pRelayExtension->iceRelayServerInfo.longTermPassword,
            longTermPassword,
            longTermPasswordLength );
    localCandidate.pRelayExtension->iceRelayServerInfo.longTermPasswordLength = longTermPasswordLength;

    /* Enable two remote candidates. */
    context.numRemoteCandidates = localRemoteCandidateArrayLength;

    memcpy( &( localCandidate.transactionId[ 0 ] ),
            &( transactionID[ 0 ] ),
            sizeof( transactionID ) );

    result = Ice_HandleStunPacket( &( context ),
                                   &( stunMessage[ 0 ] ),
                                   stunMessageLength,
                                   &( localCandidate ),
                                   &( remoteEndpoint ),
                                   &( pTransactionId ),
                                   &( pCandidatePair ) );

    TEST_ASSERT_EQUAL( ICE_HANDLE_STUN_PACKET_RESULT_UPDATED_RELAY_CANDIDATE_ADDRESS,
                       result );
    TEST_ASSERT_EQUAL( ICE_DEFAULT_TURN_CHANNEL_NUMBER_MAX + 1,
                       localCandidate.pRelayExtension->nextAvailableTurnChannelNumber );
}

/*-----------------------------------------------------------*/

/**
 * @brief Ice_HandleStunPacket recieves a ALLOCATE_SUCCESS_RESPONSE but
 * fail to add candidate pair because the number of candidate pair is full.
 */
void test_iceHandleStunPacket_AllocateSuccessResponse_FailAddCandidatePair( void )
{
    IceContext_t context = { 0 };
    IceCandidate_t localCandidate = { 0 };
    IceEndpoint_t remoteEndpoint = { 0 };
    uint8_t * pTransactionId;
    IceCandidatePair_t * pCandidatePair = NULL;
    IceResult_t iceResult;
    IceHandleStunPacketResult_t result;
    uint8_t transactionID[] =
    {
        0xFF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B
    };
    uint8_t stunMessage[] =
    {
        /* STUN header: Message Type = ALLOCATE_SUCCESS_RESPONSE (0x0103), Length = 72 bytes (excluding 20 bytes header). */
        0x01, 0x03, 0x00, 0x48,
        /* Magic Cookie (0x2112A442). */
        0x21, 0x12, 0xA4, 0x42,
        /* 12 bytes (96 bits) transaction ID which is same as transactionID above. */
        0xFF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
        /* Attribute Type = Error Code (0x0009), Attribute Length = 16 (2 reserved bytes, 2 byte error code and 12 byte error phrase). */
        0x00, 0x09, 0x00, 0x10,
        /* Reserved = 0x0000, Error Class = 0, Error Number = 00 (Error Code = 0 Success). */
        0x00, 0x00, 0x00, 0x00,
        /* Error Phrase = "Error Phrase". */
        0x45, 0x72, 0x72, 0x6F,
        0x72, 0x20, 0x50, 0x68,
        0x72, 0x61, 0x73, 0x65,
        /* Attribute type = Relay Transport Address (0x0016), Length = 8 bytes. */
        0x00, 0x16, 0x00, 0x08,
        /* Attribute Value = Family: 0x01, Port: 0x1234 IP: 192.168.1.100. XOR with 0x2112A442. */
        0x00, 0x01, 0x33, 0x26,
        0xE1, 0xBA, 0xA5, 0x26,
        /* Attribute type = LIFETIME (0x000D), Length = 4 bytes. */
        0x00, 0x0D, 0x00, 0x04,
        /* Attribute Value: 600 as ICE_DEFAULT_TURN_ALLOCATION_LIFETIME_SECONDS. */
        0x00, 0x00, 0x02, 0x58,
        /* Attribute type = MESSAGE-INTEGRITY (0x0008), Length = 20 bytes. */
        0x00, 0x08, 0x00, 0x14,
        /* Attribute Value = HMAC value as computed by testHmacFxn_FixedFF. */
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        /* Attribute type = FINGERPRINT (0x8028), Length = 4 bytes. */
        0x80, 0x28, 0x00, 0x04,
        /* Attribute Value: 0x00000000 as calculated by testCrc32Fxn_Fixed. */
        0x00, 0x00, 0x00, 0x00
    };
    size_t stunMessageLength = sizeof( stunMessage );
    char longTermPassword[] = "LongTermPassword";
    size_t longTermPasswordLength = strlen( longTermPassword );

    /* Set CRC32 function to testCrc32Fxn_Fixed to make fingerprint always 0x00000000 */
    initInfo.cryptoFunctions.crc32Fxn = testCrc32Fxn_Fixed;
    /* Set CRC32 function to testHmacFxn_FixedFF to make integrity always 0xFF. */
    initInfo.cryptoFunctions.hmacFxn = testHmacFxn_FixedFF;
    initInfo.getCurrentTimeSecondsFxn = testGetCurrentTime_FixedZero;

    iceResult = Ice_Init( &( context ),
                          &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       iceResult );

    memset( &( localCandidate ),
            0,
            sizeof( IceCandidate_t ) );
    localCandidate.candidateType = ICE_CANDIDATE_TYPE_RELAY;
    localCandidate.state = ICE_CANDIDATE_STATE_ALLOCATING;
    context.numRelayExtensions = 1;
    localCandidate.pRelayExtension = &( context.pRelayExtensionsArray[ 0 ] );
    memcpy( localCandidate.pRelayExtension->iceRelayServerInfo.longTermPassword,
            longTermPassword,
            longTermPasswordLength );
    localCandidate.pRelayExtension->iceRelayServerInfo.longTermPasswordLength = longTermPasswordLength;

    /* Enable two remote candidates. */
    context.numRemoteCandidates = 2;
    context.numCandidatePairs = CANDIDATE_PAIR_ARRAY_SIZE;

    memcpy( &( localCandidate.transactionId[ 0 ] ),
            &( transactionID[ 0 ] ),
            sizeof( transactionID ) );

    result = Ice_HandleStunPacket( &( context ),
                                   &( stunMessage[ 0 ] ),
                                   stunMessageLength,
                                   &( localCandidate ),
                                   &( remoteEndpoint ),
                                   &( pTransactionId ),
                                   &( pCandidatePair ) );

    TEST_ASSERT_EQUAL( ICE_HANDLE_STUN_PACKET_RESULT_UPDATED_RELAY_CANDIDATE_ADDRESS,
                       result );
    TEST_ASSERT_EQUAL( CANDIDATE_PAIR_ARRAY_SIZE,
                       context.numCandidatePairs );
}

/*-----------------------------------------------------------*/

/**
 * @brief Ice_HandleStunPacket recieves a CREATE_PERMISSION_ERROR_RESPONSE and
 * the candidate pair is found in the ICE context.
 */
void test_iceHandleStunPacket_CreatePermissionErrorResponse_Pass( void )
{
    IceContext_t context = { 0 };
    IceCandidate_t localCandidate = { 0 };
    IceEndpoint_t remoteEndpoint = { 0 };
    uint8_t * pTransactionId;
    IceCandidatePair_t * pCandidatePair = NULL;
    IceResult_t iceResult;
    IceHandleStunPacketResult_t result;
    uint8_t transactionID[] =
    {
        0xFF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B
    };
    uint8_t stunMessage[] =
    {
        /* STUN header: Message Type = CREATE_PERMISSION_ERROR_RESPONSE (0x0118), Length = 52 bytes (excluding 20 bytes header). */
        0x01, 0x18, 0x00, 0x34,
        /* Magic Cookie (0x2112A442). */
        0x21, 0x12, 0xA4, 0x42,
        /* 12 bytes (96 bits) transaction ID which is same as transactionID above. */
        0xFF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
        /* Attribute Type = Error Code (0x0009), Attribute Length = 16 (2 reserved bytes, 2 byte error code and 12 byte error phrase). */
        0x00, 0x09, 0x00, 0x10,
        /* Reserved = 0x0000, Error Class = 0, Error Number = 00 (Error Code = 0 Success). */
        0x00, 0x00, 0x00, 0x00,
        /* Error Phrase = "Error Phrase". */
        0x45, 0x72, 0x72, 0x6F,
        0x72, 0x20, 0x50, 0x68,
        0x72, 0x61, 0x73, 0x65,
        /* Attribute type = MESSAGE-INTEGRITY (0x0008), Length = 20 bytes. */
        0x00, 0x08, 0x00, 0x14,
        /* Attribute Value = HMAC value as computed by testHmacFxn_FixedFF. */
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        /* Attribute type = FINGERPRINT (0x8028), Length = 4 bytes. */
        0x80, 0x28, 0x00, 0x04,
        /* Attribute Value: 0x00000000 as calculated by testCrc32Fxn_Fixed. */
        0x00, 0x00, 0x00, 0x00
    };
    size_t stunMessageLength = sizeof( stunMessage );
    char longTermPassword[] = "LongTermPassword";
    size_t longTermPasswordLength = strlen( longTermPassword );

    /* Set CRC32 function to testCrc32Fxn_Fixed to make fingerprint always 0x00000000 */
    initInfo.cryptoFunctions.crc32Fxn = testCrc32Fxn_Fixed;
    /* Set CRC32 function to testHmacFxn_FixedFF to make integrity always 0xFF. */
    initInfo.cryptoFunctions.hmacFxn = testHmacFxn_FixedFF;
    initInfo.getCurrentTimeSecondsFxn = testGetCurrentTime_FixedZero;

    iceResult = Ice_Init( &( context ),
                          &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       iceResult );

    memset( &( localCandidate ),
            0,
            sizeof( IceCandidate_t ) );
    localCandidate.candidateType = ICE_CANDIDATE_TYPE_RELAY;
    localCandidate.state = ICE_CANDIDATE_STATE_VALID;
    context.numRelayExtensions = 1;
    localCandidate.pRelayExtension = &( context.pRelayExtensionsArray[ 0 ] );
    memcpy( localCandidate.pRelayExtension->iceRelayServerInfo.longTermPassword,
            longTermPassword,
            longTermPasswordLength );
    localCandidate.pRelayExtension->iceRelayServerInfo.longTermPasswordLength = longTermPasswordLength;

    context.numCandidatePairs = 2;
    memset( context.pCandidatePairs[ 0 ].transactionId, 0, sizeof( transactionID ) );
    memcpy( context.pCandidatePairs[ 1 ].transactionId, transactionID, sizeof( transactionID ) );
    context.pCandidatePairs[ 1 ].state = ICE_CANDIDATE_PAIR_STATE_CREATE_PERMISSION;

    result = Ice_HandleStunPacket( &( context ),
                                   &( stunMessage[ 0 ] ),
                                   stunMessageLength,
                                   &( localCandidate ),
                                   &( remoteEndpoint ),
                                   &( pTransactionId ),
                                   &( pCandidatePair ) );

    TEST_ASSERT_EQUAL( ICE_HANDLE_STUN_PACKET_RESULT_OK,
                       result );
    TEST_ASSERT_EQUAL( ICE_CANDIDATE_PAIR_STATE_INVALID,
                       pCandidatePair->state );
}

/*-----------------------------------------------------------*/

/**
 * @brief Ice_HandleStunPacket recieves a CREATE_PERMISSION_ERROR_RESPONSE and
 * the candidate pair having transaction ID is not creating permission.
 */
void test_iceHandleStunPacket_CreatePermissionErrorResponse_PairNotCreatePermission( void )
{
    IceContext_t context = { 0 };
    IceCandidate_t localCandidate = { 0 };
    IceEndpoint_t remoteEndpoint = { 0 };
    uint8_t * pTransactionId;
    IceCandidatePair_t * pCandidatePair = NULL;
    IceResult_t iceResult;
    IceHandleStunPacketResult_t result;
    uint8_t transactionID[] =
    {
        0xFF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B
    };
    uint8_t stunMessage[] =
    {
        /* STUN header: Message Type = CREATE_PERMISSION_ERROR_RESPONSE (0x0118), Length = 52 bytes (excluding 20 bytes header). */
        0x01, 0x18, 0x00, 0x34,
        /* Magic Cookie (0x2112A442). */
        0x21, 0x12, 0xA4, 0x42,
        /* 12 bytes (96 bits) transaction ID which is same as transactionID above. */
        0xFF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
        /* Attribute Type = Error Code (0x0009), Attribute Length = 16 (2 reserved bytes, 2 byte error code and 12 byte error phrase). */
        0x00, 0x09, 0x00, 0x10,
        /* Reserved = 0x0000, Error Class = 0, Error Number = 00 (Error Code = 0 Success). */
        0x00, 0x00, 0x00, 0x00,
        /* Error Phrase = "Error Phrase". */
        0x45, 0x72, 0x72, 0x6F,
        0x72, 0x20, 0x50, 0x68,
        0x72, 0x61, 0x73, 0x65,
        /* Attribute type = MESSAGE-INTEGRITY (0x0008), Length = 20 bytes. */
        0x00, 0x08, 0x00, 0x14,
        /* Attribute Value = HMAC value as computed by testHmacFxn_FixedFF. */
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        /* Attribute type = FINGERPRINT (0x8028), Length = 4 bytes. */
        0x80, 0x28, 0x00, 0x04,
        /* Attribute Value: 0x00000000 as calculated by testCrc32Fxn_Fixed. */
        0x00, 0x00, 0x00, 0x00
    };
    size_t stunMessageLength = sizeof( stunMessage );
    char longTermPassword[] = "LongTermPassword";
    size_t longTermPasswordLength = strlen( longTermPassword );

    /* Set CRC32 function to testCrc32Fxn_Fixed to make fingerprint always 0x00000000 */
    initInfo.cryptoFunctions.crc32Fxn = testCrc32Fxn_Fixed;
    /* Set CRC32 function to testHmacFxn_FixedFF to make integrity always 0xFF. */
    initInfo.cryptoFunctions.hmacFxn = testHmacFxn_FixedFF;
    initInfo.getCurrentTimeSecondsFxn = testGetCurrentTime_FixedZero;

    iceResult = Ice_Init( &( context ),
                          &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       iceResult );

    memset( &( localCandidate ),
            0,
            sizeof( IceCandidate_t ) );
    localCandidate.candidateType = ICE_CANDIDATE_TYPE_RELAY;
    localCandidate.state = ICE_CANDIDATE_STATE_VALID;
    context.numRelayExtensions = 1;
    localCandidate.pRelayExtension = &( context.pRelayExtensionsArray[ 0 ] );
    memcpy( localCandidate.pRelayExtension->iceRelayServerInfo.longTermPassword,
            longTermPassword,
            longTermPasswordLength );
    localCandidate.pRelayExtension->iceRelayServerInfo.longTermPasswordLength = longTermPasswordLength;

    context.numCandidatePairs = 2;
    memset( context.pCandidatePairs[ 0 ].transactionId, 0, sizeof( transactionID ) );
    memcpy( context.pCandidatePairs[ 1 ].transactionId, transactionID, sizeof( transactionID ) );
    context.pCandidatePairs[ 1 ].state = ICE_CANDIDATE_PAIR_STATE_CHANNEL_BIND;

    result = Ice_HandleStunPacket( &( context ),
                                   &( stunMessage[ 0 ] ),
                                   stunMessageLength,
                                   &( localCandidate ),
                                   &( remoteEndpoint ),
                                   &( pTransactionId ),
                                   &( pCandidatePair ) );

    TEST_ASSERT_EQUAL( ICE_HANDLE_STUN_PACKET_RESULT_RELAY_CANDIDATE_PAIR_NOT_CREATING_PERMISSION,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Ice_HandleStunPacket recieves a CREATE_PERMISSION_ERROR_RESPONSE and
 * the candidate pair is not found for that transaction ID.
 */
void test_iceHandleStunPacket_CreatePermissionErrorResponse_CandidatePairNotFound( void )
{
    IceContext_t context = { 0 };
    IceCandidate_t localCandidate = { 0 };
    IceEndpoint_t remoteEndpoint = { 0 };
    uint8_t * pTransactionId;
    IceCandidatePair_t * pCandidatePair = NULL;
    IceResult_t iceResult;
    IceHandleStunPacketResult_t result;
    uint8_t stunMessage[] =
    {
        /* STUN header: Message Type = CREATE_PERMISSION_ERROR_RESPONSE (0x0118), Length = 52 bytes (excluding 20 bytes header). */
        0x01, 0x18, 0x00, 0x34,
        /* Magic Cookie (0x2112A442). */
        0x21, 0x12, 0xA4, 0x42,
        /* 12 bytes (96 bits) transaction ID which is same as transactionID above. */
        0xFF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
        /* Attribute Type = Error Code (0x0009), Attribute Length = 16 (2 reserved bytes, 2 byte error code and 12 byte error phrase). */
        0x00, 0x09, 0x00, 0x10,
        /* Reserved = 0x0000, Error Class = 0, Error Number = 00 (Error Code = 0 Success). */
        0x00, 0x00, 0x00, 0x00,
        /* Error Phrase = "Error Phrase". */
        0x45, 0x72, 0x72, 0x6F,
        0x72, 0x20, 0x50, 0x68,
        0x72, 0x61, 0x73, 0x65,
        /* Attribute type = MESSAGE-INTEGRITY (0x0008), Length = 20 bytes. */
        0x00, 0x08, 0x00, 0x14,
        /* Attribute Value = HMAC value as computed by testHmacFxn_FixedFF. */
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        /* Attribute type = FINGERPRINT (0x8028), Length = 4 bytes. */
        0x80, 0x28, 0x00, 0x04,
        /* Attribute Value: 0x00000000 as calculated by testCrc32Fxn_Fixed. */
        0x00, 0x00, 0x00, 0x00
    };
    size_t stunMessageLength = sizeof( stunMessage );
    char longTermPassword[] = "LongTermPassword";
    size_t longTermPasswordLength = strlen( longTermPassword );

    /* Set CRC32 function to testCrc32Fxn_Fixed to make fingerprint always 0x00000000 */
    initInfo.cryptoFunctions.crc32Fxn = testCrc32Fxn_Fixed;
    /* Set CRC32 function to testHmacFxn_FixedFF to make integrity always 0xFF. */
    initInfo.cryptoFunctions.hmacFxn = testHmacFxn_FixedFF;
    initInfo.getCurrentTimeSecondsFxn = testGetCurrentTime_FixedZero;

    iceResult = Ice_Init( &( context ),
                          &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       iceResult );

    memset( &( localCandidate ),
            0,
            sizeof( IceCandidate_t ) );
    localCandidate.candidateType = ICE_CANDIDATE_TYPE_RELAY;
    localCandidate.state = ICE_CANDIDATE_STATE_VALID;
    context.numRelayExtensions = 1;
    localCandidate.pRelayExtension = &( context.pRelayExtensionsArray[ 0 ] );
    memcpy( localCandidate.pRelayExtension->iceRelayServerInfo.longTermPassword,
            longTermPassword,
            longTermPasswordLength );
    localCandidate.pRelayExtension->iceRelayServerInfo.longTermPasswordLength = longTermPasswordLength;

    context.numCandidatePairs = 2;
    memset( context.pCandidatePairs[ 0 ].transactionId, 0, STUN_HEADER_TRANSACTION_ID_LENGTH );
    memset( context.pCandidatePairs[ 1 ].transactionId, 0, STUN_HEADER_TRANSACTION_ID_LENGTH );
    context.pCandidatePairs[ 1 ].state = ICE_CANDIDATE_PAIR_STATE_CREATE_PERMISSION;

    result = Ice_HandleStunPacket( &( context ),
                                   &( stunMessage[ 0 ] ),
                                   stunMessageLength,
                                   &( localCandidate ),
                                   &( remoteEndpoint ),
                                   &( pTransactionId ),
                                   &( pCandidatePair ) );

    TEST_ASSERT_EQUAL( ICE_HANDLE_STUN_PACKET_RESULT_CANDIDATE_PAIR_NOT_FOUND,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Ice_HandleStunPacket recieves a CREATE_PERMISSION_ERROR_RESPONSE and
 * the password is missing while deserializing STUN packet.
 */
void test_iceHandleStunPacket_CreatePermissionErrorResponse_DeserializeStunFail( void )
{
    IceContext_t context = { 0 };
    IceCandidate_t localCandidate = { 0 };
    IceEndpoint_t remoteEndpoint = { 0 };
    uint8_t * pTransactionId;
    IceCandidatePair_t * pCandidatePair = NULL;
    IceResult_t iceResult;
    IceHandleStunPacketResult_t result;
    uint8_t transactionID[] =
    {
        0xFF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B
    };
    uint8_t stunMessage[] =
    {
        /* STUN header: Message Type = CREATE_PERMISSION_ERROR_RESPONSE (0x0118), Length = 52 bytes (excluding 20 bytes header). */
        0x01, 0x18, 0x00, 0x34,
        /* Magic Cookie (0x2112A442). */
        0x21, 0x12, 0xA4, 0x42,
        /* 12 bytes (96 bits) transaction ID which is same as transactionID above. */
        0xFF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
        /* Attribute Type = Error Code (0x0009), Attribute Length = 16 (2 reserved bytes, 2 byte error code and 12 byte error phrase). */
        0x00, 0x09, 0x00, 0x10,
        /* Reserved = 0x0000, Error Class = 0, Error Number = 00 (Error Code = 0 Success). */
        0x00, 0x00, 0x00, 0x00,
        /* Error Phrase = "Error Phrase". */
        0x45, 0x72, 0x72, 0x6F,
        0x72, 0x20, 0x50, 0x68,
        0x72, 0x61, 0x73, 0x65,
        /* Attribute type = MESSAGE-INTEGRITY (0x0008), Length = 20 bytes. */
        0x00, 0x08, 0x00, 0x14,
        /* Attribute Value = HMAC value as computed by testHmacFxn_FixedFF. */
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        /* Attribute type = FINGERPRINT (0x8028), Length = 4 bytes. */
        0x80, 0x28, 0x00, 0x04,
        /* Attribute Value: 0x00000000 as calculated by testCrc32Fxn_Fixed. */
        0x00, 0x00, 0x00, 0x00
    };
    size_t stunMessageLength = sizeof( stunMessage );

    /* Set CRC32 function to testCrc32Fxn_Fixed to make fingerprint always 0x00000000 */
    initInfo.cryptoFunctions.crc32Fxn = testCrc32Fxn_Fixed;
    /* Set CRC32 function to testHmacFxn_FixedFF to make integrity always 0xFF. */
    initInfo.cryptoFunctions.hmacFxn = testHmacFxn_FixedFF;
    initInfo.getCurrentTimeSecondsFxn = testGetCurrentTime_FixedZero;

    iceResult = Ice_Init( &( context ),
                          &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       iceResult );

    memset( &( localCandidate ),
            0,
            sizeof( IceCandidate_t ) );
    localCandidate.candidateType = ICE_CANDIDATE_TYPE_RELAY;
    localCandidate.state = ICE_CANDIDATE_STATE_VALID;
    context.numRelayExtensions = 1;
    localCandidate.pRelayExtension = &( context.pRelayExtensionsArray[ 0 ] );

    context.numCandidatePairs = 2;
    memset( context.pCandidatePairs[ 0 ].transactionId, 0, sizeof( transactionID ) );
    memcpy( context.pCandidatePairs[ 1 ].transactionId, transactionID, sizeof( transactionID ) );
    context.pCandidatePairs[ 1 ].state = ICE_CANDIDATE_PAIR_STATE_CREATE_PERMISSION;

    result = Ice_HandleStunPacket( &( context ),
                                   &( stunMessage[ 0 ] ),
                                   stunMessageLength,
                                   &( localCandidate ),
                                   &( remoteEndpoint ),
                                   &( pTransactionId ),
                                   &( pCandidatePair ) );

    TEST_ASSERT_EQUAL( ICE_HANDLE_STUN_PACKET_RESULT_DESERIALIZE_ERROR,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Ice_HandleStunPacket recieves a CREATE_PERMISSION_SUCCESS_RESPONSE and
 * the candidate pair is found in the ICE context.
 */
void test_iceHandleStunPacket_CreatePermissionSuccessResponse_Pass_StateCreatePermission( void )
{
    IceContext_t context = { 0 };
    IceCandidate_t localCandidate = { 0 };
    IceEndpoint_t remoteEndpoint = { 0 };
    uint8_t * pTransactionId;
    IceCandidatePair_t * pCandidatePair = NULL;
    IceResult_t iceResult;
    IceHandleStunPacketResult_t result;
    uint8_t transactionID[] =
    {
        0xFF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B
    };
    uint8_t stunMessage[] =
    {
        /* STUN header: Message Type = CREATE_PERMISSION_SUCCESS_RESPONSE (0x0108), Length = 52 bytes (excluding 20 bytes header). */
        0x01, 0x08, 0x00, 0x34,
        /* Magic Cookie (0x2112A442). */
        0x21, 0x12, 0xA4, 0x42,
        /* 12 bytes (96 bits) transaction ID which is same as transactionID above. */
        0xFF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
        /* Attribute Type = Error Code (0x0009), Attribute Length = 16 (2 reserved bytes, 2 byte error code and 12 byte error phrase). */
        0x00, 0x09, 0x00, 0x10,
        /* Reserved = 0x0000, Error Class = 0, Error Number = 00 (Error Code = 0 Success). */
        0x00, 0x00, 0x00, 0x00,
        /* Error Phrase = "Error Phrase". */
        0x45, 0x72, 0x72, 0x6F,
        0x72, 0x20, 0x50, 0x68,
        0x72, 0x61, 0x73, 0x65,
        /* Attribute type = MESSAGE-INTEGRITY (0x0008), Length = 20 bytes. */
        0x00, 0x08, 0x00, 0x14,
        /* Attribute Value = HMAC value as computed by testHmacFxn_FixedFF. */
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        /* Attribute type = FINGERPRINT (0x8028), Length = 4 bytes. */
        0x80, 0x28, 0x00, 0x04,
        /* Attribute Value: 0x00000000 as calculated by testCrc32Fxn_Fixed. */
        0x00, 0x00, 0x00, 0x00
    };
    size_t stunMessageLength = sizeof( stunMessage );
    char longTermPassword[] = "LongTermPassword";
    size_t longTermPasswordLength = strlen( longTermPassword );

    /* Set CRC32 function to testCrc32Fxn_Fixed to make fingerprint always 0x00000000 */
    initInfo.cryptoFunctions.crc32Fxn = testCrc32Fxn_Fixed;
    /* Set CRC32 function to testHmacFxn_FixedFF to make integrity always 0xFF. */
    initInfo.cryptoFunctions.hmacFxn = testHmacFxn_FixedFF;
    initInfo.getCurrentTimeSecondsFxn = testGetCurrentTime_FixedZero;

    iceResult = Ice_Init( &( context ),
                          &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       iceResult );

    memset( &( localCandidate ),
            0,
            sizeof( IceCandidate_t ) );
    localCandidate.candidateType = ICE_CANDIDATE_TYPE_RELAY;
    localCandidate.state = ICE_CANDIDATE_STATE_VALID;
    context.numRelayExtensions = 1;
    localCandidate.pRelayExtension = &( context.pRelayExtensionsArray[ 0 ] );
    memcpy( localCandidate.pRelayExtension->iceRelayServerInfo.longTermPassword,
            longTermPassword,
            longTermPasswordLength );
    localCandidate.pRelayExtension->iceRelayServerInfo.longTermPasswordLength = longTermPasswordLength;

    context.numCandidatePairs = 2;
    memset( context.pCandidatePairs[ 0 ].transactionId, 0, sizeof( transactionID ) );
    memcpy( context.pCandidatePairs[ 1 ].transactionId, transactionID, sizeof( transactionID ) );
    context.pCandidatePairs[ 1 ].state = ICE_CANDIDATE_PAIR_STATE_CREATE_PERMISSION;

    result = Ice_HandleStunPacket( &( context ),
                                   &( stunMessage[ 0 ] ),
                                   stunMessageLength,
                                   &( localCandidate ),
                                   &( remoteEndpoint ),
                                   &( pTransactionId ),
                                   &( pCandidatePair ) );

    TEST_ASSERT_EQUAL( ICE_HANDLE_STUN_PACKET_RESULT_SEND_CHANNEL_BIND_REQUEST,
                       result );
    TEST_ASSERT_EQUAL( ICE_CANDIDATE_PAIR_STATE_CHANNEL_BIND,
                       pCandidatePair->state );
    TEST_ASSERT_EQUAL( ICE_DEFAULT_TURN_PERMISSION_LIFETIME_SECONDS,
                       pCandidatePair->turnPermissionExpirationSeconds );
}

/*-----------------------------------------------------------*/

/**
 * @brief Ice_HandleStunPacket recieves a CREATE_PERMISSION_SUCCESS_RESPONSE and
 * the candidate pair is found in the ICE context.
 */
void test_iceHandleStunPacket_CreatePermissionSuccessResponse_Pass_StateSucceeded( void )
{
    IceContext_t context = { 0 };
    IceCandidate_t localCandidate = { 0 };
    IceEndpoint_t remoteEndpoint = { 0 };
    uint8_t * pTransactionId;
    IceCandidatePair_t * pCandidatePair = NULL;
    IceResult_t iceResult;
    IceHandleStunPacketResult_t result;
    uint8_t transactionID[] =
    {
        0xFF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B
    };
    uint8_t stunMessage[] =
    {
        /* STUN header: Message Type = CREATE_PERMISSION_SUCCESS_RESPONSE (0x0108), Length = 52 bytes (excluding 20 bytes header). */
        0x01, 0x08, 0x00, 0x34,
        /* Magic Cookie (0x2112A442). */
        0x21, 0x12, 0xA4, 0x42,
        /* 12 bytes (96 bits) transaction ID which is same as transactionID above. */
        0xFF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
        /* Attribute Type = Error Code (0x0009), Attribute Length = 16 (2 reserved bytes, 2 byte error code and 12 byte error phrase). */
        0x00, 0x09, 0x00, 0x10,
        /* Reserved = 0x0000, Error Class = 0, Error Number = 00 (Error Code = 0 Success). */
        0x00, 0x00, 0x00, 0x00,
        /* Error Phrase = "Error Phrase". */
        0x45, 0x72, 0x72, 0x6F,
        0x72, 0x20, 0x50, 0x68,
        0x72, 0x61, 0x73, 0x65,
        /* Attribute type = MESSAGE-INTEGRITY (0x0008), Length = 20 bytes. */
        0x00, 0x08, 0x00, 0x14,
        /* Attribute Value = HMAC value as computed by testHmacFxn_FixedFF. */
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        /* Attribute type = FINGERPRINT (0x8028), Length = 4 bytes. */
        0x80, 0x28, 0x00, 0x04,
        /* Attribute Value: 0x00000000 as calculated by testCrc32Fxn_Fixed. */
        0x00, 0x00, 0x00, 0x00
    };
    size_t stunMessageLength = sizeof( stunMessage );
    char longTermPassword[] = "LongTermPassword";
    size_t longTermPasswordLength = strlen( longTermPassword );

    /* Set CRC32 function to testCrc32Fxn_Fixed to make fingerprint always 0x00000000 */
    initInfo.cryptoFunctions.crc32Fxn = testCrc32Fxn_Fixed;
    /* Set CRC32 function to testHmacFxn_FixedFF to make integrity always 0xFF. */
    initInfo.cryptoFunctions.hmacFxn = testHmacFxn_FixedFF;
    initInfo.getCurrentTimeSecondsFxn = testGetCurrentTime_FixedZero;

    iceResult = Ice_Init( &( context ),
                          &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       iceResult );

    memset( &( localCandidate ),
            0,
            sizeof( IceCandidate_t ) );
    localCandidate.candidateType = ICE_CANDIDATE_TYPE_RELAY;
    localCandidate.state = ICE_CANDIDATE_STATE_VALID;
    context.numRelayExtensions = 1;
    localCandidate.pRelayExtension = &( context.pRelayExtensionsArray[ 0 ] );
    memcpy( localCandidate.pRelayExtension->iceRelayServerInfo.longTermPassword,
            longTermPassword,
            longTermPasswordLength );
    localCandidate.pRelayExtension->iceRelayServerInfo.longTermPasswordLength = longTermPasswordLength;

    context.numCandidatePairs = 2;
    memset( context.pCandidatePairs[ 0 ].transactionId, 0, sizeof( transactionID ) );
    memcpy( context.pCandidatePairs[ 1 ].transactionId, transactionID, sizeof( transactionID ) );
    context.pCandidatePairs[ 1 ].state = ICE_CANDIDATE_PAIR_STATE_SUCCEEDED;

    result = Ice_HandleStunPacket( &( context ),
                                   &( stunMessage[ 0 ] ),
                                   stunMessageLength,
                                   &( localCandidate ),
                                   &( remoteEndpoint ),
                                   &( pTransactionId ),
                                   &( pCandidatePair ) );

    TEST_ASSERT_EQUAL( ICE_HANDLE_STUN_PACKET_RESULT_OK,
                       result );
    TEST_ASSERT_EQUAL( ICE_CANDIDATE_PAIR_STATE_SUCCEEDED,
                       pCandidatePair->state );
    TEST_ASSERT_EQUAL( ICE_DEFAULT_TURN_PERMISSION_LIFETIME_SECONDS,
                       pCandidatePair->turnPermissionExpirationSeconds );
}

/*-----------------------------------------------------------*/

/**
 * @brief Ice_HandleStunPacket recieves a CREATE_PERMISSION_SUCCESS_RESPONSE but
 * random returns fail while creating new transaction ID.
 */
void test_iceHandleStunPacket_CreatePermissionSuccessResponse_RandomFail( void )
{
    IceContext_t context = { 0 };
    IceCandidate_t localCandidate = { 0 };
    IceEndpoint_t remoteEndpoint = { 0 };
    uint8_t * pTransactionId;
    IceCandidatePair_t * pCandidatePair = NULL;
    IceResult_t iceResult;
    IceHandleStunPacketResult_t result;
    uint8_t transactionID[] =
    {
        0xFF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B
    };
    uint8_t stunMessage[] =
    {
        /* STUN header: Message Type = CREATE_PERMISSION_SUCCESS_RESPONSE (0x0108), Length = 52 bytes (excluding 20 bytes header). */
        0x01, 0x08, 0x00, 0x34,
        /* Magic Cookie (0x2112A442). */
        0x21, 0x12, 0xA4, 0x42,
        /* 12 bytes (96 bits) transaction ID which is same as transactionID above. */
        0xFF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
        /* Attribute Type = Error Code (0x0009), Attribute Length = 16 (2 reserved bytes, 2 byte error code and 12 byte error phrase). */
        0x00, 0x09, 0x00, 0x10,
        /* Reserved = 0x0000, Error Class = 0, Error Number = 00 (Error Code = 0 Success). */
        0x00, 0x00, 0x00, 0x00,
        /* Error Phrase = "Error Phrase". */
        0x45, 0x72, 0x72, 0x6F,
        0x72, 0x20, 0x50, 0x68,
        0x72, 0x61, 0x73, 0x65,
        /* Attribute type = MESSAGE-INTEGRITY (0x0008), Length = 20 bytes. */
        0x00, 0x08, 0x00, 0x14,
        /* Attribute Value = HMAC value as computed by testHmacFxn_FixedFF. */
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        /* Attribute type = FINGERPRINT (0x8028), Length = 4 bytes. */
        0x80, 0x28, 0x00, 0x04,
        /* Attribute Value: 0x00000000 as calculated by testCrc32Fxn_Fixed. */
        0x00, 0x00, 0x00, 0x00
    };
    size_t stunMessageLength = sizeof( stunMessage );
    char longTermPassword[] = "LongTermPassword";
    size_t longTermPasswordLength = strlen( longTermPassword );

    /* Set CRC32 function to testCrc32Fxn_Fixed to make fingerprint always 0x00000000 */
    initInfo.cryptoFunctions.crc32Fxn = testCrc32Fxn_Fixed;
    /* Set CRC32 function to testHmacFxn_FixedFF to make integrity always 0xFF. */
    initInfo.cryptoFunctions.hmacFxn = testHmacFxn_FixedFF;
    initInfo.getCurrentTimeSecondsFxn = testGetCurrentTime_FixedZero;

    iceResult = Ice_Init( &( context ),
                          &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       iceResult );

    /* Ice uses random to generate tie breaker. So we overwrite it after init. */
    context.cryptoFunctions.randomFxn = testRandomFxn_Wrong;

    memset( &( localCandidate ),
            0,
            sizeof( IceCandidate_t ) );
    localCandidate.candidateType = ICE_CANDIDATE_TYPE_RELAY;
    localCandidate.state = ICE_CANDIDATE_STATE_VALID;
    context.numRelayExtensions = 1;
    localCandidate.pRelayExtension = &( context.pRelayExtensionsArray[ 0 ] );
    memcpy( localCandidate.pRelayExtension->iceRelayServerInfo.longTermPassword,
            longTermPassword,
            longTermPasswordLength );
    localCandidate.pRelayExtension->iceRelayServerInfo.longTermPasswordLength = longTermPasswordLength;

    context.numCandidatePairs = 2;
    memset( context.pCandidatePairs[ 0 ].transactionId, 0, sizeof( transactionID ) );
    memcpy( context.pCandidatePairs[ 1 ].transactionId, transactionID, sizeof( transactionID ) );
    context.pCandidatePairs[ 1 ].state = ICE_CANDIDATE_PAIR_STATE_SUCCEEDED;

    result = Ice_HandleStunPacket( &( context ),
                                   &( stunMessage[ 0 ] ),
                                   stunMessageLength,
                                   &( localCandidate ),
                                   &( remoteEndpoint ),
                                   &( pTransactionId ),
                                   &( pCandidatePair ) );

    TEST_ASSERT_EQUAL( ICE_HANDLE_STUN_PACKET_RESULT_RANDOM_ERROR_CODE,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Ice_HandleStunPacket recieves a CREATE_PERMISSION_SUCCESS_RESPONSE but
 * the candidate pair state is neither create permission nor succeeded.
 */
void test_iceHandleStunPacket_CreatePermissionSuccessResponse_StateNotWaitingCreatePermission( void )
{
    IceContext_t context = { 0 };
    IceCandidate_t localCandidate = { 0 };
    IceEndpoint_t remoteEndpoint = { 0 };
    uint8_t * pTransactionId;
    IceCandidatePair_t * pCandidatePair = NULL;
    IceResult_t iceResult;
    IceHandleStunPacketResult_t result;
    uint8_t transactionID[] =
    {
        0xFF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B
    };
    uint8_t stunMessage[] =
    {
        /* STUN header: Message Type = CREATE_PERMISSION_SUCCESS_RESPONSE (0x0108), Length = 52 bytes (excluding 20 bytes header). */
        0x01, 0x08, 0x00, 0x34,
        /* Magic Cookie (0x2112A442). */
        0x21, 0x12, 0xA4, 0x42,
        /* 12 bytes (96 bits) transaction ID which is same as transactionID above. */
        0xFF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
        /* Attribute Type = Error Code (0x0009), Attribute Length = 16 (2 reserved bytes, 2 byte error code and 12 byte error phrase). */
        0x00, 0x09, 0x00, 0x10,
        /* Reserved = 0x0000, Error Class = 0, Error Number = 00 (Error Code = 0 Success). */
        0x00, 0x00, 0x00, 0x00,
        /* Error Phrase = "Error Phrase". */
        0x45, 0x72, 0x72, 0x6F,
        0x72, 0x20, 0x50, 0x68,
        0x72, 0x61, 0x73, 0x65,
        /* Attribute type = MESSAGE-INTEGRITY (0x0008), Length = 20 bytes. */
        0x00, 0x08, 0x00, 0x14,
        /* Attribute Value = HMAC value as computed by testHmacFxn_FixedFF. */
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        /* Attribute type = FINGERPRINT (0x8028), Length = 4 bytes. */
        0x80, 0x28, 0x00, 0x04,
        /* Attribute Value: 0x00000000 as calculated by testCrc32Fxn_Fixed. */
        0x00, 0x00, 0x00, 0x00
    };
    size_t stunMessageLength = sizeof( stunMessage );
    char longTermPassword[] = "LongTermPassword";
    size_t longTermPasswordLength = strlen( longTermPassword );

    /* Set CRC32 function to testCrc32Fxn_Fixed to make fingerprint always 0x00000000 */
    initInfo.cryptoFunctions.crc32Fxn = testCrc32Fxn_Fixed;
    /* Set CRC32 function to testHmacFxn_FixedFF to make integrity always 0xFF. */
    initInfo.cryptoFunctions.hmacFxn = testHmacFxn_FixedFF;
    initInfo.getCurrentTimeSecondsFxn = testGetCurrentTime_FixedZero;

    iceResult = Ice_Init( &( context ),
                          &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       iceResult );

    memset( &( localCandidate ),
            0,
            sizeof( IceCandidate_t ) );
    localCandidate.candidateType = ICE_CANDIDATE_TYPE_RELAY;
    localCandidate.state = ICE_CANDIDATE_STATE_VALID;
    context.numRelayExtensions = 1;
    localCandidate.pRelayExtension = &( context.pRelayExtensionsArray[ 0 ] );
    memcpy( localCandidate.pRelayExtension->iceRelayServerInfo.longTermPassword,
            longTermPassword,
            longTermPasswordLength );
    localCandidate.pRelayExtension->iceRelayServerInfo.longTermPasswordLength = longTermPasswordLength;

    context.numCandidatePairs = 2;
    memset( context.pCandidatePairs[ 0 ].transactionId, 0, sizeof( transactionID ) );
    memcpy( context.pCandidatePairs[ 1 ].transactionId, transactionID, sizeof( transactionID ) );
    context.pCandidatePairs[ 1 ].state = ICE_CANDIDATE_PAIR_STATE_CHANNEL_BIND;

    result = Ice_HandleStunPacket( &( context ),
                                   &( stunMessage[ 0 ] ),
                                   stunMessageLength,
                                   &( localCandidate ),
                                   &( remoteEndpoint ),
                                   &( pTransactionId ),
                                   &( pCandidatePair ) );

    TEST_ASSERT_EQUAL( ICE_HANDLE_STUN_PACKET_RESULT_RELAY_CANDIDATE_PAIR_NOT_CREATING_PERMISSION,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Ice_HandleStunPacket recieves a CREATE_PERMISSION_SUCCESS_RESPONSE but
 * no candidate pair has that transaction ID.
 */
void test_iceHandleStunPacket_CreatePermissionSuccessResponse_CandidateNotFound( void )
{
    IceContext_t context = { 0 };
    IceCandidate_t localCandidate = { 0 };
    IceEndpoint_t remoteEndpoint = { 0 };
    uint8_t * pTransactionId;
    IceCandidatePair_t * pCandidatePair = NULL;
    IceResult_t iceResult;
    IceHandleStunPacketResult_t result;
    uint8_t stunMessage[] =
    {
        /* STUN header: Message Type = CREATE_PERMISSION_SUCCESS_RESPONSE (0x0108), Length = 52 bytes (excluding 20 bytes header). */
        0x01, 0x08, 0x00, 0x34,
        /* Magic Cookie (0x2112A442). */
        0x21, 0x12, 0xA4, 0x42,
        /* 12 bytes (96 bits) transaction ID which is same as transactionID above. */
        0xFF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
        /* Attribute Type = Error Code (0x0009), Attribute Length = 16 (2 reserved bytes, 2 byte error code and 12 byte error phrase). */
        0x00, 0x09, 0x00, 0x10,
        /* Reserved = 0x0000, Error Class = 0, Error Number = 00 (Error Code = 0 Success). */
        0x00, 0x00, 0x00, 0x00,
        /* Error Phrase = "Error Phrase". */
        0x45, 0x72, 0x72, 0x6F,
        0x72, 0x20, 0x50, 0x68,
        0x72, 0x61, 0x73, 0x65,
        /* Attribute type = MESSAGE-INTEGRITY (0x0008), Length = 20 bytes. */
        0x00, 0x08, 0x00, 0x14,
        /* Attribute Value = HMAC value as computed by testHmacFxn_FixedFF. */
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        /* Attribute type = FINGERPRINT (0x8028), Length = 4 bytes. */
        0x80, 0x28, 0x00, 0x04,
        /* Attribute Value: 0x00000000 as calculated by testCrc32Fxn_Fixed. */
        0x00, 0x00, 0x00, 0x00
    };
    size_t stunMessageLength = sizeof( stunMessage );
    char longTermPassword[] = "LongTermPassword";
    size_t longTermPasswordLength = strlen( longTermPassword );

    /* Set CRC32 function to testCrc32Fxn_Fixed to make fingerprint always 0x00000000 */
    initInfo.cryptoFunctions.crc32Fxn = testCrc32Fxn_Fixed;
    /* Set CRC32 function to testHmacFxn_FixedFF to make integrity always 0xFF. */
    initInfo.cryptoFunctions.hmacFxn = testHmacFxn_FixedFF;
    initInfo.getCurrentTimeSecondsFxn = testGetCurrentTime_FixedZero;

    iceResult = Ice_Init( &( context ),
                          &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       iceResult );

    memset( &( localCandidate ),
            0,
            sizeof( IceCandidate_t ) );
    localCandidate.candidateType = ICE_CANDIDATE_TYPE_RELAY;
    localCandidate.state = ICE_CANDIDATE_STATE_VALID;
    context.numRelayExtensions = 1;
    localCandidate.pRelayExtension = &( context.pRelayExtensionsArray[ 0 ] );
    memcpy( localCandidate.pRelayExtension->iceRelayServerInfo.longTermPassword,
            longTermPassword,
            longTermPasswordLength );
    localCandidate.pRelayExtension->iceRelayServerInfo.longTermPasswordLength = longTermPasswordLength;

    context.numCandidatePairs = 2;
    memset( context.pCandidatePairs[ 0 ].transactionId, 0, STUN_HEADER_TRANSACTION_ID_LENGTH );
    memset( context.pCandidatePairs[ 1 ].transactionId, 0, STUN_HEADER_TRANSACTION_ID_LENGTH );
    context.pCandidatePairs[ 1 ].state = ICE_CANDIDATE_PAIR_STATE_SUCCEEDED;

    result = Ice_HandleStunPacket( &( context ),
                                   &( stunMessage[ 0 ] ),
                                   stunMessageLength,
                                   &( localCandidate ),
                                   &( remoteEndpoint ),
                                   &( pTransactionId ),
                                   &( pCandidatePair ) );

    TEST_ASSERT_EQUAL( ICE_HANDLE_STUN_PACKET_RESULT_CANDIDATE_PAIR_NOT_FOUND,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Ice_HandleStunPacket recieves a CREATE_PERMISSION_SUCCESS_RESPONSE but
 * the error code is non-zero.
 */
void test_iceHandleStunPacket_CreatePermissionSuccessResponse_NonZeroError( void )
{
    IceContext_t context = { 0 };
    IceCandidate_t localCandidate = { 0 };
    IceEndpoint_t remoteEndpoint = { 0 };
    uint8_t * pTransactionId;
    IceCandidatePair_t * pCandidatePair = NULL;
    IceResult_t iceResult;
    IceHandleStunPacketResult_t result;
    uint8_t stunMessage[] =
    {
        /* STUN header: Message Type = CREATE_PERMISSION_SUCCESS_RESPONSE (0x0108), Length = 52 bytes (excluding 20 bytes header). */
        0x01, 0x08, 0x00, 0x34,
        /* Magic Cookie (0x2112A442). */
        0x21, 0x12, 0xA4, 0x42,
        /* 12 bytes (96 bits) transaction ID which is same as transactionID above. */
        0xFF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
        /* Attribute Type = Error Code (0x0009), Attribute Length = 16 (2 reserved bytes, 2 byte error code and 12 byte error phrase). */
        0x00, 0x09, 0x00, 0x10,
        /* Reserved = 0x0000, Error Class = 4, Error Number = 01 (Error Code = 401 Unauthorized). */
        0x00, 0x00, 0x04, 0x01,
        /* Error Phrase = "Error Phrase". */
        0x45, 0x72, 0x72, 0x6F,
        0x72, 0x20, 0x50, 0x68,
        0x72, 0x61, 0x73, 0x65,
        /* Attribute type = MESSAGE-INTEGRITY (0x0008), Length = 20 bytes. */
        0x00, 0x08, 0x00, 0x14,
        /* Attribute Value = HMAC value as computed by testHmacFxn_FixedFF. */
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        /* Attribute type = FINGERPRINT (0x8028), Length = 4 bytes. */
        0x80, 0x28, 0x00, 0x04,
        /* Attribute Value: 0x00000000 as calculated by testCrc32Fxn_Fixed. */
        0x00, 0x00, 0x00, 0x00
    };
    size_t stunMessageLength = sizeof( stunMessage );
    char longTermPassword[] = "LongTermPassword";
    size_t longTermPasswordLength = strlen( longTermPassword );

    /* Set CRC32 function to testCrc32Fxn_Fixed to make fingerprint always 0x00000000 */
    initInfo.cryptoFunctions.crc32Fxn = testCrc32Fxn_Fixed;
    /* Set CRC32 function to testHmacFxn_FixedFF to make integrity always 0xFF. */
    initInfo.cryptoFunctions.hmacFxn = testHmacFxn_FixedFF;
    initInfo.getCurrentTimeSecondsFxn = testGetCurrentTime_FixedZero;

    iceResult = Ice_Init( &( context ),
                          &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       iceResult );

    memset( &( localCandidate ),
            0,
            sizeof( IceCandidate_t ) );
    localCandidate.candidateType = ICE_CANDIDATE_TYPE_RELAY;
    localCandidate.state = ICE_CANDIDATE_STATE_VALID;
    context.numRelayExtensions = 1;
    localCandidate.pRelayExtension = &( context.pRelayExtensionsArray[ 0 ] );
    memcpy( localCandidate.pRelayExtension->iceRelayServerInfo.longTermPassword,
            longTermPassword,
            longTermPasswordLength );
    localCandidate.pRelayExtension->iceRelayServerInfo.longTermPasswordLength = longTermPasswordLength;

    result = Ice_HandleStunPacket( &( context ),
                                   &( stunMessage[ 0 ] ),
                                   stunMessageLength,
                                   &( localCandidate ),
                                   &( remoteEndpoint ),
                                   &( pTransactionId ),
                                   &( pCandidatePair ) );

    TEST_ASSERT_EQUAL( ICE_HANDLE_STUN_PACKET_RESULT_NON_ZERO_ERROR_CODE,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Ice_HandleStunPacket recieves a CREATE_PERMISSION_SUCCESS_RESPONSE but
 * the password is missing while deserializing STUN packet.
 */
void test_iceHandleStunPacket_CreatePermissionSuccessResponse_DeserializeStunFail( void )
{
    IceContext_t context = { 0 };
    IceCandidate_t localCandidate = { 0 };
    IceEndpoint_t remoteEndpoint = { 0 };
    uint8_t * pTransactionId;
    IceCandidatePair_t * pCandidatePair = NULL;
    IceResult_t iceResult;
    IceHandleStunPacketResult_t result;
    uint8_t stunMessage[] =
    {
        /* STUN header: Message Type = CREATE_PERMISSION_SUCCESS_RESPONSE (0x0108), Length = 52 bytes (excluding 20 bytes header). */
        0x01, 0x08, 0x00, 0x34,
        /* Magic Cookie (0x2112A442). */
        0x21, 0x12, 0xA4, 0x42,
        /* 12 bytes (96 bits) transaction ID which is same as transactionID above. */
        0xFF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
        /* Attribute Type = Error Code (0x0009), Attribute Length = 16 (2 reserved bytes, 2 byte error code and 12 byte error phrase). */
        0x00, 0x09, 0x00, 0x10,
        /* Reserved = 0x0000, Error Class = 0, Error Number = 00 (Error Code = 0 Success). */
        0x00, 0x00, 0x00, 0x00,
        /* Error Phrase = "Error Phrase". */
        0x45, 0x72, 0x72, 0x6F,
        0x72, 0x20, 0x50, 0x68,
        0x72, 0x61, 0x73, 0x65,
        /* Attribute type = MESSAGE-INTEGRITY (0x0008), Length = 20 bytes. */
        0x00, 0x08, 0x00, 0x14,
        /* Attribute Value = HMAC value as computed by testHmacFxn_FixedFF. */
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        /* Attribute type = FINGERPRINT (0x8028), Length = 4 bytes. */
        0x80, 0x28, 0x00, 0x04,
        /* Attribute Value: 0x00000000 as calculated by testCrc32Fxn_Fixed. */
        0x00, 0x00, 0x00, 0x00
    };
    size_t stunMessageLength = sizeof( stunMessage );

    /* Set CRC32 function to testCrc32Fxn_Fixed to make fingerprint always 0x00000000 */
    initInfo.cryptoFunctions.crc32Fxn = testCrc32Fxn_Fixed;
    /* Set CRC32 function to testHmacFxn_FixedFF to make integrity always 0xFF. */
    initInfo.cryptoFunctions.hmacFxn = testHmacFxn_FixedFF;
    initInfo.getCurrentTimeSecondsFxn = testGetCurrentTime_FixedZero;

    iceResult = Ice_Init( &( context ),
                          &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       iceResult );

    localCandidate.candidateType = ICE_CANDIDATE_TYPE_RELAY;
    context.numRelayExtensions = 1;
    localCandidate.pRelayExtension = &( context.pRelayExtensionsArray[ 0 ] );

    result = Ice_HandleStunPacket( &( context ),
                                   &( stunMessage[ 0 ] ),
                                   stunMessageLength,
                                   &( localCandidate ),
                                   &( remoteEndpoint ),
                                   &( pTransactionId ),
                                   &( pCandidatePair ) );

    TEST_ASSERT_EQUAL( ICE_HANDLE_STUN_PACKET_RESULT_DESERIALIZE_ERROR,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Ice_HandleStunPacket recieves a CHANNEL_BIND_ERROR_RESPONSE and
 * the candidate pair is found in the ICE context.
 */
void test_iceHandleStunPacket_ChannelBindErrorResponse_Pass( void )
{
    IceContext_t context = { 0 };
    IceCandidate_t localCandidate = { 0 };
    IceEndpoint_t remoteEndpoint = { 0 };
    uint8_t * pTransactionId;
    IceCandidatePair_t * pCandidatePair = NULL;
    IceResult_t iceResult;
    IceHandleStunPacketResult_t result;
    uint8_t transactionID[] =
    {
        0xFF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B
    };
    uint8_t stunMessage[] =
    {
        /* STUN header: Message Type = CHANNEL_BIND_ERROR_RESPONSE (0x0119), Length = 52 bytes (excluding 20 bytes header). */
        0x01, 0x19, 0x00, 0x34,
        /* Magic Cookie (0x2112A442). */
        0x21, 0x12, 0xA4, 0x42,
        /* 12 bytes (96 bits) transaction ID which is same as transactionID above. */
        0xFF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
        /* Attribute Type = Error Code (0x0009), Attribute Length = 16 (2 reserved bytes, 2 byte error code and 12 byte error phrase). */
        0x00, 0x09, 0x00, 0x10,
        /* Reserved = 0x0000, Error Class = 0, Error Number = 00 (Error Code = 0 Success). */
        0x00, 0x00, 0x00, 0x00,
        /* Error Phrase = "Error Phrase". */
        0x45, 0x72, 0x72, 0x6F,
        0x72, 0x20, 0x50, 0x68,
        0x72, 0x61, 0x73, 0x65,
        /* Attribute type = MESSAGE-INTEGRITY (0x0008), Length = 20 bytes. */
        0x00, 0x08, 0x00, 0x14,
        /* Attribute Value = HMAC value as computed by testHmacFxn_FixedFF. */
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        /* Attribute type = FINGERPRINT (0x8028), Length = 4 bytes. */
        0x80, 0x28, 0x00, 0x04,
        /* Attribute Value: 0x00000000 as calculated by testCrc32Fxn_Fixed. */
        0x00, 0x00, 0x00, 0x00
    };
    size_t stunMessageLength = sizeof( stunMessage );
    char longTermPassword[] = "LongTermPassword";
    size_t longTermPasswordLength = strlen( longTermPassword );

    /* Set CRC32 function to testCrc32Fxn_Fixed to make fingerprint always 0x00000000 */
    initInfo.cryptoFunctions.crc32Fxn = testCrc32Fxn_Fixed;
    /* Set CRC32 function to testHmacFxn_FixedFF to make integrity always 0xFF. */
    initInfo.cryptoFunctions.hmacFxn = testHmacFxn_FixedFF;
    initInfo.getCurrentTimeSecondsFxn = testGetCurrentTime_FixedZero;

    iceResult = Ice_Init( &( context ),
                          &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       iceResult );

    memset( &( localCandidate ),
            0,
            sizeof( IceCandidate_t ) );
    localCandidate.candidateType = ICE_CANDIDATE_TYPE_RELAY;
    localCandidate.state = ICE_CANDIDATE_STATE_VALID;
    context.numRelayExtensions = 1;
    localCandidate.pRelayExtension = &( context.pRelayExtensionsArray[ 0 ] );
    memcpy( localCandidate.pRelayExtension->iceRelayServerInfo.longTermPassword,
            longTermPassword,
            longTermPasswordLength );
    localCandidate.pRelayExtension->iceRelayServerInfo.longTermPasswordLength = longTermPasswordLength;

    context.numCandidatePairs = 2;
    memset( context.pCandidatePairs[ 0 ].transactionId, 0, sizeof( transactionID ) );
    memcpy( context.pCandidatePairs[ 1 ].transactionId, transactionID, sizeof( transactionID ) );
    context.pCandidatePairs[ 1 ].state = ICE_CANDIDATE_PAIR_STATE_CHANNEL_BIND;

    result = Ice_HandleStunPacket( &( context ),
                                   &( stunMessage[ 0 ] ),
                                   stunMessageLength,
                                   &( localCandidate ),
                                   &( remoteEndpoint ),
                                   &( pTransactionId ),
                                   &( pCandidatePair ) );

    TEST_ASSERT_EQUAL( ICE_HANDLE_STUN_PACKET_RESULT_OK,
                       result );
    TEST_ASSERT_EQUAL( ICE_CANDIDATE_PAIR_STATE_INVALID,
                       pCandidatePair->state );
}

/*-----------------------------------------------------------*/

/**
 * @brief Ice_HandleStunPacket recieves a CHANNEL_BIND_ERROR_RESPONSE but
 * the candidate pair state is not waiting for channel bind response.
 */
void test_iceHandleStunPacket_ChannelBindErrorResponse_StateNotChannelBind( void )
{
    IceContext_t context = { 0 };
    IceCandidate_t localCandidate = { 0 };
    IceEndpoint_t remoteEndpoint = { 0 };
    uint8_t * pTransactionId;
    IceCandidatePair_t * pCandidatePair = NULL;
    IceResult_t iceResult;
    IceHandleStunPacketResult_t result;
    uint8_t transactionID[] =
    {
        0xFF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B
    };
    uint8_t stunMessage[] =
    {
        /* STUN header: Message Type = CHANNEL_BIND_ERROR_RESPONSE (0x0119), Length = 52 bytes (excluding 20 bytes header). */
        0x01, 0x19, 0x00, 0x34,
        /* Magic Cookie (0x2112A442). */
        0x21, 0x12, 0xA4, 0x42,
        /* 12 bytes (96 bits) transaction ID which is same as transactionID above. */
        0xFF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
        /* Attribute Type = Error Code (0x0009), Attribute Length = 16 (2 reserved bytes, 2 byte error code and 12 byte error phrase). */
        0x00, 0x09, 0x00, 0x10,
        /* Reserved = 0x0000, Error Class = 0, Error Number = 00 (Error Code = 0 Success). */
        0x00, 0x00, 0x00, 0x00,
        /* Error Phrase = "Error Phrase". */
        0x45, 0x72, 0x72, 0x6F,
        0x72, 0x20, 0x50, 0x68,
        0x72, 0x61, 0x73, 0x65,
        /* Attribute type = MESSAGE-INTEGRITY (0x0008), Length = 20 bytes. */
        0x00, 0x08, 0x00, 0x14,
        /* Attribute Value = HMAC value as computed by testHmacFxn_FixedFF. */
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        /* Attribute type = FINGERPRINT (0x8028), Length = 4 bytes. */
        0x80, 0x28, 0x00, 0x04,
        /* Attribute Value: 0x00000000 as calculated by testCrc32Fxn_Fixed. */
        0x00, 0x00, 0x00, 0x00
    };
    size_t stunMessageLength = sizeof( stunMessage );
    char longTermPassword[] = "LongTermPassword";
    size_t longTermPasswordLength = strlen( longTermPassword );

    /* Set CRC32 function to testCrc32Fxn_Fixed to make fingerprint always 0x00000000 */
    initInfo.cryptoFunctions.crc32Fxn = testCrc32Fxn_Fixed;
    /* Set CRC32 function to testHmacFxn_FixedFF to make integrity always 0xFF. */
    initInfo.cryptoFunctions.hmacFxn = testHmacFxn_FixedFF;
    initInfo.getCurrentTimeSecondsFxn = testGetCurrentTime_FixedZero;

    iceResult = Ice_Init( &( context ),
                          &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       iceResult );

    memset( &( localCandidate ),
            0,
            sizeof( IceCandidate_t ) );
    localCandidate.candidateType = ICE_CANDIDATE_TYPE_RELAY;
    localCandidate.state = ICE_CANDIDATE_STATE_VALID;
    context.numRelayExtensions = 1;
    localCandidate.pRelayExtension = &( context.pRelayExtensionsArray[ 0 ] );
    memcpy( localCandidate.pRelayExtension->iceRelayServerInfo.longTermPassword,
            longTermPassword,
            longTermPasswordLength );
    localCandidate.pRelayExtension->iceRelayServerInfo.longTermPasswordLength = longTermPasswordLength;

    context.numCandidatePairs = 2;
    memset( context.pCandidatePairs[ 0 ].transactionId, 0, sizeof( transactionID ) );
    memcpy( context.pCandidatePairs[ 1 ].transactionId, transactionID, sizeof( transactionID ) );
    context.pCandidatePairs[ 1 ].state = ICE_CANDIDATE_PAIR_STATE_SUCCEEDED;

    result = Ice_HandleStunPacket( &( context ),
                                   &( stunMessage[ 0 ] ),
                                   stunMessageLength,
                                   &( localCandidate ),
                                   &( remoteEndpoint ),
                                   &( pTransactionId ),
                                   &( pCandidatePair ) );

    TEST_ASSERT_EQUAL( ICE_HANDLE_STUN_PACKET_RESULT_RELAY_CANDIDATE_PAIR_NOT_CHANNEL_BINDING,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Ice_HandleStunPacket recieves a CHANNEL_BIND_ERROR_RESPONSE but
 * no candidate pair has same transaction ID.
 */
void test_iceHandleStunPacket_ChannelBindErrorResponse_CandidatePairNotFound( void )
{
    IceContext_t context = { 0 };
    IceCandidate_t localCandidate = { 0 };
    IceEndpoint_t remoteEndpoint = { 0 };
    uint8_t * pTransactionId;
    IceCandidatePair_t * pCandidatePair = NULL;
    IceResult_t iceResult;
    IceHandleStunPacketResult_t result;
    uint8_t stunMessage[] =
    {
        /* STUN header: Message Type = CHANNEL_BIND_ERROR_RESPONSE (0x0119), Length = 52 bytes (excluding 20 bytes header). */
        0x01, 0x19, 0x00, 0x34,
        /* Magic Cookie (0x2112A442). */
        0x21, 0x12, 0xA4, 0x42,
        /* 12 bytes (96 bits) transaction ID which is same as transactionID above. */
        0xFF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
        /* Attribute Type = Error Code (0x0009), Attribute Length = 16 (2 reserved bytes, 2 byte error code and 12 byte error phrase). */
        0x00, 0x09, 0x00, 0x10,
        /* Reserved = 0x0000, Error Class = 0, Error Number = 00 (Error Code = 0 Success). */
        0x00, 0x00, 0x00, 0x00,
        /* Error Phrase = "Error Phrase". */
        0x45, 0x72, 0x72, 0x6F,
        0x72, 0x20, 0x50, 0x68,
        0x72, 0x61, 0x73, 0x65,
        /* Attribute type = MESSAGE-INTEGRITY (0x0008), Length = 20 bytes. */
        0x00, 0x08, 0x00, 0x14,
        /* Attribute Value = HMAC value as computed by testHmacFxn_FixedFF. */
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        /* Attribute type = FINGERPRINT (0x8028), Length = 4 bytes. */
        0x80, 0x28, 0x00, 0x04,
        /* Attribute Value: 0x00000000 as calculated by testCrc32Fxn_Fixed. */
        0x00, 0x00, 0x00, 0x00
    };
    size_t stunMessageLength = sizeof( stunMessage );
    char longTermPassword[] = "LongTermPassword";
    size_t longTermPasswordLength = strlen( longTermPassword );

    /* Set CRC32 function to testCrc32Fxn_Fixed to make fingerprint always 0x00000000 */
    initInfo.cryptoFunctions.crc32Fxn = testCrc32Fxn_Fixed;
    /* Set CRC32 function to testHmacFxn_FixedFF to make integrity always 0xFF. */
    initInfo.cryptoFunctions.hmacFxn = testHmacFxn_FixedFF;
    initInfo.getCurrentTimeSecondsFxn = testGetCurrentTime_FixedZero;

    iceResult = Ice_Init( &( context ),
                          &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       iceResult );

    memset( &( localCandidate ),
            0,
            sizeof( IceCandidate_t ) );
    localCandidate.candidateType = ICE_CANDIDATE_TYPE_RELAY;
    localCandidate.state = ICE_CANDIDATE_STATE_VALID;
    context.numRelayExtensions = 1;
    localCandidate.pRelayExtension = &( context.pRelayExtensionsArray[ 0 ] );
    memcpy( localCandidate.pRelayExtension->iceRelayServerInfo.longTermPassword,
            longTermPassword,
            longTermPasswordLength );
    localCandidate.pRelayExtension->iceRelayServerInfo.longTermPasswordLength = longTermPasswordLength;

    context.numCandidatePairs = 2;
    memset( context.pCandidatePairs[ 0 ].transactionId, 0, STUN_HEADER_TRANSACTION_ID_LENGTH );
    memset( context.pCandidatePairs[ 1 ].transactionId, 0, STUN_HEADER_TRANSACTION_ID_LENGTH );
    context.pCandidatePairs[ 1 ].state = ICE_CANDIDATE_PAIR_STATE_CHANNEL_BIND;

    result = Ice_HandleStunPacket( &( context ),
                                   &( stunMessage[ 0 ] ),
                                   stunMessageLength,
                                   &( localCandidate ),
                                   &( remoteEndpoint ),
                                   &( pTransactionId ),
                                   &( pCandidatePair ) );

    TEST_ASSERT_EQUAL( ICE_HANDLE_STUN_PACKET_RESULT_CANDIDATE_PAIR_NOT_FOUND,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Ice_HandleStunPacket recieves a CHANNEL_BIND_ERROR_RESPONSE but
 * the password is missing while deserializing STUN packet.
 */
void test_iceHandleStunPacket_ChannelBindErrorResponse_DeserializeStunFail( void )
{
    IceContext_t context = { 0 };
    IceCandidate_t localCandidate = { 0 };
    IceEndpoint_t remoteEndpoint = { 0 };
    uint8_t * pTransactionId;
    IceCandidatePair_t * pCandidatePair = NULL;
    IceResult_t iceResult;
    IceHandleStunPacketResult_t result;
    uint8_t transactionID[] =
    {
        0xFF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B
    };
    uint8_t stunMessage[] =
    {
        /* STUN header: Message Type = CHANNEL_BIND_ERROR_RESPONSE (0x0119), Length = 52 bytes (excluding 20 bytes header). */
        0x01, 0x19, 0x00, 0x34,
        /* Magic Cookie (0x2112A442). */
        0x21, 0x12, 0xA4, 0x42,
        /* 12 bytes (96 bits) transaction ID which is same as transactionID above. */
        0xFF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
        /* Attribute Type = Error Code (0x0009), Attribute Length = 16 (2 reserved bytes, 2 byte error code and 12 byte error phrase). */
        0x00, 0x09, 0x00, 0x10,
        /* Reserved = 0x0000, Error Class = 0, Error Number = 00 (Error Code = 0 Success). */
        0x00, 0x00, 0x00, 0x00,
        /* Error Phrase = "Error Phrase". */
        0x45, 0x72, 0x72, 0x6F,
        0x72, 0x20, 0x50, 0x68,
        0x72, 0x61, 0x73, 0x65,
        /* Attribute type = MESSAGE-INTEGRITY (0x0008), Length = 20 bytes. */
        0x00, 0x08, 0x00, 0x14,
        /* Attribute Value = HMAC value as computed by testHmacFxn_FixedFF. */
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        /* Attribute type = FINGERPRINT (0x8028), Length = 4 bytes. */
        0x80, 0x28, 0x00, 0x04,
        /* Attribute Value: 0x00000000 as calculated by testCrc32Fxn_Fixed. */
        0x00, 0x00, 0x00, 0x00
    };
    size_t stunMessageLength = sizeof( stunMessage );

    /* Set CRC32 function to testCrc32Fxn_Fixed to make fingerprint always 0x00000000 */
    initInfo.cryptoFunctions.crc32Fxn = testCrc32Fxn_Fixed;
    /* Set CRC32 function to testHmacFxn_FixedFF to make integrity always 0xFF. */
    initInfo.cryptoFunctions.hmacFxn = testHmacFxn_FixedFF;
    initInfo.getCurrentTimeSecondsFxn = testGetCurrentTime_FixedZero;

    iceResult = Ice_Init( &( context ),
                          &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       iceResult );

    memset( &( localCandidate ),
            0,
            sizeof( IceCandidate_t ) );
    localCandidate.candidateType = ICE_CANDIDATE_TYPE_RELAY;
    localCandidate.state = ICE_CANDIDATE_STATE_VALID;
    context.numRelayExtensions = 1;
    localCandidate.pRelayExtension = &( context.pRelayExtensionsArray[ 0 ] );


    context.numCandidatePairs = 2;
    memset( context.pCandidatePairs[ 0 ].transactionId, 0, sizeof( transactionID ) );
    memcpy( context.pCandidatePairs[ 1 ].transactionId, transactionID, sizeof( transactionID ) );
    context.pCandidatePairs[ 1 ].state = ICE_CANDIDATE_PAIR_STATE_CHANNEL_BIND;

    result = Ice_HandleStunPacket( &( context ),
                                   &( stunMessage[ 0 ] ),
                                   stunMessageLength,
                                   &( localCandidate ),
                                   &( remoteEndpoint ),
                                   &( pTransactionId ),
                                   &( pCandidatePair ) );

    TEST_ASSERT_EQUAL( ICE_HANDLE_STUN_PACKET_RESULT_DESERIALIZE_ERROR,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Ice_HandleStunPacket recieves a CHANNEL_BIND_SUCCESS_RESPONSE and
 * the candidate pair is found in the ICE context.
 */
void test_iceHandleStunPacket_ChannelBindSuccessResponse_Pass( void )
{
    IceContext_t context = { 0 };
    IceCandidate_t localCandidate = { 0 };
    IceEndpoint_t remoteEndpoint = { 0 };
    uint8_t * pTransactionId;
    IceCandidatePair_t * pCandidatePair = NULL;
    IceResult_t iceResult;
    IceHandleStunPacketResult_t result;
    uint8_t transactionID[] =
    {
        0xFF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B
    };
    uint8_t stunMessage[] =
    {
        /* STUN header: Message Type = CHANNEL_BIND_SUCCESS_RESPONSE (0x0109), Length = 52 bytes (excluding 20 bytes header). */
        0x01, 0x09, 0x00, 0x34,
        /* Magic Cookie (0x2112A442). */
        0x21, 0x12, 0xA4, 0x42,
        /* 12 bytes (96 bits) transaction ID which is same as transactionID above. */
        0xFF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
        /* Attribute Type = Error Code (0x0009), Attribute Length = 16 (2 reserved bytes, 2 byte error code and 12 byte error phrase). */
        0x00, 0x09, 0x00, 0x10,
        /* Reserved = 0x0000, Error Class = 0, Error Number = 00 (Error Code = 0 Success). */
        0x00, 0x00, 0x00, 0x00,
        /* Error Phrase = "Error Phrase". */
        0x45, 0x72, 0x72, 0x6F,
        0x72, 0x20, 0x50, 0x68,
        0x72, 0x61, 0x73, 0x65,
        /* Attribute type = MESSAGE-INTEGRITY (0x0008), Length = 20 bytes. */
        0x00, 0x08, 0x00, 0x14,
        /* Attribute Value = HMAC value as computed by testHmacFxn_FixedFF. */
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        /* Attribute type = FINGERPRINT (0x8028), Length = 4 bytes. */
        0x80, 0x28, 0x00, 0x04,
        /* Attribute Value: 0x00000000 as calculated by testCrc32Fxn_Fixed. */
        0x00, 0x00, 0x00, 0x00
    };
    size_t stunMessageLength = sizeof( stunMessage );
    char longTermPassword[] = "LongTermPassword";
    size_t longTermPasswordLength = strlen( longTermPassword );

    /* Set CRC32 function to testCrc32Fxn_Fixed to make fingerprint always 0x00000000 */
    initInfo.cryptoFunctions.crc32Fxn = testCrc32Fxn_Fixed;
    /* Set CRC32 function to testHmacFxn_FixedFF to make integrity always 0xFF. */
    initInfo.cryptoFunctions.hmacFxn = testHmacFxn_FixedFF;
    initInfo.getCurrentTimeSecondsFxn = testGetCurrentTime_FixedZero;

    iceResult = Ice_Init( &( context ),
                          &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       iceResult );

    memset( &( localCandidate ),
            0,
            sizeof( IceCandidate_t ) );
    localCandidate.candidateType = ICE_CANDIDATE_TYPE_RELAY;
    localCandidate.state = ICE_CANDIDATE_STATE_VALID;
    context.numRelayExtensions = 1;
    localCandidate.pRelayExtension = &( context.pRelayExtensionsArray[ 0 ] );
    memcpy( localCandidate.pRelayExtension->iceRelayServerInfo.longTermPassword,
            longTermPassword,
            longTermPasswordLength );
    localCandidate.pRelayExtension->iceRelayServerInfo.longTermPasswordLength = longTermPasswordLength;

    context.numCandidatePairs = 2;
    memset( context.pCandidatePairs[ 0 ].transactionId, 0, sizeof( transactionID ) );
    memcpy( context.pCandidatePairs[ 1 ].transactionId, transactionID, sizeof( transactionID ) );
    context.pCandidatePairs[ 1 ].state = ICE_CANDIDATE_PAIR_STATE_CHANNEL_BIND;

    result = Ice_HandleStunPacket( &( context ),
                                   &( stunMessage[ 0 ] ),
                                   stunMessageLength,
                                   &( localCandidate ),
                                   &( remoteEndpoint ),
                                   &( pTransactionId ),
                                   &( pCandidatePair ) );

    TEST_ASSERT_EQUAL( ICE_HANDLE_STUN_PACKET_RESULT_SEND_CONNECTIVITY_BINDING_REQUEST,
                       result );
    TEST_ASSERT_EQUAL( ICE_CANDIDATE_PAIR_STATE_WAITING,
                       pCandidatePair->state );
}

/*-----------------------------------------------------------*/

/**
 * @brief Ice_HandleStunPacket recieves a CHANNEL_BIND_SUCCESS_RESPONSE but
 * it gets fail when generating transaction ID by calling random function.
 */
void test_iceHandleStunPacket_ChannelBindSuccessResponse_RandomFail( void )
{
    IceContext_t context = { 0 };
    IceCandidate_t localCandidate = { 0 };
    IceEndpoint_t remoteEndpoint = { 0 };
    uint8_t * pTransactionId;
    IceCandidatePair_t * pCandidatePair = NULL;
    IceResult_t iceResult;
    IceHandleStunPacketResult_t result;
    uint8_t transactionID[] =
    {
        0xFF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B
    };
    uint8_t stunMessage[] =
    {
        /* STUN header: Message Type = CHANNEL_BIND_SUCCESS_RESPONSE (0x0109), Length = 52 bytes (excluding 20 bytes header). */
        0x01, 0x09, 0x00, 0x34,
        /* Magic Cookie (0x2112A442). */
        0x21, 0x12, 0xA4, 0x42,
        /* 12 bytes (96 bits) transaction ID which is same as transactionID above. */
        0xFF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
        /* Attribute Type = Error Code (0x0009), Attribute Length = 16 (2 reserved bytes, 2 byte error code and 12 byte error phrase). */
        0x00, 0x09, 0x00, 0x10,
        /* Reserved = 0x0000, Error Class = 0, Error Number = 00 (Error Code = 0 Success). */
        0x00, 0x00, 0x00, 0x00,
        /* Error Phrase = "Error Phrase". */
        0x45, 0x72, 0x72, 0x6F,
        0x72, 0x20, 0x50, 0x68,
        0x72, 0x61, 0x73, 0x65,
        /* Attribute type = MESSAGE-INTEGRITY (0x0008), Length = 20 bytes. */
        0x00, 0x08, 0x00, 0x14,
        /* Attribute Value = HMAC value as computed by testHmacFxn_FixedFF. */
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        /* Attribute type = FINGERPRINT (0x8028), Length = 4 bytes. */
        0x80, 0x28, 0x00, 0x04,
        /* Attribute Value: 0x00000000 as calculated by testCrc32Fxn_Fixed. */
        0x00, 0x00, 0x00, 0x00
    };
    size_t stunMessageLength = sizeof( stunMessage );
    char longTermPassword[] = "LongTermPassword";
    size_t longTermPasswordLength = strlen( longTermPassword );

    /* Set CRC32 function to testCrc32Fxn_Fixed to make fingerprint always 0x00000000 */
    initInfo.cryptoFunctions.crc32Fxn = testCrc32Fxn_Fixed;
    /* Set CRC32 function to testHmacFxn_FixedFF to make integrity always 0xFF. */
    initInfo.cryptoFunctions.hmacFxn = testHmacFxn_FixedFF;
    initInfo.getCurrentTimeSecondsFxn = testGetCurrentTime_FixedZero;

    iceResult = Ice_Init( &( context ),
                          &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       iceResult );

    /* Ice uses random to generate tie breaker. So we overwrite it after init. */
    context.cryptoFunctions.randomFxn = testRandomFxn_Wrong;

    memset( &( localCandidate ),
            0,
            sizeof( IceCandidate_t ) );
    localCandidate.candidateType = ICE_CANDIDATE_TYPE_RELAY;
    localCandidate.state = ICE_CANDIDATE_STATE_VALID;
    context.numRelayExtensions = 1;
    localCandidate.pRelayExtension = &( context.pRelayExtensionsArray[ 0 ] );
    memcpy( localCandidate.pRelayExtension->iceRelayServerInfo.longTermPassword,
            longTermPassword,
            longTermPasswordLength );
    localCandidate.pRelayExtension->iceRelayServerInfo.longTermPasswordLength = longTermPasswordLength;

    context.numCandidatePairs = 2;
    memset( context.pCandidatePairs[ 0 ].transactionId, 0, sizeof( transactionID ) );
    memcpy( context.pCandidatePairs[ 1 ].transactionId, transactionID, sizeof( transactionID ) );
    context.pCandidatePairs[ 1 ].state = ICE_CANDIDATE_PAIR_STATE_CHANNEL_BIND;

    result = Ice_HandleStunPacket( &( context ),
                                   &( stunMessage[ 0 ] ),
                                   stunMessageLength,
                                   &( localCandidate ),
                                   &( remoteEndpoint ),
                                   &( pTransactionId ),
                                   &( pCandidatePair ) );

    TEST_ASSERT_EQUAL( ICE_HANDLE_STUN_PACKET_RESULT_RANDOM_ERROR_CODE,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Ice_HandleStunPacket recieves a CHANNEL_BIND_SUCCESS_RESPONSE but
 * the candidate pair state is not waiting for channel binding.
 */
void test_iceHandleStunPacket_ChannelBindSuccessResponse_StateNotBinding( void )
{
    IceContext_t context = { 0 };
    IceCandidate_t localCandidate = { 0 };
    IceEndpoint_t remoteEndpoint = { 0 };
    uint8_t * pTransactionId;
    IceCandidatePair_t * pCandidatePair = NULL;
    IceResult_t iceResult;
    IceHandleStunPacketResult_t result;
    uint8_t transactionID[] =
    {
        0xFF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B
    };
    uint8_t stunMessage[] =
    {
        /* STUN header: Message Type = CHANNEL_BIND_SUCCESS_RESPONSE (0x0109), Length = 52 bytes (excluding 20 bytes header). */
        0x01, 0x09, 0x00, 0x34,
        /* Magic Cookie (0x2112A442). */
        0x21, 0x12, 0xA4, 0x42,
        /* 12 bytes (96 bits) transaction ID which is same as transactionID above. */
        0xFF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
        /* Attribute Type = Error Code (0x0009), Attribute Length = 16 (2 reserved bytes, 2 byte error code and 12 byte error phrase). */
        0x00, 0x09, 0x00, 0x10,
        /* Reserved = 0x0000, Error Class = 0, Error Number = 00 (Error Code = 0 Success). */
        0x00, 0x00, 0x00, 0x00,
        /* Error Phrase = "Error Phrase". */
        0x45, 0x72, 0x72, 0x6F,
        0x72, 0x20, 0x50, 0x68,
        0x72, 0x61, 0x73, 0x65,
        /* Attribute type = MESSAGE-INTEGRITY (0x0008), Length = 20 bytes. */
        0x00, 0x08, 0x00, 0x14,
        /* Attribute Value = HMAC value as computed by testHmacFxn_FixedFF. */
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        /* Attribute type = FINGERPRINT (0x8028), Length = 4 bytes. */
        0x80, 0x28, 0x00, 0x04,
        /* Attribute Value: 0x00000000 as calculated by testCrc32Fxn_Fixed. */
        0x00, 0x00, 0x00, 0x00
    };
    size_t stunMessageLength = sizeof( stunMessage );
    char longTermPassword[] = "LongTermPassword";
    size_t longTermPasswordLength = strlen( longTermPassword );

    /* Set CRC32 function to testCrc32Fxn_Fixed to make fingerprint always 0x00000000 */
    initInfo.cryptoFunctions.crc32Fxn = testCrc32Fxn_Fixed;
    /* Set CRC32 function to testHmacFxn_FixedFF to make integrity always 0xFF. */
    initInfo.cryptoFunctions.hmacFxn = testHmacFxn_FixedFF;
    initInfo.getCurrentTimeSecondsFxn = testGetCurrentTime_FixedZero;

    iceResult = Ice_Init( &( context ),
                          &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       iceResult );

    memset( &( localCandidate ),
            0,
            sizeof( IceCandidate_t ) );
    localCandidate.candidateType = ICE_CANDIDATE_TYPE_RELAY;
    localCandidate.state = ICE_CANDIDATE_STATE_VALID;
    context.numRelayExtensions = 1;
    localCandidate.pRelayExtension = &( context.pRelayExtensionsArray[ 0 ] );
    memcpy( localCandidate.pRelayExtension->iceRelayServerInfo.longTermPassword,
            longTermPassword,
            longTermPasswordLength );
    localCandidate.pRelayExtension->iceRelayServerInfo.longTermPasswordLength = longTermPasswordLength;

    context.numCandidatePairs = 2;
    memset( context.pCandidatePairs[ 0 ].transactionId, 0, sizeof( transactionID ) );
    memcpy( context.pCandidatePairs[ 1 ].transactionId, transactionID, sizeof( transactionID ) );
    context.pCandidatePairs[ 1 ].state = ICE_CANDIDATE_PAIR_STATE_INVALID;

    result = Ice_HandleStunPacket( &( context ),
                                   &( stunMessage[ 0 ] ),
                                   stunMessageLength,
                                   &( localCandidate ),
                                   &( remoteEndpoint ),
                                   &( pTransactionId ),
                                   &( pCandidatePair ) );

    TEST_ASSERT_EQUAL( ICE_HANDLE_STUN_PACKET_RESULT_RELAY_CANDIDATE_PAIR_NOT_CHANNEL_BINDING,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Ice_HandleStunPacket recieves a CHANNEL_BIND_SUCCESS_RESPONSE but
 * no candidate pair has same transaction ID.
 */
void test_iceHandleStunPacket_ChannelBindSuccessResponse_CandidatePairNotFound( void )
{
    IceContext_t context = { 0 };
    IceCandidate_t localCandidate = { 0 };
    IceEndpoint_t remoteEndpoint = { 0 };
    uint8_t * pTransactionId;
    IceCandidatePair_t * pCandidatePair = NULL;
    IceResult_t iceResult;
    IceHandleStunPacketResult_t result;
    uint8_t stunMessage[] =
    {
        /* STUN header: Message Type = CHANNEL_BIND_SUCCESS_RESPONSE (0x0109), Length = 52 bytes (excluding 20 bytes header). */
        0x01, 0x09, 0x00, 0x34,
        /* Magic Cookie (0x2112A442). */
        0x21, 0x12, 0xA4, 0x42,
        /* 12 bytes (96 bits) transaction ID which is same as transactionID above. */
        0xFF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
        /* Attribute Type = Error Code (0x0009), Attribute Length = 16 (2 reserved bytes, 2 byte error code and 12 byte error phrase). */
        0x00, 0x09, 0x00, 0x10,
        /* Reserved = 0x0000, Error Class = 0, Error Number = 00 (Error Code = 0 Success). */
        0x00, 0x00, 0x00, 0x00,
        /* Error Phrase = "Error Phrase". */
        0x45, 0x72, 0x72, 0x6F,
        0x72, 0x20, 0x50, 0x68,
        0x72, 0x61, 0x73, 0x65,
        /* Attribute type = MESSAGE-INTEGRITY (0x0008), Length = 20 bytes. */
        0x00, 0x08, 0x00, 0x14,
        /* Attribute Value = HMAC value as computed by testHmacFxn_FixedFF. */
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        /* Attribute type = FINGERPRINT (0x8028), Length = 4 bytes. */
        0x80, 0x28, 0x00, 0x04,
        /* Attribute Value: 0x00000000 as calculated by testCrc32Fxn_Fixed. */
        0x00, 0x00, 0x00, 0x00
    };
    size_t stunMessageLength = sizeof( stunMessage );
    char longTermPassword[] = "LongTermPassword";
    size_t longTermPasswordLength = strlen( longTermPassword );

    /* Set CRC32 function to testCrc32Fxn_Fixed to make fingerprint always 0x00000000 */
    initInfo.cryptoFunctions.crc32Fxn = testCrc32Fxn_Fixed;
    /* Set CRC32 function to testHmacFxn_FixedFF to make integrity always 0xFF. */
    initInfo.cryptoFunctions.hmacFxn = testHmacFxn_FixedFF;
    initInfo.getCurrentTimeSecondsFxn = testGetCurrentTime_FixedZero;

    iceResult = Ice_Init( &( context ),
                          &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       iceResult );

    memset( &( localCandidate ),
            0,
            sizeof( IceCandidate_t ) );
    localCandidate.candidateType = ICE_CANDIDATE_TYPE_RELAY;
    localCandidate.state = ICE_CANDIDATE_STATE_VALID;
    context.numRelayExtensions = 1;
    localCandidate.pRelayExtension = &( context.pRelayExtensionsArray[ 0 ] );
    memcpy( localCandidate.pRelayExtension->iceRelayServerInfo.longTermPassword,
            longTermPassword,
            longTermPasswordLength );
    localCandidate.pRelayExtension->iceRelayServerInfo.longTermPasswordLength = longTermPasswordLength;

    context.numCandidatePairs = 2;
    memset( context.pCandidatePairs[ 0 ].transactionId, 0, STUN_HEADER_TRANSACTION_ID_LENGTH );
    memset( context.pCandidatePairs[ 1 ].transactionId, 0, STUN_HEADER_TRANSACTION_ID_LENGTH );
    context.pCandidatePairs[ 1 ].state = ICE_CANDIDATE_PAIR_STATE_CHANNEL_BIND;

    result = Ice_HandleStunPacket( &( context ),
                                   &( stunMessage[ 0 ] ),
                                   stunMessageLength,
                                   &( localCandidate ),
                                   &( remoteEndpoint ),
                                   &( pTransactionId ),
                                   &( pCandidatePair ) );

    TEST_ASSERT_EQUAL( ICE_HANDLE_STUN_PACKET_RESULT_CANDIDATE_PAIR_NOT_FOUND,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Ice_HandleStunPacket recieves a CHANNEL_BIND_SUCCESS_RESPONSE but
 * the error code is non-zero.
 */
void test_iceHandleStunPacket_ChannelBindSuccessResponse_NonZeroError( void )
{
    IceContext_t context = { 0 };
    IceCandidate_t localCandidate = { 0 };
    IceEndpoint_t remoteEndpoint = { 0 };
    uint8_t * pTransactionId;
    IceCandidatePair_t * pCandidatePair = NULL;
    IceResult_t iceResult;
    IceHandleStunPacketResult_t result;
    uint8_t stunMessage[] =
    {
        /* STUN header: Message Type = CHANNEL_BIND_SUCCESS_RESPONSE (0x0109), Length = 52 bytes (excluding 20 bytes header). */
        0x01, 0x09, 0x00, 0x34,
        /* Magic Cookie (0x2112A442). */
        0x21, 0x12, 0xA4, 0x42,
        /* 12 bytes (96 bits) transaction ID which is same as transactionID above. */
        0xFF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
        /* Attribute Type = Error Code (0x0009), Attribute Length = 16 (2 reserved bytes, 2 byte error code and 12 byte error phrase). */
        0x00, 0x09, 0x00, 0x10,
        /* Reserved = 0x0000, Error Class = 4, Error Number = 01 (Error Code = 401). */
        0x00, 0x00, 0x04, 0x01,
        /* Error Phrase = "Error Phrase". */
        0x45, 0x72, 0x72, 0x6F,
        0x72, 0x20, 0x50, 0x68,
        0x72, 0x61, 0x73, 0x65,
        /* Attribute type = MESSAGE-INTEGRITY (0x0008), Length = 20 bytes. */
        0x00, 0x08, 0x00, 0x14,
        /* Attribute Value = HMAC value as computed by testHmacFxn_FixedFF. */
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        /* Attribute type = FINGERPRINT (0x8028), Length = 4 bytes. */
        0x80, 0x28, 0x00, 0x04,
        /* Attribute Value: 0x00000000 as calculated by testCrc32Fxn_Fixed. */
        0x00, 0x00, 0x00, 0x00
    };
    size_t stunMessageLength = sizeof( stunMessage );
    char longTermPassword[] = "LongTermPassword";
    size_t longTermPasswordLength = strlen( longTermPassword );

    /* Set CRC32 function to testCrc32Fxn_Fixed to make fingerprint always 0x00000000 */
    initInfo.cryptoFunctions.crc32Fxn = testCrc32Fxn_Fixed;
    /* Set CRC32 function to testHmacFxn_FixedFF to make integrity always 0xFF. */
    initInfo.cryptoFunctions.hmacFxn = testHmacFxn_FixedFF;
    initInfo.getCurrentTimeSecondsFxn = testGetCurrentTime_FixedZero;

    iceResult = Ice_Init( &( context ),
                          &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       iceResult );

    memset( &( localCandidate ),
            0,
            sizeof( IceCandidate_t ) );
    localCandidate.candidateType = ICE_CANDIDATE_TYPE_RELAY;
    localCandidate.state = ICE_CANDIDATE_STATE_VALID;
    context.numRelayExtensions = 1;
    localCandidate.pRelayExtension = &( context.pRelayExtensionsArray[ 0 ] );
    memcpy( localCandidate.pRelayExtension->iceRelayServerInfo.longTermPassword,
            longTermPassword,
            longTermPasswordLength );
    localCandidate.pRelayExtension->iceRelayServerInfo.longTermPasswordLength = longTermPasswordLength;

    result = Ice_HandleStunPacket( &( context ),
                                   &( stunMessage[ 0 ] ),
                                   stunMessageLength,
                                   &( localCandidate ),
                                   &( remoteEndpoint ),
                                   &( pTransactionId ),
                                   &( pCandidatePair ) );

    TEST_ASSERT_EQUAL( ICE_HANDLE_STUN_PACKET_RESULT_NON_ZERO_ERROR_CODE,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Ice_HandleStunPacket recieves a CHANNEL_BIND_SUCCESS_RESPONSE but
 * the password is missing while deserializing STUN packet.
 */
void test_iceHandleStunPacket_ChannelBindSuccessResponse_DeserializeStunFail( void )
{
    IceContext_t context = { 0 };
    IceCandidate_t localCandidate = { 0 };
    IceEndpoint_t remoteEndpoint = { 0 };
    uint8_t * pTransactionId;
    IceCandidatePair_t * pCandidatePair = NULL;
    IceResult_t iceResult;
    IceHandleStunPacketResult_t result;
    uint8_t stunMessage[] =
    {
        /* STUN header: Message Type = CHANNEL_BIND_SUCCESS_RESPONSE (0x0109), Length = 52 bytes (excluding 20 bytes header). */
        0x01, 0x09, 0x00, 0x34,
        /* Magic Cookie (0x2112A442). */
        0x21, 0x12, 0xA4, 0x42,
        /* 12 bytes (96 bits) transaction ID which is same as transactionID above. */
        0xFF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
        /* Attribute Type = Error Code (0x0009), Attribute Length = 16 (2 reserved bytes, 2 byte error code and 12 byte error phrase). */
        0x00, 0x09, 0x00, 0x10,
        /* Reserved = 0x0000, Error Class = 0, Error Number = 00 (Error Code = 0 Success). */
        0x00, 0x00, 0x00, 0x00,
        /* Error Phrase = "Error Phrase". */
        0x45, 0x72, 0x72, 0x6F,
        0x72, 0x20, 0x50, 0x68,
        0x72, 0x61, 0x73, 0x65,
        /* Attribute type = MESSAGE-INTEGRITY (0x0008), Length = 20 bytes. */
        0x00, 0x08, 0x00, 0x14,
        /* Attribute Value = HMAC value as computed by testHmacFxn_FixedFF. */
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        /* Attribute type = FINGERPRINT (0x8028), Length = 4 bytes. */
        0x80, 0x28, 0x00, 0x04,
        /* Attribute Value: 0x00000000 as calculated by testCrc32Fxn_Fixed. */
        0x00, 0x00, 0x00, 0x00
    };
    size_t stunMessageLength = sizeof( stunMessage );

    /* Set CRC32 function to testCrc32Fxn_Fixed to make fingerprint always 0x00000000 */
    initInfo.cryptoFunctions.crc32Fxn = testCrc32Fxn_Fixed;
    /* Set CRC32 function to testHmacFxn_FixedFF to make integrity always 0xFF. */
    initInfo.cryptoFunctions.hmacFxn = testHmacFxn_FixedFF;
    initInfo.getCurrentTimeSecondsFxn = testGetCurrentTime_FixedZero;

    iceResult = Ice_Init( &( context ),
                          &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       iceResult );

    localCandidate.candidateType = ICE_CANDIDATE_TYPE_RELAY;
    context.numRelayExtensions = 1;
    localCandidate.pRelayExtension = &( context.pRelayExtensionsArray[ 0 ] );

    result = Ice_HandleStunPacket( &( context ),
                                   &( stunMessage[ 0 ] ),
                                   stunMessageLength,
                                   &( localCandidate ),
                                   &( remoteEndpoint ),
                                   &( pTransactionId ),
                                   &( pCandidatePair ) );

    TEST_ASSERT_EQUAL( ICE_HANDLE_STUN_PACKET_RESULT_DESERIALIZE_ERROR,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Ice_HandleStunPacket recieves a REFRESH_ERROR_RESPONSE and
 * the candidate is found in the ICE context with error code Authorized.
 */
void test_iceHandleStunPacket_RefreshErrorResponse_Pass_ErrorUnauthorized( void )
{
    IceContext_t context = { 0 };
    IceCandidate_t localCandidate = { 0 };
    IceEndpoint_t remoteEndpoint = { 0 };
    uint8_t * pTransactionId;
    IceCandidatePair_t * pCandidatePair = NULL;
    IceResult_t iceResult;
    IceHandleStunPacketResult_t result;
    uint8_t transactionID[] =
    {
        0xFF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B
    };
    uint8_t stunMessage[] =
    {
        /* STUN header: Message Type = REFRESH_ERROR_RESPONSE (0x0114), Length = 60 bytes (excluding 20 bytes header). */
        0x01, 0x14, 0x00, 0x3C,
        /* Magic Cookie (0x2112A442). */
        0x21, 0x12, 0xA4, 0x42,
        /* 12 bytes (96 bits) transaction ID which is same as transactionID above. */
        0xFF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
        /* Attribute Type = Error Code (0x0009), Attribute Length = 16 (2 reserved bytes, 2 byte error code and 12 byte error phrase). */
        0x00, 0x09, 0x00, 0x10,
        /* Reserved = 0x0000, Error Class = 4, Error Number = 01 (Error Code = 401 Unauthorized). */
        0x00, 0x00, 0x04, 0x01,
        /* Error Phrase = "Error Phrase". */
        0x45, 0x72, 0x72, 0x6F,
        0x72, 0x20, 0x50, 0x68,
        0x72, 0x61, 0x73, 0x65,
        /* Attribute type = REALM (0x0014), Length = 5 bytes. */
        0x00, 0x14, 0x00, 0x05,
        /* Attribute Value: "realm". */
        0x72, 0x65, 0x61, 0x6C,
        0x6D, 0x00, 0x00, 0x00,
        /* Attribute type = NONCE (0x0015), Length = 5 bytes. */
        0x00, 0x15, 0x00, 0x05,
        /* Attribute Value: "nonce". */
        0x6E, 0x6F, 0x6E, 0x63,
        0x65, 0x00, 0x00, 0x00,
        /* Attribute type = LIFETIME (0x000D), Length = 4 bytes. */
        0x00, 0x0D, 0x00, 0x04,
        /* Attribute Value: 0. */
        0x00, 0x00, 0x00, 0x00,
        /* Attribute type = FINGERPRINT (0x8028), Length = 4 bytes. */
        0x80, 0x28, 0x00, 0x04,
        /* Attribute Value: 0x00000000 as calculated by testCrc32Fxn_Fixed. */
        0x00, 0x00, 0x00, 0x00
    };
    size_t stunMessageLength = sizeof( stunMessage );
    char * pUsername = "username";
    size_t usernameLength = strlen( pUsername );
    char * pPassword = "password";
    size_t passwordLength = strlen( pPassword );
    char * pRealm = "realm";
    size_t realmLength = strlen( pRealm );
    char * pNonce = "nonce";
    size_t nonceLength = strlen( pNonce );
    char longTermPassword[] = "LongTermPassword";
    size_t longTermPasswordLength = strlen( longTermPassword );
    char * pPreLongTermPassword = "username:realm:password"; /* Follow https://datatracker.ietf.org/doc/html/rfc5389#section-15.4. */
    size_t preLongTermPasswordLength = strlen( pPreLongTermPassword );
    uint16_t expectedLongTermPasswordLength = 16; /* It's always 16 bytes as MD5 result. */
    uint8_t pExpectedLongTermPassword[ expectedLongTermPasswordLength ];

    /* Set CRC32 function to testCrc32Fxn_Fixed to make fingerprint always 0x00000000 */
    initInfo.cryptoFunctions.crc32Fxn = testCrc32Fxn_Fixed;
    /* Set CRC32 function to testHmacFxn_FixedFF to make integrity always 0xFF. */
    initInfo.cryptoFunctions.hmacFxn = testHmacFxn_FixedFF;
    initInfo.getCurrentTimeSecondsFxn = testGetCurrentTime_FixedZero;

    iceResult = Ice_Init( &( context ),
                          &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       iceResult );

    memset( &( localCandidate ),
            0,
            sizeof( IceCandidate_t ) );
    localCandidate.candidateType = ICE_CANDIDATE_TYPE_RELAY;
    localCandidate.state = ICE_CANDIDATE_STATE_VALID;
    context.numRelayExtensions = 1;
    localCandidate.pRelayExtension = &( context.pRelayExtensionsArray[ 0 ] );
    memcpy( localCandidate.pRelayExtension->iceRelayServerInfo.longTermPassword,
            longTermPassword,
            longTermPasswordLength );
    localCandidate.pRelayExtension->iceRelayServerInfo.longTermPasswordLength = longTermPasswordLength;
    memcpy( &localCandidate.pRelayExtension->iceRelayServerInfo.userName, pUsername, usernameLength );
    localCandidate.pRelayExtension->iceRelayServerInfo.userNameLength = usernameLength;
    memcpy( &localCandidate.pRelayExtension->iceRelayServerInfo.password, pPassword, passwordLength );
    localCandidate.pRelayExtension->iceRelayServerInfo.passwordLength = passwordLength;
    memcpy( &localCandidate.pRelayExtension->iceRelayServerInfo.realm, pRealm, realmLength );
    localCandidate.pRelayExtension->iceRelayServerInfo.realmLength = realmLength;
    memcpy( &localCandidate.pRelayExtension->iceRelayServerInfo.nonce, pNonce, nonceLength );
    localCandidate.pRelayExtension->iceRelayServerInfo.nonceLength = nonceLength;

    memcpy( &( localCandidate.transactionId[ 0 ] ),
            &( transactionID[ 0 ] ),
            sizeof( transactionID ) );

    /* Prepare expected long term password by calling testMd5 API. */
    ( void ) testMd5Fxn( ( const uint8_t * ) pPreLongTermPassword,
                         preLongTermPasswordLength,
                         pExpectedLongTermPassword,
                         &expectedLongTermPasswordLength );

    result = Ice_HandleStunPacket( &( context ),
                                   &( stunMessage[ 0 ] ),
                                   stunMessageLength,
                                   &( localCandidate ),
                                   &( remoteEndpoint ),
                                   &( pTransactionId ),
                                   &( pCandidatePair ) );

    TEST_ASSERT_EQUAL( ICE_HANDLE_STUN_PACKET_RESULT_OK,
                       result );
    TEST_ASSERT_EQUAL( nonceLength,
                       localCandidate.pRelayExtension->iceRelayServerInfo.nonceLength );
    TEST_ASSERT_EQUAL_UINT8_ARRAY( pNonce,
                                   localCandidate.pRelayExtension->iceRelayServerInfo.nonce,
                                   nonceLength );
    TEST_ASSERT_EQUAL( realmLength,
                       localCandidate.pRelayExtension->iceRelayServerInfo.realmLength );
    TEST_ASSERT_EQUAL_UINT8_ARRAY( pRealm,
                                   localCandidate.pRelayExtension->iceRelayServerInfo.realm,
                                   realmLength );
    TEST_ASSERT_EQUAL( expectedLongTermPasswordLength,
                       localCandidate.pRelayExtension->iceRelayServerInfo.longTermPasswordLength );
    TEST_ASSERT_EQUAL_UINT8_ARRAY( pExpectedLongTermPassword,
                                   localCandidate.pRelayExtension->iceRelayServerInfo.longTermPassword,
                                   expectedLongTermPasswordLength );
}

/*-----------------------------------------------------------*/

/**
 * @brief Ice_HandleStunPacket recieves a REFRESH_ERROR_RESPONSE and
 * the candidate is found in the ICE context with error code Stale Nonce.
 */
void test_iceHandleStunPacket_RefreshErrorResponse_Pass_ErrorStaleNonce( void )
{
    IceContext_t context = { 0 };
    IceCandidate_t localCandidate = { 0 };
    IceEndpoint_t remoteEndpoint = { 0 };
    uint8_t * pTransactionId;
    IceCandidatePair_t * pCandidatePair = NULL;
    IceResult_t iceResult;
    IceHandleStunPacketResult_t result;
    uint8_t transactionID[] =
    {
        0xFF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B
    };
    uint8_t stunMessage[] =
    {
        /* STUN header: Message Type = REFRESH_ERROR_RESPONSE (0x0114), Length = 60 bytes (excluding 20 bytes header). */
        0x01, 0x14, 0x00, 0x3C,
        /* Magic Cookie (0x2112A442). */
        0x21, 0x12, 0xA4, 0x42,
        /* 12 bytes (96 bits) transaction ID which is same as transactionID above. */
        0xFF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
        /* Attribute Type = Error Code (0x0009), Attribute Length = 16 (2 reserved bytes, 2 byte error code and 12 byte error phrase). */
        0x00, 0x09, 0x00, 0x10,
        /* Reserved = 0x0000, Error Class = 4, Error Number = 01 (Error Code = 438 Stale Nonce). */
        0x00, 0x00, 0x04, 0x26,
        /* Error Phrase = "Error Phrase". */
        0x45, 0x72, 0x72, 0x6F,
        0x72, 0x20, 0x50, 0x68,
        0x72, 0x61, 0x73, 0x65,
        /* Attribute type = REALM (0x0014), Length = 5 bytes. */
        0x00, 0x14, 0x00, 0x05,
        /* Attribute Value: "realm". */
        0x72, 0x65, 0x61, 0x6C,
        0x6D, 0x00, 0x00, 0x00,
        /* Attribute type = NONCE (0x0015), Length = 5 bytes. */
        0x00, 0x15, 0x00, 0x05,
        /* Attribute Value: "nonce". */
        0x6E, 0x6F, 0x6E, 0x63,
        0x65, 0x00, 0x00, 0x00,
        /* Attribute type = LIFETIME (0x000D), Length = 4 bytes. */
        0x00, 0x0D, 0x00, 0x04,
        /* Attribute Value: 0. */
        0x00, 0x00, 0x00, 0x00,
        /* Attribute type = FINGERPRINT (0x8028), Length = 4 bytes. */
        0x80, 0x28, 0x00, 0x04,
        /* Attribute Value: 0x00000000 as calculated by testCrc32Fxn_Fixed. */
        0x00, 0x00, 0x00, 0x00
    };
    size_t stunMessageLength = sizeof( stunMessage );
    char * pUsername = "username";
    size_t usernameLength = strlen( pUsername );
    char * pPassword = "password";
    size_t passwordLength = strlen( pPassword );
    char * pRealm = "realm";
    size_t realmLength = strlen( pRealm );
    char * pNonce = "nonce";
    size_t nonceLength = strlen( pNonce );
    char longTermPassword[] = "LongTermPassword";
    size_t longTermPasswordLength = strlen( longTermPassword );
    char * pPreLongTermPassword = "username:realm:password"; /* Follow https://datatracker.ietf.org/doc/html/rfc5389#section-15.4. */
    size_t preLongTermPasswordLength = strlen( pPreLongTermPassword );
    uint16_t expectedLongTermPasswordLength = 16; /* It's always 16 bytes as MD5 result. */
    uint8_t pExpectedLongTermPassword[ expectedLongTermPasswordLength ];

    /* Set CRC32 function to testCrc32Fxn_Fixed to make fingerprint always 0x00000000 */
    initInfo.cryptoFunctions.crc32Fxn = testCrc32Fxn_Fixed;
    /* Set CRC32 function to testHmacFxn_FixedFF to make integrity always 0xFF. */
    initInfo.cryptoFunctions.hmacFxn = testHmacFxn_FixedFF;
    initInfo.getCurrentTimeSecondsFxn = testGetCurrentTime_FixedZero;

    iceResult = Ice_Init( &( context ),
                          &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       iceResult );

    memset( &( localCandidate ),
            0,
            sizeof( IceCandidate_t ) );
    localCandidate.candidateType = ICE_CANDIDATE_TYPE_RELAY;
    localCandidate.state = ICE_CANDIDATE_STATE_VALID;
    context.numRelayExtensions = 1;
    localCandidate.pRelayExtension = &( context.pRelayExtensionsArray[ 0 ] );
    memcpy( localCandidate.pRelayExtension->iceRelayServerInfo.longTermPassword,
            longTermPassword,
            longTermPasswordLength );
    localCandidate.pRelayExtension->iceRelayServerInfo.longTermPasswordLength = longTermPasswordLength;
    memcpy( &localCandidate.pRelayExtension->iceRelayServerInfo.userName, pUsername, usernameLength );
    localCandidate.pRelayExtension->iceRelayServerInfo.userNameLength = usernameLength;
    memcpy( &localCandidate.pRelayExtension->iceRelayServerInfo.password, pPassword, passwordLength );
    localCandidate.pRelayExtension->iceRelayServerInfo.passwordLength = passwordLength;
    memcpy( &localCandidate.pRelayExtension->iceRelayServerInfo.realm, pRealm, realmLength );
    localCandidate.pRelayExtension->iceRelayServerInfo.realmLength = realmLength;
    memcpy( &localCandidate.pRelayExtension->iceRelayServerInfo.nonce, pNonce, nonceLength );
    localCandidate.pRelayExtension->iceRelayServerInfo.nonceLength = nonceLength;

    memcpy( &( localCandidate.transactionId[ 0 ] ),
            &( transactionID[ 0 ] ),
            sizeof( transactionID ) );

    /* Prepare expected long term password by calling testMd5 API. */
    ( void ) testMd5Fxn( ( const uint8_t * ) pPreLongTermPassword,
                         preLongTermPasswordLength,
                         pExpectedLongTermPassword,
                         &expectedLongTermPasswordLength );

    result = Ice_HandleStunPacket( &( context ),
                                   &( stunMessage[ 0 ] ),
                                   stunMessageLength,
                                   &( localCandidate ),
                                   &( remoteEndpoint ),
                                   &( pTransactionId ),
                                   &( pCandidatePair ) );

    TEST_ASSERT_EQUAL( ICE_HANDLE_STUN_PACKET_RESULT_OK,
                       result );
    TEST_ASSERT_EQUAL( nonceLength,
                       localCandidate.pRelayExtension->iceRelayServerInfo.nonceLength );
    TEST_ASSERT_EQUAL_UINT8_ARRAY( pNonce,
                                   localCandidate.pRelayExtension->iceRelayServerInfo.nonce,
                                   nonceLength );
    TEST_ASSERT_EQUAL( realmLength,
                       localCandidate.pRelayExtension->iceRelayServerInfo.realmLength );
    TEST_ASSERT_EQUAL_UINT8_ARRAY( pRealm,
                                   localCandidate.pRelayExtension->iceRelayServerInfo.realm,
                                   realmLength );
    TEST_ASSERT_EQUAL( expectedLongTermPasswordLength,
                       localCandidate.pRelayExtension->iceRelayServerInfo.longTermPasswordLength );
    TEST_ASSERT_EQUAL_UINT8_ARRAY( pExpectedLongTermPassword,
                                   localCandidate.pRelayExtension->iceRelayServerInfo.longTermPassword,
                                   expectedLongTermPasswordLength );
}

/*-----------------------------------------------------------*/

/**
 * @brief Ice_HandleStunPacket recieves a REFRESH_ERROR_RESPONSE and
 * the candidate is found in the ICE context with unknown error code.
 */
void test_iceHandleStunPacket_RefreshErrorResponse_UnknownError( void )
{
    IceContext_t context = { 0 };
    IceCandidate_t localCandidate = { 0 };
    IceEndpoint_t remoteEndpoint = { 0 };
    uint8_t * pTransactionId;
    IceCandidatePair_t * pCandidatePair = NULL;
    IceResult_t iceResult;
    IceHandleStunPacketResult_t result;
    uint8_t transactionID[] =
    {
        0xFF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B
    };
    uint8_t stunMessage[] =
    {
        /* STUN header: Message Type = REFRESH_ERROR_RESPONSE (0x0114), Length = 60 bytes (excluding 20 bytes header). */
        0x01, 0x14, 0x00, 0x3C,
        /* Magic Cookie (0x2112A442). */
        0x21, 0x12, 0xA4, 0x42,
        /* 12 bytes (96 bits) transaction ID which is same as transactionID above. */
        0xFF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
        /* Attribute Type = Error Code (0x0009), Attribute Length = 16 (2 reserved bytes, 2 byte error code and 12 byte error phrase). */
        0x00, 0x09, 0x00, 0x10,
        /* Reserved = 0x0000, Error Class = 4, Error Number = 00 (Error Code = 400 Unknown). */
        0x00, 0x00, 0x04, 0x00,
        /* Error Phrase = "Error Phrase". */
        0x45, 0x72, 0x72, 0x6F,
        0x72, 0x20, 0x50, 0x68,
        0x72, 0x61, 0x73, 0x65,
        /* Attribute type = REALM (0x0014), Length = 5 bytes. */
        0x00, 0x14, 0x00, 0x05,
        /* Attribute Value: "realm". */
        0x72, 0x65, 0x61, 0x6C,
        0x6D, 0x00, 0x00, 0x00,
        /* Attribute type = NONCE (0x0015), Length = 5 bytes. */
        0x00, 0x15, 0x00, 0x05,
        /* Attribute Value: "nonce". */
        0x6E, 0x6F, 0x6E, 0x63,
        0x65, 0x00, 0x00, 0x00,
        /* Attribute type = LIFETIME (0x000D), Length = 4 bytes. */
        0x00, 0x0D, 0x00, 0x04,
        /* Attribute Value: 0. */
        0x00, 0x00, 0x00, 0x00,
        /* Attribute type = FINGERPRINT (0x8028), Length = 4 bytes. */
        0x80, 0x28, 0x00, 0x04,
        /* Attribute Value: 0x00000000 as calculated by testCrc32Fxn_Fixed. */
        0x00, 0x00, 0x00, 0x00
    };
    size_t stunMessageLength = sizeof( stunMessage );
    char * pUsername = "username";
    size_t usernameLength = strlen( pUsername );
    char * pPassword = "password";
    size_t passwordLength = strlen( pPassword );
    char * pRealm = "realm";
    size_t realmLength = strlen( pRealm );
    char * pNonce = "nonce";
    size_t nonceLength = strlen( pNonce );
    char longTermPassword[] = "LongTermPassword";
    size_t longTermPasswordLength = strlen( longTermPassword );
    char * pPreLongTermPassword = "username:realm:password"; /* Follow https://datatracker.ietf.org/doc/html/rfc5389#section-15.4. */
    size_t preLongTermPasswordLength = strlen( pPreLongTermPassword );
    uint16_t expectedLongTermPasswordLength = 16; /* It's always 16 bytes as MD5 result. */
    uint8_t pExpectedLongTermPassword[ expectedLongTermPasswordLength ];

    /* Set CRC32 function to testCrc32Fxn_Fixed to make fingerprint always 0x00000000 */
    initInfo.cryptoFunctions.crc32Fxn = testCrc32Fxn_Fixed;
    /* Set CRC32 function to testHmacFxn_FixedFF to make integrity always 0xFF. */
    initInfo.cryptoFunctions.hmacFxn = testHmacFxn_FixedFF;
    initInfo.getCurrentTimeSecondsFxn = testGetCurrentTime_FixedZero;

    iceResult = Ice_Init( &( context ),
                          &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       iceResult );

    memset( &( localCandidate ),
            0,
            sizeof( IceCandidate_t ) );
    localCandidate.candidateType = ICE_CANDIDATE_TYPE_RELAY;
    localCandidate.state = ICE_CANDIDATE_STATE_VALID;
    context.numRelayExtensions = 1;
    localCandidate.pRelayExtension = &( context.pRelayExtensionsArray[ 0 ] );
    memcpy( localCandidate.pRelayExtension->iceRelayServerInfo.longTermPassword,
            longTermPassword,
            longTermPasswordLength );
    localCandidate.pRelayExtension->iceRelayServerInfo.longTermPasswordLength = longTermPasswordLength;
    memcpy( &localCandidate.pRelayExtension->iceRelayServerInfo.userName, pUsername, usernameLength );
    localCandidate.pRelayExtension->iceRelayServerInfo.userNameLength = usernameLength;
    memcpy( &localCandidate.pRelayExtension->iceRelayServerInfo.password, pPassword, passwordLength );
    localCandidate.pRelayExtension->iceRelayServerInfo.passwordLength = passwordLength;
    memcpy( &localCandidate.pRelayExtension->iceRelayServerInfo.realm, pRealm, realmLength );
    localCandidate.pRelayExtension->iceRelayServerInfo.realmLength = realmLength;
    memcpy( &localCandidate.pRelayExtension->iceRelayServerInfo.nonce, pNonce, nonceLength );
    localCandidate.pRelayExtension->iceRelayServerInfo.nonceLength = nonceLength;

    memcpy( &( localCandidate.transactionId[ 0 ] ),
            &( transactionID[ 0 ] ),
            sizeof( transactionID ) );

    /* Prepare expected long term password by calling testMd5 API. */
    ( void ) testMd5Fxn( ( const uint8_t * ) pPreLongTermPassword,
                         preLongTermPasswordLength,
                         pExpectedLongTermPassword,
                         &expectedLongTermPasswordLength );

    result = Ice_HandleStunPacket( &( context ),
                                   &( stunMessage[ 0 ] ),
                                   stunMessageLength,
                                   &( localCandidate ),
                                   &( remoteEndpoint ),
                                   &( pTransactionId ),
                                   &( pCandidatePair ) );

    TEST_ASSERT_EQUAL( ICE_HANDLE_STUN_PACKET_RESULT_REFRESH_UNKNOWN_ERROR,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Ice_HandleStunPacket recieves a REFRESH_ERROR_RESPONSE and
 * the error code in STUN message is zero.
 */
void test_iceHandleStunPacket_RefreshErrorResponse_ZeroError( void )
{
    IceContext_t context = { 0 };
    IceCandidate_t localCandidate = { 0 };
    IceEndpoint_t remoteEndpoint = { 0 };
    uint8_t * pTransactionId;
    IceCandidatePair_t * pCandidatePair = NULL;
    IceResult_t iceResult;
    IceHandleStunPacketResult_t result;
    uint8_t transactionID[] =
    {
        0xFF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B
    };
    uint8_t stunMessage[] =
    {
        /* STUN header: Message Type = REFRESH_ERROR_RESPONSE (0x0114), Length = 60 bytes (excluding 20 bytes header). */
        0x01, 0x14, 0x00, 0x3C,
        /* Magic Cookie (0x2112A442). */
        0x21, 0x12, 0xA4, 0x42,
        /* 12 bytes (96 bits) transaction ID which is same as transactionID above. */
        0xFF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
        /* Attribute Type = Error Code (0x0009), Attribute Length = 16 (2 reserved bytes, 2 byte error code and 12 byte error phrase). */
        0x00, 0x09, 0x00, 0x10,
        /* Reserved = 0x0000, Error Class = 0, Error Number = 01 (Error Code = 0 Success). */
        0x00, 0x00, 0x00, 0x00,
        /* Error Phrase = "Error Phrase". */
        0x45, 0x72, 0x72, 0x6F,
        0x72, 0x20, 0x50, 0x68,
        0x72, 0x61, 0x73, 0x65,
        /* Attribute type = REALM (0x0014), Length = 5 bytes. */
        0x00, 0x14, 0x00, 0x05,
        /* Attribute Value: "realm". */
        0x72, 0x65, 0x61, 0x6C,
        0x6D, 0x00, 0x00, 0x00,
        /* Attribute type = NONCE (0x0015), Length = 5 bytes. */
        0x00, 0x15, 0x00, 0x05,
        /* Attribute Value: "nonce". */
        0x6E, 0x6F, 0x6E, 0x63,
        0x65, 0x00, 0x00, 0x00,
        /* Attribute type = LIFETIME (0x000D), Length = 4 bytes. */
        0x00, 0x0D, 0x00, 0x04,
        /* Attribute Value: 0. */
        0x00, 0x00, 0x00, 0x00,
        /* Attribute type = FINGERPRINT (0x8028), Length = 4 bytes. */
        0x80, 0x28, 0x00, 0x04,
        /* Attribute Value: 0x00000000 as calculated by testCrc32Fxn_Fixed. */
        0x00, 0x00, 0x00, 0x00
    };
    size_t stunMessageLength = sizeof( stunMessage );
    char * pUsername = "username";
    size_t usernameLength = strlen( pUsername );
    char * pPassword = "password";
    size_t passwordLength = strlen( pPassword );
    char * pRealm = "realm";
    size_t realmLength = strlen( pRealm );
    char * pNonce = "nonce";
    size_t nonceLength = strlen( pNonce );
    char longTermPassword[] = "LongTermPassword";
    size_t longTermPasswordLength = strlen( longTermPassword );
    char * pPreLongTermPassword = "username:realm:password"; /* Follow https://datatracker.ietf.org/doc/html/rfc5389#section-15.4. */
    size_t preLongTermPasswordLength = strlen( pPreLongTermPassword );
    uint16_t expectedLongTermPasswordLength = 16; /* It's always 16 bytes as MD5 result. */
    uint8_t pExpectedLongTermPassword[ expectedLongTermPasswordLength ];

    /* Set CRC32 function to testCrc32Fxn_Fixed to make fingerprint always 0x00000000 */
    initInfo.cryptoFunctions.crc32Fxn = testCrc32Fxn_Fixed;
    /* Set CRC32 function to testHmacFxn_FixedFF to make integrity always 0xFF. */
    initInfo.cryptoFunctions.hmacFxn = testHmacFxn_FixedFF;
    initInfo.getCurrentTimeSecondsFxn = testGetCurrentTime_FixedZero;

    iceResult = Ice_Init( &( context ),
                          &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       iceResult );

    memset( &( localCandidate ),
            0,
            sizeof( IceCandidate_t ) );
    localCandidate.candidateType = ICE_CANDIDATE_TYPE_RELAY;
    localCandidate.state = ICE_CANDIDATE_STATE_VALID;
    context.numRelayExtensions = 1;
    localCandidate.pRelayExtension = &( context.pRelayExtensionsArray[ 0 ] );
    memcpy( localCandidate.pRelayExtension->iceRelayServerInfo.longTermPassword,
            longTermPassword,
            longTermPasswordLength );
    localCandidate.pRelayExtension->iceRelayServerInfo.longTermPasswordLength = longTermPasswordLength;
    memcpy( &localCandidate.pRelayExtension->iceRelayServerInfo.userName, pUsername, usernameLength );
    localCandidate.pRelayExtension->iceRelayServerInfo.userNameLength = usernameLength;
    memcpy( &localCandidate.pRelayExtension->iceRelayServerInfo.password, pPassword, passwordLength );
    localCandidate.pRelayExtension->iceRelayServerInfo.passwordLength = passwordLength;
    memcpy( &localCandidate.pRelayExtension->iceRelayServerInfo.realm, pRealm, realmLength );
    localCandidate.pRelayExtension->iceRelayServerInfo.realmLength = realmLength;
    memcpy( &localCandidate.pRelayExtension->iceRelayServerInfo.nonce, pNonce, nonceLength );
    localCandidate.pRelayExtension->iceRelayServerInfo.nonceLength = nonceLength;

    memcpy( &( localCandidate.transactionId[ 0 ] ),
            &( transactionID[ 0 ] ),
            sizeof( transactionID ) );

    /* Prepare expected long term password by calling testMd5 API. */
    ( void ) testMd5Fxn( ( const uint8_t * ) pPreLongTermPassword,
                         preLongTermPasswordLength,
                         pExpectedLongTermPassword,
                         &expectedLongTermPasswordLength );

    result = Ice_HandleStunPacket( &( context ),
                                   &( stunMessage[ 0 ] ),
                                   stunMessageLength,
                                   &( localCandidate ),
                                   &( remoteEndpoint ),
                                   &( pTransactionId ),
                                   &( pCandidatePair ) );

    TEST_ASSERT_EQUAL( ICE_HANDLE_STUN_PACKET_RESULT_FRESH_COMPLETE,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Ice_HandleStunPacket recieves a REFRESH_ERROR_RESPONSE but
 * the fingerprint in STUN packet is wrong.
 */
void test_iceHandleStunPacket_RefreshErrorResponse_DeserializeStunFail( void )
{
    IceContext_t context = { 0 };
    IceCandidate_t localCandidate = { 0 };
    IceEndpoint_t remoteEndpoint = { 0 };
    uint8_t * pTransactionId;
    IceCandidatePair_t * pCandidatePair = NULL;
    IceResult_t iceResult;
    IceHandleStunPacketResult_t result;
    uint8_t transactionID[] =
    {
        0xFF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B
    };
    uint8_t stunMessage[] =
    {
        /* STUN header: Message Type = REFRESH_ERROR_RESPONSE (0x0114), Length = 60 bytes (excluding 20 bytes header). */
        0x01, 0x14, 0x00, 0x3C,
        /* Magic Cookie (0x2112A442). */
        0x21, 0x12, 0xA4, 0x42,
        /* 12 bytes (96 bits) transaction ID which is same as transactionID above. */
        0xFF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
        /* Attribute Type = Error Code (0x0009), Attribute Length = 16 (2 reserved bytes, 2 byte error code and 12 byte error phrase). */
        0x00, 0x09, 0x00, 0x10,
        /* Reserved = 0x0000, Error Class = 4, Error Number = 01 (Error Code = 438 Stale Nonce). */
        0x00, 0x00, 0x04, 0x26,
        /* Error Phrase = "Error Phrase". */
        0x45, 0x72, 0x72, 0x6F,
        0x72, 0x20, 0x50, 0x68,
        0x72, 0x61, 0x73, 0x65,
        /* Attribute type = REALM (0x0014), Length = 5 bytes. */
        0x00, 0x14, 0x00, 0x05,
        /* Attribute Value: "realm". */
        0x72, 0x65, 0x61, 0x6C,
        0x6D, 0x00, 0x00, 0x00,
        /* Attribute type = NONCE (0x0015), Length = 5 bytes. */
        0x00, 0x15, 0x00, 0x05,
        /* Attribute Value: "nonce". */
        0x6E, 0x6F, 0x6E, 0x63,
        0x65, 0x00, 0x00, 0x00,
        /* Attribute type = LIFETIME (0x000D), Length = 4 bytes. */
        0x00, 0x0D, 0x00, 0x04,
        /* Attribute Value: 0. */
        0x00, 0x00, 0x00, 0x00,
        /* Attribute type = FINGERPRINT (0x8028), Length = 4 bytes. */
        0x80, 0x28, 0x00, 0x04,
        /* Attribute Value: 0x01010101 to make it wrong (correct one: 0x00000000). */
        0x01, 0x01, 0x01, 0x01
    };
    size_t stunMessageLength = sizeof( stunMessage );
    char * pUsername = "username";
    size_t usernameLength = strlen( pUsername );
    char * pPassword = "password";
    size_t passwordLength = strlen( pPassword );
    char * pRealm = "realm";
    size_t realmLength = strlen( pRealm );
    char * pNonce = "nonce";
    size_t nonceLength = strlen( pNonce );
    char longTermPassword[] = "LongTermPassword";
    size_t longTermPasswordLength = strlen( longTermPassword );
    char * pPreLongTermPassword = "username:realm:password"; /* Follow https://datatracker.ietf.org/doc/html/rfc5389#section-15.4. */
    size_t preLongTermPasswordLength = strlen( pPreLongTermPassword );
    uint16_t expectedLongTermPasswordLength = 16; /* It's always 16 bytes as MD5 result. */
    uint8_t pExpectedLongTermPassword[ expectedLongTermPasswordLength ];

    /* Set CRC32 function to testCrc32Fxn_Fixed to make fingerprint always 0x00000000 */
    initInfo.cryptoFunctions.crc32Fxn = testCrc32Fxn_Fixed;
    /* Set CRC32 function to testHmacFxn_FixedFF to make integrity always 0xFF. */
    initInfo.cryptoFunctions.hmacFxn = testHmacFxn_FixedFF;
    initInfo.getCurrentTimeSecondsFxn = testGetCurrentTime_FixedZero;

    iceResult = Ice_Init( &( context ),
                          &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       iceResult );

    memset( &( localCandidate ),
            0,
            sizeof( IceCandidate_t ) );
    localCandidate.candidateType = ICE_CANDIDATE_TYPE_RELAY;
    localCandidate.state = ICE_CANDIDATE_STATE_VALID;
    context.numRelayExtensions = 1;
    localCandidate.pRelayExtension = &( context.pRelayExtensionsArray[ 0 ] );
    memcpy( localCandidate.pRelayExtension->iceRelayServerInfo.longTermPassword,
            longTermPassword,
            longTermPasswordLength );
    localCandidate.pRelayExtension->iceRelayServerInfo.longTermPasswordLength = longTermPasswordLength;
    memcpy( &localCandidate.pRelayExtension->iceRelayServerInfo.userName, pUsername, usernameLength );
    localCandidate.pRelayExtension->iceRelayServerInfo.userNameLength = usernameLength;
    memcpy( &localCandidate.pRelayExtension->iceRelayServerInfo.password, pPassword, passwordLength );
    localCandidate.pRelayExtension->iceRelayServerInfo.passwordLength = passwordLength;
    memcpy( &localCandidate.pRelayExtension->iceRelayServerInfo.realm, pRealm, realmLength );
    localCandidate.pRelayExtension->iceRelayServerInfo.realmLength = realmLength;
    memcpy( &localCandidate.pRelayExtension->iceRelayServerInfo.nonce, pNonce, nonceLength );
    localCandidate.pRelayExtension->iceRelayServerInfo.nonceLength = nonceLength;

    memcpy( &( localCandidate.transactionId[ 0 ] ),
            &( transactionID[ 0 ] ),
            sizeof( transactionID ) );

    /* Prepare expected long term password by calling testMd5 API. */
    ( void ) testMd5Fxn( ( const uint8_t * ) pPreLongTermPassword,
                         preLongTermPasswordLength,
                         pExpectedLongTermPassword,
                         &expectedLongTermPasswordLength );

    result = Ice_HandleStunPacket( &( context ),
                                   &( stunMessage[ 0 ] ),
                                   stunMessageLength,
                                   &( localCandidate ),
                                   &( remoteEndpoint ),
                                   &( pTransactionId ),
                                   &( pCandidatePair ) );

    TEST_ASSERT_EQUAL( ICE_HANDLE_STUN_PACKET_RESULT_FINGERPRINT_MISMATCH,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Ice_HandleStunPacket recieves a REFRESH_ERROR_RESPONSE and
 * the candidate is found in the ICE context with error code Stale Nonce.
 * And the candidate state is releasing.
 */
void test_iceHandleStunPacket_RefreshErrorResponse_Pass_ErrorStaleNonce_StateReleasing( void )
{
    IceContext_t context = { 0 };
    IceCandidate_t localCandidate = { 0 };
    IceEndpoint_t remoteEndpoint = { 0 };
    uint8_t * pTransactionId;
    IceCandidatePair_t * pCandidatePair = NULL;
    IceResult_t iceResult;
    IceHandleStunPacketResult_t result;
    uint8_t transactionID[] =
    {
        0xFF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B
    };
    uint8_t stunMessage[] =
    {
        /* STUN header: Message Type = REFRESH_ERROR_RESPONSE (0x0114), Length = 60 bytes (excluding 20 bytes header). */
        0x01, 0x14, 0x00, 0x3C,
        /* Magic Cookie (0x2112A442). */
        0x21, 0x12, 0xA4, 0x42,
        /* 12 bytes (96 bits) transaction ID which is same as transactionID above. */
        0xFF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
        /* Attribute Type = Error Code (0x0009), Attribute Length = 16 (2 reserved bytes, 2 byte error code and 12 byte error phrase). */
        0x00, 0x09, 0x00, 0x10,
        /* Reserved = 0x0000, Error Class = 4, Error Number = 01 (Error Code = 438 Stale Nonce). */
        0x00, 0x00, 0x04, 0x26,
        /* Error Phrase = "Error Phrase". */
        0x45, 0x72, 0x72, 0x6F,
        0x72, 0x20, 0x50, 0x68,
        0x72, 0x61, 0x73, 0x65,
        /* Attribute type = REALM (0x0014), Length = 5 bytes. */
        0x00, 0x14, 0x00, 0x05,
        /* Attribute Value: "realm". */
        0x72, 0x65, 0x61, 0x6C,
        0x6D, 0x00, 0x00, 0x00,
        /* Attribute type = NONCE (0x0015), Length = 5 bytes. */
        0x00, 0x15, 0x00, 0x05,
        /* Attribute Value: "nonce". */
        0x6E, 0x6F, 0x6E, 0x63,
        0x65, 0x00, 0x00, 0x00,
        /* Attribute type = LIFETIME (0x000D), Length = 4 bytes. */
        0x00, 0x0D, 0x00, 0x04,
        /* Attribute Value: 0. */
        0x00, 0x00, 0x00, 0x00,
        /* Attribute type = FINGERPRINT (0x8028), Length = 4 bytes. */
        0x80, 0x28, 0x00, 0x04,
        /* Attribute Value: 0x00000000 as calculated by testCrc32Fxn_Fixed. */
        0x00, 0x00, 0x00, 0x00
    };
    size_t stunMessageLength = sizeof( stunMessage );
    char * pUsername = "username";
    size_t usernameLength = strlen( pUsername );
    char * pPassword = "password";
    size_t passwordLength = strlen( pPassword );
    char * pRealm = "realm";
    size_t realmLength = strlen( pRealm );
    char * pNonce = "nonce";
    size_t nonceLength = strlen( pNonce );
    char longTermPassword[] = "LongTermPassword";
    size_t longTermPasswordLength = strlen( longTermPassword );
    char * pPreLongTermPassword = "username:realm:password"; /* Follow https://datatracker.ietf.org/doc/html/rfc5389#section-15.4. */
    size_t preLongTermPasswordLength = strlen( pPreLongTermPassword );
    uint16_t expectedLongTermPasswordLength = 16; /* It's always 16 bytes as MD5 result. */
    uint8_t pExpectedLongTermPassword[ expectedLongTermPasswordLength ];

    /* Set CRC32 function to testCrc32Fxn_Fixed to make fingerprint always 0x00000000 */
    initInfo.cryptoFunctions.crc32Fxn = testCrc32Fxn_Fixed;
    /* Set CRC32 function to testHmacFxn_FixedFF to make integrity always 0xFF. */
    initInfo.cryptoFunctions.hmacFxn = testHmacFxn_FixedFF;
    initInfo.getCurrentTimeSecondsFxn = testGetCurrentTime_FixedZero;

    iceResult = Ice_Init( &( context ),
                          &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       iceResult );

    memset( &( localCandidate ),
            0,
            sizeof( IceCandidate_t ) );
    localCandidate.candidateType = ICE_CANDIDATE_TYPE_RELAY;
    localCandidate.state = ICE_CANDIDATE_STATE_RELEASING;
    context.numRelayExtensions = 1;
    localCandidate.pRelayExtension = &( context.pRelayExtensionsArray[ 0 ] );
    memcpy( localCandidate.pRelayExtension->iceRelayServerInfo.longTermPassword,
            longTermPassword,
            longTermPasswordLength );
    localCandidate.pRelayExtension->iceRelayServerInfo.longTermPasswordLength = longTermPasswordLength;
    memcpy( &localCandidate.pRelayExtension->iceRelayServerInfo.userName, pUsername, usernameLength );
    localCandidate.pRelayExtension->iceRelayServerInfo.userNameLength = usernameLength;
    memcpy( &localCandidate.pRelayExtension->iceRelayServerInfo.password, pPassword, passwordLength );
    localCandidate.pRelayExtension->iceRelayServerInfo.passwordLength = passwordLength;
    memcpy( &localCandidate.pRelayExtension->iceRelayServerInfo.realm, pRealm, realmLength );
    localCandidate.pRelayExtension->iceRelayServerInfo.realmLength = realmLength;
    memcpy( &localCandidate.pRelayExtension->iceRelayServerInfo.nonce, pNonce, nonceLength );
    localCandidate.pRelayExtension->iceRelayServerInfo.nonceLength = nonceLength;

    memcpy( &( localCandidate.transactionId[ 0 ] ),
            &( transactionID[ 0 ] ),
            sizeof( transactionID ) );

    /* Prepare expected long term password by calling testMd5 API. */
    ( void ) testMd5Fxn( ( const uint8_t * ) pPreLongTermPassword,
                         preLongTermPasswordLength,
                         pExpectedLongTermPassword,
                         &expectedLongTermPasswordLength );

    result = Ice_HandleStunPacket( &( context ),
                                   &( stunMessage[ 0 ] ),
                                   stunMessageLength,
                                   &( localCandidate ),
                                   &( remoteEndpoint ),
                                   &( pTransactionId ),
                                   &( pCandidatePair ) );

    TEST_ASSERT_EQUAL( ICE_HANDLE_STUN_PACKET_RESULT_TURN_SESSION_TERMINATED,
                       result );
    TEST_ASSERT_EQUAL( ICE_CANDIDATE_STATE_RELEASED,
                       localCandidate.state );
}

/*-----------------------------------------------------------*/

/**
 * @brief Ice_HandleStunPacket recieves a REFRESH_ERROR_RESPONSE and
 * the transaction ID is not found in store.
 */
void test_iceHandleStunPacket_RefreshErrorResponse_TransactionIdNotFound( void )
{
    IceContext_t context = { 0 };
    IceCandidate_t localCandidate = { 0 };
    IceEndpoint_t remoteEndpoint = { 0 };
    uint8_t * pTransactionId;
    IceCandidatePair_t * pCandidatePair = NULL;
    IceResult_t iceResult;
    IceHandleStunPacketResult_t result;
    uint8_t stunMessage[] =
    {
        /* STUN header: Message Type = REFRESH_ERROR_RESPONSE (0x0114), Length = 60 bytes (excluding 20 bytes header). */
        0x01, 0x14, 0x00, 0x3C,
        /* Magic Cookie (0x2112A442). */
        0x21, 0x12, 0xA4, 0x42,
        /* 12 bytes (96 bits) transaction ID which is same as transactionID above. */
        0xFF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
        /* Attribute Type = Error Code (0x0009), Attribute Length = 16 (2 reserved bytes, 2 byte error code and 12 byte error phrase). */
        0x00, 0x09, 0x00, 0x10,
        /* Reserved = 0x0000, Error Class = 4, Error Number = 01 (Error Code = 438 Stale Nonce). */
        0x00, 0x00, 0x04, 0x26,
        /* Error Phrase = "Error Phrase". */
        0x45, 0x72, 0x72, 0x6F,
        0x72, 0x20, 0x50, 0x68,
        0x72, 0x61, 0x73, 0x65,
        /* Attribute type = REALM (0x0014), Length = 5 bytes. */
        0x00, 0x14, 0x00, 0x05,
        /* Attribute Value: "realm". */
        0x72, 0x65, 0x61, 0x6C,
        0x6D, 0x00, 0x00, 0x00,
        /* Attribute type = NONCE (0x0015), Length = 5 bytes. */
        0x00, 0x15, 0x00, 0x05,
        /* Attribute Value: "nonce". */
        0x6E, 0x6F, 0x6E, 0x63,
        0x65, 0x00, 0x00, 0x00,
        /* Attribute type = LIFETIME (0x000D), Length = 4 bytes. */
        0x00, 0x0D, 0x00, 0x04,
        /* Attribute Value: 0. */
        0x00, 0x00, 0x00, 0x00,
        /* Attribute type = FINGERPRINT (0x8028), Length = 4 bytes. */
        0x80, 0x28, 0x00, 0x04,
        /* Attribute Value: 0x00000000 as calculated by testCrc32Fxn_Fixed. */
        0x00, 0x00, 0x00, 0x00
    };
    size_t stunMessageLength = sizeof( stunMessage );

    /* Set CRC32 function to testCrc32Fxn_Fixed to make fingerprint always 0x00000000 */
    initInfo.cryptoFunctions.crc32Fxn = testCrc32Fxn_Fixed;
    /* Set CRC32 function to testHmacFxn_FixedFF to make integrity always 0xFF. */
    initInfo.cryptoFunctions.hmacFxn = testHmacFxn_FixedFF;
    initInfo.getCurrentTimeSecondsFxn = testGetCurrentTime_FixedZero;

    iceResult = Ice_Init( &( context ),
                          &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       iceResult );

    memset( &( localCandidate ),
            0,
            sizeof( IceCandidate_t ) );
    localCandidate.candidateType = ICE_CANDIDATE_TYPE_RELAY;
    localCandidate.state = ICE_CANDIDATE_STATE_VALID;

    result = Ice_HandleStunPacket( &( context ),
                                   &( stunMessage[ 0 ] ),
                                   stunMessageLength,
                                   &( localCandidate ),
                                   &( remoteEndpoint ),
                                   &( pTransactionId ),
                                   &( pCandidatePair ) );

    TEST_ASSERT_EQUAL( ICE_HANDLE_STUN_PACKET_RESULT_DROP_PACKET,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Ice_HandleStunPacket recieves a REFRESH_SUCCESS_RESPONSE and
 * the candidate is found in the ICE context.
 */
void test_iceHandleStunPacket_RefreshSuccessResponse_Pass( void )
{
    IceContext_t context = { 0 };
    IceCandidate_t localCandidate = { 0 };
    IceEndpoint_t remoteEndpoint = { 0 };
    uint8_t * pTransactionId;
    IceCandidatePair_t * pCandidatePair = NULL;
    IceResult_t iceResult;
    IceHandleStunPacketResult_t result;
    uint8_t transactionID[] =
    {
        0xFF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B
    };
    uint8_t stunMessage[] =
    {
        /* STUN header: Message Type = REFRESH_SUCCESS_RESPONSE (0x0104), Length = 84 bytes (excluding 20 bytes header). */
        0x01, 0x04, 0x00, 0x54,
        /* Magic Cookie (0x2112A442). */
        0x21, 0x12, 0xA4, 0x42,
        /* 12 bytes (96 bits) transaction ID which is same as transactionID above. */
        0xFF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
        /* Attribute Type = Error Code (0x0009), Attribute Length = 16 (2 reserved bytes, 2 byte error code and 12 byte error phrase). */
        0x00, 0x09, 0x00, 0x10,
        /* Reserved = 0x0000, Error Class = 4, Error Number = 01 (Error Code = 401 Unauthorized). */
        0x00, 0x00, 0x04, 0x01,
        /* Error Phrase = "Error Phrase". */
        0x45, 0x72, 0x72, 0x6F,
        0x72, 0x20, 0x50, 0x68,
        0x72, 0x61, 0x73, 0x65,
        /* Attribute type = REALM (0x0014), Length = 5 bytes. */
        0x00, 0x14, 0x00, 0x05,
        /* Attribute Value: "realm". */
        0x72, 0x65, 0x61, 0x6C,
        0x6D, 0x00, 0x00, 0x00,
        /* Attribute type = NONCE (0x0015), Length = 5 bytes. */
        0x00, 0x15, 0x00, 0x05,
        /* Attribute Value: "nonce". */
        0x6E, 0x6F, 0x6E, 0x63,
        0x65, 0x00, 0x00, 0x00,
        /* Attribute type = LIFETIME (0x000D), Length = 4 bytes. */
        0x00, 0x0D, 0x00, 0x04,
        /* Attribute Value: 600 as ICE_DEFAULT_TURN_ALLOCATION_LIFETIME_SECONDS. */
        0x00, 0x00, 0x02, 0x58,
        /* Attribute type = MESSAGE-INTEGRITY (0x0008), Length = 20 bytes. */
        0x00, 0x08, 0x00, 0x14,
        /* Attribute Value = HMAC value as computed by testHmacFxn_FixedFF. */
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        /* Attribute type = FINGERPRINT (0x8028), Length = 4 bytes. */
        0x80, 0x28, 0x00, 0x04,
        /* Attribute Value: 0x00000000 as calculated by testCrc32Fxn_Fixed. */
        0x00, 0x00, 0x00, 0x00
    };
    size_t stunMessageLength = sizeof( stunMessage );
    char longTermPassword[] = "LongTermPassword";
    size_t longTermPasswordLength = strlen( longTermPassword );

    /* Set CRC32 function to testCrc32Fxn_Fixed to make fingerprint always 0x00000000 */
    initInfo.cryptoFunctions.crc32Fxn = testCrc32Fxn_Fixed;
    /* Set CRC32 function to testHmacFxn_FixedFF to make integrity always 0xFF. */
    initInfo.cryptoFunctions.hmacFxn = testHmacFxn_FixedFF;
    initInfo.getCurrentTimeSecondsFxn = testGetCurrentTime_FixedZero;

    iceResult = Ice_Init( &( context ),
                          &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       iceResult );

    memset( &( localCandidate ),
            0,
            sizeof( IceCandidate_t ) );
    localCandidate.candidateType = ICE_CANDIDATE_TYPE_RELAY;
    localCandidate.state = ICE_CANDIDATE_STATE_VALID;
    context.numRelayExtensions = 1;
    localCandidate.pRelayExtension = &( context.pRelayExtensionsArray[ 0 ] );
    memcpy( localCandidate.pRelayExtension->iceRelayServerInfo.longTermPassword,
            longTermPassword,
            longTermPasswordLength );
    localCandidate.pRelayExtension->iceRelayServerInfo.longTermPasswordLength = longTermPasswordLength;

    memcpy( &( localCandidate.transactionId[ 0 ] ),
            &( transactionID[ 0 ] ),
            sizeof( transactionID ) );

    result = Ice_HandleStunPacket( &( context ),
                                   &( stunMessage[ 0 ] ),
                                   stunMessageLength,
                                   &( localCandidate ),
                                   &( remoteEndpoint ),
                                   &( pTransactionId ),
                                   &( pCandidatePair ) );

    TEST_ASSERT_EQUAL( ICE_HANDLE_STUN_PACKET_RESULT_FRESH_COMPLETE,
                       result );
    TEST_ASSERT_EQUAL( ICE_DEFAULT_TURN_ALLOCATION_LIFETIME_SECONDS,
                       localCandidate.pRelayExtension->turnAllocationExpirationSeconds );
}

/*-----------------------------------------------------------*/

/**
 * @brief Ice_HandleStunPacket recieves a REFRESH_SUCCESS_RESPONSE and
 * the candidate is releasing.
 */
void test_iceHandleStunPacket_RefreshSuccessResponse_CandidateReleasing( void )
{
    IceContext_t context = { 0 };
    IceCandidate_t localCandidate = { 0 };
    IceEndpoint_t remoteEndpoint = { 0 };
    uint8_t * pTransactionId;
    IceCandidatePair_t * pCandidatePair = NULL;
    IceResult_t iceResult;
    IceHandleStunPacketResult_t result;
    uint8_t transactionID[] =
    {
        0xFF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B
    };
    uint8_t stunMessage[] =
    {
        /* STUN header: Message Type = REFRESH_SUCCESS_RESPONSE (0x0104), Length = 84 bytes (excluding 20 bytes header). */
        0x01, 0x04, 0x00, 0x54,
        /* Magic Cookie (0x2112A442). */
        0x21, 0x12, 0xA4, 0x42,
        /* 12 bytes (96 bits) transaction ID which is same as transactionID above. */
        0xFF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
        /* Attribute Type = Error Code (0x0009), Attribute Length = 16 (2 reserved bytes, 2 byte error code and 12 byte error phrase). */
        0x00, 0x09, 0x00, 0x10,
        /* Reserved = 0x0000, Error Class = 4, Error Number = 01 (Error Code = 401 Unauthorized). */
        0x00, 0x00, 0x04, 0x01,
        /* Error Phrase = "Error Phrase". */
        0x45, 0x72, 0x72, 0x6F,
        0x72, 0x20, 0x50, 0x68,
        0x72, 0x61, 0x73, 0x65,
        /* Attribute type = REALM (0x0014), Length = 5 bytes. */
        0x00, 0x14, 0x00, 0x05,
        /* Attribute Value: "realm". */
        0x72, 0x65, 0x61, 0x6C,
        0x6D, 0x00, 0x00, 0x00,
        /* Attribute type = NONCE (0x0015), Length = 5 bytes. */
        0x00, 0x15, 0x00, 0x05,
        /* Attribute Value: "nonce". */
        0x6E, 0x6F, 0x6E, 0x63,
        0x65, 0x00, 0x00, 0x00,
        /* Attribute type = LIFETIME (0x000D), Length = 4 bytes. */
        0x00, 0x0D, 0x00, 0x04,
        /* Attribute Value: 600 as ICE_DEFAULT_TURN_ALLOCATION_LIFETIME_SECONDS. */
        0x00, 0x00, 0x02, 0x58,
        /* Attribute type = MESSAGE-INTEGRITY (0x0008), Length = 20 bytes. */
        0x00, 0x08, 0x00, 0x14,
        /* Attribute Value = HMAC value as computed by testHmacFxn_FixedFF. */
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        /* Attribute type = FINGERPRINT (0x8028), Length = 4 bytes. */
        0x80, 0x28, 0x00, 0x04,
        /* Attribute Value: 0x00000000 as calculated by testCrc32Fxn_Fixed. */
        0x00, 0x00, 0x00, 0x00
    };
    size_t stunMessageLength = sizeof( stunMessage );
    char longTermPassword[] = "LongTermPassword";
    size_t longTermPasswordLength = strlen( longTermPassword );

    /* Set CRC32 function to testCrc32Fxn_Fixed to make fingerprint always 0x00000000 */
    initInfo.cryptoFunctions.crc32Fxn = testCrc32Fxn_Fixed;
    /* Set CRC32 function to testHmacFxn_FixedFF to make integrity always 0xFF. */
    initInfo.cryptoFunctions.hmacFxn = testHmacFxn_FixedFF;
    initInfo.getCurrentTimeSecondsFxn = testGetCurrentTime_FixedZero;

    iceResult = Ice_Init( &( context ),
                          &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       iceResult );

    memset( &( localCandidate ),
            0,
            sizeof( IceCandidate_t ) );
    localCandidate.candidateType = ICE_CANDIDATE_TYPE_RELAY;
    localCandidate.state = ICE_CANDIDATE_STATE_RELEASING;
    context.numRelayExtensions = 1;
    localCandidate.pRelayExtension = &( context.pRelayExtensionsArray[ 0 ] );
    memcpy( localCandidate.pRelayExtension->iceRelayServerInfo.longTermPassword,
            longTermPassword,
            longTermPasswordLength );
    localCandidate.pRelayExtension->iceRelayServerInfo.longTermPasswordLength = longTermPasswordLength;

    memcpy( &( localCandidate.transactionId[ 0 ] ),
            &( transactionID[ 0 ] ),
            sizeof( transactionID ) );

    result = Ice_HandleStunPacket( &( context ),
                                   &( stunMessage[ 0 ] ),
                                   stunMessageLength,
                                   &( localCandidate ),
                                   &( remoteEndpoint ),
                                   &( pTransactionId ),
                                   &( pCandidatePair ) );

    TEST_ASSERT_EQUAL( ICE_HANDLE_STUN_PACKET_RESULT_TURN_SESSION_TERMINATED,
                       result );
    TEST_ASSERT_EQUAL( ICE_CANDIDATE_STATE_RELEASED,
                       localCandidate.state );
}

/*-----------------------------------------------------------*/

/**
 * @brief Ice_HandleStunPacket recieves a REFRESH_SUCCESS_RESPONSE but
 * the password is missing while deserializing STUN packet.
 */
void test_iceHandleStunPacket_RefreshSuccessResponse_DeserializeStunFail( void )
{
    IceContext_t context = { 0 };
    IceCandidate_t localCandidate = { 0 };
    IceEndpoint_t remoteEndpoint = { 0 };
    uint8_t * pTransactionId;
    IceCandidatePair_t * pCandidatePair = NULL;
    IceResult_t iceResult;
    IceHandleStunPacketResult_t result;
    uint8_t transactionID[] =
    {
        0xFF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B
    };
    uint8_t stunMessage[] =
    {
        /* STUN header: Message Type = REFRESH_SUCCESS_RESPONSE (0x0104), Length = 84 bytes (excluding 20 bytes header). */
        0x01, 0x04, 0x00, 0x54,
        /* Magic Cookie (0x2112A442). */
        0x21, 0x12, 0xA4, 0x42,
        /* 12 bytes (96 bits) transaction ID which is same as transactionID above. */
        0xFF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
        /* Attribute Type = Error Code (0x0009), Attribute Length = 16 (2 reserved bytes, 2 byte error code and 12 byte error phrase). */
        0x00, 0x09, 0x00, 0x10,
        /* Reserved = 0x0000, Error Class = 4, Error Number = 01 (Error Code = 401 Unauthorized). */
        0x00, 0x00, 0x04, 0x01,
        /* Error Phrase = "Error Phrase". */
        0x45, 0x72, 0x72, 0x6F,
        0x72, 0x20, 0x50, 0x68,
        0x72, 0x61, 0x73, 0x65,
        /* Attribute type = REALM (0x0014), Length = 5 bytes. */
        0x00, 0x14, 0x00, 0x05,
        /* Attribute Value: "realm". */
        0x72, 0x65, 0x61, 0x6C,
        0x6D, 0x00, 0x00, 0x00,
        /* Attribute type = NONCE (0x0015), Length = 5 bytes. */
        0x00, 0x15, 0x00, 0x05,
        /* Attribute Value: "nonce". */
        0x6E, 0x6F, 0x6E, 0x63,
        0x65, 0x00, 0x00, 0x00,
        /* Attribute type = LIFETIME (0x000D), Length = 4 bytes. */
        0x00, 0x0D, 0x00, 0x04,
        /* Attribute Value: 600 as ICE_DEFAULT_TURN_ALLOCATION_LIFETIME_SECONDS. */
        0x00, 0x00, 0x02, 0x58,
        /* Attribute type = MESSAGE-INTEGRITY (0x0008), Length = 20 bytes. */
        0x00, 0x08, 0x00, 0x14,
        /* Attribute Value = HMAC value as computed by testHmacFxn_FixedFF. */
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        /* Attribute type = FINGERPRINT (0x8028), Length = 4 bytes. */
        0x80, 0x28, 0x00, 0x04,
        /* Attribute Value: 0x00000000 as calculated by testCrc32Fxn_Fixed. */
        0x00, 0x00, 0x00, 0x00
    };
    size_t stunMessageLength = sizeof( stunMessage );

    /* Set CRC32 function to testCrc32Fxn_Fixed to make fingerprint always 0x00000000 */
    initInfo.cryptoFunctions.crc32Fxn = testCrc32Fxn_Fixed;
    /* Set CRC32 function to testHmacFxn_FixedFF to make integrity always 0xFF. */
    initInfo.cryptoFunctions.hmacFxn = testHmacFxn_FixedFF;
    initInfo.getCurrentTimeSecondsFxn = testGetCurrentTime_FixedZero;

    iceResult = Ice_Init( &( context ),
                          &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       iceResult );

    memset( &( localCandidate ),
            0,
            sizeof( IceCandidate_t ) );
    localCandidate.candidateType = ICE_CANDIDATE_TYPE_RELAY;
    localCandidate.state = ICE_CANDIDATE_STATE_VALID;
    context.numRelayExtensions = 1;
    localCandidate.pRelayExtension = &( context.pRelayExtensionsArray[ 0 ] );

    memcpy( &( localCandidate.transactionId[ 0 ] ),
            &( transactionID[ 0 ] ),
            sizeof( transactionID ) );

    result = Ice_HandleStunPacket( &( context ),
                                   &( stunMessage[ 0 ] ),
                                   stunMessageLength,
                                   &( localCandidate ),
                                   &( remoteEndpoint ),
                                   &( pTransactionId ),
                                   &( pCandidatePair ) );

    TEST_ASSERT_EQUAL( ICE_HANDLE_STUN_PACKET_RESULT_DESERIALIZE_ERROR,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Ice_HandleStunPacket recieves a REFRESH_SUCCESS_RESPONSE but
 * the transaction ID is not found in store.
 */
void test_iceHandleStunPacket_RefreshSuccessResponse_TransactionIdNotFound( void )
{
    IceContext_t context = { 0 };
    IceCandidate_t localCandidate = { 0 };
    IceEndpoint_t remoteEndpoint = { 0 };
    uint8_t * pTransactionId;
    IceCandidatePair_t * pCandidatePair = NULL;
    IceResult_t iceResult;
    IceHandleStunPacketResult_t result;
    uint8_t stunMessage[] =
    {
        /* STUN header: Message Type = REFRESH_SUCCESS_RESPONSE (0x0104), Length = 84 bytes (excluding 20 bytes header). */
        0x01, 0x04, 0x00, 0x54,
        /* Magic Cookie (0x2112A442). */
        0x21, 0x12, 0xA4, 0x42,
        /* 12 bytes (96 bits) transaction ID which is same as transactionID above. */
        0xFF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
        /* Attribute Type = Error Code (0x0009), Attribute Length = 16 (2 reserved bytes, 2 byte error code and 12 byte error phrase). */
        0x00, 0x09, 0x00, 0x10,
        /* Reserved = 0x0000, Error Class = 4, Error Number = 01 (Error Code = 401 Unauthorized). */
        0x00, 0x00, 0x04, 0x01,
        /* Error Phrase = "Error Phrase". */
        0x45, 0x72, 0x72, 0x6F,
        0x72, 0x20, 0x50, 0x68,
        0x72, 0x61, 0x73, 0x65,
        /* Attribute type = REALM (0x0014), Length = 5 bytes. */
        0x00, 0x14, 0x00, 0x05,
        /* Attribute Value: "realm". */
        0x72, 0x65, 0x61, 0x6C,
        0x6D, 0x00, 0x00, 0x00,
        /* Attribute type = NONCE (0x0015), Length = 5 bytes. */
        0x00, 0x15, 0x00, 0x05,
        /* Attribute Value: "nonce". */
        0x6E, 0x6F, 0x6E, 0x63,
        0x65, 0x00, 0x00, 0x00,
        /* Attribute type = LIFETIME (0x000D), Length = 4 bytes. */
        0x00, 0x0D, 0x00, 0x04,
        /* Attribute Value: 600 as ICE_DEFAULT_TURN_ALLOCATION_LIFETIME_SECONDS. */
        0x00, 0x00, 0x02, 0x58,
        /* Attribute type = MESSAGE-INTEGRITY (0x0008), Length = 20 bytes. */
        0x00, 0x08, 0x00, 0x14,
        /* Attribute Value = HMAC value as computed by testHmacFxn_FixedFF. */
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        /* Attribute type = FINGERPRINT (0x8028), Length = 4 bytes. */
        0x80, 0x28, 0x00, 0x04,
        /* Attribute Value: 0x00000000 as calculated by testCrc32Fxn_Fixed. */
        0x00, 0x00, 0x00, 0x00
    };
    size_t stunMessageLength = sizeof( stunMessage );

    /* Set CRC32 function to testCrc32Fxn_Fixed to make fingerprint always 0x00000000 */
    initInfo.cryptoFunctions.crc32Fxn = testCrc32Fxn_Fixed;
    /* Set CRC32 function to testHmacFxn_FixedFF to make integrity always 0xFF. */
    initInfo.cryptoFunctions.hmacFxn = testHmacFxn_FixedFF;
    initInfo.getCurrentTimeSecondsFxn = testGetCurrentTime_FixedZero;

    iceResult = Ice_Init( &( context ),
                          &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       iceResult );

    memset( &( localCandidate ),
            0,
            sizeof( IceCandidate_t ) );
    localCandidate.candidateType = ICE_CANDIDATE_TYPE_RELAY;
    localCandidate.state = ICE_CANDIDATE_STATE_VALID;

    result = Ice_HandleStunPacket( &( context ),
                                   &( stunMessage[ 0 ] ),
                                   stunMessageLength,
                                   &( localCandidate ),
                                   &( remoteEndpoint ),
                                   &( pTransactionId ),
                                   &( pCandidatePair ) );

    TEST_ASSERT_EQUAL( ICE_HANDLE_STUN_PACKET_RESULT_DROP_PACKET,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate ICE Get Local Candidate Count fail functionality for Bad Parameters.
 */
void test_iceGetLocalCandidateCount_BadParams( void )
{
    IceContext_t context = { 0 };
    size_t numLocalCandidates = 0;
    IceResult_t result;

    result = Ice_GetLocalCandidateCount( NULL,
                                         &( numLocalCandidates ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_BAD_PARAM,
                       result );

    result = Ice_GetLocalCandidateCount( &( context ),
                                         NULL );

    TEST_ASSERT_EQUAL( ICE_RESULT_BAD_PARAM,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate ICE Get Local Candidate Count functionality.
 */
void test_iceGetLocalCandidateCount( void )
{
    IceContext_t context = { 0 };
    size_t numLocalCandidates = 0;
    IceResult_t result;

    result = Ice_Init( &( context ),
                       &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       result );

    result = Ice_GetLocalCandidateCount( &( context ),
                                         &( numLocalCandidates ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       result );
    TEST_ASSERT_EQUAL( numLocalCandidates,
                       context.numLocalCandidates );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate ICE Get Remote Candidate Count fail functionality for Bad Parameters.
 */
void test_iceGetRemoteCandidateCount_BadParams( void )
{
    IceContext_t context = { 0 };
    size_t numRemoteCandidates = 0;
    IceResult_t result;

    result = Ice_GetRemoteCandidateCount( NULL,
                                          &( numRemoteCandidates ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_BAD_PARAM,
                       result );

    result = Ice_GetRemoteCandidateCount( &( context ),
                                          NULL );

    TEST_ASSERT_EQUAL( ICE_RESULT_BAD_PARAM,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate ICE Get Remote Candidate Count functionality.
 */
void test_iceGetRemoteCandidateCount( void )
{
    IceContext_t context = { 0 };
    size_t numRemoteCandidates = 0;
    IceResult_t result;

    result = Ice_Init( &( context ),
                       &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       result );

    result = Ice_GetRemoteCandidateCount( &( context ),
                                          &( numRemoteCandidates ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       result );
    TEST_ASSERT_EQUAL( numRemoteCandidates,
                       context.numRemoteCandidates );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate ICE Get Candidate Pair Count fail functionality for Bad Parameters.
 */
void test_iceGetCandidatePairCount_BadParams( void )
{
    IceContext_t context = { 0 };
    size_t numCandidatePairs = 0;
    IceResult_t result;

    result = Ice_GetCandidatePairCount( NULL,
                                        &( numCandidatePairs ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_BAD_PARAM,
                       result );

    result = Ice_GetCandidatePairCount( &( context ),
                                        NULL );

    TEST_ASSERT_EQUAL( ICE_RESULT_BAD_PARAM,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate ICE Get Candidate Pair Count functionality.
 */
void test_iceGetCandidatePairCount( void )
{
    IceContext_t context = { 0 };
    size_t numCandidatePairs = 0;
    IceResult_t result;

    result = Ice_Init( &( context ),
                       &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       result );

    result = Ice_GetCandidatePairCount( &( context ),
                                        &( numCandidatePairs ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       result );
    TEST_ASSERT_EQUAL( numCandidatePairs,
                       context.numCandidatePairs );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate Ice_CreateTurnChannelDataMessage functionality with
 * bad parameters.
 */
void test_Ice_CreateTurnChannelDataMessage_BadParams( void )
{
    IceContext_t context = { 0 };
    IceCandidatePair_t candidatePair;
    IceResult_t result;
    uint8_t inputBuffer[ 16 ];
    size_t inputBufferLength = sizeof( inputBuffer );
    uint8_t outputBuffer[ 16 ];
    size_t outputBufferLength = sizeof( outputBuffer );

    result = Ice_CreateTurnChannelDataMessage( NULL,
                                               &( candidatePair ),
                                               inputBuffer,
                                               inputBufferLength,
                                               outputBuffer,
                                               &outputBufferLength );

    TEST_ASSERT_EQUAL( ICE_RESULT_BAD_PARAM,
                       result );

    result = Ice_CreateTurnChannelDataMessage( &( context ),
                                               NULL,
                                               inputBuffer,
                                               inputBufferLength,
                                               outputBuffer,
                                               &outputBufferLength );

    TEST_ASSERT_EQUAL( ICE_RESULT_BAD_PARAM,
                       result );

    result = Ice_CreateTurnChannelDataMessage( &( context ),
                                               &( candidatePair ),
                                               NULL,
                                               inputBufferLength,
                                               outputBuffer,
                                               &outputBufferLength );

    TEST_ASSERT_EQUAL( ICE_RESULT_BAD_PARAM,
                       result );

    result = Ice_CreateTurnChannelDataMessage( &( context ),
                                               &( candidatePair ),
                                               inputBuffer,
                                               inputBufferLength,
                                               NULL,
                                               &outputBufferLength );

    TEST_ASSERT_EQUAL( ICE_RESULT_BAD_PARAM,
                       result );

    result = Ice_CreateTurnChannelDataMessage( &( context ),
                                               &( candidatePair ),
                                               inputBuffer,
                                               inputBufferLength,
                                               outputBuffer,
                                               NULL );

    TEST_ASSERT_EQUAL( ICE_RESULT_BAD_PARAM,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate Ice_CreateTurnChannelDataMessage returns ICE_RESULT_OUT_OF_MEMORY
 * when the buffer is not enough to append TURN channel header.
 */
void test_Ice_CreateTurnChannelDataMessage_BufferTooSmall( void )
{
    IceContext_t context = { 0 };
    IceCandidatePair_t candidatePair;
    IceResult_t result;
    uint8_t inputBuffer[ 16 ];
    size_t inputBufferLength = sizeof( inputBuffer );
    uint8_t outputBuffer[ 16 ];
    size_t outputBufferLength = sizeof( outputBuffer );

    /* Set inputBuffer length equal to max length to simulate a full inputBuffer. */
    inputBufferLength = outputBufferLength;
    result = Ice_CreateTurnChannelDataMessage( &( context ),
                                               &( candidatePair ),
                                               inputBuffer,
                                               inputBufferLength,
                                               outputBuffer,
                                               &outputBufferLength );

    TEST_ASSERT_EQUAL( ICE_RESULT_OUT_OF_MEMORY,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate Ice_CreateTurnChannelDataMessage returns ICE_RESULT_TURN_PREFIX_NOT_REQUIRED
 * when the candidate pair doesn't need to append the header.
 */
void test_Ice_CreateTurnChannelDataMessage_StateNoNeedTurnChannelHeader( void )
{
    IceContext_t context = { 0 };
    IceCandidatePair_t candidatePair;
    IceResult_t result;
    uint8_t inputBuffer[ 16 ];
    size_t inputBufferLength = sizeof( inputBuffer ) - 4;
    uint8_t outputBuffer[ 16 ];
    size_t outputBufferLength = sizeof( outputBuffer );

    memset( &candidatePair, 0, sizeof( candidatePair ) );
    candidatePair.state = ICE_CANDIDATE_PAIR_STATE_CREATE_PERMISSION;
    result = Ice_CreateTurnChannelDataMessage( &( context ),
                                               &( candidatePair ),
                                               inputBuffer,
                                               inputBufferLength,
                                               outputBuffer,
                                               &outputBufferLength );

    TEST_ASSERT_EQUAL( ICE_RESULT_TURN_PREFIX_NOT_REQUIRED,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate Ice_CreateTurnChannelDataMessage returns ICE_RESULT_OK
 * when the candidate pair append the channel header successfully at
 * the state waiting.
 */
void test_Ice_CreateTurnChannelDataMessage_StateWaiting_Success( void )
{
    IceContext_t context = { 0 };
    IceCandidatePair_t candidatePair;
    IceResult_t result;
    uint8_t buffer[ 16 ] = {
        0x12, 0x34, 0x56, 0x78,
        0x9A, 0xBC, 0xDE, 0xF0,
        0x12, 0x34, 0x56, 0x78
    };
    size_t inputBufferLength = sizeof( buffer ) - 4; // Reserve 4 bytes for channel header.
    size_t outputBufferLength = sizeof( buffer );
    uint8_t expectedBuffer[ 16 ] = {
        /* Channel header + length. */
        0x40, 0x00, 0x00, 0x0C,
        0x12, 0x34, 0x56, 0x78,
        0x9A, 0xBC, 0xDE, 0xF0,
        0x12, 0x34, 0x56, 0x78
    };
    size_t expectedBufferLength = sizeof( expectedBuffer );

    result = Ice_Init( &( context ),
                       &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       result );

    memset( &candidatePair, 0, sizeof( candidatePair ) );
    candidatePair.state = ICE_CANDIDATE_PAIR_STATE_WAITING;
    candidatePair.turnChannelNumber = 0x4000U;
    result = Ice_CreateTurnChannelDataMessage( &( context ),
                                               &( candidatePair ),
                                               buffer,
                                               inputBufferLength,
                                               buffer,
                                               &outputBufferLength );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       result );
    TEST_ASSERT_EQUAL( expectedBufferLength,
                       outputBufferLength );
    TEST_ASSERT_EQUAL_UINT8_ARRAY( &( expectedBuffer[ 0 ] ),
                                   &( buffer[ 0 ] ),
                                   outputBufferLength );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate Ice_CreateTurnChannelDataMessage returns ICE_RESULT_OK
 * when the candidate pair append the channel header successfully at
 * the state valid.
 */
void test_Ice_CreateTurnChannelDataMessage_StateValid_Success( void )
{
    IceContext_t context = { 0 };
    IceCandidatePair_t candidatePair;
    IceResult_t result;
    uint8_t buffer[ 16 ] = {
        0x12, 0x34, 0x56, 0x78,
        0x9A, 0xBC, 0xDE, 0xF0,
        0x12, 0x34, 0x56, 0x78
    };
    size_t inputBufferLength = sizeof( buffer ) - 4; // Reserve 4 bytes for channel header.
    size_t outputBufferLength = sizeof( buffer );
    uint8_t expectedBuffer[ 16 ] = {
        /* Channel header + length. */
        0x40, 0x00, 0x00, 0x0C,
        0x12, 0x34, 0x56, 0x78,
        0x9A, 0xBC, 0xDE, 0xF0,
        0x12, 0x34, 0x56, 0x78
    };
    size_t expectedBufferLength = sizeof( expectedBuffer );

    result = Ice_Init( &( context ),
                       &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       result );

    memset( &candidatePair, 0, sizeof( candidatePair ) );
    candidatePair.state = ICE_CANDIDATE_PAIR_STATE_VALID;
    candidatePair.turnChannelNumber = 0x4000U;
    result = Ice_CreateTurnChannelDataMessage( &( context ),
                                               &( candidatePair ),
                                               buffer,
                                               inputBufferLength,
                                               buffer,
                                               &outputBufferLength );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       result );
    TEST_ASSERT_EQUAL( expectedBufferLength,
                       outputBufferLength );
    TEST_ASSERT_EQUAL_UINT8_ARRAY( &( expectedBuffer[ 0 ] ),
                                   &( buffer[ 0 ] ),
                                   outputBufferLength );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate Ice_CreateTurnChannelDataMessage returns ICE_RESULT_OK
 * when the candidate pair append the channel header successfully at
 * the state nominated.
 */
void test_Ice_CreateTurnChannelDataMessage_StateNominated_Success( void )
{
    IceContext_t context = { 0 };
    IceCandidatePair_t candidatePair;
    IceResult_t result;
    uint8_t buffer[ 16 ] = {
        0x12, 0x34, 0x56, 0x78,
        0x9A, 0xBC, 0xDE, 0xF0,
        0x12, 0x34, 0x56, 0x78
    };
    size_t inputBufferLength = sizeof( buffer ) - 4; // Reserve 4 bytes for channel header.
    size_t outputBufferLength = sizeof( buffer );
    uint8_t expectedBuffer[ 16 ] = {
        /* Channel header + length. */
        0x40, 0x00, 0x00, 0x0C,
        0x12, 0x34, 0x56, 0x78,
        0x9A, 0xBC, 0xDE, 0xF0,
        0x12, 0x34, 0x56, 0x78
    };
    size_t expectedBufferLength = sizeof( expectedBuffer );

    result = Ice_Init( &( context ),
                       &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       result );

    memset( &candidatePair, 0, sizeof( candidatePair ) );
    candidatePair.state = ICE_CANDIDATE_PAIR_STATE_NOMINATED;
    candidatePair.turnChannelNumber = 0x4000U;
    result = Ice_CreateTurnChannelDataMessage( &( context ),
                                               &( candidatePair ),
                                               buffer,
                                               inputBufferLength,
                                               buffer,
                                               &outputBufferLength );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       result );
    TEST_ASSERT_EQUAL( expectedBufferLength,
                       outputBufferLength );
    TEST_ASSERT_EQUAL_UINT8_ARRAY( &( expectedBuffer[ 0 ] ),
                                   &( buffer[ 0 ] ),
                                   outputBufferLength );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate Ice_CreateTurnChannelDataMessage returns ICE_RESULT_OK
 * when the candidate pair append the channel header successfully at
 * the state succeeded.
 */
void test_Ice_CreateTurnChannelDataMessage_StateSucceeded_Success( void )
{
    IceContext_t context = { 0 };
    IceCandidatePair_t candidatePair;
    IceResult_t result;
    uint8_t buffer[ 16 ] = {
        0x12, 0x34, 0x56, 0x78,
        0x9A, 0xBC, 0xDE, 0xF0,
        0x12, 0x34, 0x56, 0x78
    };
    size_t inputBufferLength = sizeof( buffer ) - 4; // Reserve 4 bytes for channel header.
    size_t outputBufferLength = sizeof( buffer );
    uint8_t expectedBuffer[ 16 ] = {
        /* Channel header + length. */
        0x40, 0x00, 0x00, 0x0C,
        0x12, 0x34, 0x56, 0x78,
        0x9A, 0xBC, 0xDE, 0xF0,
        0x12, 0x34, 0x56, 0x78
    };
    size_t expectedBufferLength = sizeof( expectedBuffer );

    result = Ice_Init( &( context ),
                       &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       result );

    memset( &candidatePair, 0, sizeof( candidatePair ) );
    candidatePair.state = ICE_CANDIDATE_PAIR_STATE_SUCCEEDED;
    candidatePair.turnChannelNumber = 0x4000U;
    result = Ice_CreateTurnChannelDataMessage( &( context ),
                                               &( candidatePair ),
                                               buffer,
                                               inputBufferLength,
                                               buffer,
                                               &outputBufferLength );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       result );
    TEST_ASSERT_EQUAL( expectedBufferLength,
                       outputBufferLength );
    TEST_ASSERT_EQUAL_UINT8_ARRAY( &( expectedBuffer[ 0 ] ),
                                   &( buffer[ 0 ] ),
                                   outputBufferLength );
}

/*-----------------------------------------------------------*/
