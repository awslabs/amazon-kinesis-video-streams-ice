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
#define TRANSACTION_ID_SLOTS_ARRAY_ARRAY_SIZE    32

IceInitInfo_t initInfo;
TransactionIdStore_t transactionIdStore;
IceCandidate_t localCandidateArray[ LOCAL_CANDIDATE_ARRAY_SIZE ];
IceCandidate_t remoteCandidateArray[ REMOTE_CANDIDATE_ARRAY_SIZE ];
IceCandidatePair_t candidatePairArray[ CANDIDATE_PAIR_ARRAY_SIZE ];
TransactionIdSlot_t transactionIdSlots[ TRANSACTION_ID_SLOTS_ARRAY_ARRAY_SIZE ];

/* ===========================  EXTERN FUNCTIONS   =========================== */

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
    initInfo.pStunBindingRequestTransactionIdStore = &( transactionIdStore );
    initInfo.cryptoFunctions.randomFxn = testRandomFxn;
    initInfo.cryptoFunctions.crc32Fxn = testCrc32Fxn;
    initInfo.cryptoFunctions.hmacFxn = testHmacFxn;
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
            CANDIDATE_PAIR_ARRAY_SIZE * sizeof( IceCandidate_t ) );

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
 * @brief Validate ICE Add Server Reflexive Candidate fail functionality for Bad Parameters.
 */
void test_iceAddServerReflexiveCandidate_BadParams( void )
{
    IceContext_t context = { 0 };
    IceEndpoint_t endPoint = { 0 };
    uint8_t stunMessageBuffer[ 10 ];
    size_t stunMessageBufferLength = sizeof( stunMessageBuffer );
    IceResult_t result;

    result = Ice_AddServerReflexiveCandidate( NULL,
                                              &( endPoint ),
                                              &( stunMessageBuffer[ 0 ] ),
                                              &( stunMessageBufferLength ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_BAD_PARAM,
                       result );

    result = Ice_AddServerReflexiveCandidate( &( context ),
                                              NULL,
                                              &( stunMessageBuffer[ 0 ] ),
                                              &( stunMessageBufferLength ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_BAD_PARAM,
                       result );

    result = Ice_AddServerReflexiveCandidate( &( context ),
                                              &( endPoint ),
                                              NULL,
                                              &( stunMessageBufferLength ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_BAD_PARAM,
                       result );

    result = Ice_AddServerReflexiveCandidate( &( context ),
                                              &( endPoint ),
                                              &( stunMessageBuffer[ 0 ] ),
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
    uint8_t stunMessageBuffer[ 10 ];
    size_t stunMessageBufferLength = sizeof( stunMessageBuffer );
    IceResult_t result;

    result = Ice_Init( &( context ),
                       &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       result );

    /* Mark the local candidate array as full. */
    context.numLocalCandidates = LOCAL_CANDIDATE_ARRAY_SIZE;

    result = Ice_AddServerReflexiveCandidate( &( context ),
                                              &( endPoint ),
                                              &( stunMessageBuffer[ 0 ] ),
                                              &( stunMessageBufferLength ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_MAX_CANDIDATE_THRESHOLD,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate ICE Add Server Reflexive Candidate fail functionality when stun library returns error.
 */
void test_iceAddServerReflexiveCandidate_StunError( void )
{
    IceResult_t result;
    IceContext_t context = { 0 };
    IceEndpoint_t endPoint = { 0 };
    uint8_t stunMessageBuffer[] = { 0 };
    /* STUN library returns error because the STUN message is too small. */
    size_t stunMessageBufferLength = sizeof( stunMessageBuffer );

    result = Ice_Init( &( context ),
                       &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       result );

    result = Ice_AddServerReflexiveCandidate( &( context ),
                                              &( endPoint ),
                                              &( stunMessageBuffer[ 0 ] ),
                                              &( stunMessageBufferLength ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_STUN_ERROR,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate ICE Add Server Reflexive Candidate fail functionality while Inserting Transaction ID.
 */
void test_iceAddServerReflexiveCandidate_TransactionIDStoreError( void )
{
    IceResult_t result;
    IceContext_t context = { 0 };
    IceEndpoint_t endPoint = { 0 };
    uint8_t stunMessageBuffer[ 32 ];
    size_t stunMessageBufferLength = 32;

    result = Ice_Init( &( context ),
                       &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       result );

    /* Setting the Transaction ID Store to NULL so that we fail to insert the
     * transaction ID. */
    context.pStunBindingRequestTransactionIdStore = NULL;

    result = Ice_AddServerReflexiveCandidate( &( context ),
                                              &( endPoint ),
                                              &( stunMessageBuffer[ 0 ] ),
                                              &( stunMessageBufferLength ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_TRANSACTION_ID_STORE_ERROR,
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

    result = Ice_AddServerReflexiveCandidate( &( context ),
                                              &( endPoint ),
                                              &( stunMessageBuffer[ 0 ] ),
                                              &( stunMessageBufferLength ) );

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
    TEST_ASSERT_EQUAL( expectedStunMessageLength,
                       stunMessageBufferLength );
    TEST_ASSERT_EQUAL_UINT8_ARRAY( &( expectedStunMessage[ 0 ] ),
                                   &( stunMessageBuffer[ 0 ] ),
                                   expectedStunMessageLength );
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
    uint8_t stunMessageBuffer[ 32 ];
    size_t stunMessageBufferLength = 32;
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
                                              &( endpoint ),
                                              &( stunMessageBuffer[ 0 ] ),
                                              &( stunMessageBufferLength ) );

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
 * @brief Validate ICE Create Stun Packet for connectivity check fail functionality for Bad Parameters.
 */
void test_iceCreateRequestForConnectivityCheck_BadParams( void )
{
    IceContext_t context = { 0 };
    IceCandidatePair_t candidatePair = { 0 };
    uint8_t stunMessageBuffer[ 10 ];
    size_t stunMessageBufferLength = sizeof( stunMessageBuffer );
    IceResult_t result;

    result = Ice_CreateRequestForConnectivityCheck( NULL,
                                                    &( candidatePair ),
                                                    &( stunMessageBuffer[ 0 ] ),
                                                    &( stunMessageBufferLength ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_BAD_PARAM,
                       result );

    result = Ice_CreateRequestForConnectivityCheck( &( context ),
                                                    NULL,
                                                    &( stunMessageBuffer[ 0 ] ),
                                                    &( stunMessageBufferLength ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_BAD_PARAM,
                       result );

    result = Ice_CreateRequestForConnectivityCheck( &( context ),
                                                    &( candidatePair ),
                                                    NULL,
                                                    &( stunMessageBufferLength ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_BAD_PARAM,
                       result );

    result = Ice_CreateRequestForConnectivityCheck( &( context ),
                                                    &( candidatePair ),
                                                    &( stunMessageBuffer[ 0 ] ),
                                                    NULL );

    TEST_ASSERT_EQUAL( ICE_RESULT_BAD_PARAM,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate ICE Create Stun Packet for connectivity check fail
 * functionality for Stun errors.
 */
void test_iceCreateRequestForConnectivityCheck_StunError( void )
{
    IceContext_t context = { 0 };
    IceRemoteCandidateInfo_t remoteCandidateInfo = { 0 };
    IceEndpoint_t endpoint = { 0 };
    uint8_t stunMessageBuffer[ 10 ]; /* Too small to be able to contain a Stun message. */
    size_t stunMessageBufferLength = 10;
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

    result = Ice_CreateRequestForConnectivityCheck( &( context ),
                                                    &( context.pCandidatePairs[ 0 ] ),
                                                    &( stunMessageBuffer[ 0 ] ),
                                                    &( stunMessageBufferLength ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_STUN_ERROR,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate ICE Create Stun Packet for connectivity check functionality
 * when the ICE agent is not controlling.
 */
void test_iceCreateRequestForConnectivityCheck_Controlled( void )
{
    IceContext_t context = { 0 };
    IceRemoteCandidateInfo_t remoteCandidateInfo = { 0 };
    IceEndpoint_t endpoint = { 0 };
    uint8_t stunMessageBuffer[ 128 ];
    size_t stunMessageBufferLength = 128;
    uint8_t expectedStunMessage[] =
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
        /* Attribute Value = HMAC value as computed by testHmacFxn. */
        0x72, 0x64, 0x6D, 0x2F,
        0x55, 0x77, 0xF4, 0x23,
        0x73, 0x72, 0x75, 0x6C,
        0x76, 0x61, 0x74, 0x62,
        0x65, 0x66, 0x7E, 0x6E,
        /* Attribute type = FINGERPRINT (0x8028), Length = 4 bytes. */
        0x80, 0x28, 0x00, 0x04,
        /* Attribute Value = 0xB5F5C42F as calculated by testCrc32Fxn. */
        0xB5, 0xF5, 0xC4, 0x2F
    };
    size_t expectedStunMessageLength = sizeof( expectedStunMessage );
    IceResult_t result;

    initInfo.isControlling = 0;
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

    result = Ice_CreateRequestForConnectivityCheck( &( context ),
                                                    &( context.pCandidatePairs[ 0 ] ),
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
 * @brief Validate ICE Create Stun Packet for connectivity check functionality for invalid HMAC LENGTH i.e. 20 Bytes.
 */
void test_iceCreateRequestForConnectivityCheck_HmacError( void )
{
    IceContext_t context = { 0 };
    IceRemoteCandidateInfo_t remoteCandidateInfo = { 0 };
    IceEndpoint_t endpoint = { 0 };
    uint8_t stunMessageBuffer[ 128 ];
    size_t stunMessageBufferLength = 128;
    IceResult_t result;

    initInfo.cryptoFunctions.hmacFxn = testHmacFxn_Wrong;  /* We are initializing the context to a wrong HMAC Function */

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

    result = Ice_CreateRequestForConnectivityCheck( &( context ),
                                                    &( context.pCandidatePairs[ 0 ] ),
                                                    &( stunMessageBuffer[ 0 ] ),
                                                    &( stunMessageBufferLength ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_HMAC_ERROR,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate ICE Create Stun Packet for connectivity check functionality.
 */
void test_iceCreateRequestForConnectivityCheck_Controlling( void )
{
    IceContext_t context = { 0 };
    IceRemoteCandidateInfo_t remoteCandidateInfo = { 0 };
    IceEndpoint_t endpoint = { 0 };
    uint8_t stunMessageBuffer[ 128 ];
    size_t stunMessageBufferLength = 128;
    uint8_t expectedStunMessage[] =
    {
        /* STUN header: Message Type = Binding Request (0x0001), Length = 0x48 bytes (excluding 20 bytes header). */
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
        /* Attribute type = ICE-CONTROLLING ( 0x802A ), Length = 8 bytes. */
        0x80, 0x2A, 0x00, 0x08,
        /* Attribute Value = 0x0706050403020100. */
        0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00,
        /* Attribute type = MESSAGE-INTEGRITY (0x0008), Length = 20 bytes. */
        0x00, 0x08, 0x00, 0x14,
        /* Attribute Value = HMAC value as computed by testHmacFxn. */
        0x72, 0x64, 0x6D, 0x2F,
        0x55, 0x77, 0xF4, 0x23,
        0x73, 0x72, 0x75, 0x6C,
        0x76, 0x61, 0x74, 0x62,
        0x65, 0x66, 0x7E, 0x6E,
        /* Attribute type = FINGERPRINT (0x8028), Length = 4 bytes. */
        0x80, 0x28, 0x00, 0x04,
        /* Attribute Value: 0x3E26FA36 as calculated by testCrc32Fxn. */
        0x3E, 0x26, 0XFA, 0x36
    };
    size_t expectedStunMessageLength = sizeof( expectedStunMessage );
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

    result = Ice_CreateRequestForConnectivityCheck( &( context ),
                                                    &( context.pCandidatePairs[ 0 ] ),
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
 * @brief Validate ICE Create Stun Packet for nomination of valid candidate pair fail functionality for Bad Parameters.
 */
void test_iceCreateRequestForNominatingCandidatePair_BadParams( void )
{
    IceContext_t context = { 0 };
    IceCandidatePair_t candidatePair = { 0 };
    uint8_t stunMessageBuffer[ 10 ];
    size_t stunMessageBufferLength = sizeof( stunMessageBuffer );
    IceResult_t result;


    result = Ice_CreateRequestForNominatingCandidatePair( NULL,
                                                          &( candidatePair ),
                                                          &( stunMessageBuffer[ 0 ] ),
                                                          &( stunMessageBufferLength ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_BAD_PARAM,
                       result );

    result = Ice_CreateRequestForNominatingCandidatePair( &( context ),
                                                          NULL,
                                                          &( stunMessageBuffer[ 0 ] ),
                                                          &( stunMessageBufferLength ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_BAD_PARAM,
                       result );

    result = Ice_CreateRequestForNominatingCandidatePair( &( context ),
                                                          &( candidatePair ),
                                                          NULL,
                                                          &( stunMessageBufferLength ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_BAD_PARAM,
                       result );

    result = Ice_CreateRequestForNominatingCandidatePair( &( context ),
                                                          &( candidatePair ),
                                                          &( stunMessageBuffer[ 0 ] ),
                                                          NULL );

    TEST_ASSERT_EQUAL( ICE_RESULT_BAD_PARAM,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate ICE Create Stun Packet for nomination of valid candidate pair fail functionality for Stun Error.
 */
void test_iceCreateRequestForNominatingCandidatePair_StunError( void )
{
    IceContext_t context = { 0 };
    IceRemoteCandidateInfo_t remoteCandidateInfo = { 0 };
    IceEndpoint_t endpoint = { 0 };
    uint8_t stunMessageBuffer[ 10 ]; /* Too small to be able to contain a Stun message. */
    size_t stunMessageBufferLength = sizeof( stunMessageBuffer );
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

    result = Ice_CreateRequestForNominatingCandidatePair( &( context ),
                                                          &( context.pCandidatePairs[ 0 ] ),
                                                          &( stunMessageBuffer[ 0 ] ),
                                                          &( stunMessageBufferLength ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_STUN_ERROR,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate ICE Create Stun Packet for nomination of valid candidate pair functionality.
 */
void test_iceCreateRequestForNominatingCandidatePair( void )
{
    IceContext_t context = { 0 };
    IceRemoteCandidateInfo_t remoteCandidateInfo = { 0 };
    IceEndpoint_t endpoint = { 0 };
    uint8_t stunMessageBuffer[ 128 ];
    size_t stunMessageBufferLength = sizeof( stunMessageBuffer );
    uint8_t expectedStunMessage[] =
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
        0x07, 0x06, 0x05, 0x04 ,0x03, 0x02, 0x01, 0x00,
        /* Attribute Type = STUN_ATTRIBUTE_TYPE_USE_CANDIDATE (0x0025), Length = 0 bytes. */
        0x00, 0x25, 0x00, 0x00,
        /* Attribute type = MESSAGE-INTEGRITY (0x0008), Length = 20 bytes. */
        0x00, 0x08, 0x00, 0x14,
        /* Attribute Value = HMAC value as computed by testHmacFxn. */
        0x72, 0x64, 0x6D, 0x2B,
        0x55, 0x77, 0xF4, 0x23,
        0x73, 0x72, 0x75, 0x6C,
        0x76, 0x61, 0x74, 0x62,
        0x65, 0x66, 0x7E, 0x6E,
        /* Attribute type = FINGERPRINT (0x8028), Length = 4 bytes. */
        0x80, 0x28, 0x00, 0x04,
        /* Attribute Value: 0x1035F9DB as calculated by testCrc32Fxn. */
        0x10, 0x35, 0xF9, 0xDB,
    };
    size_t expectedStunMessageLength = sizeof( expectedStunMessage );
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

    result = Ice_CreateRequestForNominatingCandidatePair( &( context ),
                                                          &( context.pCandidatePairs[ 0 ] ),
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
 * @brief Validate ICE Handle Stun Packet fail functionality for Bad Parameters.
 */
void test_iceHandleStunPacket_BadParams( void )
{
    IceContext_t context = { 0 };
    uint8_t stunMessage[ 10 ];
    size_t stunMessageLength = sizeof( stunMessage );
    IceEndpoint_t endpoint = { 0 };
    uint8_t * transactionId[ STUN_HEADER_TRANSACTION_ID_LENGTH ];
    IceCandidatePair_t * candidatePair = { 0 };
    IceHandleStunPacketResult_t result;

    result = Ice_HandleStunPacket( NULL,
                                   &( stunMessage[ 0 ] ),
                                   stunMessageLength,
                                   &( endpoint ),
                                   &( endpoint ),
                                   &( transactionId[ 0 ] ),
                                   &( candidatePair ) );

    TEST_ASSERT_EQUAL( ICE_HANDLE_STUN_PACKET_RESULT_BAD_PARAM,
                       result );

    result = Ice_HandleStunPacket( &( context ),
                                   NULL,
                                   0,
                                   &( endpoint ),
                                   &( endpoint ),
                                   &( transactionId[ 0 ] ),
                                   &( candidatePair ) );

    TEST_ASSERT_EQUAL( ICE_HANDLE_STUN_PACKET_RESULT_BAD_PARAM,
                       result );

    result = Ice_HandleStunPacket( &( context ),
                                   &( stunMessage[ 0 ] ),
                                   stunMessageLength,
                                   NULL,
                                   &( endpoint ),
                                   &( transactionId[ 0 ] ),
                                   &( candidatePair ) );

    TEST_ASSERT_EQUAL( ICE_HANDLE_STUN_PACKET_RESULT_BAD_PARAM,
                       result );

    result = Ice_HandleStunPacket( &( context ),
                                   &( stunMessage[ 0 ] ),
                                   stunMessageLength,
                                   &( endpoint ),
                                   NULL,
                                   &( transactionId[ 0 ] ),
                                   &( candidatePair ) );

    TEST_ASSERT_EQUAL( ICE_HANDLE_STUN_PACKET_RESULT_BAD_PARAM,
                       result );

    result = Ice_HandleStunPacket( &( context ),
                                   &( stunMessage[ 0 ] ),
                                   stunMessageLength,
                                   &( endpoint ),
                                   &( endpoint ),
                                   NULL,
                                   &( candidatePair ) );

    TEST_ASSERT_EQUAL( ICE_HANDLE_STUN_PACKET_RESULT_BAD_PARAM,
                       result );

    result = Ice_HandleStunPacket( &( context ),
                                   &( stunMessage[ 0 ] ),
                                   stunMessageLength,
                                   &( endpoint ),
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
    IceCandidatePair_t * candidatePair = { 0 };
    IceHandleStunPacketResult_t result;

    result = Ice_HandleStunPacket( &( context ),
                                   &( stunMessage[ 0 ] ),
                                   stunMessageLength,
                                   &( endpoint ),
                                   &( endpoint ),
                                   &( transactionId[ 0 ] ),
                                   &( candidatePair ) );

    TEST_ASSERT_EQUAL( ICE_HANDLE_STUN_PACKET_RESULT_DESERIALIZE_ERROR,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate ICE Handle Stun Packet functionality for Binding Request Type for Unknown Attribute.
 */
void test_iceHandleStunPacket_BindingRequest_Invalid( void )
{
    IceContext_t context = { 0 };
    IceEndpoint_t localEndpoint = { 0 };
    IceEndpoint_t remoteEndpoint = { 0 };
    IceRemoteCandidateInfo_t remoteCandidateInfo = { 0 };
    uint8_t * pTransactionId;
    IceCandidatePair_t * pCandidatePair;
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
        /* Attribute Type = STUN_ATTRIBUTE_TYPE_USE_CANDIDATE (0x0025), Length = 0 bytes. */
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

    localEndpoint.isPointToPoint = 1;
    localEndpoint.transportAddress.family = 0x01;
    localEndpoint.transportAddress.port = 8080;
    memcpy( ( void * ) &( localEndpoint.transportAddress.address[ 0 ] ),
            ( const void * ) ipAddress,
            sizeof( ipAddress ) );

    remoteEndpoint = localEndpoint; /* For simplicity, use the same endpoint for remote. */

    iceResult = Ice_AddHostCandidate( &( context ),
                                      &( localEndpoint ) );

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
                                   &( localEndpoint ),
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
    IceEndpoint_t localEndpoint = { 0 };
    IceEndpoint_t remoteEndpoint = { 0 };
    IceRemoteCandidateInfo_t remoteCandidateInfo = { 0 };
    uint8_t * pTransactionId;
    IceCandidatePair_t * pCandidatePair;
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
        /* Attribute Type = STUN_ATTRIBUTE_TYPE_USE_CANDIDATE (0x0025), Length = 0 bytes. */
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

    localEndpoint.isPointToPoint = 1;
    localEndpoint.transportAddress.family = 0x01;
    localEndpoint.transportAddress.port = 8080;
    memcpy( ( void * ) &( localEndpoint.transportAddress.address[ 0 ] ),
            ( const void * ) ipAddress,
            sizeof( ipAddress ) );

    remoteEndpoint = localEndpoint; /* For simplicity, use the same endpoint for remote. */

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
                                   &( localEndpoint ),
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
    IceEndpoint_t localEndpoint = { 0 };
    IceEndpoint_t remoteEndpoint = { 0 };
    IceRemoteCandidateInfo_t remoteCandidateInfo = { 0 };
    uint8_t * pTransactionId;
    IceCandidatePair_t * pCandidatePair;
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
        /* Attribute Type = STUN_ATTRIBUTE_TYPE_USE_CANDIDATE (0x0025), Length = 0 bytes. */
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

    localEndpoint.isPointToPoint = 1;
    localEndpoint.transportAddress.family = 0x01;
    localEndpoint.transportAddress.port = 8080;
    memcpy( ( void * ) &( localEndpoint.transportAddress.address[ 0 ] ),
            ( const void * ) ipAddress,
            sizeof( ipAddress ) );

    remoteEndpoint = localEndpoint; /* For simplicity, use the same endpoint for remote. */

    iceResult = Ice_AddHostCandidate( &( context ),
                                      &( localEndpoint ) );

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
                                   &( localEndpoint ),
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
    IceEndpoint_t localEndpoint = { 0 };
    IceEndpoint_t remoteEndpoint = { 0 };
    IceRemoteCandidateInfo_t remoteCandidateInfo = { 0 };
    uint8_t * pTransactionId;
    IceCandidatePair_t * pCandidatePair;
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
        /* Attribute Type = STUN_ATTRIBUTE_TYPE_USE_CANDIDATE (0x0025), Length = 0 bytes. */
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

    localEndpoint.isPointToPoint = 1;
    localEndpoint.transportAddress.family = 0x01;
    localEndpoint.transportAddress.port = 8080;
    memcpy( ( void * ) &( localEndpoint.transportAddress.address[ 0 ] ),
            ( const void * ) ipAddress,
            sizeof( ipAddress ) );

    remoteEndpoint = localEndpoint; /* For simplicity, use the same endpoint for remote. */

    iceResult = Ice_AddHostCandidate( &( context ),
                                      &( localEndpoint ) );

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
                                   &( localEndpoint ),
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
    IceEndpoint_t localEndpoint = { 0 };
    IceEndpoint_t remoteEndpoint = { 0 };
    IceRemoteCandidateInfo_t remoteCandidateInfo = { 0 };
    uint8_t * pTransactionId;
    IceCandidatePair_t * pCandidatePair;
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
        /* Attribute Type = STUN_ATTRIBUTE_TYPE_USE_CANDIDATE (0x0025), Length = 0 bytes. */
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

    localEndpoint.isPointToPoint = 1;
    localEndpoint.transportAddress.family = 0x01;
    localEndpoint.transportAddress.port = 8080;
    memcpy( ( void * ) &( localEndpoint.transportAddress.address[ 0 ] ),
            ( const void * ) ipAddress,
            sizeof( ipAddress ) );

    remoteEndpoint = localEndpoint; /* For simplicity, use the same endpoint for remote. */

    iceResult = Ice_AddHostCandidate( &( context ),
                                      &( localEndpoint ) );

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
                                   &( localEndpoint ),
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
    IceEndpoint_t localEndpoint = { 0 };
    IceEndpoint_t remoteEndpoint = { 0 };
    IceRemoteCandidateInfo_t remoteCandidateInfo = { 0 };
    uint8_t * pTransactionId;
    IceCandidatePair_t * pCandidatePair;
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
        /* Attribute Type = STUN_ATTRIBUTE_TYPE_USE_CANDIDATE (0x0025), Length = 0 bytes. */
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

    localEndpoint.isPointToPoint = 1;
    localEndpoint.transportAddress.family = 0x01;
    localEndpoint.transportAddress.port = 8080;
    memcpy( ( void * ) &( localEndpoint.transportAddress.address[ 0 ] ),
            ( const void * ) ipAddress,
            sizeof( ipAddress ) );

    remoteEndpoint = localEndpoint; /* For simplicity, use the same endpoint for remote. */

    iceResult = Ice_AddHostCandidate( &( context ),
                                      &( localEndpoint ) );

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
    context.pCandidatePairs[ 0 ].connectivityCheckFlags = ICE_STUN_REQUEST_SENT_FLAG | ICE_STUN_RESPONSE_RECEIVED_FLAG | ICE_STUN_REQUEST_RECEIVED_FLAG | ICE_STUN_RESPONSE_SENT_FLAG;

    /* The tests covers that all 4 steps are done and for the
     * chosen candidate Pair the state has been modified to Nominated.*/
    result = Ice_HandleStunPacket( &( context ),
                                   &( stunMessage[ 0 ] ),
                                   stunMessageLength,
                                   &( localEndpoint ),
                                   &( remoteEndpoint ),
                                   &( pTransactionId ),
                                   &( pCandidatePair ) );

    TEST_ASSERT_EQUAL( ICE_HANDLE_STUN_PACKET_RESULT_SEND_RESPONSE_FOR_NOMINATION,
                       result );
    TEST_ASSERT_EQUAL_PTR( &( stunMessage[ 8 ] ),
                           pTransactionId );
    TEST_ASSERT_EQUAL( 1, context.numRemoteCandidates );
    TEST_ASSERT_EQUAL( ICE_CANDIDATE_PAIR_STATE_NOMINATED, pCandidatePair->state );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate ICE Handle Stun Packet functionality for Binding Request Type.
 */
void test_iceHandleStunPacket_BindingRequest_DeserializationError( void )
{
    IceContext_t context = { 0 };
    IceEndpoint_t localEndpoint = { 0 };
    IceEndpoint_t remoteEndpoint = { 0 };
    uint8_t * pTransactionId;
    IceCandidatePair_t * pCandidatePair;
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
        0x63, 0x6F, 0x6D, 0x62 ,0x69, 0x6E, 0x65, 0x64,
        0x55, 0x73, 0x65, 0x72, 0x6E, 0x61, 0x6D, 0x65,
        /* Attribute type = PRIORITY (0x0024), Length = 4 bytes. */
        0x00, 0x24, 0x00, 0x04,
        /* Attribute Value = 0x7E0000FF. */
        0x7E, 0x00, 0x00, 0xFF,
        /* Attribute type = ICE-CONTROLLING (0x802A), Length = 8 bytes. */
        0x80, 0x2A, 0x00, 0x08,
        /* Attribute Value = 0x0706050403020100. */
        0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00,
        /* Attribute Type = STUN_ATTRIBUTE_TYPE_USE_CANDIDATE (0x0025), Length = 0 bytes. */
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
                                   &( localEndpoint ),
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
    IceEndpoint_t localEndpoint = { 0 };
    IceEndpoint_t remoteEndpoint = { 0 };
    uint8_t * pTransactionId;
    IceCandidatePair_t * pCandidatePair;
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
        /* Attribute Type = STUN_ATTRIBUTE_TYPE_USE_CANDIDATE (0x0025), Length = 0 bytes. */
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
                                   &( localEndpoint ),
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
    IceEndpoint_t localEndpoint = { 0 };
    IceEndpoint_t remoteEndpoint = { 0 };
    uint8_t * pTransactionId;
    IceCandidatePair_t * pCandidatePair;
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

    localEndpoint.isPointToPoint = 1;
    localEndpoint.transportAddress.family = 0x01;
    localEndpoint.transportAddress.port = 8080;
    memcpy( ( void * ) &( localEndpoint.transportAddress.address[ 0 ] ),
            ( const void * ) ipAddress,
            sizeof( ipAddress ) );

    remoteEndpoint = localEndpoint; /* For simplicity, use the same endpoint for remote. */

    result = Ice_HandleStunPacket( &( context ),
                                   &( stunMessage[ 0 ] ),
                                   stunMessageLength,
                                   &( localEndpoint ),
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
    IceEndpoint_t localEndpoint = { 0 };
    IceEndpoint_t remoteEndpoint = { 0 };
    IceRemoteCandidateInfo_t remoteCandidateInfo = { 0 };
    uint8_t * pTransactionId;
    IceCandidatePair_t * pCandidatePair;
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

    localEndpoint.isPointToPoint = 1;
    localEndpoint.transportAddress.family = 0x01;
    localEndpoint.transportAddress.port = 8080;
    memcpy( ( void * ) &( localEndpoint.transportAddress.address[ 0 ] ),
            ( const void * ) ipAddress,
            sizeof( ipAddress ) );

    remoteEndpoint = localEndpoint; /* For simplicity, use the same endpoint for remote. */

    iceResult = Ice_AddHostCandidate( &( context ),
                                      &( localEndpoint ) );

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
                                   &( localEndpoint ),
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
    IceEndpoint_t localEndpoint = { 0 };
    IceEndpoint_t remoteEndpoint = { 0 };
    IceRemoteCandidateInfo_t remoteCandidateInfo = { 0 };
    uint8_t * pTransactionId;
    IceCandidatePair_t * pCandidatePair;
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

    localEndpoint.isPointToPoint = 1;
    localEndpoint.transportAddress.family = 0x01;
    localEndpoint.transportAddress.port = 8080;
    memcpy( ( void * ) &( localEndpoint.transportAddress.address[ 0 ] ),
            ( const void * ) ipAddress,
            sizeof( ipAddress ) );

    remoteEndpoint = localEndpoint; /* For simplicity, use the same endpoint for remote. */

    iceResult = Ice_AddHostCandidate( &( context ),
                                      &( localEndpoint ) );

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
                                   &( localEndpoint ),
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
    IceEndpoint_t localEndpoint = { 0 };
    IceEndpoint_t remoteEndpoint = { 0 };
    IceRemoteCandidateInfo_t remoteCandidateInfo = { 0 };
    uint8_t * pTransactionId;
    IceCandidatePair_t * pCandidatePair;
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

    localEndpoint.isPointToPoint = 1;
    localEndpoint.transportAddress.family = 0x01;
    localEndpoint.transportAddress.port = 8080;
    memcpy( ( void * ) &( localEndpoint.transportAddress.address[ 0 ] ),
            ( const void * ) ipAddress,
            sizeof( ipAddress ) );

    remoteEndpoint = localEndpoint; /* For simplicity, use the same endpoint for remote. */

    iceResult = Ice_AddHostCandidate( &( context ),
                                      &( localEndpoint ) );

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
                                   &( localEndpoint ),
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
    IceEndpoint_t localEndpoint = { 0 };
    IceEndpoint_t remoteEndpoint = { 0 };
    uint8_t * pTransactionId;
    IceCandidatePair_t * pCandidatePair;
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

    localEndpoint.isPointToPoint = 1;
    localEndpoint.transportAddress.family = 0x01;
    localEndpoint.transportAddress.port = 8080;
    memcpy( ( void * ) &( localEndpoint.transportAddress.address[ 0 ] ),
            ( const void * ) ipAddress,
            sizeof( ipAddress ) );

    remoteEndpoint = localEndpoint; /* For simplicity, use the same endpoint for remote */

    iceResult = Ice_AddHostCandidate( &( context ),
                                      &( localEndpoint ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       iceResult );

    TEST_ASSERT_EQUAL( 0,
                       context.numCandidatePairs );

    result = Ice_HandleStunPacket( &( context ),
                                   &( stunMessageReceived[ 0 ] ),
                                   stunMessageReceivedLength,
                                   &( localEndpoint ),
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
    uint8_t stunMessageBufferLocal[ 32 ];
    size_t stunMessageBufferLocalLength = 32;
    IceEndpoint_t localEndpoint = { 0 };
    IceEndpoint_t remoteEndpoint = { 0 };
    IceRemoteCandidateInfo_t remoteCandidateInfo = { 0 };
    uint8_t * pTransactionId;
    IceCandidatePair_t * pCandidatePair;
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

    localEndpoint.isPointToPoint = 1;
    localEndpoint.transportAddress.family = 0x01;
    localEndpoint.transportAddress.port = 8080;
    memcpy( ( void * ) &( localEndpoint.transportAddress.address[ 0 ] ),
            ( const void * ) ipAddress,
            sizeof( ipAddress ) );

    remoteEndpoint = localEndpoint; /* For simplicity, use the same endpoint for remote */

    iceResult = Ice_AddServerReflexiveCandidate( &( context ),
                                                 &( localEndpoint ),
                                                 &( stunMessageBufferLocal[ 0 ] ),
                                                 &( stunMessageBufferLocalLength ) );

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
                                   &( localEndpoint ),
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
 * @brief Validate ICE Handle Stun Packet functionality when No Address is Found. (Address Family is neither IPV4 nor IPV6)
 */
void test_iceHandleStunPacket_BindingResponseSuccess_NoAddressFound( void )
{
    IceContext_t context = { 0 };
    IceEndpoint_t localEndpoint = { 0 };
    IceEndpoint_t remoteEndpoint = { 0 };
    IceRemoteCandidateInfo_t remoteCandidateInfo = { 0 };
    uint8_t * pTransactionId;
    IceCandidatePair_t * pCandidatePair;
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

    localEndpoint.isPointToPoint = 1;
    localEndpoint.transportAddress.family = 0x01;
    localEndpoint.transportAddress.port = 8080;
    memcpy( ( void * ) &( localEndpoint.transportAddress.address[ 0 ] ),
            ( const void * ) ipAddress,
            sizeof( ipAddress ) );

    remoteEndpoint = localEndpoint; /* For simplicity, use the same endpoint for remote */

    iceResult = Ice_AddHostCandidate( &( context ),
                                      &( localEndpoint ) );

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
                                   &( localEndpoint ),
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
    uint8_t stunMessageBufferLocal[ 32 ];
    size_t stunMessageBufferLocalLength = 32;
    IceEndpoint_t localEndpoint = { 0 };
    IceEndpoint_t remoteEndpoint = { 0 };
    IceRemoteCandidateInfo_t remoteCandidateInfo = { 0 };
    uint8_t * pTransactionId;
    IceCandidatePair_t * pCandidatePair;
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

    localEndpoint.isPointToPoint = 1;
    localEndpoint.transportAddress.family = 0x01;
    localEndpoint.transportAddress.port = 8080;
    memcpy( ( void * ) &( localEndpoint.transportAddress.address[ 0 ] ),
            ( const void * ) ipAddress,
            sizeof( ipAddress ) );

    remoteEndpoint = localEndpoint; /* For simplicity, use the same endpoint for remote */

    iceResult = Ice_AddServerReflexiveCandidate( &( context ),
                                                 &( localEndpoint ),
                                                 &( stunMessageBufferLocal[ 0 ] ),
                                                 &( stunMessageBufferLocalLength ) );

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
                                   &( localEndpoint ),
                                   &( remoteEndpoint ),
                                   &( pTransactionId ),
                                   &( pCandidatePair ) );

    TEST_ASSERT_EQUAL( ICE_HANDLE_STUN_PACKET_RESULT_OK,
                       result );
    TEST_ASSERT_EQUAL( ICE_CANDIDATE_STATE_VALID,
                       pCandidatePair->state );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate ICE Handle Stun Packet functionality.
 */
void test_iceHandleStunPacket_BindingResponseSuccess_CandidatePairReady( void )
{
    IceContext_t context = { 0 };
    IceEndpoint_t localEndpoint = { 0 };
    IceEndpoint_t remoteEndpoint = { 0 };
    IceRemoteCandidateInfo_t remoteCandidateInfo = { 0 };
    uint8_t * pTransactionId;
    IceCandidatePair_t * pCandidatePair;
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

    localEndpoint.isPointToPoint = 1;
    localEndpoint.transportAddress.family = 0x01;
    localEndpoint.transportAddress.port = 8080;
    memcpy( ( void * ) &( localEndpoint.transportAddress.address[ 0 ] ),
            ( const void * ) ipAddress,
            sizeof( ipAddress ) );

    remoteEndpoint = localEndpoint; /* For simplicity, use the same endpoint for remote. */

    iceResult = Ice_AddHostCandidate( &( context ),
                                      &( localEndpoint ) );

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
                                   &( localEndpoint ),
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
    uint8_t stunMessageBufferLocal[ 32 ];
    size_t stunMessageBufferLocalLength = 32;
    IceEndpoint_t localEndpoint = { 0 };
    IceEndpoint_t remoteEndpoint = { 0 };
    IceRemoteCandidateInfo_t remoteCandidateInfo = { 0 };
    uint8_t * pTransactionId;
    IceCandidatePair_t * pCandidatePair;
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

    localEndpoint.isPointToPoint = 1;
    localEndpoint.transportAddress.family = 0x01;
    localEndpoint.transportAddress.port = 16002;
    memcpy( ( void * ) &( localEndpoint.transportAddress.address[ 0 ] ),
            ( const void * ) ipAddress,
            sizeof( ipAddress ) );

    iceResult = Ice_AddServerReflexiveCandidate( &( context ),
                                                 &( localEndpoint ),
                                                 &( stunMessageBufferLocal[ 0 ] ),
                                                 &( stunMessageBufferLocalLength ) );

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
                                   &( localEndpoint ),
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
    IceEndpoint_t localEndpoint = { 0 };
    IceEndpoint_t remoteEndpoint = { 0 };
    IceRemoteCandidateInfo_t remoteCandidateInfo = { 0 };
    uint8_t * pTransactionId;
    IceCandidatePair_t * pCandidatePair;
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

    localEndpoint.isPointToPoint = 1;
    localEndpoint.transportAddress.family = 0x01;
    localEndpoint.transportAddress.port = 8080;
    memcpy( ( void * ) &( localEndpoint.transportAddress.address[ 0 ] ),
            ( const void * ) ipAddress,
            sizeof( ipAddress ) );

    remoteEndpoint = localEndpoint; /* For simplicity, use the same endpoint for remote. */

    iceResult = Ice_AddHostCandidate( &( context ),
                                      &( localEndpoint ) );

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
                                   &( localEndpoint ),
                                   &( remoteEndpoint ),
                                   &( pTransactionId ),
                                   &( pCandidatePair ) );

    TEST_ASSERT_EQUAL( ICE_HANDLE_STUN_PACKET_RESULT_NON_ZERO_ERROR_CODE,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate ICE Handle Stun Packet functionality for Binding Successful
 * Response when Transaction ID is in the Store but Local Candidate doesn't
 * exist.
 */
void test_iceHandleStunPacket_BindingResponseSuccess_CandidateNotFound( void )
{
    IceContext_t context = { 0 };
    IceEndpoint_t localEndpoint = { 0 };
    IceEndpoint_t remoteEndpoint = { 0 };
    uint8_t * pTransactionId;
    IceCandidatePair_t * pCandidatePair;
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

    localEndpoint.isPointToPoint = 1;
    localEndpoint.transportAddress.family = 0x01;
    localEndpoint.transportAddress.port = 8080;
    memcpy( ( void * ) &( localEndpoint.transportAddress.address[ 0 ] ),
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
                                   &( localEndpoint ),
                                   &( remoteEndpoint ),
                                   &( pTransactionId ),
                                   &( pCandidatePair ) );

    TEST_ASSERT_EQUAL( ICE_HANDLE_STUN_PACKET_RESULT_CANDIDATE_NOT_FOUND,
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
    uint8_t stunMessageBufferLocal[ 32 ];
    size_t stunMessageBufferLocalLength = 32;
    IceEndpoint_t localEndpoint = { 0 };
    IceEndpoint_t remoteEndpoint = { 0 };
    IceRemoteCandidateInfo_t remoteCandidateInfo = { 0 };
    uint8_t * pTransactionId;
    IceCandidatePair_t * pCandidatePair;
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

    localEndpoint.isPointToPoint = 1;
    localEndpoint.transportAddress.family = 0x01;
    localEndpoint.transportAddress.port = 8080;
    memcpy( ( void * ) &( localEndpoint.transportAddress.address[ 0 ] ),
            ( const void * ) ipAddress,
            sizeof( ipAddress ) );

    /* When a server-reflexive candidate is added, it starts in "New" state
     * and transitions to "Valid" state later when a STUN response is received. */
    iceResult = Ice_AddServerReflexiveCandidate( &( context ),
                                                 &( localEndpoint ),
                                                 &( stunMessageBufferLocal[ 0 ] ),
                                                 &( stunMessageBufferLocalLength ) );

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
                                   &( localEndpoint ),
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
 * @brief Validate ICE Handle Stun Packet functionality for Invalid Packets.
 */
void test_iceHandleStunPacket_InvalidPacket( void )
{
    IceContext_t context = { 0 };
    IceEndpoint_t localEndpoint = { 0 };
    IceEndpoint_t remoteEndpoint = { 0 };
    uint8_t * pTransactionId;
    IceCandidatePair_t * pCandidatePair;
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
                                   &( localEndpoint ),
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
    IceEndpoint_t localEndpoint = { 0 };
    IceEndpoint_t remoteEndpoint = { 0 };
    uint8_t * pTransactionId;
    IceCandidatePair_t * pCandidatePair;
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
                                   &( localEndpoint ),
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
