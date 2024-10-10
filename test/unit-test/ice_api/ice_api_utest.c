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
 * @brief Validate ICE Create Stun Packet for connectivity check functionality.
 */
void test_iceCreateRequestForConnectivityCheck( void )
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
        0x6C, 0x6E, 0x63, 0x21,
        0x4D, 0x42, 0xC5, 0x31,
        0x73, 0x76, 0x6D, 0x71,
        0x60, 0x69, 0x69, 0x64,
        0x69, 0x65, 0x5A, 0x6A,
        /* Attribute type = FINGERPRINT (0x8028), Length = 4 bytes. */
        0x80, 0x28, 0x00, 0x04,
        /* Attribute Value: 0xB49B420F as calculated by testCrc32Fxn. */
        0xB4, 0x9B, 0x42, 0x0F
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
        /* Attribute type = ICE-CONTROLLED  ( 0x8029 ), Length = 8 bytes. */
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
    uint8_t stunMessageBuffer[ 10 ];
    size_t stunMessageBufferLength = sizeof( stunMessageBuffer );
    IceEndpoint_t endpoint = { 0 };
    uint8_t * transactionId[ STUN_HEADER_TRANSACTION_ID_LENGTH ];
    IceCandidatePair_t * candidatePair = { 0 };
    IceHandleStunPacketResult_t result;

    result = Ice_HandleStunPacket( NULL,
                                   &( stunMessageBuffer[ 0 ] ),
                                   stunMessageBufferLength,
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
                                   &( stunMessageBuffer[ 0 ] ),
                                   stunMessageBufferLength,
                                   NULL,
                                   &( endpoint ),
                                   &( transactionId[ 0 ] ),
                                   &( candidatePair ) );

    TEST_ASSERT_EQUAL( ICE_HANDLE_STUN_PACKET_RESULT_BAD_PARAM,
                       result );

    result = Ice_HandleStunPacket( &( context ),
                                   &( stunMessageBuffer[ 0 ] ),
                                   stunMessageBufferLength,
                                   &( endpoint ),
                                   NULL,
                                   &( transactionId[ 0 ] ),
                                   &( candidatePair ) );

    TEST_ASSERT_EQUAL( ICE_HANDLE_STUN_PACKET_RESULT_BAD_PARAM,
                       result );

    result = Ice_HandleStunPacket( &( context ),
                                   &( stunMessageBuffer[ 0 ] ),
                                   stunMessageBufferLength,
                                   &( endpoint ),
                                   &( endpoint ),
                                   NULL,
                                   &( candidatePair ) );

    TEST_ASSERT_EQUAL( ICE_HANDLE_STUN_PACKET_RESULT_BAD_PARAM,
                       result );

    result = Ice_HandleStunPacket( &( context ),
                                   &( stunMessageBuffer[ 0 ] ),
                                   stunMessageBufferLength,
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
    uint8_t stunMessageBuffer[ 10 ]; /* Too small to be able to contain a Stun message. */
    size_t stunMessageBufferLength = sizeof( stunMessageBuffer );
    IceEndpoint_t endpoint = { 0 };
    uint8_t * transactionId[ STUN_HEADER_TRANSACTION_ID_LENGTH ];
    IceCandidatePair_t * candidatePair = { 0 };
    IceHandleStunPacketResult_t result;

    result = Ice_HandleStunPacket( &( context ),
                                   &( stunMessageBuffer[ 0 ] ),
                                   stunMessageBufferLength,
                                   &( endpoint ),
                                   &( endpoint ),
                                   &( transactionId[ 0 ] ),
                                   &( candidatePair ) );

    TEST_ASSERT_EQUAL( ICE_HANDLE_STUN_PACKET_RESULT_DESERIALIZE_ERROR,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate ICE Handle Stun Packet functionality for Binding Request Type.
 */
void test_iceHandleStunPacket_BindingRequest( void )
{
    IceContext_t context = { 0 };
    IceEndpoint_t localEndpoint = { 0 };
    IceEndpoint_t remoteEndpoint = { 0 };
    IceRemoteCandidateInfo_t remoteCandidateInfo = { 0 };
    uint8_t * pTransactionId;
    IceCandidatePair_t * pCandidatePair;
    IceResult_t resultIce;
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

    resultIce = Ice_Init( &( context ),
                          &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       resultIce );

    localEndpoint.isPointToPoint = 1;
    localEndpoint.transportAddress.family = 0x01;
    localEndpoint.transportAddress.port = 8080;
    memcpy( ( void * ) &( localEndpoint.transportAddress.address[ 0 ] ),
            ( const void * ) ipAddress,
            sizeof( ipAddress ) );

    remoteEndpoint = localEndpoint; /* For simplicity, use the same endpoint for remote. */

    resultIce = Ice_AddHostCandidate( &( context ),
                                      &( localEndpoint ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       resultIce );

    remoteCandidateInfo.candidateType = ICE_CANDIDATE_TYPE_HOST;
    remoteCandidateInfo.remoteProtocol = ICE_SOCKET_PROTOCOL_UDP;
    remoteCandidateInfo.priority = 1000;
    remoteCandidateInfo.pEndpoint = &( remoteEndpoint );

    resultIce = Ice_AddRemoteCandidate( &( context ),
                                        &( remoteCandidateInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       resultIce );

    pCandidatePair = &( context.pCandidatePairs[ 0 ] );

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
 * @brief Validate ICE Handle Stun Packet functionality.
 */
void test_iceHandleStunPacket_IntegrityMismatch( void )
{
    IceContext_t context = { 0 };
    IceEndpoint_t localEndpoint = { 0 };
    IceEndpoint_t remoteEndpoint = { 0 };
    uint8_t * pTransactionId;
    IceCandidatePair_t * pCandidatePair;
    IceResult_t resultIce;
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
    size_t stunMessageBufferLength = sizeof( stunMessageBuffer );

    resultIce = Ice_Init( &( context ),
                          &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       resultIce );

    result = Ice_HandleStunPacket( &( context ),
                                   &( stunMessageBuffer[ 0 ] ),
                                   stunMessageBufferLength,
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
    IceResult_t resultIce;
    IceHandleStunPacketResult_t result;
    uint8_t stunMessageBuffer[] =
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
        /* Attribute type = ICE-CONTROLLED  ( 0x8029 ), Length = 8 bytes. */
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
        /* Attribute Actual Value: 0xBCD5BE24 as calculated by testCrc32Fxn whereas Attribute Value being Passed: 0xB1D5BE24. */
        0xB1, 0xD5, 0xBE, 0x24
    };
    size_t stunMessageBufferLength = sizeof( stunMessageBuffer );

    resultIce = Ice_Init( &( context ),
                          &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       resultIce );

    localEndpoint.isPointToPoint = 1;
    localEndpoint.transportAddress.family = 0x01;
    localEndpoint.transportAddress.port = 8080;
    memcpy( ( void * ) &( localEndpoint.transportAddress.address[ 0 ] ),
            ( const void * ) ipAddress,
            sizeof( ipAddress ) );

    remoteEndpoint = localEndpoint; /* For simplicity, use the same endpoint for remote. */

    result = Ice_HandleStunPacket( &( context ),
                                   &( stunMessageBuffer[ 0 ] ),
                                   stunMessageBufferLength,
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
    IceResult_t resultIce;
    IceHandleStunPacketResult_t result;
    uint8_t stunMessageBuffer[] =
    {
        /* STUN header: Message Type = BINDING_SUCCESS_RESPONSE (0x0101), Length = 56 bytes (excluding 20 bytes header). */
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
    size_t stunMessageBufferLength = sizeof( stunMessageBuffer );

    resultIce = Ice_Init( &( context ),
                          &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       resultIce );

    localEndpoint.isPointToPoint = 1;
    localEndpoint.transportAddress.family = 0x01;
    localEndpoint.transportAddress.port = 8080;
    memcpy( ( void * ) &( localEndpoint.transportAddress.address[ 0 ] ),
            ( const void * ) ipAddress,
            sizeof( ipAddress ) );

    remoteEndpoint = localEndpoint; /* For simplicity, use the same endpoint for remote. */

    resultIce = Ice_AddHostCandidate( &( context ),
                                      &( localEndpoint ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       resultIce );

    remoteCandidateInfo.candidateType = ICE_CANDIDATE_TYPE_HOST;
    remoteCandidateInfo.remoteProtocol = ICE_SOCKET_PROTOCOL_UDP;
    remoteCandidateInfo.priority = 1000;
    remoteCandidateInfo.pEndpoint = &( remoteEndpoint );

    resultIce = Ice_AddRemoteCandidate( &( context ),
                                        &( remoteCandidateInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       resultIce );

    pCandidatePair = &context.pCandidatePairs[ 0 ];

    result = Ice_HandleStunPacket( &( context ),
                                   &( stunMessageBuffer[ 0 ] ),
                                   stunMessageBufferLength,
                                   &( localEndpoint ),
                                   &( remoteEndpoint ),
                                   &( pTransactionId ),
                                   &( pCandidatePair ) );

    TEST_ASSERT_EQUAL( ICE_HANDLE_STUN_PACKET_RESULT_OK,
                       result );
    TEST_ASSERT_EQUAL_PTR( &( stunMessageBuffer[ 8 ] ),
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
