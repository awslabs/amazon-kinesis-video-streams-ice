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
#define ICE_TURN_SERVER_ARRAY_SIZE               10
#define TRANSACTION_ID_SLOTS_ARRAY_ARRAY_SIZE    32

/* Specific TURN channel number used for testing. */
#define TEST_TURN_CHANNEL_NUMBER_START           ( 0x4010 )

IceInitInfo_t initInfo;
TransactionIdStore_t transactionIdStore;
IceCandidate_t localCandidateArray[ LOCAL_CANDIDATE_ARRAY_SIZE ];
IceCandidate_t remoteCandidateArray[ REMOTE_CANDIDATE_ARRAY_SIZE ];
IceCandidatePair_t candidatePairArray[ CANDIDATE_PAIR_ARRAY_SIZE ];
IceTurnServer_t iceTurnServerArray[ ICE_TURN_SERVER_ARRAY_SIZE ];
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

IceResult_t testHmacFxn_Wrong( const uint8_t * pPassword,
                               size_t passwordLength,
                               const uint8_t * pBuffer,
                               size_t bufferLength,
                               uint8_t * pOutputBuffer,
                               uint16_t * pOutputBufferLength )
{
    /* Assume a fixed HMAC output length of 16 bytes (128 bits). */
    const uint16_t hmacLength = 16; /* This HMAC Length is not correct. */
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

IceResult_t testMd5Fxn( const uint8_t * pBuffer,
                        size_t bufferLength,
                        uint8_t * pOutputBuffer,
                        uint16_t * pOutputBufferLength )
{
    IceResult_t ret = ICE_RESULT_OK;
    const uint16_t md5Length = 16U;
    uint16_t i;

    if( ( pBuffer == NULL ) ||
        ( pOutputBuffer == NULL ) ||
        ( pOutputBufferLength == NULL ) )
    {
        ret = ICE_RESULT_MD5_ERROR;
    }

    if( ret == ICE_RESULT_OK )
    {
        if( *pOutputBufferLength < md5Length )
        {
            ret = ICE_RESULT_MD5_ERROR;
        }
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
    initInfo.pTurnServerArray = &( iceTurnServerArray[ 0 ] );
    initInfo.pStunBindingRequestTransactionIdStore = &( transactionIdStore );
    initInfo.cryptoFunctions.randomFxn = testRandomFxn;
    initInfo.cryptoFunctions.crc32Fxn = testCrc32Fxn;
    initInfo.cryptoFunctions.hmacFxn = testHmacFxn;
    initInfo.cryptoFunctions.md5Fxn = testMd5Fxn;
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
    initInfo.turnServerArrayLength = ICE_TURN_SERVER_ARRAY_SIZE;
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

    memset( &( iceTurnServerArray[ 0 ] ),
            0,
            ICE_TURN_SERVER_ARRAY_SIZE * sizeof( IceTurnServer_t ) );

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
                                   &( remoteCandidate ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_BAD_PARAM,
                       result );

    result = Ice_AddCandidatePair( &( context ),
                                   NULL,
                                   &( remoteCandidate ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_BAD_PARAM,
                       result );

    result = Ice_AddCandidatePair( &( context ),
                                   &( localCandidate ),
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
                                   &( remoteCandidate ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_MAX_CANDIDATE_PAIR_THRESHOLD,
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

    context.numTurnServers = 1;
    localCandidate.pTurnServer = &( context.pTurnServers[ 0 ] );
    localCandidate.candidateType = ICE_CANDIDATE_TYPE_RELAY;
    localCandidate.pTurnServer->nextAvailableTurnChannelNumber = ICE_DEFAULT_TURN_CHANNEL_NUMBER_MAX + 1;

    result = Ice_AddCandidatePair( &( context ),
                                   &( localCandidate ),
                                   &( remoteCandidate ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_MAX_CHANNEL_NUMBER_THRESHOLD,
                       result );
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

    initInfo.cryptoFunctions.hmacFxn = testHmacFxn_Wrong;  /* We are initializing the context to a wrong HMAC Function. */

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
 * @brief Validate ICE Create Stun Packet for connectivity check functionality for HMAC return error.
 */
void test_iceCreateRequestForConnectivityCheck_HmacReturnError( void )
{
    IceContext_t context = { 0 };
    IceRemoteCandidateInfo_t remoteCandidateInfo = { 0 };
    IceEndpoint_t endpoint = { 0 };
    uint8_t stunMessageBuffer[ 128 ];
    size_t stunMessageBufferLength = 128;
    IceResult_t result;

    initInfo.cryptoFunctions.hmacFxn = testHmacFxn_ReturnError;

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
 * @brief Validate ICE Create Stun Packet for connectivity check functionality for CRC32 return error.
 */
void test_iceCreateRequestForConnectivityCheck_Crc32ReturnError( void )
{
    IceContext_t context = { 0 };
    IceRemoteCandidateInfo_t remoteCandidateInfo = { 0 };
    IceEndpoint_t endpoint = { 0 };
    uint8_t stunMessageBuffer[ 128 ];
    size_t stunMessageBufferLength = 128;
    IceResult_t result;

    initInfo.cryptoFunctions.crc32Fxn = testCrc32Fxn_ReturnError;

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

    TEST_ASSERT_EQUAL( ICE_RESULT_CRC32_ERROR,
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
 * @brief Validate ICE Create Stun Packet with TURN header
 * for connectivity check functionality.
 */
void test_iceCreateRequestForConnectivityCheck_TurnChannelHeader( void )
{
    IceContext_t context = { 0 };
    IceRemoteCandidateInfo_t remoteCandidateInfo = { 0 };
    IceEndpoint_t endpoint = { 0 };
    char * pUsername = "username";
    size_t usernameLength = strlen( pUsername );
    char * pPassword = "password";
    size_t passwordLength = strlen( pPassword );
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
        /* Attribute Value = 0x000000FF. */
        0x00, 0x00, 0x00, 0xFF,
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
        /* Channel Number. */
        0x40, 0x10,
        /* Content Length = 0x5C ( 0x48 + STUN header 20 bytes ). */
        0x00, 0x5C
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
    endpoint.transportAddress.family = 0;
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
                           context.pLocalCandidates[ 0 ].pTurnServer );

    context.pLocalCandidates[ 0 ].state = ICE_CANDIDATE_STATE_VALID;
    context.pLocalCandidates[ 0 ].pTurnServer->nextAvailableTurnChannelNumber = TEST_TURN_CHANNEL_NUMBER_START;

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

    result = Ice_CreateRequestForConnectivityCheck( &( context ),
                                                    &( context.pCandidatePairs[ 0 ] ),
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
        0x07, 0x06, 0x05, 0x04,0x03, 0x02, 0x01, 0x00,
        /* Attribute Type = USE-CANDIDATE (0x0025), Length = 0 bytes. */
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
 * @brief Validate ICE Create Stun Packet with TURN header
 * for nominating request.
 */
void test_iceCreateRequestForNominatingCandidatePair_TurnChannelHeader( void )
{
    IceContext_t context = { 0 };
    IceRemoteCandidateInfo_t remoteCandidateInfo = { 0 };
    IceEndpoint_t endpoint = { 0 };
    char * pUsername = "username";
    size_t usernameLength = strlen( pUsername );
    char * pPassword = "password";
    size_t passwordLength = strlen( pPassword );
    uint8_t stunMessageBuffer[ 128 ];
    size_t stunMessageBufferLength = 128;
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
        /* Attribute Value = 0x000000FF. */
        0x00, 0x00, 0x00, 0xFF,
        /* Attribute type = ICE-CONTROLLING (0x802A), Length = 8 bytes. */
        0x80, 0x2A, 0x00, 0x08,
        /* Attribute Value = 0x0706050403020100. */
        0x07, 0x06, 0x05, 0x04,0x03, 0x02, 0x01, 0x00,
        /* Attribute Type = USE-CANDIDATE (0x0025), Length = 0 bytes. */
        0x00, 0x25, 0x00, 0x00,
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
        /* Channel Number. */
        0x40, 0x10,
        /* Content Length = 0x60 ( 0x4C + STUN header 20 bytes ). */
        0x00, 0x60
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
    endpoint.transportAddress.family = 0;
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
                           context.pLocalCandidates[ 0 ].pTurnServer );

    context.pLocalCandidates[ 0 ].state = ICE_CANDIDATE_STATE_VALID;
    context.pLocalCandidates[ 0 ].pTurnServer->nextAvailableTurnChannelNumber = TEST_TURN_CHANNEL_NUMBER_START;

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

    result = Ice_CreateRequestForNominatingCandidatePair( &( context ),
                                                          &( context.pCandidatePairs[ 0 ] ),
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
 * @brief Validate ICE Create TURN refresh packet but the buffer
 * is too small to store STUN header.
 */
void test_iceCreateRequestForNominatingCandidatePair_StunBufferTooSmallToInit( void )
{
    IceContext_t context = { 0 };
    uint8_t stunMessageBuffer[ 10 ];
    size_t stunMessageBufferLength = sizeof( stunMessageBuffer );
    IceResult_t result;
    IceCandidate_t localCandidate = { 0 };

    result = Ice_Init( &( context ),
                       &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       result );

    memset( &( localCandidate ), 0, sizeof( IceCandidate_t ) );
    context.numTurnServers = 1;
    localCandidate.pTurnServer = &( context.pTurnServers[ 0 ] );

    result = Ice_CreateRefreshRequest( &( context ),
                                       &( localCandidate ),
                                       0,
                                       &( stunMessageBuffer[ 0 ] ),
                                       &( stunMessageBufferLength ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_STUN_ERROR,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate ICE Create TURN refresh packet but the buffer
 * is too small to store STUN attribute lifetime.
 */
void test_iceCreateRequestForNominatingCandidatePair_StunBufferTooSmallToAddLifetime( void )
{
    IceContext_t context = { 0 };
    uint8_t stunMessageBuffer[ 20 ];
    size_t stunMessageBufferLength = sizeof( stunMessageBuffer );
    IceResult_t result;
    IceCandidate_t localCandidate = { 0 };

    result = Ice_Init( &( context ),
                       &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       result );

    memset( &( localCandidate ), 0, sizeof( IceCandidate_t ) );
    context.numTurnServers = 1;
    localCandidate.pTurnServer = &( context.pTurnServers[ 0 ] );

    result = Ice_CreateRefreshRequest( &( context ),
                                       &( localCandidate ),
                                       0,
                                       &( stunMessageBuffer[ 0 ] ),
                                       &( stunMessageBufferLength ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_STUN_ERROR_ADD_LIFETIME,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate ICE Create TURN refresh packet but the buffer
 * is too small to store STUN attribute username.
 */
void test_iceCreateRequestForNominatingCandidatePair_StunBufferTooSmallToAddUsername( void )
{
    IceContext_t context = { 0 };
    uint8_t stunMessageBuffer[ 28 ];
    size_t stunMessageBufferLength = sizeof( stunMessageBuffer );
    IceResult_t result;
    IceCandidate_t localCandidate = { 0 };
    char * pUsername = "username";
    size_t usernameLength = strlen( pUsername );
    char * pPassword = "password";
    size_t passwordLength = strlen( pPassword );

    result = Ice_Init( &( context ),
                       &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       result );

    memset( &( localCandidate ), 0, sizeof( IceCandidate_t ) );
    context.numTurnServers = 1;
    localCandidate.pTurnServer = &( context.pTurnServers[ 0 ] );
    memcpy( &( localCandidate.pTurnServer->userName[ 0 ] ),
            pUsername,
            usernameLength );
    localCandidate.pTurnServer->userNameLength = usernameLength;
    memcpy( &( localCandidate.pTurnServer->password[ 0 ] ),
            pPassword,
            passwordLength );
    localCandidate.pTurnServer->passwordLength = passwordLength;

    result = Ice_CreateRefreshRequest( &( context ),
                                       &( localCandidate ),
                                       0,
                                       &( stunMessageBuffer[ 0 ] ),
                                       &( stunMessageBufferLength ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_STUN_ERROR_ADD_USERNAME,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate ICE Create TURN refresh packet but the buffer
 * is too small to store STUN attribute realm.
 */
void test_iceCreateRequestForNominatingCandidatePair_StunBufferTooSmallToAddRealm( void )
{
    IceContext_t context = { 0 };
    uint8_t stunMessageBuffer[ 40 ];
    size_t stunMessageBufferLength = sizeof( stunMessageBuffer );
    IceResult_t result;
    IceCandidate_t localCandidate = { 0 };
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

    memset( &( localCandidate ), 0, sizeof( IceCandidate_t ) );
    context.numTurnServers = 1;
    localCandidate.pTurnServer = &( context.pTurnServers[ 0 ] );
    memcpy( &( localCandidate.pTurnServer->userName[ 0 ] ),
            pUsername,
            usernameLength );
    localCandidate.pTurnServer->userNameLength = usernameLength;
    memcpy( &( localCandidate.pTurnServer->password[ 0 ] ),
            pPassword,
            passwordLength );
    localCandidate.pTurnServer->passwordLength = passwordLength;
    memcpy( &( localCandidate.pTurnServer->realm[ 0 ] ),
            pRealm,
            realmLength );
    localCandidate.pTurnServer->realmLength = realmLength;
    memcpy( &( localCandidate.pTurnServer->nonce[ 0 ] ),
            pNonce,
            nonceLength );
    localCandidate.pTurnServer->nonceLength = nonceLength;

    result = Ice_CreateRefreshRequest( &( context ),
                                       &( localCandidate ),
                                       0,
                                       &( stunMessageBuffer[ 0 ] ),
                                       &( stunMessageBufferLength ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_STUN_ERROR_ADD_REALM,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate ICE Create TURN refresh packet but the buffer
 * is too small to store STUN attribute nonce.
 */
void test_iceCreateRequestForNominatingCandidatePair_StunBufferTooSmallToAddNonce( void )
{
    IceContext_t context = { 0 };
    uint8_t stunMessageBuffer[ 52 ];
    size_t stunMessageBufferLength = sizeof( stunMessageBuffer );
    IceResult_t result;
    IceCandidate_t localCandidate = { 0 };
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

    memset( &( localCandidate ), 0, sizeof( IceCandidate_t ) );
    context.numTurnServers = 1;
    localCandidate.pTurnServer = &( context.pTurnServers[ 0 ] );
    memcpy( &( localCandidate.pTurnServer->userName[ 0 ] ),
            pUsername,
            usernameLength );
    localCandidate.pTurnServer->userNameLength = usernameLength;
    memcpy( &( localCandidate.pTurnServer->password[ 0 ] ),
            pPassword,
            passwordLength );
    localCandidate.pTurnServer->passwordLength = passwordLength;
    memcpy( &( localCandidate.pTurnServer->realm[ 0 ] ),
            pRealm,
            realmLength );
    localCandidate.pTurnServer->realmLength = realmLength;
    memcpy( &( localCandidate.pTurnServer->nonce[ 0 ] ),
            pNonce,
            nonceLength );
    localCandidate.pTurnServer->nonceLength = nonceLength;

    result = Ice_CreateRefreshRequest( &( context ),
                                       &( localCandidate ),
                                       0,
                                       &( stunMessageBuffer[ 0 ] ),
                                       &( stunMessageBufferLength ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_STUN_ERROR_ADD_NONCE,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate ICE Add Candidate Pair fail functionality for NULL stun context.
 */
void test_iceFinalizeStunPacket_StunError_NullStunContext( void )
{
    IceContext_t context = { 0 };
    size_t bufferLength = 128;
    IceResult_t result;

    result = Ice_Init( &( context ),
                       &( initInfo ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       result );

    result = Ice_FinalizeStunPacket( &( context ),
                                     NULL,
                                     context.creds.pLocalPassword,
                                     context.creds.localPasswordLength,
                                     &( bufferLength ) );

    TEST_ASSERT_EQUAL( ICE_RESULT_STUN_ERROR,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate ICE Same Transport Address check fail functionality for Bad Parameters.
 */
void test_iceIsSameTransportAddress_BadParms( void )
{
    IceTransportAddress_t transportAddress1;
    IceTransportAddress_t transportAddress2;
    uint8_t result;

    transportAddress1.port = 3478;
    transportAddress1.family = 0;
    memcpy( ( void * ) &( transportAddress1.address[ 0 ] ),
            ( const void * ) &( ipAddress[ 0 ] ),
            sizeof( ipAddress ) );

    transportAddress2.port = 3478;
    transportAddress2.family = 1;
    memcpy( ( void * ) &( transportAddress2.address[ 0 ] ),
            ( const void * ) ipAddress,
            sizeof( ipAddress ) );

    result = Ice_IsSameTransportAddress( NULL,
                                         &( transportAddress2 ) );

    TEST_ASSERT_EQUAL( 0,
                       result );

    result = Ice_IsSameTransportAddress( &( transportAddress1 ),
                                         NULL );

    TEST_ASSERT_EQUAL( 0,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate ICE Same Transport Address check fail functionality.
 */
void test_iceIsSameTransportAddress_DifferentFamily( void )
{
    IceTransportAddress_t transportAddress1;
    IceTransportAddress_t transportAddress2;
    uint8_t result;

    transportAddress1.port = 3478;
    transportAddress1.family = 0;
    memcpy( ( void * ) &( transportAddress1.address[ 0 ] ),
            ( const void * ) &( ipAddress[ 0 ] ),
            sizeof( ipAddress ) );

    transportAddress2.port = 3478;
    transportAddress2.family = 1;
    memcpy( ( void * ) &( transportAddress2.address[ 0 ] ),
            ( const void * ) &( ipAddress[ 0 ] ),
            sizeof( ipAddress ) );

    result = Ice_IsSameTransportAddress( &( transportAddress1 ),
                                         &( transportAddress2 ) );

    TEST_ASSERT_EQUAL( 0,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate ICE Same Transport Address check fail functionality.
 */
void test_iceIsSameTransportAddress_DifferentPort( void )
{
    IceTransportAddress_t transportAddress1;
    IceTransportAddress_t transportAddress2;
    uint8_t result;

    transportAddress1.port = 3478;
    transportAddress1.family = 1;
    memcpy( ( void * ) &( transportAddress1.address[ 0 ] ),
            ( const void * ) &( ipAddress[ 0 ] ),
            sizeof( ipAddress ) );

    transportAddress2.port = 2002;
    transportAddress2.family = 1;
    memcpy( ( void * ) &( transportAddress2.address[ 0 ] ),
            ( const void * ) &( ipAddress[ 0 ] ),
            sizeof( ipAddress ) );

    result = Ice_IsSameTransportAddress( &( transportAddress1 ),
                                         &( transportAddress2 ) );

    TEST_ASSERT_EQUAL( 0,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate ICE Same Transport Address check fail functionality.
 */
void test_iceIsSameTransportAddress_DifferentIpAddress( void )
{
    IceTransportAddress_t transportAddress1;
    IceTransportAddress_t transportAddress2;
    uint8_t ipAddress1[] = { 0xC0, 0xA8, 0x01, 0x64 }; /* "192.168.1.100". */
    uint8_t ipAddress2[] = { 0x78, 0xA8, 0x01, 0x6E }; /* "192.168.1.110". */
    uint8_t result;

    transportAddress1.port = 3478;
    transportAddress1.family = 1;
    memcpy( ( void * ) &( transportAddress1.address[ 0 ] ),
            ( const void * ) &( ipAddress1[ 0 ] ),
            sizeof( ipAddress1 ) );

    transportAddress2.port = 3478;
    transportAddress2.family = 1;
    memcpy( ( void * ) &( transportAddress2.address[ 0 ] ),
            ( const void * ) &( ipAddress2[ 0 ] ),
            sizeof( ipAddress2 ) );


    result = Ice_IsSameTransportAddress( &( transportAddress1 ),
                                         &( transportAddress2 ) );

    TEST_ASSERT_EQUAL( 0,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate ICE Same IP Address check fail functionality.
 */
void test_iceIsSameIPAddress_BadParams( void )
{
    IceTransportAddress_t transportAddress1;
    IceTransportAddress_t transportAddress2;
    uint8_t result;

    transportAddress1.family = 0x01;
    transportAddress2.family = 0x02;

    result = Ice_IsSameIpAddress( NULL,
                                  &( transportAddress2 ) );

    TEST_ASSERT_EQUAL( 0,
                       result );

    result = Ice_IsSameIpAddress( &( transportAddress1 ),
                                  NULL );

    TEST_ASSERT_EQUAL( 0,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate ICE Same IP Address check fail functionality.
 */
void test_iceIsSameIPAddress_DifferentIpAddress( void )
{
    IceTransportAddress_t transportAddress1;
    IceTransportAddress_t transportAddress2;
    uint8_t ipAddress[] = { 0xC0, 0xA8, 0x01, 0x64 };        /* "192.168.1.100". */
    uint8_t ipAddress2[] = { 0x78, 0xA8, 0x01, 0x6E };       /* "192.168.1.110". */
    uint8_t result;

    transportAddress1.family = 0x01;
    memcpy( ( void * ) &( transportAddress1.address[ 0 ] ),
            ( const void * ) ipAddress,
            sizeof( ipAddress ) );

    transportAddress2.family = 0x01;
    memcpy( ( void * ) &( transportAddress2.address[ 0 ] ),
            ( const void * ) ipAddress2,
            sizeof( ipAddress2 ) );


    result = Ice_IsSameIpAddress( &( transportAddress1 ),
                                  &( transportAddress2 ) );

    TEST_ASSERT_EQUAL( 0,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate ICE Compute Candidate Priority check fail functionality.
 */
void test_iceComputeCandidatePriority_Invalid( void )
{
    IceCandidateType_t candidateType;
    uint8_t isPointToPoint;
    uint64_t result;

    candidateType = 5; /* Unkown Type. */
    isPointToPoint = 1;

    /* Priority calculation formula:
     * priority = ( 2^24 ) * ( type preference ) +
     *            ( 2^8 )  * ( local preference) +
     *            ( 2^0 )  * ( 256 - component ID ).
     *
     * In this test,
     * priority = ( 2^24 ) * ( 0 ) + ( 2^8 ) * ( 0 ) + 255 = 255.
     */

    result = Ice_ComputeCandidatePriority( candidateType,
                                           isPointToPoint );

    TEST_ASSERT_EQUAL( 255,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate ICE Compute Candidate Priority check functionality for Peer Reflexive Candidate Type.
 */
void test_iceComputeCandidatePriority_PeerReflexive( void )
{
    IceCandidateType_t candidateType;
    uint8_t isPointToPoint;
    uint64_t result;

    candidateType = ICE_CANDIDATE_TYPE_PEER_REFLEXIVE;
    isPointToPoint = 1;

    /* Priority calculation formula:
     * priority = ( 2^24 ) * ( type preference ) +
     *            ( 2^8 )  * ( local preference) +
     *            ( 2^0 )  * ( 256 - component ID ).
     *
     * In this test,
     * priority = ( 2^24 ) * ( 110 ) + ( 2^8 ) * ( 0 ) + 255 = 1845494015.
     */

    result = Ice_ComputeCandidatePriority( candidateType,
                                           isPointToPoint );

    TEST_ASSERT_EQUAL( 1845494015,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate ICE Compute Candidate Priority check functionality for Relayed Candidate Type.
 */
void test_iceComputeCandidatePriority_Relayed( void )
{
    IceCandidateType_t candidateType;
    uint8_t isPointToPoint;
    uint64_t result;

    candidateType = ICE_CANDIDATE_TYPE_RELAY;
    isPointToPoint = 1;

    /* Priority calculation formula:
     * priority = ( 2^24 ) * ( type preference ) +
     *            ( 2^8 )  * ( local preference) +
     *            ( 2^0 )  * ( 256 - component ID ).
     *
     * In this test,
     * priority = ( 2^24 ) * ( 0 ) + ( 2^8 ) * ( 0 ) + 255 = 255.
     */

    result = Ice_ComputeCandidatePriority( candidateType,
                                           isPointToPoint );

    TEST_ASSERT_EQUAL( 255,
                       result );
}

/*-----------------------------------------------------------*/
