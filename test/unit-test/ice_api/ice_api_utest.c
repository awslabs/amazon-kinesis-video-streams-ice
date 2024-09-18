/* Unity includes. */
#include "unity.h"
#include "catch_assert.h"

/* Standard includes. */
#include <stdlib.h>
#include <time.h>
#include <string.h>

/* API includes. */
#include "ice_api.h"

/* ===========================  EXTERN VARIABLES  =========================== */
IceResult_t testRandomFxn( uint8_t * pDest,
                           size_t length )
{
    // Fill the buffer with a repeating pattern
    for(size_t i = 0; i < length; i++)
    {
        pDest[i] = ( uint8_t )( i % 256 );
    }
    return ICE_RESULT_OK;
}

IceResult_t testCrc32Fxn( uint32_t initialResult,
                          const uint8_t * pBuffer,
                          size_t bufferLength,
                          uint32_t * pCalculatedCrc32 )
{
    // Initialize the CRC32 value
    uint32_t crc32 = initialResult;

    // Calculate the CRC32 using a simple algorithm
    for(size_t i = 0; i < bufferLength; i++)
    {
        crc32 ^= pBuffer[i];
        for(int j = 0; j < 8; j++)
        {
            if( crc32 & 1 )
                crc32 = ( crc32 >> 1 ) ^ 0xEDB88320;
            else
                crc32 = ( crc32 >> 1 );
        }
    }

    // Store the calculated CRC32 value
    *pCalculatedCrc32 = crc32;

    return ICE_RESULT_OK;
}

IceResult_t testHmacFxn( const uint8_t * pPassword,
                         size_t passwordLength,
                         const uint8_t * pBuffer,
                         size_t bufferLength,
                         uint8_t * pOutputBuffer,
                         uint16_t * pOutputBufferLength )
{
    // Assume a fixed HMAC output length of 32 bytes (256-bit)
    const uint16_t hmacLength = 32;

    // Check if the output buffer is large enough
    if( *pOutputBufferLength < hmacLength )
    {
        return ICE_RESULT_BAD_PARAM;
    }

    // Calculate the HMAC using a simple algorithm
    for(uint16_t i = 0; i < hmacLength; i++)
    {
        // Perform a simple XOR operation with the password and input buffer
        pOutputBuffer[i] = pPassword[i % passwordLength] ^ pBuffer[i % bufferLength];
    }

    // Update the output buffer length
    *pOutputBufferLength = hmacLength;

    return ICE_RESULT_OK;
}


/* ==============================  Test Cases  ============================== */

/**
 * @brief Validate ICE Init fail functionality for Bad Parameters.
 */
void test_iceInit_BadParams( void )
{
    IceContext_t context = { 0 };
    IceInitInfo_t initInfo = { 0 };
    IceResult_t result;
    IceCandidate_t localCandidateArray[ 0 ];
    IceCandidatePair_t candidatePairArray[ 0 ];
    TransactionIdStore_t transactionIdStore[ 0 ];
    uint8_t buffer[ 10 ];


    result = Ice_Init( NULL,
                       &( initInfo ));

    TEST_ASSERT_EQUAL( ICE_RESULT_BAD_PARAM,
                       result );

    result = Ice_Init( &( context ),
                       NULL );

    TEST_ASSERT_EQUAL( ICE_RESULT_BAD_PARAM,
                       result );

    initInfo.pLocalCandidatesArray = NULL;

    result = Ice_Init( &( context ),
                       &( initInfo ));

    TEST_ASSERT_EQUAL( ICE_RESULT_BAD_PARAM,
                       result );


    initInfo.pLocalCandidatesArray = &( localCandidateArray[ 0 ] );
    initInfo.pRemoteCandidatesArray = NULL;

    result = Ice_Init( &( context ),
                       &( initInfo ));

    TEST_ASSERT_EQUAL( ICE_RESULT_BAD_PARAM,
                       result );

    initInfo.pRemoteCandidatesArray = &( localCandidateArray[ 0 ] );
    initInfo.pCandidatePairsArray = NULL;

    result = Ice_Init( &( context ),
                       &( initInfo ));

    TEST_ASSERT_EQUAL( ICE_RESULT_BAD_PARAM,
                       result );

    initInfo.pCandidatePairsArray = &( candidatePairArray[ 0 ] );
    initInfo.pStunBindingRequestTransactionIdStore = NULL;

    result = Ice_Init( &( context ),
                       &( initInfo ));

    TEST_ASSERT_EQUAL( ICE_RESULT_BAD_PARAM,
                       result );

    initInfo.pStunBindingRequestTransactionIdStore = &( transactionIdStore[ 0 ] );
    initInfo.cryptoFunctions.randomFxn = NULL;

    result = Ice_Init( &( context ),
                       &( initInfo ));

    TEST_ASSERT_EQUAL( ICE_RESULT_BAD_PARAM,
                       result );

    initInfo.cryptoFunctions.randomFxn = testRandomFxn;
    initInfo.cryptoFunctions.crc32Fxn = NULL;

    result = Ice_Init( &( context ),
                       &( initInfo ));

    TEST_ASSERT_EQUAL( ICE_RESULT_BAD_PARAM,
                       result );

    initInfo.cryptoFunctions.crc32Fxn = testCrc32Fxn;
    initInfo.cryptoFunctions.hmacFxn = NULL;

    result = Ice_Init( &( context ),
                       &( initInfo ));

    TEST_ASSERT_EQUAL( ICE_RESULT_BAD_PARAM,
                       result );

    initInfo.cryptoFunctions.hmacFxn = testHmacFxn;
    initInfo.creds.pLocalUsername = NULL;

    result = Ice_Init( &( context ),
                       &( initInfo ));

    TEST_ASSERT_EQUAL( ICE_RESULT_BAD_PARAM,
                       result );

    initInfo.creds.pLocalUsername = &( buffer[ 0 ] );
    initInfo.creds.pLocalPassword = NULL;

    result = Ice_Init( &( context ),
                       &( initInfo ));

    TEST_ASSERT_EQUAL( ICE_RESULT_BAD_PARAM,
                       result );

    initInfo.creds.pLocalPassword = &( buffer[ 0 ] );
    initInfo.creds.pRemoteUsername = NULL;

    result = Ice_Init( &( context ),
                       &( initInfo ));

    TEST_ASSERT_EQUAL( ICE_RESULT_BAD_PARAM,
                       result );

    initInfo.creds.pRemoteUsername = &( buffer[ 0 ] );
    initInfo.creds.pRemotePassword = NULL;

    result = Ice_Init( &( context ),
                       &( initInfo ));

    TEST_ASSERT_EQUAL( ICE_RESULT_BAD_PARAM,
                       result );

    initInfo.creds.pRemotePassword = &( buffer[ 0 ] );
    initInfo.creds.pCombinedUsername = NULL;

    result = Ice_Init( &( context ),
                       &( initInfo ));

    TEST_ASSERT_EQUAL( ICE_RESULT_BAD_PARAM,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate ICE Init functionality.
 */
void test_iceInit( void )
{
    IceContext_t context;
    IceInitInfo_t initInfo = { 0 };
    IceResult_t result;
    IceCandidate_t localCandidateArray[ 10 ], remoteCandidateArray[ 10 ];
    IceCandidatePair_t candidatePairArray[ 100 ];
    TransactionIdStore_t transactionIdStore[ 16 ];

    initInfo.pLocalCandidatesArray = &( localCandidateArray[ 0 ] );
    initInfo.pRemoteCandidatesArray = &( remoteCandidateArray[ 0 ] );
    initInfo.pCandidatePairsArray = &( candidatePairArray[ 0 ] );
    initInfo.pStunBindingRequestTransactionIdStore = &( transactionIdStore[ 0 ] );
    initInfo.cryptoFunctions.randomFxn = testRandomFxn;
    initInfo.cryptoFunctions.crc32Fxn = testCrc32Fxn;
    initInfo.cryptoFunctions.hmacFxn = testHmacFxn;
    initInfo.creds.pLocalUsername = ( uint8_t * ) "localUsername";
    initInfo.creds.pLocalPassword = ( uint8_t * ) "localPassword";
    initInfo.creds.pRemoteUsername = ( uint8_t * )  "remoteUsername";
    initInfo.creds.pRemotePassword = ( uint8_t * ) "remotePassword";
    initInfo.creds.pCombinedUsername = ( uint8_t * ) "combinedUsername";
    initInfo.isControlling = 1;

    result = Ice_Init( &( context ),
                       &( initInfo ));

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       result );
    TEST_ASSERT_EQUAL( localCandidateArray,
                       context.pLocalCandidates );
    TEST_ASSERT_EQUAL( remoteCandidateArray,
                       context.pRemoteCandidates );
    TEST_ASSERT_EQUAL( candidatePairArray,
                       context.pCandidatePairs );
    TEST_ASSERT_EQUAL( transactionIdStore,
                       context.pStunBindingRequestTransactionIdStore );
    TEST_ASSERT_EQUAL( testRandomFxn,
                       context.cryptoFunctions.randomFxn );
    TEST_ASSERT_EQUAL( testCrc32Fxn,
                       context.cryptoFunctions.crc32Fxn );
    TEST_ASSERT_EQUAL( testHmacFxn,
                       context.cryptoFunctions.hmacFxn );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate ICE Add Host Candidate fail functionality for Bad Parameters.
 */
void test_iceAddHostCandidate_BadParams( void )
{
    IceContext_t context;
    IceEndpoint_t endPoint = { 0 };
    IceResult_t result;

    result = Ice_AddHostCandidate( NULL,
                                   &( endPoint ));

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
    IceContext_t context;
    IceEndpoint_t endPoint = { 0 };
    IceResult_t result;

    context.numLocalCandidates = 1000;
    context.maxLocalCandidates = 1000;

    result = Ice_AddHostCandidate( &( context ),
                                   &( endPoint ));

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
    IceCandidate_t localCandidates[5];
    IceEndpoint_t endPoint = { 0 };
    IceResult_t result;

    context.pLocalCandidates = &( localCandidates[ 0 ] );
    context.maxLocalCandidates = 5;
    context.numLocalCandidates = 0;

    endPoint.isPointToPoint = 1;
    const uint8_t * ipAddress = ( uint8_t * ) "192.168.1.100";
    endPoint.transportAddress.family = 0;
    memcpy( endPoint.transportAddress.address,
            ipAddress,
            16 );
    // endPoint.transportAddress.address = inet_addr(ipAddress);
    endPoint.transportAddress.port = 8080;

    result = Ice_AddHostCandidate( &( context ),
                                   &( endPoint ));

    TEST_ASSERT_EQUAL( ICE_RESULT_OK,
                       result );
    TEST_ASSERT_EQUAL( 1,
                       context.numLocalCandidates );
    TEST_ASSERT_EQUAL( ICE_CANDIDATE_TYPE_HOST,
                       context.pLocalCandidates[0].candidateType );
    TEST_ASSERT_EQUAL( 0,
                       context.pLocalCandidates[0].isRemote );
    TEST_ASSERT_EQUAL( 2113929471,
                       context.pLocalCandidates[0].priority );
    TEST_ASSERT_EQUAL( ICE_SOCKET_PROTOCOL_NONE,
                       context.pLocalCandidates[0].remoteProtocol );
    TEST_ASSERT_EQUAL( ICE_CANDIDATE_STATE_VALID,
                       context.pLocalCandidates[0].state );
}

/*-----------------------------------------------------------*/

