/* Unity includes. */
#include "unity.h"
#include "catch_assert.h"

/* Standard includes. */
#include <stdlib.h>
#include <time.h>
#include <string.h>

/* API includes. */
#include "transaction_id_store.h"

/* ===========================  EXTERN VARIABLES    =========================== */

/* ===========================  EXTERN FUNCTIONS   =========================== */

/*-----------------------------------------------------------*/

void setUp( void )
{
}

/*-----------------------------------------------------------*/

void tearDown( void )
{
}

/* ==============================  Test Cases  ============================== */

/**
 * @brief Validate ICE Transaction ID Init fail functionality for Bad Parameters.
 */
void test_iceTransactionIdStore_Init_BadParams( void )
{
    TransactionIdStore_t transactionIdStore;
    TransactionIdSlot_t transactionIdSlotArray[ 32 ];
    size_t transactionIdSlotArraySize = 32;
    TransactionIdStoreResult_t result;

    result = TransactionIdStore_Init( NULL,
                                      &( transactionIdSlotArray[ 0 ] ),
                                      transactionIdSlotArraySize );

    TEST_ASSERT_EQUAL( TRANSACTION_ID_STORE_RESULT_BAD_PARAM,
                       result );

    result = TransactionIdStore_Init( &( transactionIdStore ),
                                      NULL,
                                      transactionIdSlotArraySize );

    TEST_ASSERT_EQUAL( TRANSACTION_ID_STORE_RESULT_BAD_PARAM,
                       result );

    result = TransactionIdStore_Init( &( transactionIdStore ),
                                      &( transactionIdSlotArray[ 0 ] ),
                                      0 );

    TEST_ASSERT_EQUAL( TRANSACTION_ID_STORE_RESULT_BAD_PARAM,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate ICE Transaction ID Store fail functionality for Bad Parameters.
 */
void test_iceTransactionIdStore_Insert_BadParams( void )
{
    TransactionIdStore_t transactionIdStore;
    uint8_t transactionID[ STUN_HEADER_TRANSACTION_ID_LENGTH ];
    TransactionIdStoreResult_t result;

    result = TransactionIdStore_Insert( NULL,
                                        &( transactionID[ 0 ] ) );

    TEST_ASSERT_EQUAL( TRANSACTION_ID_STORE_RESULT_BAD_PARAM,
                       result );

    result = TransactionIdStore_Insert( &( transactionIdStore ),
                                        NULL );

    TEST_ASSERT_EQUAL( TRANSACTION_ID_STORE_RESULT_BAD_PARAM,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate ICE Transaction ID Check ID fail functionality for Bad Parameters.
 */
void test_iceTransactionIdStore_HasId_BadParams( void )
{
    TransactionIdStore_t transactionIdStore;
    uint8_t transactionID[ STUN_HEADER_TRANSACTION_ID_LENGTH ];
    TransactionIdStoreResult_t result;

    result = TransactionIdStore_HasId( NULL,
                                       &( transactionID[ 0 ] ) );

    TEST_ASSERT_EQUAL( TRANSACTION_ID_STORE_RESULT_BAD_PARAM,
                       result );

    result = TransactionIdStore_HasId( &( transactionIdStore ),
                                       NULL );

    TEST_ASSERT_EQUAL( TRANSACTION_ID_STORE_RESULT_BAD_PARAM,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate ICE Transaction ID Remove ID fail functionality for Bad Parameters.
 */
void test_iceTransactionIdStore_Remove_BadParams( void )
{
    TransactionIdStore_t transactionIdStore;
    uint8_t transactionID[ STUN_HEADER_TRANSACTION_ID_LENGTH ];
    TransactionIdStoreResult_t result;

    result = TransactionIdStore_Remove( NULL,
                                        &( transactionID[ 0 ] ) );

    TEST_ASSERT_EQUAL( TRANSACTION_ID_STORE_RESULT_BAD_PARAM,
                       result );

    result = TransactionIdStore_Remove( &( transactionIdStore ),
                                        NULL );

    TEST_ASSERT_EQUAL( TRANSACTION_ID_STORE_RESULT_BAD_PARAM,
                       result );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate TransactionIdStore_Remove returns TRANSACTION_ID_STORE_RESULT_ID_NOT_FOUND
 * when the input transaction ID is not found in the store.
 */
void test_iceTransactionIdStore_Remove_TransactionIDNotFound( void )
{
    TransactionIdStore_t transactionIdStore;
    const size_t transactionIdMaxNum = 32;
    TransactionIdSlot_t transactionIdSlots[ transactionIdMaxNum ];
    uint8_t commonTransactionID[] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16
    };
    uint8_t targetTransactionID[] = {
        0xFF, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16
    };
    TransactionIdStoreResult_t result;

    result = TransactionIdStore_Init( &( transactionIdStore ),
                                      &( transactionIdSlots[ 0 ] ),
                                      transactionIdMaxNum  );

    TEST_ASSERT_EQUAL( TRANSACTION_ID_STORE_RESULT_OK,
                       result );

    /* Store two transaction IDs in the store at index 0,2. */
    transactionIdStore.numTransactionIdSlots = 3U;
    transactionIdSlots[0].inUse = 1U;
    memcpy( transactionIdSlots[0].transactionId, commonTransactionID, STUN_HEADER_TRANSACTION_ID_LENGTH );

    transactionIdSlots[1].inUse = 0U;

    transactionIdSlots[2].inUse = 1U;
    memcpy( transactionIdSlots[2].transactionId, commonTransactionID, STUN_HEADER_TRANSACTION_ID_LENGTH );

    result = TransactionIdStore_Remove( &transactionIdStore,
                                        &( targetTransactionID[ 0 ] ) );

    TEST_ASSERT_EQUAL( TRANSACTION_ID_STORE_RESULT_ID_NOT_FOUND,
                       result );
}

/*-----------------------------------------------------------*/
