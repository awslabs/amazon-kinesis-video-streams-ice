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
    TransactionIdSlot_t transactionIdSlot = { 0 };
    size_t numTransactionIdSlots = 1;
    TransactionIdStoreResult_t result;


    result = TransactionIdStore_Init( NULL,
                                      &( transactionIdSlot ),
                                      numTransactionIdSlots );

    TEST_ASSERT_EQUAL( TRANSACTION_ID_STORE_RESULT_BAD_PARAM,
                       result );

    result = TransactionIdStore_Init( &( transactionIdStore ),
                                      NULL,
                                      numTransactionIdSlots );

    TEST_ASSERT_EQUAL( TRANSACTION_ID_STORE_RESULT_BAD_PARAM,
                       result );

    result = TransactionIdStore_Init( &( transactionIdStore ),
                                      &( transactionIdSlot ),
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
