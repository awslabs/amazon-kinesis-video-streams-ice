/* Standard includes. */
#include <string.h>

/* API includes. */
#include "transaction_id_store.h"

TransactionIdStoreResult_t TransactionIdStore_Init( TransactionIdStore_t * pStore,
                                                    TransactionIdSlot_t * pTransactionIdSlots,
                                                    size_t numTransactionIdSlots )
{
    TransactionIdStoreResult_t result = TRANSACTION_ID_STORE_RESULT_OK;

    if( ( pStore == NULL ) ||
        ( pTransactionIdSlots == NULL ) ||
        ( numTransactionIdSlots == 0 ) )
    {
        result = TRANSACTION_ID_STORE_RESULT_BAD_PARAM;
    }

    if( result == TRANSACTION_ID_STORE_RESULT_OK )
    {
        pStore->pTransactionIdSlots = pTransactionIdSlots;
        pStore->numTransactionIdSlots = numTransactionIdSlots;
        pStore->writeIndex = 0;

        memset( &( pStore->pTransactionIdSlots[ 0 ] ),
                0,
                pStore->numTransactionIdSlots * sizeof( TransactionIdSlot_t ) );
    }

    return result;
}

/*----------------------------------------------------------------------------*/

TransactionIdStoreResult_t TransactionIdStore_Insert( TransactionIdStore_t * pStore,
                                                      uint8_t * pTransactionId )
{
    TransactionIdStoreResult_t result = TRANSACTION_ID_STORE_RESULT_OK;

    if( ( pStore == NULL ) ||
        ( pTransactionId == NULL ) )
    {
        result = TRANSACTION_ID_STORE_RESULT_BAD_PARAM;
    }

    if( result == TRANSACTION_ID_STORE_RESULT_OK )
    {
        memcpy( &( pStore->pTransactionIdSlots[ pStore->writeIndex ].transactionId[ 0 ] ),
                &( pTransactionId[ 0 ] ),
                STUN_HEADER_TRANSACTION_ID_LENGTH );
        pStore->pTransactionIdSlots[ pStore->writeIndex ].inUse = 1;

        pStore->writeIndex = ( pStore->writeIndex + 1 ) % pStore->numTransactionIdSlots;
    }

    return result;
}

/*----------------------------------------------------------------------------*/

TransactionIdStoreResult_t TransactionIdStore_HasId( TransactionIdStore_t * pStore,
                                                     uint8_t * pTransactionId )
{
    size_t i;
    TransactionIdStoreResult_t result = TRANSACTION_ID_STORE_RESULT_OK;

    if( ( pStore == NULL ) ||
        ( pTransactionId == NULL ) )
    {
        result = TRANSACTION_ID_STORE_RESULT_BAD_PARAM;
    }

    if( result == TRANSACTION_ID_STORE_RESULT_OK )
    {
        result = TRANSACTION_ID_STORE_RESULT_ID_NOT_FOUND;

        for( i = 0; i < pStore->numTransactionIdSlots; i++ )
        {
            if( pStore->pTransactionIdSlots[ i ].inUse == 1 )
            {
                if( memcmp( &( pStore->pTransactionIdSlots[ i ].transactionId[ 0 ] ),
                            &( pTransactionId[ 0 ] ),
                            STUN_HEADER_TRANSACTION_ID_LENGTH ) == 0 )
                {
                    result = TRANSACTION_ID_STORE_RESULT_OK;
                    break;
                }
            }
        }
    }

    return result;
}

/*----------------------------------------------------------------------------*/

TransactionIdStoreResult_t TransactionIdStore_Remove( TransactionIdStore_t * pStore,
                                                      uint8_t * pTransactionId )
{
    size_t i;
    TransactionIdStoreResult_t result = TRANSACTION_ID_STORE_RESULT_OK;

    if( ( pStore == NULL ) ||
        ( pTransactionId == NULL ) )
    {
        result = TRANSACTION_ID_STORE_RESULT_BAD_PARAM;
    }

    if( result == TRANSACTION_ID_STORE_RESULT_OK )
    {
        result = TRANSACTION_ID_STORE_RESULT_ID_NOT_FOUND;

        for( i = 0; i < pStore->numTransactionIdSlots; i++ )
        {
            if( pStore->pTransactionIdSlots[ i ].inUse == 1 )
            {
                if( memcmp( &( pStore->pTransactionIdSlots[ i ].transactionId[ 0 ] ),
                            &( pTransactionId[ 0 ] ),
                            STUN_HEADER_TRANSACTION_ID_LENGTH ) == 0 )
                {
                    memset( &( pStore->pTransactionIdSlots[ i ].transactionId[ 0 ] ),
                            0,
                            STUN_HEADER_TRANSACTION_ID_LENGTH );
                    pStore->pTransactionIdSlots[ i ].inUse = 0;

                    result = TRANSACTION_ID_STORE_RESULT_OK;
                    break;
                }
            }
        }
    }

    return result;
}

/*----------------------------------------------------------------------------*/
