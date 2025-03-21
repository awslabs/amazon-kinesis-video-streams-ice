#ifndef TRANSACTION_ID_STORE_H
#define TRANSACTION_ID_STORE_H

/* Standard includes. */
#include <stdint.h>
#include <stddef.h>

/* STUN includes. */
#include "stun_data_types.h"

/*----------------------------------------------------------------------------*/

typedef enum TransactionIdStoreResult
{
    TRANSACTION_ID_STORE_RESULT_OK,
    TRANSACTION_ID_STORE_RESULT_BAD_PARAM,
    TRANSACTION_ID_STORE_RESULT_ID_NOT_FOUND,
    TRANSACTION_ID_STORE_RESULT_STORE_FULL
} TransactionIdStoreResult_t;

/*----------------------------------------------------------------------------*/

typedef struct TransactionIdSlot
{
    uint8_t inUse;
    uint8_t transactionId[ STUN_HEADER_TRANSACTION_ID_LENGTH ];
} TransactionIdSlot_t;

typedef struct TransactionIdStore
{
    TransactionIdSlot_t * pTransactionIdSlots;
    size_t numTransactionIdSlots;
} TransactionIdStore_t;

/*----------------------------------------------------------------------------*/

TransactionIdStoreResult_t TransactionIdStore_Init( TransactionIdStore_t * pStore,
                                                    TransactionIdSlot_t * pTransactionIdSlots,
                                                    size_t numTransactionIdSlots );

TransactionIdStoreResult_t TransactionIdStore_Insert( TransactionIdStore_t * pStore,
                                                      uint8_t * pTransactionId );

TransactionIdStoreResult_t TransactionIdStore_HasId( TransactionIdStore_t * pStore,
                                                     uint8_t * pTransactionId );

TransactionIdStoreResult_t TransactionIdStore_Remove( TransactionIdStore_t * pStore,
                                                      uint8_t * pTransactionId );

/*----------------------------------------------------------------------------*/

#endif /* TRANSACTION_ID_STORE_H */
