/* Standard includes. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Ice incluudes. */
#include "ice_api.h"
#include "ice_data_types.h"
#include "stun_serializer.h"

typedef enum RequestType{
    NOMINATING_CANDIDATE,
    CONNECTIVITY_CHECK,
    RESPONSE_FOR_REQUEST
} RequestType_t;

TransactionIdStore_t buffer[MAX_STORED_TRANSACTION_ID_COUNT] = { 0 };

/*--------------------------------------------------------------------------------------------------------------------------------------------------------------------*/

void test_IceAgentInit( IceAgent_t * iceAgent )
{
    IceResult_t result;

    char str1[] = "local", str2[] = "abc123", str3[] = "remote", str4[] = "xyz789";
    char str5[] = "remote:local";

    result = Ice_CreateIceAgent( iceAgent, str1, str2, str3, str4, str5, buffer );
    
    if( result == ICE_RESULT_OK )
    {
        printf("Creation of Ice Agent is successful.\n");
    }
    else
    {
        printf("Creation of Ice Agent failed.\n");
    }
}

/*--------------------------------------------------------------------------------------------------------------------------------------------------------------------*/

void test_GenerateHostCandidate( IceAgent_t * iceAgent )
{
    printf( "\nAdding Local Host candidates\n\n");

    IceResult_t result ;
    StunAttributeAddress_t stunAddress1, stunAddress2;
    IceIPAddress_t iceIpAddress1, iceIpAddress2;
    IceCandidate_t localCandidate;

    uint8_t ipAddress1V6[] = { 0x20, 0x01, 0x0D, 0xB8, 0x12, 0x34, 0x56, 0x78,
                                0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77 }; 
    uint8_t ipAddress2V6[] = { 0x21, 0x02, 0x0D, 0xB8, 0x12, 0x34, 0x56, 0x78,
                                0x00, 0x11, 0x52, 0x33, 0x44, 0x56, 0x66, 0x77 };

    /* Initialise ICE IP address */    
    stunAddress1.family = STUN_ADDRESS_IPv6;
    stunAddress1.port = 32853;
    memcpy( stunAddress1.address, ipAddress1V6, STUN_IPV6_ADDRESS_SIZE );
    
    iceIpAddress1.ipAddress = stunAddress1;
    iceIpAddress1.isPointToPoint = 0;

    stunAddress2.family = STUN_ADDRESS_IPv6;
    stunAddress2.port = 12345;
    memcpy( stunAddress2.address, ipAddress2V6, STUN_IPV6_ADDRESS_SIZE );
    
    /* Initialise ICE IP address */
    iceIpAddress2.ipAddress = stunAddress2;
    iceIpAddress2.isPointToPoint = 1;

    result = Ice_AddHostCandidate( iceIpAddress1, iceAgent, &localCandidate );

    if( result == ICE_RESULT_OK )
    {
        printf("Local Candidate --> Port : %d\n", iceAgent->localCandidates[ 0 ].ipAddress.ipAddress.port );
    }
    else
    {
        printf( "\nAdding host candidate 1 failed\n" );
    }

    result = Ice_AddHostCandidate( iceIpAddress2, iceAgent, &localCandidate );
    
    if( result == ICE_RESULT_OK )
    {
        printf("Local Candidate --> Port : %d\n", iceAgent->localCandidates[ 1 ].ipAddress.ipAddress.port );
    }
    else
    {
        printf( "\nAdding host candidate 2 failed\n" );
    }
}

/*--------------------------------------------------------------------------------------------------------------------------------------------------------------------*/

void test_GenerateSrflxCandidate( IceAgent_t * iceAgent )
{
    printf( "\nAdding Local Srflx candidates\n");

    IceResult_t result ;
    StunAttributeAddress_t stunAddress;
    IceIPAddress_t iceIpAddress;
    uint8_t stunMessageBuffer[ 1024 ] = { 0 };
    int i;
    IceCandidate_t srflxCandidate;

    uint8_t ipAddressV6[] = { 0x20, 0x01, 0x0D, 0xB8, 0x12, 0x34, 0x56, 0x78,
                              0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77 };

    uint8_t transactionId[] = { 0xB7, 0xE7, 0xA7, 0x01, 0xBC, 0x34,
                                0xD6, 0x86, 0xFA, 0x87, 0xDF, 0xAE };

    /* Initialise ICE IP address */
    stunAddress.family = STUN_ADDRESS_IPv6;
    stunAddress.port = 11111;
    memcpy( stunAddress.address, ipAddressV6, STUN_IPV6_ADDRESS_SIZE );
    
    iceIpAddress.ipAddress = stunAddress;
    iceIpAddress.isPointToPoint = 0;

    result = Ice_AddSrflxCandidate( iceIpAddress, iceAgent, &srflxCandidate, stunMessageBuffer, transactionId );

    if( result == ICE_RESULT_OK )
    {
        printf("\nLocal Candidate --> Port %d\n", iceAgent->localCandidates[ 2 ].ipAddress.ipAddress.port );
        
        printf( "\nSerialized Message for Srflx request :\n\n" );
        
        for( i=0 ; i < 1024; i++ )
        {
            printf( "0x%02x ", stunMessageBuffer[ i ] );
        }

        printf(" \n\nTransaction Id Count %d",iceAgent->pStunBindingRequestTransactionIdStore->transactionIdCount );
    }
    else
    {
        printf( "Adding SRFLX csandidate failed\n" );
    }
}

/*--------------------------------------------------------------------------------------------------------------------------------------------------------------------*/

void test_GenerateRemoteCandidate( IceAgent_t * iceAgent )
{
    printf( "\n\nAdding Remote candidates\n\n");
    
    IceResult_t result ;
    StunAttributeAddress_t stunAddress;
    IceIPAddress_t iceIpAddress;
    IceCandidate_t * remoteCandidate = malloc( sizeof( struct IceCandidate ) );

    uint8_t ipAddressV6[] = { 0x20, 0x01, 0x0D, 0xB8, 0x12, 0x34, 0x56, 0x78,
                              0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77 }; 

    /* Initialise ICE IP address */    
    stunAddress.family = STUN_ADDRESS_IPv6;
    stunAddress.port = 54321;
    memcpy( stunAddress.address, ipAddressV6, STUN_IPV6_ADDRESS_SIZE );

    iceIpAddress.ipAddress = stunAddress;
    iceIpAddress.isPointToPoint = 0;

    result = Ice_AddRemoteCandidate( iceAgent, ICE_CANDIDATE_TYPE_SERVER_REFLEXIVE, remoteCandidate, iceIpAddress, ICE_SOCKET_PROTOCOL_TCP, 5 );

    if( result == ICE_RESULT_OK )
    {
        printf("Remote Candidate --> Port %d\n", iceAgent->remoteCandidates[ 0 ].ipAddress.ipAddress.port );
    }
    else
    {
        printf( "Adding remote candidate failed\n" );
    }
}

/*--------------------------------------------------------------------------------------------------------------------------------------------------------------------*/

void test_DisplayCandidatePairs( IceAgent_t * iceAgent )
{
    printf( "\n\nPrinting Candidate Pairs\n" );
    int i;
    for( i = 0; i < ICE_MAX_CANDIDATE_PAIR_COUNT; i++ )
    {
        if( iceAgent->iceCandidatePairs[i].state != ICE_CANDIDATE_PAIR_STATE_INVALID )
        {
            printf( "\nLocal Candidate Port %d--> Remote Candidate Port : %d\n", iceAgent->iceCandidatePairs[i].local->ipAddress.ipAddress.port , iceAgent->iceCandidatePairs[i].remote->ipAddress.ipAddress.port );
        }
        else
        {
            break;
        }
    }
}

/*--------------------------------------------------------------------------------------------------------------------------------------------------------------------*/

void test_GenerateStunRequests( IceAgent_t * iceAgent , RequestType_t index )
{
    IceResult_t result ;
    int i;
    uint8_t stunMessageBuffer[ 1024 ] = { 0 };
    uint8_t transactionId[] = { 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7,
                                0xA8, 0xA9, 0xAA, 0x87, 0xDF, 0xAE };

    switch( index ){
        case NOMINATING_CANDIDATE:
        {
            result = Ice_CreateRequestForNominatingValidCandidatePair( iceAgent, stunMessageBuffer, &( iceAgent->iceCandidatePairs[ 0 ] ), transactionId );
            if( result == ICE_RESULT_OK )
            {
                printf(" Nominating candidate pair : Local Candidate Port %d --> Remote Candidate Port %d \n",iceAgent->iceCandidatePairs[ 0 ].local->ipAddress.ipAddress.port, iceAgent->iceCandidatePairs[0].remote->ipAddress.ipAddress.port );

                printf( "\nSerialized Message for Nominating Candidate Pair :\n\n" );

                for( i=0 ; i < 1024; i++ )
                {
                    printf( "0x%02x ", stunMessageBuffer[ i ] );
                }
            }
            else
            {
                printf("Stun Request creation failed for Nominating Candidate Pair %d .\n", result );
            }
        }
            break;
        case CONNECTIVITY_CHECK:
        {
            result = Ice_CreateRequestForConnectivityCheck( iceAgent, stunMessageBuffer, transactionId );
            if( result == ICE_RESULT_OK )
            {
                printf( "\nSerialized Message for Connectivity check :\n\n" );
        
                for( i=0 ; i < 1024; i++ )
                {
                    printf( "0x%02x ", stunMessageBuffer[ i ] );
                }
            }
            else
            {
                printf("Stun Request creation failed for Connectivity Check. %d \n" ,  result );
            }
        }
            break;
        case RESPONSE_FOR_REQUEST:
        {
            result = Ice_CreateResponseForRequest( iceAgent, stunMessageBuffer, &( iceAgent->iceCandidatePairs[1].remote->ipAddress ), transactionId );
            if( result == ICE_RESULT_OK )
            {
                printf( "\nSerialized Message for Response to Request from Remote candidate :\n\n" );
        
                for( i=0 ; i < 1024; i++ )
                {
                    printf( "0x%02x ", stunMessageBuffer[ i ] );
                }
            }
            else
            {
                printf("Stun Request creation failed  for Response to Request from Remote candidate. %d \n" ,  result );
            }
        }
        default: 
            break;
    }
}

/*--------------------------------------------------------------------------------------------------------------------------------------------------------------------*/

void test_HandleStunResponseFromIceServerForSrflxCandidate( IceAgent_t * iceAgent )
{
    printf("\nHandling Stun Response from IceServer. \n");
    
    IceResult_t result;
    StunContext_t pStunCxt;
    StunHeader_t pStunHeader;
    uint8_t stunMessageBuffer[ 1024 ] = { 0 };
    uint8_t transactionId[] = { 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7,
                                0xA8, 0xA9, 0xAA, 0x87, 0xDF, 0xAE };
    StunAttributeAddress_t stunAddress;

    uint8_t ipAddressV6[] = { 0x20, 0x01, 0x0D, 0xB8, 0x12, 0x34, 0x56, 0x78,
                              0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77 }; 

    /* Initialise ICE IP address */    
    stunAddress.family = STUN_ADDRESS_IPv6;
    stunAddress.port = 15243;
    memcpy( stunAddress.address, ipAddressV6, STUN_IPV6_ADDRESS_SIZE );

    /* Initialise Dummy STUN Response and add it to Transaction ID store */
    result = Ice_InitializeStunPacket( &pStunCxt, transactionId, stunMessageBuffer, &pStunHeader, 0, 0 );
    result = StunSerializer_AddAttributeXorMappedAddress( &pStunCxt , &stunAddress );

    if( result == ICE_RESULT_OK )
    {
        Ice_TransactionIdStoreInsert( iceAgent->pStunBindingRequestTransactionIdStore, pStunHeader.pTransactionId );

        result = Ice_PackageStunPacket( &pStunCxt, NULL, 0 );
    }

    printf("\n");
    /* Call API for handling the STUN repsonse*/
    result = Ice_HandleStunResponse( iceAgent, stunMessageBuffer, 52, transactionId, &( iceAgent->localCandidates[2] ), iceAgent->localCandidates[2].ipAddress, &( iceAgent->iceCandidatePairs[2] ) );

    if( result == ICE_RESULT_OK )
    {
        test_DisplayCandidatePairs( iceAgent );
    }
    else
    {
        printf( "Updating Srflx candidate IP address failed with retStatus=%d. \n",result );
    }
}

/*--------------------------------------------------------------------------------------------------------------------------------------------------------------------*/

void test_HandleStunRequestFromRemoteCandidate( IceAgent_t * iceAgent )
{
    printf("\nHandling Stun Request from Remote Candidate. \n");

    IceResult_t result;
    int i;
    StunContext_t pStunCxt;
    StunHeader_t pStunHeader;
    uint8_t stunMessageBuffer[ 1024 ] = { 0 };
    uint8_t transactionId[ STUN_HEADER_TRANSACTION_ID_LENGTH ] = { 0 };
    StunAttributeAddress_t stunAddress;
    IceIPAddress_t iceIpAddress;

    uint8_t ipAddressV6[] = { 0x20, 0x01, 0x0D, 0xB8, 0x12, 0x34, 0x56, 0x78,
                              0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77 }; 

    /* Initialise ICE IP address */    
    stunAddress.family = STUN_ADDRESS_IPv6;
    stunAddress.port = 13254;
    memcpy( stunAddress.address, ipAddressV6, STUN_IPV6_ADDRESS_SIZE );
    
    iceIpAddress.ipAddress = stunAddress;
    iceIpAddress.isPointToPoint = 0;

    /* Initialise Dummy STUN Request */
    result = Ice_InitializeStunPacket( &pStunCxt, transactionId, stunMessageBuffer, &pStunHeader, 1, 1 );
    result =  StunSerializer_AddAttributeXorMappedAddress( &pStunCxt , &stunAddress );

    if( result == ICE_RESULT_OK )
    {
        result = Ice_PackageStunPacket( &pStunCxt, NULL, 0 );
    }
    /* Call API for handling the STUN repsonse. */
    result = Ice_HandleStunResponse( iceAgent, stunMessageBuffer, 52, transactionId, iceAgent->iceCandidatePairs[0].local, iceIpAddress, &( iceAgent->iceCandidatePairs[0] ) );

    if( iceAgent->iceCandidatePairs[0].connectivityChecks == 13 )
    {
        printf("Success, waiting for response from remote candidate.\n");
    }
    else
    {
        printf("Failure with connectivity check of the Candidate Pair = %d\n",iceAgent->iceCandidatePairs[0].connectivityChecks);
    }
}

/*--------------------------------------------------------------------------------------------------------------------------------------------------------------------*/

void test_HandleStunResponseFromRemoteInResponseToLocalCandidateRequest( IceAgent_t * iceAgent )
{
    printf("\nHandling Stun Response from Remote Candidate. \n");
    IceResult_t result;
    StunContext_t pStunCxt;
    StunHeader_t pStunHeader;
    uint8_t stunMessageBuffer[ 1024 ] = { 0 };
    uint8_t transactionId[] = { 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7,
                                0xA8, 0xA9, 0xAA, 0x87, 0xDF, 0xAE };
    StunAttributeAddress_t stunAddress;
    IceIPAddress_t iceIpAddress;

    uint8_t ipAddressV6[] = { 0x20, 0x01, 0x0D, 0xB8, 0x12, 0x34, 0x56, 0x78,
                              0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77 }; 

    /* Initialise ICE IP address */    
    stunAddress.family = STUN_ADDRESS_IPv6;
    stunAddress.port = 15243;
    memcpy( stunAddress.address, ipAddressV6, STUN_IPV6_ADDRESS_SIZE );

    iceIpAddress.ipAddress = stunAddress;
    iceIpAddress.isPointToPoint = 0;

    /* Initialise Dummy STUN Response */
    result = Ice_InitializeStunPacket( &pStunCxt, transactionId, stunMessageBuffer, &pStunHeader, 1, 0 );
    result =  StunSerializer_AddAttributeXorMappedAddress( &pStunCxt , &stunAddress );

    if( result == ICE_RESULT_OK )
    {
        result = Ice_PackageStunPacket( &pStunCxt, NULL, 0 );
    }
    /* Call API for handling the STUN repsonse. */
    result = Ice_HandleStunResponse( iceAgent, stunMessageBuffer, 52, transactionId, iceAgent->iceCandidatePairs[0].local, iceIpAddress, &( iceAgent->iceCandidatePairs[0] ) );
    
    if( iceAgent->iceCandidatePairs[0].connectivityChecks == ICE_CONNECTIVITY_SUCCESS_FLAG )
    {
        printf("Success, candidate Pair is moved to Valid List.\n");
    }
    else
    {
        printf("Failure with connectivity check of the Candidate Pair = %d\n",iceAgent->iceCandidatePairs[0].connectivityChecks);
    }
}

/*--------------------------------------------------------------------------------------------------------------------------------------------------------------------*/

void test_HandleStunResponseForNominatingCandidatePair( IceAgent_t * iceAgent )
{
    printf("\nHandling Stun Request for Nominating Candidate Pair. \n");
    IceResult_t result;
    StunContext_t pStunCxt;
    StunHeader_t pStunHeader;
    uint8_t stunMessageBuffer[ 1024 ] = { 0 };
    uint8_t transactionId[] = { 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7,
                                0xA8, 0xA9, 0xAA, 0x87, 0xDF, 0xAE };
    StunAttributeAddress_t stunAddress;
    IceIPAddress_t iceIpAddress;

    uint8_t ipAddressV6[] = { 0x20, 0x01, 0x0D, 0xB8, 0x12, 0x34, 0x56, 0x78,
                              0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77 }; 

    /* Initialise ICE IP address */    
    stunAddress.family = STUN_ADDRESS_IPv6;
    stunAddress.port = 15243;
    memcpy( stunAddress.address, ipAddressV6, STUN_IPV6_ADDRESS_SIZE );

    iceIpAddress.ipAddress = stunAddress;
    iceIpAddress.isPointToPoint = 0;

    /* Initialise Dummy STUN Response */
    result = Ice_InitializeStunPacket( &pStunCxt, transactionId, stunMessageBuffer, &pStunHeader, 1, 1 );
    result = StunSerializer_AddAttributeUseCandidate( &pStunCxt );

    if( result == ICE_RESULT_OK )
    {
        result = Ice_PackageStunPacket( &pStunCxt, NULL, 0 );
    }
    /* Call API for handling the STUN repsonse. */
    result = Ice_HandleStunResponse( iceAgent, stunMessageBuffer, 32, transactionId, iceAgent->iceCandidatePairs[0].local, iceIpAddress, &( iceAgent->iceCandidatePairs[0] ) );
    
    if( iceAgent->iceCandidatePairs[0].state != ICE_CANDIDATE_PAIR_STATE_NOMINATED )
    {
        printf("Failure in handling response with candidate flag : Result - %d\n",result);
    }
}

/*--------------------------------------------------------------------------------------------------------------------------------------------------------------------*/

void test_HandleStunResponseInResponseToNominatingCandidatePairRequest( IceAgent_t * iceAgent )
{
    printf("\nHandling Stun Response for Nominating Candidate Pair. \n");
    IceResult_t result;
    StunContext_t pStunCxt;
    StunHeader_t pStunHeader;
    uint8_t stunMessageBuffer[ 1024 ] = { 0 };
    uint8_t transactionId[] = { 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7,
                                0xA8, 0xA9, 0xAA, 0x87, 0xDF, 0xAE };
    StunAttributeAddress_t stunAddress;
    IceIPAddress_t iceIpAddress;

    uint8_t ipAddressV6[] = { 0x20, 0x01, 0x0D, 0xB8, 0x12, 0x34, 0x56, 0x78,
                              0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77 }; 

    /* Initialise ICE IP address */    
    stunAddress.family = STUN_ADDRESS_IPv6;
    stunAddress.port = 15243;
    memcpy( stunAddress.address, ipAddressV6, STUN_IPV6_ADDRESS_SIZE );

    iceIpAddress.ipAddress = stunAddress;
    iceIpAddress.isPointToPoint = 0;

    /* Initialise Dummy STUN Response */
    result = Ice_InitializeStunPacket( &pStunCxt, transactionId, stunMessageBuffer, &pStunHeader, 1, 0 );
    result =  StunSerializer_AddAttributeXorMappedAddress( &pStunCxt , &stunAddress );
    result = StunSerializer_AddAttributeUseCandidate( &pStunCxt );
    if( result == ICE_RESULT_OK )
    {
        result = Ice_PackageStunPacket( &pStunCxt, NULL, 0 );
    }
    /* Call API for handling the STUN repsonse. */
    result = Ice_HandleStunResponse( iceAgent, stunMessageBuffer, 56, transactionId, iceAgent->iceCandidatePairs[0].local, iceIpAddress, &( iceAgent->iceCandidatePairs[0] ) );
    if( result == ICE_RESULT_CANDIDATE_PAIR_READY )
    {
        printf("Candidate Pair at index 0 : Local Candidate Port : %d --> Remote Candidate Port %d is selected pair for Data Transfer.\n",iceAgent->iceCandidatePairs[0].local->ipAddress.ipAddress.port,iceAgent->iceCandidatePairs[0].remote->ipAddress.ipAddress.port);
    }
    else
    {
        printf("Failed in selecting nominated candidate pair.\n");
    }
}

/*--------------------------------------------------------------------------------------------------------------------------------------------------------------------*/

int main( void )
{
    IceAgent_t * iceAgent = malloc(sizeof(struct IceAgent));

    test_IceAgentInit( iceAgent );

    test_GenerateHostCandidate( iceAgent );

    test_GenerateSrflxCandidate( iceAgent );

    test_GenerateRemoteCandidate( iceAgent );

    test_DisplayCandidatePairs( iceAgent );

    /* Test Stun Request creation for Nominating Candidate Pair. */
    test_GenerateStunRequests( iceAgent, 0 );

    /* Test Stun Request creation for Connectivity Check. */
    test_GenerateStunRequests( iceAgent, 1 );

    /* Test Stun Request creation for Response for Remote candidate requests. */
    test_GenerateStunRequests( iceAgent, 2 );

    /* Test Parsing Stun responses. */
    test_HandleStunResponseFromIceServerForSrflxCandidate( iceAgent );

    test_HandleStunRequestFromRemoteCandidate( iceAgent );

    test_HandleStunResponseFromRemoteInResponseToLocalCandidateRequest( iceAgent );

    test_HandleStunResponseForNominatingCandidatePair( iceAgent );

    test_HandleStunResponseInResponseToNominatingCandidatePairRequest( iceAgent );

    return 0;
}

/*--------------------------------------------------------------------------------------------------------------------------------------------------------------------*/
