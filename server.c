#include <stdio.h> /* for printf() and fprintf() */
#include <sys/socket.h> /* for socket(), bind(), sendto() and recvfrom() */
#include <sys/ioctl.h> 
#include <netinet/in.h> 
#include <net/if.h> 
#include <arpa/inet.h> /* for sockaddr_in and inet_ntoa() */
#include <stdlib.h> /* for atoi() and exit() */
#include <string.h> /* for memset() */
#include <unistd.h> /* for close() */
#include <time.h>

#define MAX_SIZE 512 /* Longest string to echo */

unsigned int getIP();
int availabelIPNumber(char file[]);
void offerIP(unsigned char MAC[6]);
int checkLease(unsigned int IP, unsigned char MAC[6]);
void retrieveIP(unsigned int IP);
void renewLease(unsigned int IP);

int main(int argc, char *argv[]){
    int sock; /* Socket */
    struct sockaddr_in svrAddr; /* Local address */
    struct sockaddr_in cltAddr; /* Client address */
    struct sockaddr_in broadcastAddr; /* Client address */
    unsigned int cliAddrLen; /* Length of client address */

    char recvBuf[MAX_SIZE]; /* Buffer for echo string */
    char sendBuf[MAX_SIZE]; /* Buffer for echo string */

    int recvMsgSize; /* Size of received message */
    int i; /* Counter */
    int broadcastFlag = 0;
    int discoverFlag = 0;

    /* Create socket for sending/receiving datagrams */
    if ((sock = socket(PF_INET, SOCK_DGRAM, 0)) < 0)
       printf("socket() failed.\n");

    struct timeval timeout;
    timeout.tv_sec = 1;
    timeout.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

    int x = 1;
    setsockopt(sock, SOL_SOCKET, SO_BROADCAST | SO_REUSEADDR, &x, sizeof(int));

	struct ifreq if_eth1;
    strcpy(if_eth1.ifr_name, "eth1");
    setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, (char*)&if_eth1, sizeof(if_eth1));
    
    // Broadcast
    memset(&broadcastAddr, 0, sizeof(broadcastAddr));/*Zero out structure*/
    broadcastAddr.sin_family = AF_INET; /* Internet addr family */
    broadcastAddr.sin_addr.s_addr = inet_addr("255.255.255.255");/*Server IP address*/
    broadcastAddr.sin_port = htons(68); /* Server port */

    /* Construct local address structure */
    memset(&svrAddr, 0, sizeof(svrAddr));
    svrAddr.sin_family = AF_INET;
    svrAddr.sin_addr.s_addr = htonl(INADDR_ANY);
    svrAddr.sin_port = htons(67);
    /* Bind to the local address */
    if ((bind(sock, (struct sockaddr *) &svrAddr, sizeof(svrAddr))) < 0)
       printf("bind() failed.\n");
    
    while(1)
    {
        /* Set the size of the in-out parameter */
        cliAddrLen = sizeof(cltAddr);
        /* Block until receive message from a client */
        recvMsgSize = recvfrom(sock, recvBuf, MAX_SIZE, 0,(struct sockaddr *) &cltAddr, &cliAddrLen);

        if ((recvMsgSize < 0) && (discoverFlag == 1))
		{
			discoverFlag = 0;
			continue;
		}
        else if (recvMsgSize < 312)
            continue;
            
        printf("Received: %d\n", recvMsgSize);
        memcpy(sendBuf, recvBuf, 243);

        int sendSize = 240;

        FILE* upop;
        if ((upop = fopen("dhcp.config","r")) == NULL)  
        {     
            printf("Cannot open dhcp.config\n");  
            return 0;  
        }  
        char string[16];

        // Subnet Mask
        fscanf(upop,"%s",string);
        unsigned int MASK = (inet_addr(string));

        // Router
        fscanf(upop,"%s",string);
        unsigned int ROUTER = (inet_addr(string));

        // DNS
        fscanf(upop,"%s",string);
        unsigned int DNS = (inet_addr(string));

        // IP address lease time
        fscanf(upop,"%s",string);
        unsigned int LEASETIME = (inet_addr(string));

        // IP (prepared)
        fscanf(upop,"%s",string);
        unsigned int IP = (inet_addr(string));

        fclose(upop);  
                    
        switch(recvBuf[242])
        {
            case 0x01: // DHCP Discover (Response Offer)
            {
                //printf("%d\n", availabelIPNumber("dhcp.config"));
                printf("Received: Discover\n");
                if(availabelIPNumber("dhcp.config") <= 0)
                {
                    sendSize = 0;
                    printf("No available IP Address, does not response\n");
                }
                else
                {
                    printf("Send: Offer\n");
                    
                    unsigned short bootFlags;
                    memcpy(&bootFlags, &sendBuf[10], sizeof(unsigned short));
                    
                    if(bootFlags == htons(0x8000))
                    	broadcastFlag = 1;
                    else if(bootFlags == htons(0x0000)) 
                    {
                    	broadcastFlag = 0;
                    	cltAddr.sin_addr.s_addr = (IP);
 					}
 					
                    discoverFlag = 1;

                    unsigned char messageType = (0x02);
                    memcpy(&sendBuf[0], &messageType, sizeof(unsigned char));

                    unsigned int yourIPAddress = IP;
                    memcpy(&sendBuf[16], &yourIPAddress, sizeof(unsigned int));

                    // Option 53 DHCP Message Type
                    unsigned char option53_DhcpMessageType = (0x02);
                    memcpy(&sendBuf[242], &option53_DhcpMessageType, sizeof(unsigned char));

                    // Option 54 DHCP Server Identifier
                    unsigned char option54 = (0x36);
                    memcpy(&sendBuf[243], &option54, sizeof(unsigned char));

                    unsigned char option54_Length = (0x04);
                    memcpy(&sendBuf[244], &option54_Length, sizeof(unsigned char));

                    unsigned int option54_DhcpServerIdentifier = getIP();
                    memcpy(&sendBuf[245], &option54_DhcpServerIdentifier, sizeof(unsigned int));

                    // Option 51 IP address Lease Time
                    unsigned char option51 = (0x33);
                    memcpy(&sendBuf[249], &option51, sizeof(unsigned char));

                    unsigned char option51_Length = (0x04);
                    memcpy(&sendBuf[250], &option51_Length, sizeof(unsigned char));

                    unsigned int option51_IPAddressLeaseTime = LEASETIME;
                    memcpy(&sendBuf[251], &option51_IPAddressLeaseTime, sizeof(unsigned int));

                    // Option 1 Subnet Mask
                    unsigned char option1 = (0x01);
                    memcpy(&sendBuf[255], &option1, sizeof(unsigned char));

                    unsigned char option1_Length = (0x04);
                    memcpy(&sendBuf[256], &option1_Length, sizeof(unsigned char));

                    unsigned int option1_SubnetMask = MASK;
                    memcpy(&sendBuf[257], &option1_SubnetMask, sizeof(unsigned int));

                    // Option 3 Router
                    unsigned char option3 = (0x03);
                    memcpy(&sendBuf[261], &option3, sizeof(unsigned char));

                    unsigned char option3_Length = (0x04);
                    memcpy(&sendBuf[262], &option3_Length, sizeof(unsigned char));

                    unsigned int option3_Router = ROUTER;
                    memcpy(&sendBuf[263], &option3_Router, sizeof(unsigned int));

                    // Option 6 DNS
                    unsigned char option6 = (0x06);
                    memcpy(&sendBuf[267], &option6, sizeof(unsigned char));

                    unsigned char option6_Length = (0x04);
                    memcpy(&sendBuf[268], &option6_Length, sizeof(unsigned char));

                    unsigned int option6_DNS = DNS;
                    memcpy(&sendBuf[269], &option6_DNS, sizeof(unsigned int));

                    // Option 58 DHCP Renewal Time T1
                    unsigned char option58 = (0x3a);
                    memcpy(&sendBuf[273], &option58, sizeof(unsigned char));

                    unsigned char option58_Length = (0x04);
                    memcpy(&sendBuf[274], &option58_Length, sizeof(unsigned char));

                    unsigned int option58_DHCPRenewalTimeT1 = LEASETIME / 2;
                    memcpy(&sendBuf[275], &option58_DHCPRenewalTimeT1, sizeof(unsigned int));

                    // Option 59 DHCP Rebinding Time T2
                    unsigned char option59 = (0x3b);
                    memcpy(&sendBuf[279], &option59, sizeof(unsigned char));

                    unsigned char option59_Length = (0x04);
                    memcpy(&sendBuf[280], &option59_Length, sizeof(unsigned char));

                    unsigned int option59_DHCPRebindingTimeT2 = LEASETIME * 7 / 8;
                    memcpy(&sendBuf[281], &option59_DHCPRebindingTimeT2, sizeof(unsigned int));

                    // Option 255 End
                    unsigned char option255 = (0xff);
                    memcpy(&sendBuf[285], &option255, sizeof(unsigned char));

                    // Padding
                    unsigned char padding[312 - 286];
                    for(i = 0; i < (312 - 286); i++){
                        padding[i] = (0x00);
                    }
                    memcpy(&sendBuf[286], &padding, (312 - 286));
                    sendSize = 312;
                }
                break;
            }
            case 0x02: // DHCP Offer
            {
                // Do nothing
                break;
            }
            case 0x03: // DHCP Request (Response ACK)
            {
                unsigned int clientIP;
                memcpy(&clientIP, &recvBuf[12], sizeof(unsigned int));

                if(clientIP == 0x00000000) // For Discover-Offer-Request-ACK loop
                {
                	unsigned short bootFlags;
                    memcpy(&bootFlags, &sendBuf[10], sizeof(unsigned short));
                    
                    if(bootFlags == htons(0x8000))
                    	broadcastFlag = 1;
                    else if(bootFlags == htons(0x0000)) 
                    {
                    	broadcastFlag = 0;
                    	cltAddr.sin_addr.s_addr = (IP);
 					}

                    if (discoverFlag == 1)
                    {
                        printf("Received: Request (address aquisition)\n");
                        //printf("123\n");
                        unsigned char messageType = (0x02);
                        memcpy(&sendBuf[0], &messageType, sizeof(unsigned char));

                        unsigned int yourIPAddress = IP;
                        memcpy(&sendBuf[16], &yourIPAddress, sizeof(unsigned int));

                        // Option 53 DHCP Message Type
                        unsigned char option53_DhcpMessageType = (0x05);
                        memcpy(&sendBuf[242], &option53_DhcpMessageType, sizeof(unsigned char));

                        // Option 54 DHCP Server Identifier
                        unsigned char option54 = (0x36);
                        memcpy(&sendBuf[243], &option54, sizeof(unsigned char));

                        unsigned char option54_Length = (0x04);
                        memcpy(&sendBuf[244], &option54_Length, sizeof(unsigned char));

                        unsigned int option54_DhcpServerIdentifier = getIP();
                        memcpy(&sendBuf[245], &option54_DhcpServerIdentifier, sizeof(unsigned int));

                        // Option 51 IP address Lease Time
                        unsigned char option51 = (0x33);
                        memcpy(&sendBuf[249], &option51, sizeof(unsigned char));

                        unsigned char option51_Length = (0x04);
                        memcpy(&sendBuf[250], &option51_Length, sizeof(unsigned char));

                        unsigned int option51_IPAddressLeaseTime = LEASETIME;
                        memcpy(&sendBuf[251], &option51_IPAddressLeaseTime, sizeof(unsigned int));

                        // Option 1 Subnet Mask
                        unsigned char option1 = (0x01);
                        memcpy(&sendBuf[255], &option1, sizeof(unsigned char));

                        unsigned char option1_Length = (0x04);
                        memcpy(&sendBuf[256], &option1_Length, sizeof(unsigned char));

                        unsigned int option1_SubnetMask = MASK;
                        memcpy(&sendBuf[257], &option1_SubnetMask, sizeof(unsigned int));

                        // Option 3 Router
                        unsigned char option3 = (0x03);
                        memcpy(&sendBuf[261], &option3, sizeof(unsigned char));

                        unsigned char option3_Length = (0x04);
                        memcpy(&sendBuf[262], &option3_Length, sizeof(unsigned char));

                        unsigned int option3_Router = ROUTER;
                        memcpy(&sendBuf[263], &option3_Router, sizeof(unsigned int));

                        // Option 6 DNS
                        unsigned char option6 = (0x06);
                        memcpy(&sendBuf[267], &option6, sizeof(unsigned char));

                        unsigned char option6_Length = (0x04);
                        memcpy(&sendBuf[268], &option6_Length, sizeof(unsigned char));

                        unsigned int option6_DNS = DNS;
                        memcpy(&sendBuf[269], &option6_DNS, sizeof(unsigned int));

                        // Option 58 DHCP Renewal Time T1
                        unsigned char option58 = (0x3a);
                        memcpy(&sendBuf[273], &option58, sizeof(unsigned char));

                        unsigned char option58_Length = (0x04);
                        memcpy(&sendBuf[274], &option58_Length, sizeof(unsigned char));

                        unsigned int option58_DHCPRenewalTimeT1 = LEASETIME / 2;
                        memcpy(&sendBuf[275], &option58_DHCPRenewalTimeT1, sizeof(unsigned int));

                        // Option 59 DHCP Rebinding Time T2
                        unsigned char option59 = (0x3b);
                        memcpy(&sendBuf[279], &option59, sizeof(unsigned char));

                        unsigned char option59_Length = (0x04);
                        memcpy(&sendBuf[280], &option59_Length, sizeof(unsigned char));

                        unsigned int option59_DHCPRebindingTimeT2 = LEASETIME * 7 / 8;
                        memcpy(&sendBuf[281], &option59_DHCPRebindingTimeT2, sizeof(unsigned int));

                        // Option 255 End
                        unsigned char option255 = (0xff);
                        memcpy(&sendBuf[285], &option255, sizeof(unsigned char));

                        // Padding
                        unsigned char padding[312 - 286];
                        for(i = 0; i < (312 - 286); i++){
                            padding[i] = (0x00);
                        }
                        memcpy(&sendBuf[286], &padding, (312 - 286));
                        sendSize = 312;

                        // Modify IP pool & add the client into the log
                        unsigned char MAC[6];
                        memcpy(&MAC, &recvBuf[28], sizeof(unsigned char) * 6);

                        offerIP(MAC);
                    }
                    // else // Renew the IP address
                    // {
                    //     // check in the dhcp.lease
                    //     // If the IP is not the recorded IP, then send NAK else send ACK
                    //     broadcastFlag = 0;

                    //     unsigned char messageType = (0x02);
                    //     memcpy(&sendBuf[0], &messageType, sizeof(unsigned char));

                    //     unsigned int requestedIP;
                    //     memcpy(&requestedIP, &recvBuf[12], sizeof(unsigned int));

                    //     unsigned char requestedMAC[6];
                    //     memcpy(&requestedMAC, &recvBuf[28], sizeof(unsigned char) * 6);

                    //     int IPAddressValid = checkLease(requestedIP, requestedMAC);
                    //     printf("%d\n", IPAddressValid);
                    //     if(IPAddressValid == 1) // Allow the client to renew the IP (ACK)
                    //     {
                    //         // Renew the recording in the dhcp.lease file
                    //         renewLease(requestedIP);

                    //         // Release the IP
                    //         unsigned int yourIPAddress = clientIP;
                    //         memcpy(&sendBuf[16], &yourIPAddress, sizeof(unsigned int));

                    //         // Set the next server as the server itself
                    //         unsigned int nextServerIPAddress = getIP();
                    //         memcpy(&sendBuf[20], &nextServerIPAddress, sizeof(unsigned int));

                    //         // Option 53 DHCP Message Type
                    //         unsigned char option53_DhcpMessageType = (0x05);
                    //         memcpy(&sendBuf[242], &option53_DhcpMessageType, sizeof(unsigned char));

                    //         // Option 54 DHCP Server Identifier
                    //         unsigned char option54 = (0x36);
                    //         memcpy(&sendBuf[243], &option54, sizeof(unsigned char));

                    //         unsigned char option54_Length = (0x04);
                    //         memcpy(&sendBuf[244], &option54_Length, sizeof(unsigned char));

                    //         unsigned int option54_DhcpServerIdentifier = getIP();
                    //         memcpy(&sendBuf[245], &option54_DhcpServerIdentifier, sizeof(unsigned int));

                    //         // Option 51 IP address Lease Time
                    //         unsigned char option51 = (0x33);
                    //         memcpy(&sendBuf[249], &option51, sizeof(unsigned char));

                    //         unsigned char option51_Length = (0x04);
                    //         memcpy(&sendBuf[250], &option51_Length, sizeof(unsigned char));

                    //         unsigned int option51_IPAddressLeaseTime = LEASETIME;
                    //         memcpy(&sendBuf[251], &option51_IPAddressLeaseTime, sizeof(unsigned int));

                    //         // Option 1 Subnet Mask
                    //         unsigned char option1 = (0x01);
                    //         memcpy(&sendBuf[255], &option1, sizeof(unsigned char));

                    //         unsigned char option1_Length = (0x04);
                    //         memcpy(&sendBuf[256], &option1_Length, sizeof(unsigned char));

                    //         unsigned int option1_SubnetMask = MASK;
                    //         memcpy(&sendBuf[257], &option1_SubnetMask, sizeof(unsigned int));

                    //         // Option 3 Router
                    //         unsigned char option3 = (0x03);
                    //         memcpy(&sendBuf[261], &option3, sizeof(unsigned char));

                    //         unsigned char option3_Length = (0x04);
                    //         memcpy(&sendBuf[262], &option3_Length, sizeof(unsigned char));

                    //         unsigned int option3_Router = ROUTER;
                    //         memcpy(&sendBuf[263], &option3_Router, sizeof(unsigned int));

                    //         // Option 6 DNS
                    //         unsigned char option6 = (0x06);
                    //         memcpy(&sendBuf[267], &option6, sizeof(unsigned char));

                    //         unsigned char option6_Length = (0x04);
                    //         memcpy(&sendBuf[268], &option6_Length, sizeof(unsigned char));

                    //         unsigned int option6_DNS = DNS;
                    //         memcpy(&sendBuf[269], &option6_DNS, sizeof(unsigned int));

                    //         // Option 58 DHCP Renewal Time T1
                    //         unsigned char option58 = (0x3a);
                    //         memcpy(&sendBuf[273], &option58, sizeof(unsigned char));

                    //         unsigned char option58_Length = (0x04);
                    //         memcpy(&sendBuf[274], &option58_Length, sizeof(unsigned char));

                    //         unsigned int option58_DHCPRenewalTimeT1 = LEASETIME / 2;
                    //         memcpy(&sendBuf[275], &option58_DHCPRenewalTimeT1, sizeof(unsigned int));

                    //         // Option 59 DHCP Rebinding Time T2
                    //         unsigned char option59 = (0x3b);
                    //         memcpy(&sendBuf[279], &option59, sizeof(unsigned char));

                    //         unsigned char option59_Length = (0x04);
                    //         memcpy(&sendBuf[280], &option59_Length, sizeof(unsigned char));

                    //         unsigned int option59_DHCPRebindingTimeT2 = LEASETIME * 7 / 8;
                    //         memcpy(&sendBuf[281], &option59_DHCPRebindingTimeT2, sizeof(unsigned int));

                    //         // Option 255 End
                    //         unsigned char option255 = (0xff);
                    //         memcpy(&sendBuf[285], &option255, sizeof(unsigned char));

                    //         // Padding
                    //         unsigned char padding[312 - 286];
                    //         for(i = 0; i < (312 - 286); i++){
                    //             padding[i] = (0x00);
                    //         }
                    //         memcpy(&sendBuf[286], &padding, (312 - 286));
                    //         sendSize = 312;
                    //     }
                    //     else // Does not allow the client renew the IP (NAK)
                    //     {
                    //         // Option 53 DHCP Message Type
                    //         unsigned char option53_DhcpMessageType = (0x06);
                    //         memcpy(&sendBuf[242], &option53_DhcpMessageType, sizeof(unsigned char));

                    //         // Option 54 DHCP Server Identifier
                    //         unsigned char option54 = (0x36);
                    //         memcpy(&sendBuf[243], &option54, sizeof(unsigned char));

                    //         unsigned char option54_Length = (0x04);
                    //         memcpy(&sendBuf[244], &option54_Length, sizeof(unsigned char));

                    //         unsigned int option54_DhcpServerIdentifier = getIP();
                    //         memcpy(&sendBuf[245], &option54_DhcpServerIdentifier, sizeof(unsigned int));

                    //         // Option 255 End
                    //         unsigned char option255 = (0xff);
                    //         memcpy(&sendBuf[249], &option255, sizeof(unsigned char));

                    //         // Padding
                    //         unsigned char padding[312 - 250];
                    //         for(i = 0; i < (312 - 250); i++){
                    //             padding[i] = (0x00);
                    //         }
                    //         memcpy(&sendBuf[250], &padding, (312 - 250));
                    //         sendSize = 312;
                    //     }
                    // }
                }
                else // For renew the IP address
                {
                    // check in the dhcp.lease
                    // If the IP is not the recorded IP, then send NAK else send ACK
                    unsigned short bootFlags;
                    memcpy(&bootFlags, &sendBuf[10], sizeof(unsigned short));

                    if(bootFlags == 0x0000)
                    {
                        broadcastFlag = 0;
                        printf("Send: (Unicast) ");
                    }
                    else
                    {
                        broadcastFlag = 1;
                        printf("Send: (Broadcast) ");
                    }

                    unsigned char messageType = (0x02);
                    memcpy(&sendBuf[0], &messageType, sizeof(unsigned char));

                    unsigned int requestedIP;
                    memcpy(&requestedIP, &recvBuf[12], sizeof(unsigned int));

                    unsigned char requestedMAC[6];
                    memcpy(&requestedMAC, &recvBuf[28], sizeof(unsigned char) * 6);

                    int IPAddressValid = checkLease(requestedIP, requestedMAC);

                    if(IPAddressValid == 1) // Allow the client to renew the IP (ACK)
                    {
                        struct sockaddr_in sin;
                        sin.sin_addr.s_addr = requestedIP;
 
                        printf("ACK\nRenew: %s\n", inet_ntoa(sin.sin_addr));
                        // Renew the recording in the dhcp.lease file
                        renewLease(requestedIP);

                        // Release the IP
                        unsigned int yourIPAddress = clientIP;
                        memcpy(&sendBuf[16], &yourIPAddress, sizeof(unsigned int));

                        // Set the next server as the server itself
                        unsigned int nextServerIPAddress = getIP();
                        memcpy(&sendBuf[20], &nextServerIPAddress, sizeof(unsigned int));

                        // Option 53 DHCP Message Type
                        unsigned char option53_DhcpMessageType = (0x05);
                        memcpy(&sendBuf[242], &option53_DhcpMessageType, sizeof(unsigned char));

                        // Option 54 DHCP Server Identifier
                        unsigned char option54 = (0x36);
                        memcpy(&sendBuf[243], &option54, sizeof(unsigned char));

                        unsigned char option54_Length = (0x04);
                        memcpy(&sendBuf[244], &option54_Length, sizeof(unsigned char));

                        unsigned int option54_DhcpServerIdentifier = getIP();
                        memcpy(&sendBuf[245], &option54_DhcpServerIdentifier, sizeof(unsigned int));

                        // Option 51 IP address Lease Time
                        unsigned char option51 = (0x33);
                        memcpy(&sendBuf[249], &option51, sizeof(unsigned char));

                        unsigned char option51_Length = (0x04);
                        memcpy(&sendBuf[250], &option51_Length, sizeof(unsigned char));

                        unsigned int option51_IPAddressLeaseTime = LEASETIME;
                        memcpy(&sendBuf[251], &option51_IPAddressLeaseTime, sizeof(unsigned int));

                        // Option 1 Subnet Mask
                        unsigned char option1 = (0x01);
                        memcpy(&sendBuf[255], &option1, sizeof(unsigned char));

                        unsigned char option1_Length = (0x04);
                        memcpy(&sendBuf[256], &option1_Length, sizeof(unsigned char));

                        unsigned int option1_SubnetMask = MASK;
                        memcpy(&sendBuf[257], &option1_SubnetMask, sizeof(unsigned int));

                        // Option 3 Router
                        unsigned char option3 = (0x03);
                        memcpy(&sendBuf[261], &option3, sizeof(unsigned char));

                        unsigned char option3_Length = (0x04);
                        memcpy(&sendBuf[262], &option3_Length, sizeof(unsigned char));

                        unsigned int option3_Router = ROUTER;
                        memcpy(&sendBuf[263], &option3_Router, sizeof(unsigned int));

                        // Option 6 DNS
                        unsigned char option6 = (0x06);
                        memcpy(&sendBuf[267], &option6, sizeof(unsigned char));

                        unsigned char option6_Length = (0x04);
                        memcpy(&sendBuf[268], &option6_Length, sizeof(unsigned char));

                        unsigned int option6_DNS = DNS;
                        memcpy(&sendBuf[269], &option6_DNS, sizeof(unsigned int));

                        // Option 58 DHCP Renewal Time T1
                        unsigned char option58 = (0x3a);
                        memcpy(&sendBuf[273], &option58, sizeof(unsigned char));

                        unsigned char option58_Length = (0x04);
                        memcpy(&sendBuf[274], &option58_Length, sizeof(unsigned char));

                        unsigned int option58_DHCPRenewalTimeT1 = LEASETIME / 2;
                        memcpy(&sendBuf[275], &option58_DHCPRenewalTimeT1, sizeof(unsigned int));

                        // Option 59 DHCP Rebinding Time T2
                        unsigned char option59 = (0x3b);
                        memcpy(&sendBuf[279], &option59, sizeof(unsigned char));

                        unsigned char option59_Length = (0x04);
                        memcpy(&sendBuf[280], &option59_Length, sizeof(unsigned char));

                        unsigned int option59_DHCPRebindingTimeT2 = LEASETIME * 7 / 8;
                        memcpy(&sendBuf[281], &option59_DHCPRebindingTimeT2, sizeof(unsigned int));

                        // Option 255 End
                        unsigned char option255 = (0xff);
                        memcpy(&sendBuf[285], &option255, sizeof(unsigned char));

                        // Padding
                        unsigned char padding[312 - 286];
                        for(i = 0; i < (312 - 286); i++){
                            padding[i] = (0x00);
                        }
                        memcpy(&sendBuf[286], &padding, (312 - 286));
                        sendSize = 312;
                    }
                    else // Does not allow the client renew the IP (NAK)
                    {
                        printf("NAK\n");
                        // Option 53 DHCP Message Type
                        unsigned char option53_DhcpMessageType = (0x06);
                        memcpy(&sendBuf[242], &option53_DhcpMessageType, sizeof(unsigned char));

                        // Option 54 DHCP Server Identifier
                        unsigned char option54 = (0x36);
                        memcpy(&sendBuf[243], &option54, sizeof(unsigned char));

                        unsigned char option54_Length = (0x04);
                        memcpy(&sendBuf[244], &option54_Length, sizeof(unsigned char));

                        unsigned int option54_DhcpServerIdentifier = getIP();
                        memcpy(&sendBuf[245], &option54_DhcpServerIdentifier, sizeof(unsigned int));

                        // Option 255 End
                        unsigned char option255 = (0xff);
                        memcpy(&sendBuf[249], &option255, sizeof(unsigned char));

                        // Padding
                        unsigned char padding[312 - 250];
                        for(i = 0; i < (312 - 250); i++){
                            padding[i] = (0x00);
                        }
                        memcpy(&sendBuf[250], &padding, (312 - 250));
                        sendSize = 312;
                    }
                }
                break;
            }
            case 0x04: // DHCP Decline
            {
                // Not required
                break;
            }
            case 0x05: // DHCP ACK
            {
                break;
            }
            case 0x06: // DHCP NAK
            {
                break;
            }
            case 0x07: // DHCP Release (Retrive the IP address without sending the ACK)
            {
                printf("Receive: Release\n");
                unsigned int releaseIP;
                memcpy(&releaseIP, &recvBuf[12], sizeof(unsigned int));

                struct sockaddr_in sin;
                sin.sin_addr.s_addr = releaseIP;
                printf("Retrive: %s\n", inet_ntoa(sin.sin_addr));

                retrieveIP(releaseIP);
                break;
            }
            case 0x08: // DHCP Inform (Response ACK without Option 51 IP address Lease Time)
            {
                printf("Receive: Inform\n");
                printf("Send: ACK\n");

                broadcastFlag = 0;

                unsigned char messageType = (0x02);
                memcpy(&sendBuf[0], &messageType, sizeof(unsigned char));

                // Option 53 DHCP Message Type
                unsigned char option53_DhcpMessageType = (0x05);
                memcpy(&sendBuf[242], &option53_DhcpMessageType, sizeof(unsigned char));

                // Option 54 DHCP Server Identifier
                unsigned char option54 = (0x36);
                memcpy(&sendBuf[243], &option54, sizeof(unsigned char));

                unsigned char option54_Length = (0x04);
                memcpy(&sendBuf[244], &option54_Length, sizeof(unsigned char));

                unsigned int option54_DhcpServerIdentifier = getIP();
                memcpy(&sendBuf[245], &option54_DhcpServerIdentifier, sizeof(unsigned int));

                // Option 1 Subnet Mask
                unsigned char option1 = (0x01);
                memcpy(&sendBuf[249], &option1, sizeof(unsigned char));

                unsigned char option1_Length = (0x04);
                memcpy(&sendBuf[250], &option1_Length, sizeof(unsigned char));

                unsigned int option1_SubnetMask = MASK;
                memcpy(&sendBuf[251], &option1_SubnetMask, sizeof(unsigned int));

                // Option 3 Router
                unsigned char option3 = (0x03);
                memcpy(&sendBuf[255], &option3, sizeof(unsigned char));

                unsigned char option3_Length = (0x04);
                memcpy(&sendBuf[256], &option3_Length, sizeof(unsigned char));

                unsigned int option3_Router = ROUTER;
                memcpy(&sendBuf[257], &option3_Router, sizeof(unsigned int));

                // Option 6 DNS
                unsigned char option6 = (0x06);
                memcpy(&sendBuf[261], &option6, sizeof(unsigned char));

                unsigned char option6_Length = (0x04);
                memcpy(&sendBuf[262], &option6_Length, sizeof(unsigned char));

                unsigned int option6_DNS = DNS;
                memcpy(&sendBuf[263], &option6_DNS, sizeof(unsigned int));

                // Option 58 DHCP Renewal Time T1
                unsigned char option58 = (0x3a);
                memcpy(&sendBuf[267], &option58, sizeof(unsigned char));

                unsigned char option58_Length = (0x04);
                memcpy(&sendBuf[268], &option58_Length, sizeof(unsigned char));

                unsigned int option58_DHCPRenewalTimeT1 = LEASETIME / 2;
                memcpy(&sendBuf[269], &option58_DHCPRenewalTimeT1, sizeof(unsigned int));

                // Option 59 DHCP Rebinding Time T2
                unsigned char option59 = (0x3b);
                memcpy(&sendBuf[273], &option59, sizeof(unsigned char));

                unsigned char option59_Length = (0x04);
                memcpy(&sendBuf[274], &option59_Length, sizeof(unsigned char));

                unsigned int option59_DHCPRebindingTimeT2 = LEASETIME * 7 / 8;
                memcpy(&sendBuf[275], &option59_DHCPRebindingTimeT2, sizeof(unsigned int));

                // Option 255 End
                unsigned char option255 = (0xff);
                memcpy(&sendBuf[279], &option255, sizeof(unsigned char));

                // Padding
                unsigned char padding[312 - 280];
                for(i = 0; i < (312 - 280); i++){
                    padding[i] = (0x00);
                }
                memcpy(&sendBuf[280], &padding, (312 - 280));
                sendSize = 312;
                break;
            }
            default:{
                // Do nothing since the Datagram is not a DHCP Datagram.
                break;
            }
        }
        
        /* Send received datagram back to the client */
        if((recvBuf[242] == 0x01 || recvBuf[242] == 0x03 || recvBuf[242] == 0x08) && (sendSize >= 312))
        {
            int length = 0;
            if(broadcastFlag == 0)
			{
                length = sendto(sock, sendBuf, sendSize, 0, (struct sockaddr *) &cltAddr, sizeof(cltAddr));
                printf("%d", length);
                if(length < 312)
                	printf("Send failed destination unreachable\n");
            }
            else if(broadcastFlag == 1)
            {
                length = sendto(sock, sendBuf, sendSize, 0, (struct sockaddr *) &broadcastAddr, sizeof(broadcastAddr));
                printf("%d", length);
                if(length < 312)
                	printf("Send failed destination unreachable\n");
        	}
        }
    }
}

unsigned int getIP()
{
    int sock;
    struct sockaddr_in sin;
    struct ifreq ifr;

    if((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
        perror("socket");

    strncpy(ifr.ifr_name, "eth1", IFNAMSIZ);
    ifr.ifr_name[IFNAMSIZ - 1] = 0;

    if(ioctl(sock, SIOCGIFADDR, &ifr) < 0)  //获取ip
        perror("ioctl"); 

    memcpy(&sin, &ifr.ifr_addr, sizeof(sin));

    unsigned int IP = sin.sin_addr.s_addr;
    return IP;
}

void offerIP(unsigned char MAC[6])
{
    FILE *infile;
    FILE *outfile;
    char string[16];
    char IP[16];

    infile = fopen("dhcp.config", "r");
    outfile = fopen("dhcp.config2", "w");

    // Subnet Mask
    fscanf(infile, "%s", string);
    fprintf(outfile, "%s\n", string);

    // Router
    fscanf(infile, "%s", string);
    fprintf(outfile, "%s\n", string);

    // DNS
    fscanf(infile, "%s", string);
    fprintf(outfile, "%s\n", string);

    // IP release time
    fscanf(infile, "%s", string);
    fprintf(outfile, "%s\n", string);

    // Remove IP
    fscanf(infile, "%s", IP);

    while (fscanf(infile, "%s", string) != EOF)
        fprintf(outfile, "%s\n", string);

    fclose(infile);
    fclose(outfile);

    if ((remove("dhcp.config") != 0) || (rename("dhcp.config2", "dhcp.config") != 0))
        printf("File Operation Failed!");
	// Write the leased IP, client MAC address and timestamp into dhcp.lease
    outfile = fopen("dhcp.lease", "a");
    time_t t;  
    t = time(NULL);  
    struct tm *lt;  
    int timestamp = time(&t);  

    fprintf(outfile, "%d %02x%02x%02x%02x%02x%02x %s\n", timestamp, MAC[0], MAC[1], MAC[2], MAC[3], MAC[4], MAC[5], IP);
    fclose(outfile);
}

int availabelIPNumber(char file[])
{
    char string[16];
    int h = 0;
    FILE *fp;

    if ((fp = fopen(file, "r")) == NULL)  
        return 0;  

    while(!feof(fp))  
    {  
        fscanf(fp, "%s", string);  
        h++;
    }
    fclose(fp);
    return h - 5;
}

int checkLease(unsigned int IP, unsigned char MAC[6])
{
    FILE *infile;
    char string[50];

    infile = fopen("dhcp.lease", "r");
    
    while(!feof(infile))
    {
        fgets(string, 50, infile);

        if(strlen(string) >= 1)
            string[strlen(string) - 1] = '\0';
        else
           break;

        char* timeStampStr = NULL;
        char* IPStr = NULL;
        char* MACStr = NULL;

        timeStampStr = strtok(string, " ");
        int timeStamp = atoi(timeStampStr);
        timeStamp += 16;

        time_t t;  
        t = time(NULL);  
        struct tm *lt;  
        int timeStampNow = time(&t);  

        MACStr = strtok(NULL, " ");

        IPStr = strtok(NULL, " ");

        if(IP == inet_addr(IPStr))
        {
            char MACASCII[12];
            sprintf(MACASCII, "%02x%02x%02x%02x%02x%02x", MAC[0], MAC[1], MAC[2], MAC[3], MAC[4] & 0x000000ff, MAC[5]);

            if(strcmp(MACASCII, MACStr) == 0)
            {
                if(timeStamp >= timeStampNow)
                {
                	fclose(infile);
                    return 1;
                }
                else
                {
                	fclose(infile);
                	return -1;
				}
            }
            else
            {
            	fclose(infile);
            	return -1;
			}
        }
        else
        {
            int i = 0;
            for(i = 0; i < 50; i++)
                string[i] = '\0';
            continue;
        }
    }
    fclose(infile);
    return -1;
}

void retrieveIP(unsigned int IP)
{
    FILE *infile;
    FILE *outfile;
    int i = 0;
    int flag = 0;
    char string[50];

    struct sockaddr_in sin;
    sin.sin_addr.s_addr = (IP);

    infile = fopen("dhcp.lease", "r");
    outfile = fopen("dhcp.lease2", "w");

    while(!feof(infile))  
    {
        fgets(string, 50, infile);

        if(strlen(string) >= 1)
            string[strlen(string) - 1] = '\0';
        else
           break;

        if(strstr(string, inet_ntoa(sin.sin_addr)) != NULL)
        {
            for(i = 0; i < 50; i++)
                string[i] = '\0';
            flag = 1;
            continue;
        }
        else
        {
            fprintf(outfile, "%s\n", string);
            for(i = 0; i < 50; i++)
                string[i] = '\0';
            continue;
        }
    }

	fclose(infile);
    fclose(outfile);
    
    if ((remove("dhcp.lease") != 0) || (rename("dhcp.lease2", "dhcp.lease") != 0))
        printf("File Operation Failed!");

    if(flag == 1)
    {
        outfile = fopen("dhcp.config", "a");
        fprintf(outfile, "%s\n", inet_ntoa(sin.sin_addr));
        fclose(outfile);
    }
}

void renewLease(unsigned int IP)
{
    FILE *infile;
    FILE *outfile;

    char string[50];

    infile = fopen("dhcp.lease", "r");
    outfile = fopen("dhcp.lease2", "w");
    
    while(!feof(infile))
    {
        fgets(string, 50, infile);

        char stringCpy[50];
        strcpy(stringCpy, string);

        if(strlen(string) >= 1)
            string[strlen(string) - 1] = '\0';
        else
           break;

        char* timeStampStr = NULL;
        char* IPStr = NULL;
        char* MACStr = NULL;

        timeStampStr = strtok(string, " ");
        MACStr = strtok(NULL, " ");
        IPStr = strtok(NULL, " ");

        if(IP == inet_addr(IPStr))
        {
            time_t t;  
            t = time(NULL);  
            struct tm *lt;  
            int timeStampNow = time(&t);

            fprintf(outfile, "%d %s %s\n", timeStampNow, MACStr, IPStr);
        }
        else
        {
            fprintf(outfile, "%s", stringCpy);
        }
        int i = 0;
        for(i = 0; i < 50; i++)
            string[i] = '\0';
    }
    
    fclose(infile);
    fclose(outfile);

    if ((remove("dhcp.lease") != 0) || (rename("dhcp.lease2", "dhcp.lease") != 0))
        printf("File Operation Failed!");
}
