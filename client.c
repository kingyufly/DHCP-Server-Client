#include <stdio.h> /* for printf() and fprintf() */
#include <sys/socket.h> /* for socket(), sendto() and recvfrom() */
#include <sys/ioctl.h> 
#include <sys/types.h>
#include <netinet/in.h> 
#include <net/if.h> 
#include <arpa/inet.h> /* for sockaddr_in and inet_addr() */
#include <stdlib.h> /* for atoi() and exit() */
#include <string.h> /* for memset() */
#include <unistd.h> /* for close() */
#include <time.h>  
#include <net/route.h>
#include <pthread.h>

#define MAX_SIZE 512 /* Longest string to echo */

int sock; /* Socket descriptor */
struct sockaddr_in sendAddr; /* Echo server address */
struct sockaddr_in svrAddr; /* Source address of echo */
struct sockaddr_in selfAddr; /* Echo server address */
unsigned short dhcpServPort = 67; /* Echo server port */

char sendBuf[MAX_SIZE]; /* Buffer for receiving echoed string */
char recvBuf[MAX_SIZE]; /* Buffer for receiving echoed string */

int sendSize = 312;
int recvSize; /* Size of received message */
    /* Set the size of the in-out parameter */
int svrAddrLen;
int counter = 0;
int discoverFlag = 0;
int broadcastFlag = 0;

unsigned int DHCPServerIPAddress = 0xffffffff;
unsigned int LeaseTime;
unsigned int T1Time;
unsigned int T2Time;
int i = 0;

pthread_t tid1;  
int rc1 = 0;  

int type = -1;
int subType = -1;
int aaType = -1; // Address acquasition type (Broadcast/Unicast)


void recvMSG(int type, int subType);
void sendMSG(int type, int subType);
unsigned int getXID();
void getMAC(unsigned char MAC[6]);
unsigned int getIP();
int SetIfAddr(char *ifname, char *Ipaddr, char *mask,char *gateway);
int SetIP(char *ifname, char *Ipaddr);
int SetMASK(char *ifname, char *mask);
int SetRouter(char *ifname, char *gateway);


void* thread1(void* arg)  
{  
    int timer = 0;
    i = 0;
    while(1)
    {
        time_t t;  
        t = time(NULL);  
        struct tm *lt;  
        int timestamp = time(&t);
        if(timestamp > timer)
        {
            timer = timestamp;
            i++;

			printf("\n\ni: %d\n\n", i);
            if(i == T1Time)
            {
                type = 3;
                subType = 2;
                sendMSG(type, subType);
                printf("T1 (Send Unicast Request) : %d\n", i);
                continue;
            }
            else if(i == T2Time)
            {
                type = 3;
                subType = 1;
                sendMSG(type, subType);
                printf("T2 (Send Broadcast Request) : %d\n", i);
                continue;
            }
            else if(i == LeaseTime)
            {
                type = 1;
                subType = 1;
                sendMSG(type, subType);
                printf("Lease Expires (Address Acquisition) : %d\n", i);
                continue;
            }
            else if((i > LeaseTime) && (i%10 == 0))
            {
            	type = 1;
                subType = 1;
            	sendMSG(type, subType);
                printf("Lease Expires (Address Acquisition) : %d\n", i);
                continue;
			}
            else
            	;
        }
    }
} 


int main(int argc, char *argv[])
{
    /* Create a datagram/UDP socket */
    if ((sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0)
       printf("socket() failed.\n");

	struct ifreq if_eth1;
    strcpy(if_eth1.ifr_name, "eth1");
    setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, (char*)&if_eth1, sizeof(if_eth1));
    
	struct timeval timeout;
    timeout.tv_sec = 1;
    timeout.tv_usec = 0;

    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

    int x = 1;
    setsockopt(sock, SOL_SOCKET, SO_BROADCAST | SO_REUSEADDR, &x, sizeof(int));
    
    memset(&selfAddr, 0, sizeof(selfAddr));/*Zero out structure*/
    selfAddr.sin_family = AF_INET; /* Internet addr family */
    selfAddr.sin_addr.s_addr = htonl(INADDR_ANY);/*Server IP address*/
    selfAddr.sin_port = htons(68); /* Server port */
    if ((bind(sock, (struct sockaddr *) &selfAddr, sizeof(selfAddr))) < 0)
        printf("bind() failed.\n");

    // DHCP Discover
    unsigned char bootRequest = (0x01);
    memcpy(&sendBuf[0], &bootRequest, sizeof(unsigned char));

    unsigned char hardwareType = (0x01);
    memcpy(&sendBuf[1], &hardwareType, sizeof(unsigned char));

    unsigned char hardwareAddressLength = (0x06);
    memcpy(&sendBuf[2], &hardwareAddressLength, sizeof(unsigned char));

    unsigned char hops = (0x00);
    memcpy(&sendBuf[3], &hops, sizeof(unsigned char));

    unsigned int XID = htonl(getXID());
    memcpy(&sendBuf[4], &XID, sizeof(unsigned int));

    unsigned short secondsElapsed = htons(0x0000);
    memcpy(&sendBuf[8], &secondsElapsed, sizeof(unsigned short));

    unsigned short bootFlags = htons(0x0000);
    memcpy(&sendBuf[10], &bootFlags, sizeof(unsigned short));

    unsigned int clientIPAddress = htonl(0x00000000);
    memcpy(&sendBuf[12], &clientIPAddress, sizeof(unsigned int));

    unsigned int yourIPAddress = htonl(0x00000000);
    memcpy(&sendBuf[16], &yourIPAddress, sizeof(unsigned int));

    unsigned int nextServerIPAddress = htonl(0x00000000);
    memcpy(&sendBuf[20], &nextServerIPAddress, sizeof(unsigned int));

    unsigned int relayAgentIPAddress = htonl(0x00000000);
    memcpy(&sendBuf[24], &relayAgentIPAddress, sizeof(unsigned int));
    
    unsigned char MAC[6];
    getMAC(MAC);
    MAC[5] = MAC[5] & 0x0000ff;
    memcpy(&sendBuf[28], &MAC[0], sizeof(unsigned char));
    memcpy(&sendBuf[29], &MAC[1], sizeof(unsigned char));
    memcpy(&sendBuf[30], &MAC[2], sizeof(unsigned char));
    memcpy(&sendBuf[31], &MAC[3], sizeof(unsigned char));
    memcpy(&sendBuf[32], &MAC[4], sizeof(unsigned char));
    memcpy(&sendBuf[33], &MAC[5], sizeof(unsigned char));

    //Hardware Address Padding
    unsigned char hardwarePadding[202];
    for(counter = 0; counter < 202; counter++)
    {
    	hardwarePadding[counter] = (0x00);
    }
	memcpy(&sendBuf[34], &hardwarePadding, 202);

	unsigned int magicCookie = htonl(0x63825363);
    memcpy(&sendBuf[236], &magicCookie, sizeof(unsigned int));


    if(argc == 2)
    {
        if(strcmp("--default", argv[1]) == 0) // Discover, Offer, Request, ACK (Broadcast)
        {
            type = 1;
            subType = 1;
            aaType = 0;
            sendMSG(type, subType);
        }
        else if(strcmp("--default2", argv[1]) == 0) // Discover, Offer, Request, ACK (Unicast)
        {
            type = 1;
            subType = 1;
            aaType = 1;
            sendMSG(type, subType);
        }
        else if(strcmp("--renew1", argv[1]) == 0) // T1 Expire
        {
            type = 3;
            subType = 2;
            sendMSG(type, subType);
        }
        else if(strcmp("--renew2", argv[1]) == 0) // T2 Expire
        {
            type = 3;
            subType = 1;
            sendMSG(type, subType);
        }
        else if(strcmp("--release", argv[1]) == 0) // Release IP
        {
            type = 7;
            subType = 1;
            sendMSG(type, subType);
        }
        else if(strcmp("--inform", argv[1]) == 0) // Inform
        {
            type = 8;
            subType = 1;
            sendMSG(type, subType);
        }
        else if(strcmp("--init", argv[1]) == 0) // Set the IP, Mask, Subnet
        {
            char *IPPointer = "192.168.0.254";
            char *MASKPointer = "255.255.255.0";
            char *RouterPointer = "192.168.0.254";
            SetIfAddr("eth1", IPPointer, MASKPointer, RouterPointer);

            printf("Init success\n");
            exit(0);
        }
        else if(strcmp("--interact", argv[1]) == 0) // Set the IP, Mask, Subnet
        {
            char *IPPointer = "192.168.0.254";
            char *MASKPointer = "255.255.255.0";
            char *RouterPointer = "192.168.0.254";
            SetIfAddr("eth1", IPPointer, MASKPointer, RouterPointer);

            printf("Init success\nStart interact");
            
            type = 1;
            subType = 1;
            aaType = 0;
            sendMSG(type, subType);

            // start the thread
            rc1 = pthread_create(&tid1, NULL, thread1, &tid1);  
            if(rc1 != 0)  
                printf("Thread create error!");  

            while(1)
            {
                char s1[50];
                printf(">");
                scanf("%s", s1);
                if(strcmp("renew", s1) == 0)
                {
                    // judge the time and send the corresponding 
                    if(i <= T2Time)
                    {
                        printf("T2 Not Expires. Manually Renew (Unicast)\n");
                        type = 3;
                        subType = 2;
                        sendMSG(type, subType);

                    }
                    else if(i <= LeaseTime)
                    {
                        printf("T2 Expires. Manually Renew (Broadcast)\n");
                        type = 3;
                        subType = 1;
                        sendMSG(type, subType);
                    }
                    else
                    {
                        printf("Lease Expires. Manually Address Acquisition\n");
                        type = 1;
                        subType = 1;
                        sendMSG(type, subType);
                    }
                }
                else if(strcmp("cancel", s1) == 0)
                {
                    printf("User's interrupt! Quit interact mode. End the program\n");
                    pthread_cancel(tid1);
                    exit(0); // stop the thread and end the program
                }
                else
                    printf(">Error command\n");
            }
        }
        else
        {
            printf("Unknown command!\n");
            exit(0);
        }
    }
    else
    {
        printf("No command!\n");
        exit(0);
    }
    close(sock);
    exit(0);
}

void recvMSG(int type, int subType)
{
    switch(type){
        case 1:{ // Read the DHCP Offer, send DHCP Request
            svrAddrLen = sizeof(svrAddr);
            recvSize = recvfrom(sock, recvBuf, MAX_SIZE, 0,(struct sockaddr *) &svrAddr, &svrAddrLen);
            // printf("recvSize: %d\n", recvSize);
            if(recvSize < 0)
                printf("Time out, no response\n");
            else if (recvSize < 312)
                printf("recvfrom failed\n");
            else
            {
                printf("Received: Offer\n");
                memcpy(&DHCPServerIPAddress, &recvBuf[245], sizeof(unsigned int));
                sendMSG(3, 1); // For Discover-Offer-Request-ACK loop
            }
            break;
        }
        case 3:{ // Read the DHCP ACK, send nothing
            svrAddrLen = sizeof(svrAddr);
            recvSize = recvfrom(sock, recvBuf, MAX_SIZE, 0,(struct sockaddr *) &svrAddr, &svrAddrLen);
            //printf("recvSize: %d\n", recvSize);
            if(recvSize < 0)
                printf("Time out, no response\n");
            else if (recvSize < 312)
                printf("recvfrom failed\n");
            
            unsigned char MessageType;
            memcpy(&MessageType, &recvBuf[242], sizeof(unsigned char));

            if (MessageType == 0x05) // ACK
            {
                printf("Received: ACK\n");
                struct sockaddr_in sin;
                FILE *outfile;

                unsigned int IP;
                char* IPPointer;
                memcpy(&IP, &recvBuf[16], sizeof(unsigned int));
                sin.sin_addr.s_addr = IP;
                IPPointer = inet_ntoa(sin.sin_addr);
                if(discoverFlag = 1)
                    SetIP("eth1", IPPointer);
                printf("IP: %s\n", IPPointer);

                unsigned int NextServer;
                memcpy(&NextServer, &recvBuf[20], sizeof(unsigned int));
                sin.sin_addr.s_addr = NextServer;
                printf("NextServer: %s\n", inet_ntoa(sin.sin_addr));

                unsigned int DHCPServer;
                memcpy(&DHCPServer, &recvBuf[245], sizeof(unsigned int));
                sin.sin_addr.s_addr = DHCPServer;

                outfile = fopen("dhcpclient.config", "w");
                fprintf(outfile, "%s", inet_ntoa(sin.sin_addr));
                fclose(outfile);

                printf("DHCPServer: %s\n", inet_ntoa(sin.sin_addr));

                if(DHCPServer != 0x00000000)
                {
                    DHCPServerIPAddress = DHCPServer;
                }

                unsigned int Lease;
                memcpy(&Lease, &recvBuf[251], sizeof(unsigned int));
                LeaseTime = htonl(Lease);
                printf("Lease: %d\n", htonl(Lease));

                unsigned int MASK;
                char* MASKPointer;
                memcpy(&MASK, &recvBuf[257], sizeof(unsigned int));
                sin.sin_addr.s_addr = MASK;
                MASKPointer = inet_ntoa(sin.sin_addr);
                if(discoverFlag = 1)
                    SetMASK("eth1", MASKPointer);
                printf("MASK: %s\n", MASKPointer);

                unsigned int Router;
                char* RouterPointer;
                memcpy(&Router, &recvBuf[263], sizeof(unsigned int));
                sin.sin_addr.s_addr = Router;
                RouterPointer = inet_ntoa(sin.sin_addr);
                if(discoverFlag = 1)
                    SetRouter("eth1", RouterPointer);
                printf("Router: %s\n", RouterPointer);

                unsigned int DNS;
                char* DNSPointer;
                memcpy(&DNS, &recvBuf[269], sizeof(unsigned int));
                sin.sin_addr.s_addr = DNS;
                DNSPointer = inet_ntoa(sin.sin_addr);
                printf("DNS: %s\n", inet_ntoa(sin.sin_addr));

                unsigned int T1;
                memcpy(&T1, &recvBuf[275], sizeof(unsigned int));
                T1Time = htonl(T1);
                printf("T1: %d\n", htonl(T1));

                unsigned int T2;
                memcpy(&T2, &recvBuf[281], sizeof(unsigned int));
                T2Time = htonl(T2);
                printf("T2: %d\n", htonl(T2));
                
                outfile = fopen("/etc/resolv.conf", "w");
                fprintf(outfile, "nameserver %s", DNSPointer);
                fclose(outfile);

                discoverFlag = 0;
                broadcastFlag = 0;
                i = 0;
            }
            else if (MessageType == 0x06) // NAK
            {
                printf("Received: NAK\n");
                printf("Start address acquisition\n");
                aaType = 0;
                sendMSG(1, 1); // For Discover-Offer-Request-ACK loop
            }
            else // Do nothing
            {

            }
            break;
        }
        case 8:{ // Read the DHCP ACK, send nothing
            svrAddrLen = sizeof(svrAddr);
            if ((recvSize = recvfrom(sock, recvBuf, MAX_SIZE, 0,(struct sockaddr *) &svrAddr, &svrAddrLen)) < 312)
                printf("recvfrom() failed.\n");

            printf("Received: ACK\n");
            struct sockaddr_in sin;
            FILE *outfile;

            unsigned int DHCPServer;
            memcpy(&DHCPServer, &recvBuf[245], sizeof(unsigned int));
            sin.sin_addr.s_addr = DHCPServer;

            outfile = fopen("dhcpclient.config", "w");
            fprintf(outfile, "%s", inet_ntoa(sin.sin_addr));
            fclose(outfile);

            printf("DHCPServer: %s\n", inet_ntoa(sin.sin_addr));

            if(DHCPServer != 0x00000000)
            {
                DHCPServerIPAddress = DHCPServer;
            }

            unsigned int MASK;
            memcpy(&MASK, &recvBuf[251], sizeof(unsigned int));
            sin.sin_addr.s_addr = MASK;
            printf("MASK: %s\n", inet_ntoa(sin.sin_addr));

            unsigned int Router;
            memcpy(&Router, &recvBuf[257], sizeof(unsigned int));
            sin.sin_addr.s_addr = Router;
            printf("Router: %s\n", inet_ntoa(sin.sin_addr));

            unsigned int DNS;
            char* DNSPointer;
            memcpy(&DNS, &recvBuf[263], sizeof(unsigned int));
            sin.sin_addr.s_addr = DNS;
            DNSPointer = inet_ntoa(sin.sin_addr);
            printf("DNS: %s\n", inet_ntoa(sin.sin_addr));

            unsigned int T1;
            memcpy(&T1, &recvBuf[269], sizeof(unsigned int));
            printf("T1: %d\n", htonl(T1));

            unsigned int T2;
            memcpy(&T2, &recvBuf[275], sizeof(unsigned int));
            printf("T2: %d\n", htonl(T2));
                
            outfile = fopen("/etc/resolv.conf", "w");
            fprintf(outfile, "nameserver %s", DNSPointer);
            fclose(outfile);

            discoverFlag = 0;
            broadcastFlag = 0;
            break;
        }
    }
    for(counter = 0; counter < 512; counter++)
        recvBuf[counter] = '\0';
}

void sendMSG(int type, int subType)
{
    FILE* DHCPFile;

    DHCPFile = fopen("dhcpclient.config", "r");

    if(DHCPFile <= 0)
        DHCPServerIPAddress = 0xffffffff;
    else
    {
        char string[50];
        fgets(string, 50, DHCPFile);
        char* DHCPServerFile = NULL;
        DHCPServerFile = strtok(string, "");
        DHCPServerIPAddress = inet_addr(DHCPServerFile);
        fclose(DHCPFile);
    }

    switch(type)
    {
        case 1: // DHCP Discover (Broadcast)
        {
            printf("Send: Discover\n");
            discoverFlag = 1;
            broadcastFlag = 1;
            
            if(!aaType) // Broadcast
            {
            	unsigned short bootFlags = htons(0x8000);
            	memcpy(&sendBuf[10], &bootFlags, sizeof(unsigned short));
			}
			else if(aaType) // Unicast
			{
				unsigned short bootFlags = htons(0x0000);
            	memcpy(&sendBuf[10], &bootFlags, sizeof(unsigned short));	
			}
			
			unsigned int XID = htonl(getXID());
    		memcpy(&sendBuf[4], &XID, sizeof(unsigned int));
    
            unsigned int clientIPAddress = htonl(0x00000000);
    		memcpy(&sendBuf[12], &clientIPAddress, sizeof(unsigned int));

            // Option 53 DHCP Message Type
            unsigned char option53 = (0x35);
            memcpy(&sendBuf[240], &option53, sizeof(unsigned char));

            unsigned char option53_Length = (0x01);
            memcpy(&sendBuf[241], &option53_Length, sizeof(unsigned char));

            unsigned char option53_DhcpMessageType = (0x01);
            memcpy(&sendBuf[242], &option53_DhcpMessageType, sizeof(unsigned char));

            // Option 60 Vendor Class Identifier (BUPT number 2014000000)
            unsigned char option60 = (0x3c);
            memcpy(&sendBuf[243], &option60, sizeof(unsigned char));

            unsigned char option60_Length = (0x05);
            memcpy(&sendBuf[244], &option60_Length, sizeof(unsigned char));

            unsigned char option60_VendorClassIdentifier1 = (0x20);
            memcpy(&sendBuf[245], &option60_VendorClassIdentifier1, sizeof(unsigned char));
            unsigned char option60_VendorClassIdentifier2 = (0x14);
            memcpy(&sendBuf[246], &option60_VendorClassIdentifier2, sizeof(unsigned char));
            unsigned char option60_VendorClassIdentifier3 = (0x00);
            memcpy(&sendBuf[247], &option60_VendorClassIdentifier3, sizeof(unsigned char));
            unsigned char option60_VendorClassIdentifier4 = (0x00);
            memcpy(&sendBuf[248], &option60_VendorClassIdentifier4, sizeof(unsigned char));
            unsigned char option60_VendorClassIdentifier5 = (0x00);
            memcpy(&sendBuf[249], &option60_VendorClassIdentifier5, sizeof(unsigned char));

            // Option 55 Parameter Request List
            unsigned char option55 = (0x37);
            memcpy(&sendBuf[250], &option55, sizeof(unsigned char));

            unsigned char option55_Length = (0x0c);
            memcpy(&sendBuf[251], &option55_Length, sizeof(unsigned char));

            unsigned char option55_Item1 = (0x01);
            memcpy(&sendBuf[252], &option55_Item1, sizeof(unsigned char));
            unsigned char option55_Item15 = (0x0f);
            memcpy(&sendBuf[253], &option55_Item15, sizeof(unsigned char));
            unsigned char option55_Item3 = (0x03);
            memcpy(&sendBuf[254], &option55_Item3, sizeof(unsigned char));
            unsigned char option55_Item6 = (0x06);
            memcpy(&sendBuf[255], &option55_Item6, sizeof(unsigned char));
            unsigned char option55_Item44 = (0x2c);
            memcpy(&sendBuf[256], &option55_Item44, sizeof(unsigned char));
            unsigned char option55_Item46 = (0x2e);
            memcpy(&sendBuf[257], &option55_Item46, sizeof(unsigned char));
            unsigned char option55_Item47 = (0x2f);
            memcpy(&sendBuf[258], &option55_Item47, sizeof(unsigned char));
            unsigned char option55_Item31 = (0x1f);
            memcpy(&sendBuf[259], &option55_Item31, sizeof(unsigned char));
            unsigned char option55_Item33 = (0x21);
            memcpy(&sendBuf[260], &option55_Item33, sizeof(unsigned char));
            unsigned char option55_Item121 = (0x79);
            memcpy(&sendBuf[261], &option55_Item121, sizeof(unsigned char));
            unsigned char option55_Item249 = (0xf9);
            memcpy(&sendBuf[262], &option55_Item249, sizeof(unsigned char));
            unsigned char option55_Item43 = (0x2b);
            memcpy(&sendBuf[263], &option55_Item43, sizeof(unsigned char));

            // Option 255 End
            unsigned char option255 = (0xff);
            memcpy(&sendBuf[264], &option255, sizeof(unsigned char));

            // Padding
            unsigned char padding[312 - 265];
            for(counter = 0; counter < (312 - 265); counter++){
                padding[counter] = (0x00);
            }
            memcpy(&sendBuf[265], &padding, (312 - 265));
            break;
        }
        case 2: // DHCP Offer
        {
            // Do nothing
            break;
        }
        case 3: // DHCP Request
        {
            if(subType == 1) // For Discover-Offer-Request-ACK loop  (Broadcast)
            {
                if(discoverFlag == 1)
                {
                    printf("Send: Request (address acquisition)\n");

                    broadcastFlag = 1;
                    
                	if(!aaType) // Broadcast
		            {
		            	unsigned short bootFlags = htons(0x8000);
		            	memcpy(&sendBuf[10], &bootFlags, sizeof(unsigned short));
					}
					else if(aaType) // Unicast
					{
						unsigned short bootFlags = htons(0x0000);
		            	memcpy(&sendBuf[10], &bootFlags, sizeof(unsigned short));	
					}

                    // Option 53 DHCP Message Type
                    unsigned char option53 = (0x35);
                    memcpy(&sendBuf[240], &option53, sizeof(unsigned char));

                    unsigned char option53_Length = (0x01);
                    memcpy(&sendBuf[241], &option53_Length, sizeof(unsigned char));

                    unsigned char option53_DhcpMessageType = (0x03);
                    memcpy(&sendBuf[242], &option53_DhcpMessageType, sizeof(unsigned char));

                    // Option 54 DHCP Server Identifier
                    unsigned char option54 = (0x36);
                    memcpy(&sendBuf[243], &option54, sizeof(unsigned char));

                    unsigned char option54_Length = (0x04);
                    memcpy(&sendBuf[244], &option54_Length, sizeof(unsigned char));

                    memcpy(&sendBuf[245], &DHCPServerIPAddress, sizeof(unsigned int));
                    
                    // Option 60 Vendor Class Identifier (BUPT number 2014000000)
                    unsigned char option60 = (0x3c);
                    memcpy(&sendBuf[249], &option60, sizeof(unsigned char));

                    unsigned char option60_Length = (0x05);
                    memcpy(&sendBuf[250], &option60_Length, sizeof(unsigned char));

                    unsigned char option60_VendorClassIdentifier1 = (0x20);
                    memcpy(&sendBuf[251], &option60_VendorClassIdentifier1, sizeof(unsigned char));
                    unsigned char option60_VendorClassIdentifier2 = (0x14);
                    memcpy(&sendBuf[252], &option60_VendorClassIdentifier2, sizeof(unsigned char));
                    unsigned char option60_VendorClassIdentifier3 = (0x00);
                    memcpy(&sendBuf[253], &option60_VendorClassIdentifier3, sizeof(unsigned char));
                    unsigned char option60_VendorClassIdentifier4 = (0x00);
                    memcpy(&sendBuf[254], &option60_VendorClassIdentifier4, sizeof(unsigned char));
                    unsigned char option60_VendorClassIdentifier5 = (0x00);
                    memcpy(&sendBuf[255], &option60_VendorClassIdentifier5, sizeof(unsigned char));

                    // Option 55 Parameter Request List
                    unsigned char option55 = (0x37);
                    memcpy(&sendBuf[256], &option55, sizeof(unsigned char));

                    unsigned char option55_Length = (0x0c);
                    memcpy(&sendBuf[257], &option55_Length, sizeof(unsigned char));

                    unsigned char option55_Item1 = (0x01);
                    memcpy(&sendBuf[258], &option55_Item1, sizeof(unsigned char));
                    unsigned char option55_Item15 = (0x0f);
                    memcpy(&sendBuf[259], &option55_Item15, sizeof(unsigned char));
                    unsigned char option55_Item3 = (0x03);
                    memcpy(&sendBuf[260], &option55_Item3, sizeof(unsigned char));
                    unsigned char option55_Item6 = (0x06);
                    memcpy(&sendBuf[261], &option55_Item6, sizeof(unsigned char));
                    unsigned char option55_Item44 = (0x2c);
                    memcpy(&sendBuf[262], &option55_Item44, sizeof(unsigned char));
                    unsigned char option55_Item46 = (0x2e);
                    memcpy(&sendBuf[263], &option55_Item46, sizeof(unsigned char));
                    unsigned char option55_Item47 = (0x2f);
                    memcpy(&sendBuf[264], &option55_Item47, sizeof(unsigned char));
                    unsigned char option55_Item31 = (0x1f);
                    memcpy(&sendBuf[265], &option55_Item31, sizeof(unsigned char));
                    unsigned char option55_Item33 = (0x21);
                    memcpy(&sendBuf[266], &option55_Item33, sizeof(unsigned char));
                    unsigned char option55_Item121 = (0x79);
                    memcpy(&sendBuf[267], &option55_Item121, sizeof(unsigned char));
                    unsigned char option55_Item249 = (0xf9);
                    memcpy(&sendBuf[268], &option55_Item249, sizeof(unsigned char));
                    unsigned char option55_Item43 = (0x2b);
                    memcpy(&sendBuf[269], &option55_Item43, sizeof(unsigned char));

                    // Option 255 End
                    unsigned char option255 = (0xff);
                    memcpy(&sendBuf[270], &option255, sizeof(unsigned char));

                    // Padding
                    unsigned char padding[312 - 271];
                    for(counter = 0; counter < (312 - 271); counter++)
                    {
                        padding[counter] = (0x00);
                    }
                    memcpy(&sendBuf[271], &padding, (312 - 271));
                }
                else if(discoverFlag != 1) // For renew the IP when T2 expires
                {
                    printf("Send: Request (T2 expire, broadcast)\n");

                    discoverFlag = 0;
                    broadcastFlag = 1;

		            unsigned short bootFlags = htons(0x8000);
		            memcpy(&sendBuf[10], &bootFlags, sizeof(unsigned short));

                    // The client IP Address
                    unsigned int clientIPAddress = getIP();
                    memcpy(&sendBuf[12], &clientIPAddress, sizeof(unsigned int));

                    // Option 53 DHCP Message Type
                    unsigned char option53 = (0x35);
                    memcpy(&sendBuf[240], &option53, sizeof(unsigned char));

                    unsigned char option53_Length = (0x01);
                    memcpy(&sendBuf[241], &option53_Length, sizeof(unsigned char));

                    unsigned char option53_DhcpMessageType = (0x03);
                    memcpy(&sendBuf[242], &option53_DhcpMessageType, sizeof(unsigned char));

                    // Option 60 Vendor Class Identifier (BUPT number 2014000000)
                    unsigned char option60 = (0x3c);
                    memcpy(&sendBuf[243], &option60, sizeof(unsigned char));

                    unsigned char option60_Length = (0x05);
                    memcpy(&sendBuf[244], &option60_Length, sizeof(unsigned char));

                    unsigned char option60_VendorClassIdentifier1 = (0x20);
                    memcpy(&sendBuf[245], &option60_VendorClassIdentifier1, sizeof(unsigned char));
                    unsigned char option60_VendorClassIdentifier2 = (0x14);
                    memcpy(&sendBuf[246], &option60_VendorClassIdentifier2, sizeof(unsigned char));
                    unsigned char option60_VendorClassIdentifier3 = (0x00);
                    memcpy(&sendBuf[247], &option60_VendorClassIdentifier3, sizeof(unsigned char));
                    unsigned char option60_VendorClassIdentifier4 = (0x00);
                    memcpy(&sendBuf[248], &option60_VendorClassIdentifier4, sizeof(unsigned char));
                    unsigned char option60_VendorClassIdentifier5 = (0x00);
                    memcpy(&sendBuf[249], &option60_VendorClassIdentifier5, sizeof(unsigned char));

                    // Option 55 Parameter Request List
                    unsigned char option55 = (0x37);
                    memcpy(&sendBuf[250], &option55, sizeof(unsigned char));

                    unsigned char option55_Length = (0x0c);
                    memcpy(&sendBuf[251], &option55_Length, sizeof(unsigned char));

                    unsigned char option55_Item1 = (0x01);
                    memcpy(&sendBuf[252], &option55_Item1, sizeof(unsigned char));
                    unsigned char option55_Item15 = (0x0f);
                    memcpy(&sendBuf[253], &option55_Item15, sizeof(unsigned char));
                    unsigned char option55_Item3 = (0x03);
                    memcpy(&sendBuf[254], &option55_Item3, sizeof(unsigned char));
                    unsigned char option55_Item6 = (0x06);
                    memcpy(&sendBuf[255], &option55_Item6, sizeof(unsigned char));
                    unsigned char option55_Item44 = (0x2c);
                    memcpy(&sendBuf[256], &option55_Item44, sizeof(unsigned char));
                    unsigned char option55_Item46 = (0x2e);
                    memcpy(&sendBuf[257], &option55_Item46, sizeof(unsigned char));
                    unsigned char option55_Item47 = (0x2f);
                    memcpy(&sendBuf[258], &option55_Item47, sizeof(unsigned char));
                    unsigned char option55_Item31 = (0x1f);
                    memcpy(&sendBuf[259], &option55_Item31, sizeof(unsigned char));
                    unsigned char option55_Item33 = (0x21);
                    memcpy(&sendBuf[260], &option55_Item33, sizeof(unsigned char));
                    unsigned char option55_Item121 = (0x79);
                    memcpy(&sendBuf[261], &option55_Item121, sizeof(unsigned char));
                    unsigned char option55_Item249 = (0xf9);
                    memcpy(&sendBuf[262], &option55_Item249, sizeof(unsigned char));
                    unsigned char option55_Item43 = (0x2b);
                    memcpy(&sendBuf[263], &option55_Item43, sizeof(unsigned char));

                    // Option 255 End
                    unsigned char option255 = (0xff);
                    memcpy(&sendBuf[264], &option255, sizeof(unsigned char));

                    // Padding
                    unsigned char padding[312 - 265];
                    for(counter = 0; counter < (312 - 265); counter++){
                        padding[counter] = (0x00);
                    }
                    memcpy(&sendBuf[265], &padding, (312 - 265));
                }
                else
                {
                    ;
                }
            }
            else if(subType == 2) // For renew the IP address (Unicast)
            {
                printf("Send: Request (T1 expire, Unicast)\n");

                discoverFlag = 0;
                broadcastFlag = 0;
				
				unsigned short bootFlags = htons(0x0000);
                memcpy(&sendBuf[10], &bootFlags, sizeof(unsigned short));
                
                // The client IP Address
                unsigned int clientIPAddress = getIP();
                memcpy(&sendBuf[12], &clientIPAddress, sizeof(unsigned int));

                // Option 53 DHCP Message Type
                unsigned char option53 = (0x35);
                memcpy(&sendBuf[240], &option53, sizeof(unsigned char));

                unsigned char option53_Length = (0x01);
                memcpy(&sendBuf[241], &option53_Length, sizeof(unsigned char));

                unsigned char option53_DhcpMessageType = (0x03);
                memcpy(&sendBuf[242], &option53_DhcpMessageType, sizeof(unsigned char));

                // Option 60 Vendor Class Identifier (BUPT number 2014000000)
                unsigned char option60 = (0x3c);
                memcpy(&sendBuf[243], &option60, sizeof(unsigned char));

                unsigned char option60_Length = (0x05);
                memcpy(&sendBuf[244], &option60_Length, sizeof(unsigned char));

                unsigned char option60_VendorClassIdentifier1 = (0x20);
                memcpy(&sendBuf[245], &option60_VendorClassIdentifier1, sizeof(unsigned char));
                unsigned char option60_VendorClassIdentifier2 = (0x14);
                memcpy(&sendBuf[246], &option60_VendorClassIdentifier2, sizeof(unsigned char));
                unsigned char option60_VendorClassIdentifier3 = (0x00);
                memcpy(&sendBuf[247], &option60_VendorClassIdentifier3, sizeof(unsigned char));
                unsigned char option60_VendorClassIdentifier4 = (0x00);
                memcpy(&sendBuf[248], &option60_VendorClassIdentifier4, sizeof(unsigned char));
                unsigned char option60_VendorClassIdentifier5 = (0x00);
                memcpy(&sendBuf[249], &option60_VendorClassIdentifier5, sizeof(unsigned char));

                // Option 55 Parameter Request List
                unsigned char option55 = (0x37);
                memcpy(&sendBuf[250], &option55, sizeof(unsigned char));

                unsigned char option55_Length = (0x0c);
                memcpy(&sendBuf[251], &option55_Length, sizeof(unsigned char));

                unsigned char option55_Item1 = (0x01);
                memcpy(&sendBuf[252], &option55_Item1, sizeof(unsigned char));
                unsigned char option55_Item15 = (0x0f);
                memcpy(&sendBuf[253], &option55_Item15, sizeof(unsigned char));
                unsigned char option55_Item3 = (0x03);
                memcpy(&sendBuf[254], &option55_Item3, sizeof(unsigned char));
                unsigned char option55_Item6 = (0x06);
                memcpy(&sendBuf[255], &option55_Item6, sizeof(unsigned char));
                unsigned char option55_Item44 = (0x2c);
                memcpy(&sendBuf[256], &option55_Item44, sizeof(unsigned char));
                unsigned char option55_Item46 = (0x2e);
                memcpy(&sendBuf[257], &option55_Item46, sizeof(unsigned char));
                unsigned char option55_Item47 = (0x2f);
                memcpy(&sendBuf[258], &option55_Item47, sizeof(unsigned char));
                unsigned char option55_Item31 = (0x1f);
                memcpy(&sendBuf[259], &option55_Item31, sizeof(unsigned char));
                unsigned char option55_Item33 = (0x21);
                memcpy(&sendBuf[260], &option55_Item33, sizeof(unsigned char));
                unsigned char option55_Item121 = (0x79);
                memcpy(&sendBuf[261], &option55_Item121, sizeof(unsigned char));
                unsigned char option55_Item249 = (0xf9);
                memcpy(&sendBuf[262], &option55_Item249, sizeof(unsigned char));
                unsigned char option55_Item43 = (0x2b);
                memcpy(&sendBuf[263], &option55_Item43, sizeof(unsigned char));

                // Option 255 End
                unsigned char option255 = (0xff);
                memcpy(&sendBuf[264], &option255, sizeof(unsigned char));

                // Padding
                unsigned char padding[312 - 265];
                for(counter = 0; counter < (312 - 265); counter++)
                {
                    padding[counter] = (0x00);
                }
                memcpy(&sendBuf[265], &padding, (312 - 265));
            }
            else
            {
                ;
            }
            break;
        }
        case 4: // DHCP Decline
        {
            // Not required
            break;
        }
        case 5: // DHCP ACK
        {
            // Do nothing
            break;
        }
        case 6: // DHCP ACK
        {
            // Do nothing
            break;
        }
        case 7: // DHCP Release (Unicast)
        {
            printf("Send: Release\n");

            broadcastFlag = 0;

            // The client IP Address
            unsigned int clientIPAddress = getIP();
            memcpy(&sendBuf[12], &clientIPAddress, sizeof(unsigned int));

            // Option 53 DHCP Message Type
            unsigned char option53 = (0x35);
            memcpy(&sendBuf[240], &option53, sizeof(unsigned char));

            unsigned char option53_Length = (0x01);
            memcpy(&sendBuf[241], &option53_Length, sizeof(unsigned char));

            unsigned char option53_DhcpMessageType = (0x07);
            memcpy(&sendBuf[242], &option53_DhcpMessageType, sizeof(unsigned char));

            // Option 54 DHCP Server Identifier
            unsigned char option54 = (0x36);
            memcpy(&sendBuf[243], &option54, sizeof(unsigned char));

            unsigned char option54_Length = (0x04);
            memcpy(&sendBuf[244], &option54_Length, sizeof(unsigned char));

            memcpy(&sendBuf[245], &DHCPServerIPAddress, sizeof(unsigned char));

            // Option 255
            unsigned char option255 = (0xff);
            memcpy(&sendBuf[249], &option255, sizeof(unsigned char));

            // Padding
            unsigned char padding[312 - 249];
            for(counter = 0; counter < (312 - 249); counter++){
                padding[counter] = (0x00);
            }
            memcpy(&sendBuf[250], &padding, (312 - 249));
            break;
        }
        case 8: // DHCP Inform (Unicast)
        {
            printf("Send: Inform\n");

            broadcastFlag = 0;
            discoverFlag = 0;

            // The client IP Address
            unsigned int clientIPAddress = getIP();
            memcpy(&sendBuf[12], &clientIPAddress, sizeof(unsigned int));

            // Option 53 DHCP Message Type
            unsigned char option53 = (0x35);
            memcpy(&sendBuf[240], &option53, sizeof(unsigned char));

            unsigned char option53_Length = (0x01);
            memcpy(&sendBuf[241], &option53_Length, sizeof(unsigned char));

            unsigned char option53_DhcpMessageType = (0x08);
            memcpy(&sendBuf[242], &option53_DhcpMessageType, sizeof(unsigned char));

            // Option 60 Vendor Class Identifier (BUPT number 2014000000)
            unsigned char option60 = (0x3c);
            memcpy(&sendBuf[243], &option60, sizeof(unsigned char));

            unsigned char option60_Length = (0x05);
            memcpy(&sendBuf[244], &option60_Length, sizeof(unsigned char));

            unsigned char option60_VendorClassIdentifier1 = (0x20);
            memcpy(&sendBuf[245], &option60_VendorClassIdentifier1, sizeof(unsigned char));
            unsigned char option60_VendorClassIdentifier2 = (0x14);
            memcpy(&sendBuf[246], &option60_VendorClassIdentifier2, sizeof(unsigned char));
            unsigned char option60_VendorClassIdentifier3 = (0x00);
            memcpy(&sendBuf[247], &option60_VendorClassIdentifier3, sizeof(unsigned char));
            unsigned char option60_VendorClassIdentifier4 = (0x00);
            memcpy(&sendBuf[248], &option60_VendorClassIdentifier4, sizeof(unsigned char));
            unsigned char option60_VendorClassIdentifier5 = (0x00);
            memcpy(&sendBuf[249], &option60_VendorClassIdentifier5, sizeof(unsigned char));

            // Option 55 Parameter Request List
            unsigned char option55 = (0x37);
            memcpy(&sendBuf[250], &option55, sizeof(unsigned char));

            unsigned char option55_Length = (0x0c);
            memcpy(&sendBuf[251], &option55_Length, sizeof(unsigned char));

            unsigned char option55_Item1 = (0x01);
            memcpy(&sendBuf[252], &option55_Item1, sizeof(unsigned char));
            unsigned char option55_Item15 = (0x0f);
            memcpy(&sendBuf[253], &option55_Item15, sizeof(unsigned char));
            unsigned char option55_Item3 = (0x03);
            memcpy(&sendBuf[254], &option55_Item3, sizeof(unsigned char));
            unsigned char option55_Item6 = (0x06);
            memcpy(&sendBuf[255], &option55_Item6, sizeof(unsigned char));
            unsigned char option55_Item44 = (0x2c);
            memcpy(&sendBuf[256], &option55_Item44, sizeof(unsigned char));
            unsigned char option55_Item46 = (0x2e);
            memcpy(&sendBuf[257], &option55_Item46, sizeof(unsigned char));
            unsigned char option55_Item47 = (0x2f);
            memcpy(&sendBuf[258], &option55_Item47, sizeof(unsigned char));
            unsigned char option55_Item31 = (0x1f);
            memcpy(&sendBuf[259], &option55_Item31, sizeof(unsigned char));
            unsigned char option55_Item33 = (0x21);
            memcpy(&sendBuf[260], &option55_Item33, sizeof(unsigned char));
            unsigned char option55_Item121 = (0x79);
            memcpy(&sendBuf[261], &option55_Item121, sizeof(unsigned char));
            unsigned char option55_Item249 = (0xf9);
            memcpy(&sendBuf[262], &option55_Item249, sizeof(unsigned char));
            unsigned char option55_Item43 = (0x2b);
            memcpy(&sendBuf[263], &option55_Item43, sizeof(unsigned char));

            // Option 255 End
            unsigned char option255 = (0xff);
            memcpy(&sendBuf[264], &option255, sizeof(unsigned char));

            // Padding
            unsigned char padding[312 - 265];
            for(counter = 0; counter < (312 - 265); counter++){
                padding[counter] = (0x00);
            }
            memcpy(&sendBuf[265], &padding, (312 - 265));
            break;
        }
        default:{

        }
    }
    //Send data
    int length;

    // Broadcast
    memset(&sendAddr, 0, sizeof(sendAddr));/*Zero out structure*/
    sendAddr.sin_family = AF_INET; /* Internet addr family */
    if(broadcastFlag == 1)
        sendAddr.sin_addr.s_addr = 0xffffffff;/*Server IP address*/
    else
        sendAddr.sin_addr.s_addr = DHCPServerIPAddress;
    sendAddr.sin_port = htons(dhcpServPort); /* Server port */

    if(type == 1 || type == 3 || type == 7 || type == 8)
    {
        if(type == 7 && getIP() == 0x01010101)
            ;
        else
            length = sendto(sock, sendBuf, sendSize, 0, (struct sockaddr *) &sendAddr, sizeof(sendAddr));
    }

    printf("send length: %d\n", length);

    if((type == 1 || type == 3 || type == 8) && (aaType != 1))
    {
        recvMSG(type, subType);
        discoverFlag = 0;
    } 
    else if(type == 7)
    {
        char *IPPointer = "192.168.0.254";
        char *MASKPointer = "255.255.255.0";
        char *RouterPointer = "192.168.0.254";
        SetIfAddr("eth1", IPPointer, MASKPointer, RouterPointer);
    }
    else if(aaType == 1 && type == 1)
    {
    	sleep(0.010);
    	sendMSG(3, 1);
	}
	else if((aaType == 1) && (type == 3))
		aaType = 0;
}

unsigned int getXID()
{
    srand((unsigned)time(NULL));  
    return rand();
}

void getMAC(unsigned char MAC[6])
{
    struct ifreq ifreq; 
    int sock; 

    if((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0)
        perror("socket "); 

    strcpy(ifreq.ifr_name, "eth1"); 
    if(ioctl(sock, SIOCGIFHWADDR, &ifreq) < 0) 
        perror("ioctl "); 

    MAC[0] = (unsigned char)ifreq.ifr_hwaddr.sa_data[0];
    MAC[1] = (unsigned char)ifreq.ifr_hwaddr.sa_data[1];
    MAC[2] = (unsigned char)ifreq.ifr_hwaddr.sa_data[2];
    MAC[3] = (unsigned char)ifreq.ifr_hwaddr.sa_data[3];
    MAC[4] = (unsigned char)ifreq.ifr_hwaddr.sa_data[4];
    MAC[5] = (unsigned char)ifreq.ifr_hwaddr.sa_data[5];
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

    if(ioctl(sock, SIOCGIFADDR, &ifr) < 0)
        perror("ioctl"); 

    memcpy(&sin, &ifr.ifr_addr, sizeof(sin));

    unsigned int IP = sin.sin_addr.s_addr;
    return IP;
}

int SetIfAddr(char *ifname, char *Ipaddr, char *mask,char *gateway)
{
    int fd;
    int rc;
    struct ifreq ifr; 
    struct sockaddr_in *sin;
    struct rtentry rt;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if(fd < 0)
    {
        perror("socket error");     
        return -1;     
    }
    memset(&ifr,0,sizeof(ifr)); 
    strcpy(ifr.ifr_name,ifname); 
    sin = (struct sockaddr_in*)&ifr.ifr_addr;     
    sin->sin_family = AF_INET;     
    //IP地址
    if(inet_aton(Ipaddr,&(sin->sin_addr)) < 0)   
    {     
        perror("inet_aton error");     
        return -2;     
    }    

    if(ioctl(fd,SIOCSIFADDR,&ifr) < 0)   
    {     
        perror("ioctl SIOCSIFADDR error");     
        return -3;     
    }
    //子网掩码
    if(inet_aton(mask,&(sin->sin_addr)) < 0)   
    {     
        perror("inet_pton error");     
        return -4;     
    }    
    if(ioctl(fd, SIOCSIFNETMASK, &ifr) < 0)
    {
        perror("ioctl");
        return -5;
    }
    //网关
    memset(&rt, 0, sizeof(struct rtentry));
    memset(sin, 0, sizeof(struct sockaddr_in));
    sin->sin_family = AF_INET;
    sin->sin_port = 0;
    if(inet_aton(gateway, &sin->sin_addr)<0)
    {
       printf("inet_aton error\n");
    }
    memcpy ( &rt.rt_gateway, sin, sizeof(struct sockaddr_in));
    ((struct sockaddr_in *)&rt.rt_dst)->sin_family=AF_INET;
    ((struct sockaddr_in *)&rt.rt_genmask)->sin_family=AF_INET;
    rt.rt_flags = RTF_GATEWAY;
    if (ioctl(fd, SIOCADDRT, &rt)<0)
    {
        //zError( "ioctl(SIOCADDRT) error in set_default_route\n");
        close(fd);
        return -1;
    }
    close(fd);
    return rc;
}

int SetIP(char *ifname, char *Ipaddr)
{
    int fd;
    int rc;
    struct ifreq ifr; 
    struct sockaddr_in *sin;
    struct rtentry rt;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if(fd < 0)
    {
        perror("socket   error");     
        return -1;     
    }
    memset(&ifr,0,sizeof(ifr)); 
    strcpy(ifr.ifr_name,ifname); 
    sin = (struct sockaddr_in*)&ifr.ifr_addr;     
    sin->sin_family = AF_INET;     
    //IP地址
    if(inet_aton(Ipaddr,&(sin->sin_addr)) < 0)   
    {     
        perror("inet_aton   error");     
        return -2;     
    }    

    if(ioctl(fd,SIOCSIFADDR,&ifr) < 0)   
    {     
        perror("ioctl   SIOCSIFADDR   error");     
        return -3;     
    }
    close(fd);
    return rc;
}

int SetMASK(char *ifname, char *mask)
{
    int fd;
    int rc;
    struct ifreq ifr; 
    struct sockaddr_in *sin;
    struct rtentry rt;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if(fd < 0)
    {
        perror("socket   error");     
        return -1;     
    }
    memset(&ifr,0,sizeof(ifr)); 
    strcpy(ifr.ifr_name,ifname); 
    sin = (struct sockaddr_in*)&ifr.ifr_addr;     
    sin->sin_family = AF_INET;     
   
    //子网掩码
    if(inet_aton(mask,&(sin->sin_addr)) < 0)   
    {     
        perror("inet_pton   error");     
        return -4;     
    }    
    if(ioctl(fd, SIOCSIFNETMASK, &ifr) < 0)
    {
        perror("ioctl");
        return -5;
    }
    close(fd);
    return rc;
}

int SetRouter(char *ifname, char *gateway)
{
    int fd;
    int rc;
    struct ifreq ifr; 
    struct sockaddr_in *sin;
    struct rtentry  rt;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if(fd < 0)
    {
    	perror("socket   error");     
        return -1;     
    }
    memset(&ifr,0,sizeof(ifr)); 
    strcpy(ifr.ifr_name,ifname); 
    sin = (struct sockaddr_in*)&ifr.ifr_addr;     
    sin->sin_family = AF_INET;     
    
    //网关
    memset(&rt, 0, sizeof(struct rtentry));
    memset(sin, 0, sizeof(struct sockaddr_in));
    sin->sin_family = AF_INET;
    sin->sin_port = 0;
    if(inet_aton(gateway, &sin->sin_addr)<0)
    {
       printf("inet_aton error\n");
    }
    memcpy ( &rt.rt_gateway, sin, sizeof(struct sockaddr_in));
    ((struct sockaddr_in *)&rt.rt_dst)->sin_family=AF_INET;
    ((struct sockaddr_in *)&rt.rt_genmask)->sin_family=AF_INET;
    rt.rt_flags = RTF_GATEWAY;
    if (ioctl(fd, SIOCADDRT, &rt)<0)
    {
        //zError( "ioctl(SIOCADDRT) error in set_default_route\n");
        close(fd);
        return -1;
    }
    close(fd);
    return rc;
}
