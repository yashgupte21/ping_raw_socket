#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <stdio.h>
#include <stdlib.h>
#define ICMP_ECHO 8 // type 9-echo request
#define ICMP_ECHOREPLY 0 // type0-echo reply
#define ICMP_MIN 12 // minimum 12 byte icmp packet (just header)
/* The IP header 20bytes*/
int count1 = 0;
int count2 = 0;
typedef struct iphdr {
    unsigned char h_len:4; // length of the header
    unsigned char version:4; // Version of IP
    unsigned char tos; // Type of service
    unsigned short total_len; // total length of the packet
    unsigned short ident; // unique identifier
    unsigned short frag_and_offset; // flags and offset
    unsigned char ttl;
    unsigned char proto; // protocol (TCP, UDP etc)
    unsigned short checksum; // IP checksum
    unsigned int sourceIP;
    unsigned int destIP;
}IpHeader;
typedef struct _ihdr {
    BYTE i_type;
    BYTE i_code; /* type sub code */
    USHORT i_cksum;
    USHORT i_id;
    USHORT i_seq;
    char *data;
    /* This is not the std header, but we reserve space for future*/
    ULONG timestamp;
}IcmpHeader;
#define STATUS_FAILED 0xFFFF
#define MAX_PACKET 1024
#define xmalloc(s) HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,(s))
#define xfree(p) HeapFree(GetProcessHeap(),0,(p))
USHORT checksum(USHORT *, int);
void fill_icmp_head(char *);
void decode_resp(char *,int ,struct sockaddr_in *);
void Usage(char *progname)
 {
     fprintf(stderr,"Usage:\n");
    fprintf(stderr,"%s <host>\n",progname);
    ExitProcess(STATUS_FAILED);
 }
int main(int argc, char **argv){
	WSADATA wsaData;
    SOCKET sockRaw;
    struct sockaddr_in dest,src;
    struct hostent *hp;
    int bread,datasize;
    int fromlen = sizeof(src);
    char *dest_ip;
    char *icmp_data;
    char *recvbuf;
    unsigned int addr=0;
    struct sockaddr_in  from;
    USHORT seq_no = 0;
    if (WSAStartup(0x0101,&wsaData) != 0){
        fprintf(stderr,"WSAStartup failed: %d\n",GetLastError());
        ExitProcess(STATUS_FAILED);
    }
    if (argc <2 ) {
    Usage(argv[0]);
    }
	if((sockRaw=socket(AF_INET,SOCK_RAW,IPPROTO_ICMP))==INVALID_SOCKET)
    {
        fprintf(stderr,"WSAStartup failed: %d\n",GetLastError());
        ExitProcess(STATUS_FAILED);
    }
    struct sockaddr_in sadr;
    sadr.sin_family = AF_INET;
    sadr.sin_addr.s_addr = inet_addr("127.0.0.1");
    //int count = 0;
    sadr.sin_port = htons(0);
    bind(sockRaw, (struct sockaddr*)&sadr, sizeof(sadr));
    recvbuf = xmalloc(MAX_PACKET); // 1024
    // memset(icmp_data,0,MAX_PACKET);
    // fill_icmp_head(icmp_data);
	while(1){
        int bwrote;
		bread = recvfrom(sockRaw,recvbuf,MAX_PACKET,0,(struct sockaddr*)&from,&fromlen);
		if (bread == SOCKET_ERROR){
	        if (WSAGetLastError() == WSAETIMEDOUT)
	        { printf("timed out\n");
	            continue; }
	        fprintf(stderr,"recvfrom failed: %d\n",WSAGetLastError());
	        perror("revffrom failed.");
	        ExitProcess(STATUS_FAILED);
	    }
	    decode_resp(recvbuf,bread,&from);
        if(count1 == 2)
            break;
	    sleep(3);
        // bwrote = sendto(sockRaw,icmp_data,datasize,0,(struct sockaddr*)&dest,sizeof(dest));
        // if (bwrote == SOCKET_ERROR){
        //     fprintf(stderr,"sendto failed: %d\n",WSAGetLastError());
        //     ExitProcess(STATUS_FAILED);
        // }
        // if (bwrote < datasize ) {
        //     fprintf(stdout,"Wrote %d bytes\n",bwrote);
        // }
        // sleep(2);
	}
    while(1) {
        int bwrote;
        ((IcmpHeader*)icmp_data)->i_cksum = 0;
        ((IcmpHeader*)icmp_data)->timestamp = GetTickCount();
        ((IcmpHeader*)icmp_data)->i_seq = seq_no++;
        ((IcmpHeader*)icmp_data)->i_cksum=checksum((USHORT*)icmp_data, sizeof(IcmpHeader));
        ((IcmpHeader*)icmp_data)->data = "abcedfghijkiufbpaiuf";
        //printf("%d", &(IcmpHeader*)imcp_data->i_type);
        bwrote = sendto(sockRaw,icmp_data,datasize,0,(struct sockaddr*)&dest,sizeof(dest));
        if(bwrote != 0)
            count2++;
        if(count2 == 6)
            break;
        if (bwrote == SOCKET_ERROR){
            fprintf(stderr,"sendto failed: %d\n",WSAGetLastError());
            ExitProcess(STATUS_FAILED);
        }
        if (bwrote < datasize ) {
            fprintf(stdout,"Wrote %d bytes\n",bwrote);
        }
        sleep(2);
        // bread = recvfrom(sockRaw,recvbuf,MAX_PACKET,0,(struct sockaddr*)&from,&fromlen);
        // if (bread == SOCKET_ERROR){
        //     if (WSAGetLastError() == WSAETIMEDOUT)
        //     { printf("timed out\n");
        //         continue; }
        //     fprintf(stderr,"recvfrom failed: %d\n",WSAGetLastError());
        //     perror("revffrom failed.");
        //     ExitProcess(STATUS_FAILED);
        // }
        // decode_resp(recvbuf,bread,&from);
        // sleep(2);
    }
	closesocket(sockRaw);
    xfree(icmp_data);
    xfree(recvbuf );
    WSACleanup();
	return 0;
} 
void decode_resp(char *buf, int bytes,struct sockaddr_in *from)
 {
    count1++;
    IpHeader *iphdr;
    IcmpHeader *icmphdr;
    unsigned short iphdrlen;
    iphdr = (IpHeader *)buf;
    iphdrlen = iphdr->h_len * 4 ; // number of 32-bit words *4 = bytes
    // if (bytes < iphdrlen + ICMP_MIN) {
    //     printf("Too few bytes from %s\n",inet_ntoa(from->sin_addr));
    // }
    icmphdr = (IcmpHeader*)(buf + iphdrlen);
    //printf("ICMP DATA %s", buf);
    //icmp_data = (IcmpHeader *)(buf)
    if (icmphdr->i_type != ICMP_ECHOREPLY) {
        fprintf(stderr,"non-echo type %d recvd\n",icmphdr->i_type);
        return;
    }

    // fp=fopen("receiveFrom.txt","a+")

    // fputs("The icmp header file receiveFrom %s\r\n" % str(icmphdr))

    // fputs("The icmp header length %s\r\n" % str(iphdrlen)) 
    // if (icmphdr->i_id != (USHORT)GetCurrentProcessId())
    // {
    //     fprintf(stderr,"someone else's packet!\n");
    //     return ;
    // }
    printf("%d bytes from %s:",bytes, inet_ntoa(from->sin_addr));
    printf(" icmp_seq = %d. ",icmphdr->i_seq);
    printf(" %d ", icmphdr->i_type);
    printf(" time: %d ms ",GetTickCount()-icmphdr->timestamp);
    printf("icmp data : %s", icmphdr->data);
    printf("\n");
    printf("Request received");
    printf("\n");

    char *filename= "Request_server.txt";
    FILE *fp = fopen(filename, "w");
    if(fp == NULL)
    {
        //error
    }
    
    //fputc(ch, fp);
   fprintf(fp,"Number of bytes:%d \n",bytes ); 
   fprintf(fp,"From IP address:%s \n ", inet_ntoa(from->sin_addr) ); 
   fprintf(fp,"Data: %s \n",  icmphdr->data);
   fclose(fp);


 }
//  void fill_icmp_head(char * icmp_data){
//     IcmpHeader *icmp_hdr;

//     icmp_hdr = (IcmpHeader*)icmp_data;
//     icmp_hdr->i_type = ICMP_ECHO;
//     icmp_hdr->i_code = 0;
//     icmp_hdr->i_cksum = 0;
//     icmp_hdr->i_id = (USHORT)GetCurrentProcessId();
//     icmp_hdr->i_seq = 0;
//     icmp_hdr->data = "";
// }
 USHORT checksum(USHORT *buffer, int size)
 {
    unsigned long cksum=0;
    while(size >1) {
        cksum+=*buffer++;
        size -=sizeof(USHORT);
    }

    if(size) {
        cksum += *(UCHAR*)buffer;
    }
    cksum = (cksum >> 16) + (cksum & 0xffff);
    cksum += (cksum >>16);
    return (USHORT)(~cksum);
} 
