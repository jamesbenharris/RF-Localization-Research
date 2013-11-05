/*
Written by Ben Harris
james.ben.harris@gmail.com

References:
libpcap

*/
#include <pcap.h> 
#include <stdio.h> 
#include <stdlib.h> 
#include <errno.h> 
#include <sys/socket.h> 
#include <netinet/in.h> 
#include <arpa/inet.h> 
#include <netinet/if_ether.h>
#include <unistd.h>
#include <signal.h>
#include <net/if.h>
#include <mysql/mysql.h>
#include <string.h>
#include <math.h>

/*
Found following specs arpsniff source code.
*/

#define ETH_HEADER_SIZE 14
#define AVS_HEADER_SIZE 64                 
#define DATA_80211_FRAME_SIZE 24           
#define LLC_HEADER_SIZE 8            
#define PRISM_HEADER_SIZE 144

/*
Found following specs arpsniff source code.
*/

typedef struct mac_header{
unsigned char fc[2];
unsigned char id[2];
unsigned char add1[6];
unsigned char add2[6];
unsigned char add3[6];
unsigned char sc[2];
}mac_header;

/* Holds Time Dependent Kahlman Variables for each source*/

struct kahlman_filter
{
  char MAC;
  float xhatkminusone;
  float pofkminusone;
};

char kalman_filter[100][50];
float kalman_xk[100];
float kalman_pk[100];

/*
Found
http://svn.ninux.org/svn/ninuxdeveloping/merpa/trunk/prism.h
*/

struct prism_value
{
 uint32_t did; // This has a different ID for each parameter
 uint16_t status;
 uint16_t len; // length of the data (u32) used 0-4
 uint32_t data; // The data value
} __attribute__ ((packed));

/*
	Found
	http://home.martin.cc/linux/prism
*/

struct prism_header
{
 uint32_t msgcode;             // = PRISM_MSGCODE
 uint32_t msglen;     // The length of the entire header - usually 144 bytes = 0x90
 char devname[16];       // The name of the device that captured this packet
 struct prism_value hosttime;  // This is measured in jiffies - I think
 struct prism_value mactime;   // This is a truncated microsecond timer,
                                  // we get the lower 32 bits of a 64 bit value
 struct prism_value channel;
 struct prism_value rssi;
 struct prism_value sq;
 struct prism_value signal;
 struct prism_value noise;
 struct prism_value rate;
 struct prism_value istx;
 struct prism_value frmlen;
 char   dot_11_header[];
} __attribute__ ((packed));


float update_kalman(int,float,float,float,float);

float locate_kalman(char MAC[50], float signal)
{

  int i;
  for (i=0; i < 99;i++)
  {
    if (strcmp(MAC,kalman_filter[i]) == 0)
    {
      signal = pow(10,signal/10);
      return update_kalman(i,signal,.5,kalman_xk[i],kalman_pk[i]);
      break;
    }
    else
    {
     if (strcmp(kalman_filter[i],"NULL") == 0)
     {
       strcpy(kalman_filter[i],MAC);
       kalman_xk[i] = 0;
       kalman_pk[i] = 1;
       break;
     }
    }
  }
  
}

float update_kalman(int number,float signal,float z, float xkminusone, float pkminusone)
{
  float k = pkminusone/(pkminusone + z);
  float xk = xkminusone + k*(signal-xkminusone);
  float pk = (1 - k)*pkminusone;
  kalman_xk[number] = xk;
  kalman_pk[number] = pk;
  return xk;
}

#define maclength 50
#define datalength 150
FILE *pf;
char mac_local[maclength];
char command_local[datalength] = "ifconfig | awk '$0 ~ /HWaddr/ {if (length($5) == 17) print $5}' | uniq";
int j=0;
int wired=0;        /* flag for wired/wireless */


void my_callback(u_char * args, const struct pcap_pkthdr *header, const u_char * packet) 
{ 
  struct ether_header *eth_header;  /* in ethernet.h included by if_eth.h */
  struct prism_header *p_header;   /* RFC 1042 encapsulation header */
  struct ether_arp *arp_packet;     /* from if_eth.h */
  struct mac_header *p;
  if (wired)     /* global flag - wired or wireless? */
  {
    eth_header = (struct ether_header *) packet;
    arp_packet = (struct ether_arp *) (packet + ETH_HEADER_SIZE);
    if (ntohs (eth_header->ether_type) != ETHERTYPE_ARP)return;
  } else {    /* wireless */
    p_header =  (struct prism_header *) packet;
    p = (struct mac_header *)(packet+PRISM_HEADER_SIZE);
  }
  if (strcmp(ether_ntoa ((struct ether_addr *)p->add2),"0:0:0:0:0:0") != 0){
    double signal = locate_kalman(ether_ntoa ((struct ether_addr *)p->add2), (int)p_header->signal.data);
    mysql_connection(ether_ntoa ((struct ether_addr *)p->add2),mac_local, signal);
  }
}

void mysql_connection(char MACC[50], char MACR[50], double signal)
{
   MYSQL *conn;
   MYSQL_RES *res;
   MYSQL_ROW row;
   char *server = "serverip";
   char *user = "username";
   char *password = "####"; /* set me first */
   char *database = "PECKHAM_RAW_DATA";
   conn = mysql_init(NULL);
   /* Connect to database */
   if (!mysql_real_connect(conn, server,
         user, password, database, 0, NULL, 0)) {
      fprintf(stderr, "%s\n", mysql_error(conn));
      exit(1);
   }
   /* send SQL query */
   char query[150] = {};
   sprintf(query, "INSERT INTO RAW_PACKET_INFO(MAC_CLIENT,MAC_ROUTER,`SIGNAL`) VALUES('%s','%s','%f')",MACC,MACR,signal);
   if (mysql_query(conn, query)) {
      fprintf(stderr, "%s\n", mysql_error(conn));
      exit(1);
   }
   mysql_close(conn);
}


int main(int argc,char **argv) 
{ 

    
    pf = popen(command_local,"r");
    fgets(mac_local,maclength,pf);
    fprintf(stdout, "Hardware Address %s\n",mac_local);
    
    int i;
    char *dev; 
    char errbuf[PCAP_ERRBUF_SIZE]; 
    pcap_t* descr; 
    const u_char *packet; 
    struct pcap_pkthdr hdr;
    struct ether_header *eptr;    /* net/ethernet.h */
    struct bpf_program fp;        /* hold compiled program */
    bpf_u_int32 maskp;            /* subnet mask */
    bpf_u_int32 netp;             /* ip */
    
    /* Now get a device */
    dev  = "ath0";
    
    for (i=0; i < 99;i++)
    {
    strcpy(kalman_filter[i],"NULL");
    }
    
    if(dev == NULL) {
        fprintf(stderr, "%s\n", errbuf);
        exit(1);
    } 
       /* Found ArpSniff */
    pcap_lookupnet(dev, &netp, &maskp, errbuf); 
 
    /* Found ArpSniff */
    descr = pcap_open_live(dev, BUFSIZ, 1,-1, errbuf); 
    if(descr == NULL) {
        printf("pcap_open_live(): %s\n", errbuf);
        exit(1);
    } 
 
   /* Found ArpSniff */
  if (pcap_datalink (descr) == DLT_EN10MB)
  {
    wired = 1;     /* ethernet link */
  } else {
    if (pcap_datalink (descr) == DLT_PRISM_HEADER)
    {
      wired = 0;  /* wireless */
      printf("Prism Headers Enabled\n");
    } else {
      fprintf (stderr, "I don't support this interface type!\n");
      exit (1);
    }
  }
     /* Found ArpSniff */
    if(pcap_compile(descr,&fp,"",0,netp) == -1)
    {fprintf(stderr,"Error calling pcap_compile\n"); exit(1); }


    /* Found ArpSniff */
    if(pcap_setfilter(descr, &fp) == -1) {
        fprintf(stderr, "Error setting filter\n");
        exit(1);
    } 
 
    /* Found ArpSniff */
    pcap_loop(descr, -1, my_callback, NULL); 
    return 0; 
}