
#include <stdio.h>
#include <string.h>


#define PACKET_MAC_LTE_DEFAULT_UDP_PORT (9877)
#define __LITTLE_ENDIAN

#define __LITTLE_ENDIAN_BITFIELD

#define IPPROTO_UDP  17	  /* User Datagram Protocol 	  */

#define MAC_LTE_DLT 147

#define ETH_P_IP		0x0800	/*Internet Protocol packet */

#define ETH_ALEN 6

#define __packed	__attribute__((__packed__))

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;


#define BigLittleSwap16(x) ((u16)(                         \
         (((u16)(x) & (u16)0x00ff) << 8) |            \
         (((u16)(x) & (u16)0xff00) << 8)))	


/* This structure gets written to the start of the file */
typedef struct pcap_hdr_s {
        unsigned int   magic_number;   /* magic number */
        unsigned short version_major;  /* major version number */
        unsigned short version_minor;  /* minor version number */
        unsigned int   thiszone;       /* GMT to local correction */
        unsigned int   sigfigs;        /* accuracy of timestamps */
        unsigned int   snaplen;        /* max length of captured packets, in octets */
        unsigned int   network;        /* data link type */
} pcap_hdr_t;

/* This structure precedes each packet */
typedef struct pcaprec_hdr_s {
        unsigned int   ts_sec;         /* timestamp seconds */
        unsigned int   ts_usec;        /* timestamp microseconds */
        unsigned int   incl_len;       /* number of octets of packet saved in file */
        unsigned int   orig_len;       /* actual length of packet */
} pcaprec_hdr_t;

pcap_hdr_t file_header = {
        0xa1b2c3d4,   /* magic number */
        2, 4,         /* version number is 2.4 */
        0,            /* timezone */
        0,            /* sigfigs - apparently all tools do this */
        65535,        /* snaplen - this should be long enough */
        0x00000001   /* Data Link Type (DLT).  Set as unused value 147 for now */
    };
struct ethhdr {
	u8 h_dest[6];
	u8 h_source[6];
	u16 h_proto;
} __packed;

#if 0
struct iphdr {
	u8 ver_len;
	u8 dscp_ecn;
	u16 total_length;
	u16 ident;
	u16 frag_off_flags;
	u8 ttl;
	u8 proto;
	u16 checksum;
	u32 src;
	u32 dest;
} __packed;
#endif

struct iphdr {
#if defined(__LITTLE_ENDIAN_BITFIELD)
	u8	ihl:4,
		version:4;
#elif defined (__BIG_ENDIAN_BITFIELD)
	u8	version:4,
  		ihl:4;
#else
#error	"Please fix <asm/byteorder.h>"
#endif
	u8	tos;
	u16	tot_len;
	u16	id;
	u16	frag_off;
	u8	ttl;
	u8	protocol;
	u16	check;
	u32	saddr;
	u32	daddr;
	/*The options start here. */
} __packed;


struct udphdr {
	u16 source;
	u16 dest;
	u16 len;
	u16 check;
} __packed;

struct ethhdr var_ethhdr;
struct iphdr var_iphdr;
struct udphdr var_udphdr;

FILE *file_fd = NULL;

static unsigned int subframesSinceCaptureStart;

static unsigned char s_payload[200];
char soumac[6]={0xA8,0x15,0x4d,0xb1,0xb4,0x82}; 
char dstmac[6]={0x10,0x78,0xd2,0xa9,0x42,0x2b};

int checkCPUendian()	
{	
   union{

		  unsigned long int i;

		  unsigned char s[4];

   }c;
   c.i = 0x12345678;
   return (0x12 == c.s[0]);
	
}

unsigned short int HtoNs(unsigned short int h)

{

       // 若本机为大端，与网络字节序同，直接返回

       // 若本机为小端，转换成大端再返回

       return checkCPUendian() ? h : BigLittleSwap16(h);

}

void generate_sdu_payload(){	
	int i=0;
	for(i=0;i<200;i++){
		s_payload[i]=i%('z'-'a')+'a';
	}
}

static inline unsigned short from32to16(unsigned int x)
{
	/* add up 16-bit and 16-bit for 16+c bit */
	x = (x & 0xffff) + (x >> 16);
	/* add up carry.. */
	x = (x & 0xffff) + (x >> 16);
	return x;
}

static unsigned int do_csum(const unsigned char *buff, int len)
{
	int odd;
	unsigned int result = 0;

	if (len <= 0)
		goto out;
	odd = 1 & (unsigned long) buff;
	if (odd) {
#ifdef __LITTLE_ENDIAN
		result += (*buff << 8);
#else
		result = *buff;
#endif
		len--;
		buff++;
	}
	if (len >= 2) {
		if (2 & (unsigned long) buff) {
			result += *(unsigned short *) buff;
			len -= 2;
			buff += 2;
		}
		if (len >= 4) {
			const unsigned char *end = buff + ((unsigned)len & ~3);
			unsigned int carry = 0;
			do {
				unsigned int w = *(unsigned int *) buff;
				buff += 4;
				result += carry;
				result += w;
				carry = (w > result);
			} while (buff < end);
			result += carry;
			result = (result & 0xffff) + (result >> 16);
		}
		if (len & 2) {
			result += *(unsigned short *) buff;
			buff += 2;
		}
	}
	if (len & 1)
#ifdef __LITTLE_ENDIAN
		result += *buff;
#else
		result += (*buff << 8);
#endif
	result = from32to16(result);
	if (odd)
		result = ((result >> 8) & 0xff) | ((result & 0xff) << 8);
out:
	return result;
}


/*
 *	This is a version of ip_compute_csum() optimized for IP headers,
 *	which always checksum on 4 octet boundaries.
 */
u16 ip_fast_csum(const void *iph, unsigned int ihl)
{
	return (u16)~do_csum(iph, ihl*4);
}
static inline unsigned short from64to16(unsigned long x)
{
	/* Using extract instructions is a bit more efficient
	   than the original shift/bitmask version.  */

	union {
		unsigned long	ul;
		unsigned int	ui[2];
		unsigned short	us[4];
	} in_v, tmp_v, out_v;

	in_v.ul = x;
	tmp_v.ul = (unsigned long) in_v.ui[0] + (unsigned long) in_v.ui[1];

	/* Since the bits of tmp_v.sh[3] are going to always be zero,
	   we don't have to bother to add that in.  */
	out_v.ul = (unsigned long) tmp_v.us[0] + (unsigned long) tmp_v.us[1]
			+ (unsigned long) tmp_v.us[2];

	/* Similarly, out_v.us[2] is always zero for the final add.  */
	return out_v.us[0] + out_v.us[1];
}

u16 csum_tcpudp_magic(u32 saddr, u32 daddr,
				   unsigned short len,
				   unsigned short proto,
				   u32 sum)
{
	return (u16)~from64to16(
		(long)saddr + (long)daddr +
		(long)sum + ((len + proto) << 8));
}

u32 csum_partial(const void *buff, int len, u32 sum)
{
	unsigned long result = do_csum(buff, len);

	/* add in old sum, and carry.. */
	result += (u32)sum;
	/* 32+c bits -> 32 bits */
	result = (result & 0xffffffff) + (result >> 32);
	return (u32)result;
}

/* Write an individual PDU (PCAP packet header + mac-context + mac-pdu) */
//after udphdr is the usrdefine hdr one byte is for type,one byte for user id two bytes for length

static void creat_extra_header(char *pheader,unsigned int *plength,int pkt_len,char type){
	char extrahead[4];
 	u32 sip = 0x82726252;
	u32 dip = 0x83736353;
	u16 sport = 0x0801;
	u16 dport = htons(PACKET_MAC_LTE_DEFAULT_UDP_PORT);
	int udp_len;
	char * smac = soumac;
	char * dmac = dstmac;
 	struct ethhdr *ethdr= &var_ethhdr;
	struct iphdr *iph = &var_iphdr;
	struct udphdr* udph= &var_udphdr;
	extrahead[0] = type;
	memcpy (extrahead+2, &pkt_len, 2);
	udp_len = sizeof(struct udphdr)+pkt_len;
	memset(udph,0,sizeof(struct udphdr));
	udph->source=sport;
	udph->dest=dport;
	udph->len=HtoNs(udp_len);
	udph->check=0;
	
    iph = &var_iphdr;
    iph->version = 4;
    iph->ihl = sizeof(struct iphdr)>>2;
    iph->frag_off = 0;
    iph->protocol = IPPROTO_UDP;
    iph->tos = 0;
    iph->daddr = dip;
    iph->saddr = sip;
    iph->ttl = 0x40;
    iph->tot_len = HtoNs(udp_len+sizeof(struct iphdr));
    iph->check = 0;
	
  	ethdr = &var_ethhdr;
    memcpy (ethdr->h_dest, dmac, ETH_ALEN);
    memcpy (ethdr->h_source, smac, ETH_ALEN);
    ethdr->h_proto = htons(ETH_P_IP);
	iph->check = ip_fast_csum(iph,iph->ihl);
	//udph->check = csum_tcpudp_magic (sip, dip, skb->len - iph->ihl * 4, IPPROTO_UDP, skb->csum);
	udph->check = csum_tcpudp_magic (sip, dip,udp_len, iph->protocol, csum_partial(udph,udp_len,0));
    memcpy (pheader, ethdr, sizeof(struct ethhdr));
	*plength += sizeof(struct ethhdr);
	pheader += sizeof(struct ethhdr);
    memcpy (pheader, iph, sizeof(struct iphdr));
	*plength += sizeof(struct iphdr);
	pheader += sizeof(struct iphdr);
    memcpy (pheader, udph, sizeof(struct udphdr));	
	*plength += sizeof(struct udphdr);
	pheader += sizeof(struct udphdr);
    memcpy (pheader, extrahead, sizeof(extrahead));
	*plength += sizeof(extrahead);
}
static int MAC_LTE_PCAP_WritePDU(const u8 *PDU, unsigned int length,char type)
{
    pcaprec_hdr_t packet_header;
    u8 context_header[256];//封装的额外的头部。一直到UDP
    int offset = 0;
	creat_extra_header(context_header,&offset,length,type);
#if defined(RTAI)
    {
        unsigned long long int current_ns;

        current_ns = rt_get_time_ns();
        packet_header.ts_sec  = current_ns / 1000000000UL;
        packet_header.ts_usec = current_ns % 1000;
    }
#else
    packet_header.ts_sec = subframesSinceCaptureStart / 1000;
    packet_header.ts_usec = (subframesSinceCaptureStart % 1000) * 1000;
#endif
    packet_header.incl_len = offset + length;
    packet_header.orig_len = offset + length;

    /***************************************************************/
    /* Now write everything to the file                            */
    fwrite(&packet_header, sizeof(pcaprec_hdr_t), 1, file_fd);//先写数据结构头，在写负载。
    fwrite(context_header, 1, offset, file_fd);//额外的头部
    fwrite(PDU, 1, length, file_fd);//真实的负载


}

int main(int argc,char* argv[]){
	int i =0;
	generate_sdu_payload();
	if((file_fd = fopen(argv[1],"wt+"))==NULL){
		printf("can't open file %s\n",argv[1]);
		exit(1);
	}
	fwrite(&file_header,sizeof(file_header),1,file_fd);
	//rec_hdr.ts_sec = 0x5593c660;
	//rec_hdr.ts_usec= 0x0006bfdc;
	/*while(!buff.empty()){
    		MAC_LTE_PCAP_WritePDU(pdu_buffer, pdu_buffer_size);
	 	subframesSinceCaptureStart++;
	}*/
	for(i = 0;i<10;i++){		
    	MAC_LTE_PCAP_WritePDU(s_payload, 100+i,i%10+1);
	 	subframesSinceCaptureStart++;
	}
#if 0

	for(i = 0; i < max;i++){

		if(pue_mac == NULL ||pue_mac->sdu_tx_list == NULL){
			//to do free
			if(pue_mac != NULL){
				free_mac_sdu(pue_mac);
			}
			pue_mac = creat_mac_sdu();
		}
		//output_Mem = ue_encode_sdu_gss(pue_mac,i+100);
		ppayload= creat_mac_payload((downlink_pdu+i)%3+1);
		rec_hdr.incl_len=rec_hdr.orig_len = mac_length + strlen(mac_hdr);
		rec_hdr.ts_usec++;
		put_head_to_file(&rec_hdr,fp);	
		
		fwrite(mac_hdr,strlen(mac_hdr),1,fp);
		fwrite(ppayload,mac_length,1,fp);
		//free_mem_block(output_Mem);
	}
	
#endif

	fclose(file_fd);
	return 0;
		
}

