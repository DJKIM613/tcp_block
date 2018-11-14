#include <cstdlib>
#include <stdio.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <string.h>
#include <arpa/inet.h>
#include <stdint.h>
#include <libnet.h>
#include <pcap.h>

void dump(const uint8_t *p, int len){
    for(int i = 0 ; i < len ; i++){
        printf("%02X ", (int)p[i]);
        if(len % 16 == 15) printf("\n");
    }
    printf("\n");
}

struct pseudo_tcp_header{
    unsigned int ip_src;
    unsigned int ip_dst;
    unsigned char zero;
    unsigned char protocol;
    unsigned short tcp_len;
    struct libnet_tcp_hdr tcp_hdr;
    unsigned char tcp_data[100];
};

struct libnet_ipv4_hdr ipv4_base_packet;

void init(){
    ipv4_base_packet.ip_hl = 5;
    ipv4_base_packet.ip_v = 4;
    ipv4_base_packet.ip_tos = 0;
    ipv4_base_packet.ip_id = 0;
    ipv4_base_packet.ip_off = 0;
    ipv4_base_packet.ip_ttl = 144;
    ipv4_base_packet.ip_p = IPPROTO_TCP;
}

const u_char tcp_redirect_data[61] = {
    0x48, 0x54, 0x54, 0x50, 0x2f, 
    0x31, 0x2e, 0x31, 0x20, 0x33,
    0x30, 0x32, 0x20, 0x52, 0x65,
    0x64, 0x69, 0x72, 0x65, 0x63,
    0x74, 0x0d, 0x0a, 0x4c, 0x6f,
    0x63, 0x61, 0x74, 0x69, 0x6f,
    0x6e, 0x3a, 0x20, 0x68, 0x74,
    0x74, 0x70, 0x3a, 0x2f, 0x2f,
    0x77, 0x77, 0x77, 0x2e, 0x77,
    0x61, 0x72, 0x6e, 0x69, 0x6e,
    0x67, 0x2e, 0x6f, 0x72, 0x2e,
    0x6b, 0x72, 0x0d, 0x0a, 0x0d,
    0x0a
};


unsigned short checksum(unsigned short *buffer, int bytes){
    unsigned long sum = 0;
    unsigned short answer = 0;
    int i = bytes;
    while(i > 0){
        sum += *buffer++;
        i -=2;
    }
    sum = (sum >> 16) +  (sum & htonl(0x000ffff));
    sum += (sum >> 16);
    return ~sum;
}

int is_tcp_packet(const u_char *packet, uint8_t len){       // return 2 at http, return 1 at tcp(not http), return 0 at else 
    if(len  < sizeof(struct libnet_ethernet_hdr)) return 0;
    
    struct libnet_ethernet_hdr *eth_hdr = (struct libnet_ethernet_hdr *)packet;
    if(ntohs(eth_hdr->ether_type) != ETHERTYPE_IP) return 0;
    
    struct libnet_ipv4_hdr *ipv4_hdr = (libnet_ipv4_hdr *)(packet + sizeof(struct libnet_ethernet_hdr));
    if(ipv4_hdr->ip_p != IPPROTO_TCP) return 0;

    struct libnet_tcp_hdr *tcp_hdr = (struct libnet_tcp_hdr *)((u_char *)ipv4_hdr + ipv4_hdr->ip_hl * 4);
    if(ntohs(tcp_hdr->th_dport) != 80) return 1;

    return 2;
}

void send_eth_ipv4_tcp_rst(pcap_t *handle, u_char *p, uint32_t len, u_char *eth_dhost, u_char *eth_shost, u_char *ipv4_src_adr, u_char *ipv4_dst_adr, uint16_t tcp_src_port, uint16_t tcp_dst_port, uint32_t tcp_seq, uint32_t tcp_ack, int is_syn, int is_ack){
    struct libnet_ethernet_hdr *eth_hdr = (struct libnet_ethernet_hdr *)p;
    memcpy(eth_hdr->ether_dhost, eth_dhost, 6);
    memcpy(eth_hdr->ether_shost, eth_shost, 6);
    eth_hdr->ether_type = htons(ETHERTYPE_IP);

    struct libnet_ipv4_hdr *ipv4_hdr = (struct libnet_ipv4_hdr *)(p + sizeof(struct libnet_ethernet_hdr));
    memcpy(ipv4_hdr, &ipv4_base_packet, sizeof(libnet_ipv4_hdr));
    memcpy(&(ipv4_hdr->ip_src), ipv4_src_adr, sizeof(struct in_addr));
    memcpy(&(ipv4_hdr->ip_dst), ipv4_dst_adr, sizeof(struct in_addr));
    ipv4_hdr->ip_len = htons(sizeof(struct libnet_ipv4_hdr) + sizeof(struct libnet_tcp_hdr));
    ipv4_hdr->ip_sum = checksum((unsigned short *)ipv4_hdr, sizeof(struct libnet_ipv4_hdr));

    struct libnet_tcp_hdr *tcp_hdr = (struct libnet_tcp_hdr *)((u_char *)ipv4_hdr + (ipv4_hdr->ip_hl) * 4);
    memset(tcp_hdr, 0, sizeof(struct libnet_tcp_hdr));
    tcp_hdr->th_sport = htons(tcp_src_port);
    tcp_hdr->th_dport = htons(tcp_dst_port);
    tcp_hdr->th_seq = htonl(tcp_seq);
    tcp_hdr->th_ack = htonl(tcp_ack);
    tcp_hdr->th_off = 5;
    tcp_hdr->th_flags |= TH_RST;    tcp_hdr->th_flags |= TH_SYN * is_syn;   tcp_hdr->th_flags |= TH_ACK * is_ack;
    printf("%02x\n", tcp_hdr->th_sport);
    struct pseudo_tcp_header psd_tcp_hdr;
    memset(&psd_tcp_hdr, 0, sizeof(struct pseudo_tcp_header));
    psd_tcp_hdr.ip_src = *(uint32_t *)ipv4_src_adr;
    psd_tcp_hdr.ip_dst = *(uint32_t *)ipv4_dst_adr;
    psd_tcp_hdr.protocol = 6;
    psd_tcp_hdr.tcp_len = htons(20);
    psd_tcp_hdr.tcp_hdr = *(tcp_hdr);

    tcp_hdr->th_sum = checksum((unsigned short *)&psd_tcp_hdr, sizeof(pseudo_tcp_header));
    dump(p, (u_char *)tcp_hdr - p + tcp_hdr->th_off * 4);
    pcap_sendpacket(handle, p, (u_char *)tcp_hdr - p + tcp_hdr->th_off * 4);
}

void send_eth_ipv4_tcp_fin(pcap_t *handle, u_char *p, uint32_t len, u_char *eth_dhost, u_char *eth_shost, u_char *ipv4_src_adr, u_char *ipv4_dst_adr, uint16_t tcp_src_port, uint16_t tcp_dst_port, uint32_t tcp_seq, uint32_t tcp_ack, int is_syn, int is_ack){
    struct libnet_ethernet_hdr *eth_hdr = (struct libnet_ethernet_hdr *)p;
    memcpy(eth_hdr->ether_dhost, eth_dhost, 6);
    memcpy(eth_hdr->ether_shost, eth_shost, 6);
    eth_hdr->ether_type = htons(ETHERTYPE_IP);

    struct libnet_ipv4_hdr *ipv4_hdr = (struct libnet_ipv4_hdr *)(p + sizeof(struct libnet_ethernet_hdr));
    memcpy(ipv4_hdr, &ipv4_base_packet, sizeof(libnet_ipv4_hdr));
    memcpy(&(ipv4_hdr->ip_src), ipv4_src_adr, sizeof(struct in_addr));
    memcpy(&(ipv4_hdr->ip_dst), ipv4_dst_adr, sizeof(struct in_addr));
    ipv4_hdr->ip_len = htons(sizeof(struct libnet_ipv4_hdr) + sizeof(struct libnet_tcp_hdr) + sizeof(tcp_redirect_data));
    ipv4_hdr->ip_sum = checksum((unsigned short *)ipv4_hdr, sizeof(struct libnet_ipv4_hdr));

    struct libnet_tcp_hdr *tcp_hdr = (struct libnet_tcp_hdr *)((u_char *)ipv4_hdr + ipv4_hdr->ip_hl * 4);
    memset(tcp_hdr, 0, sizeof(struct libnet_tcp_hdr));
    tcp_hdr->th_sport = htons(tcp_src_port);
    tcp_hdr->th_dport = htons(tcp_dst_port);
    tcp_hdr->th_seq = htonl(tcp_seq);
    tcp_hdr->th_ack = htonl(tcp_ack);
    tcp_hdr->th_off = 5;
    tcp_hdr->th_flags |= TH_FIN;    tcp_hdr->th_flags |= TH_PUSH;    tcp_hdr->th_flags |= TH_SYN * is_syn;   tcp_hdr->th_flags |= TH_ACK * is_ack;
    memcpy(tcp_hdr + 1, tcp_redirect_data, sizeof(tcp_redirect_data));

    struct pseudo_tcp_header psd_tcp_hdr;
    memset(&psd_tcp_hdr, 0, sizeof(struct pseudo_tcp_header));
    psd_tcp_hdr.ip_src = *(uint32_t *)ipv4_src_adr;
    psd_tcp_hdr.ip_dst = *(uint32_t *)ipv4_dst_adr;
    psd_tcp_hdr.protocol = 6;
    psd_tcp_hdr.tcp_len = htons(20 + sizeof(tcp_redirect_data));
    psd_tcp_hdr.tcp_hdr = *(tcp_hdr);
    memcpy(psd_tcp_hdr.tcp_data, tcp_redirect_data, sizeof(tcp_redirect_data));

    tcp_hdr->th_sum = checksum((unsigned short *)&psd_tcp_hdr, sizeof(pseudo_tcp_header));

    pcap_sendpacket(handle, p, (u_char *)tcp_hdr - p + tcp_hdr->th_off * 4 + sizeof(tcp_redirect_data));
}


int main(int argc, char **argv){
    char errbuf[PCAP_ERRBUF_SIZE];
    char *dev = argv[1];
    pcap_t *handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    
    if(handle == NULL){
        fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
        return -1;
    }

    init();

    while(true){
        struct pcap_pkthdr *header;
        const u_char *packet;
        int result = pcap_next_ex(handle, &header, &packet);
        if(result == 0) continue;
        if(result == -1 || result == -2) break;
        printf("%u bytes captured\n", header->caplen);

        int res = is_tcp_packet(packet, header->caplen);
        if(res == 0) continue;
        struct libnet_ethernet_hdr *eth_hdr = (struct libnet_ethernet_hdr *)packet;
        u_char *eth_dhost = eth_hdr->ether_dhost;
        u_char *eth_shost = eth_hdr->ether_shost;
        
        struct libnet_ipv4_hdr *ipv4_hdr = (struct libnet_ipv4_hdr *)(packet + sizeof(struct libnet_ethernet_hdr));
        u_char *ipv4_src_adr = (u_char *)(&(ipv4_hdr->ip_src));
        u_char *ipv4_dst_adr = (u_char *)(&(ipv4_hdr->ip_dst));
        
        struct libnet_tcp_hdr *tcp_hdr = (struct libnet_tcp_hdr *)((u_char *)ipv4_hdr + (ipv4_hdr->ip_hl) * 4);
        uint16_t tcp_src_port = ntohs(tcp_hdr->th_sport);
        uint16_t tcp_dst_port = ntohs(tcp_hdr->th_dport);
        
        uint32_t tcp_seq = ntohl(tcp_hdr->th_seq);
        uint32_t tcp_ack = ntohl(tcp_hdr->th_ack);
        
        uint32_t tcp_len = ntohs(ipv4_hdr->ip_len) - (ipv4_hdr->ip_hl) * 4 - (tcp_hdr->th_off) * 4;
        printf("seq : %lld\n", tcp_seq + tcp_len);
        u_char *p = (u_char *)malloc(200);

        if(res == 2){
            printf("hi\n");
            send_eth_ipv4_tcp_rst(handle, p, 200, eth_dhost, eth_shost, ipv4_src_adr, ipv4_dst_adr, tcp_src_port, tcp_dst_port, tcp_seq + tcp_len, tcp_ack, 1, 0);          //original_path
            send_eth_ipv4_tcp_fin(handle, p, 200, eth_shost, eth_dhost, ipv4_dst_adr, ipv4_src_adr, tcp_dst_port, tcp_src_port, tcp_ack, tcp_seq + tcp_len, 0, 1);          //reverse_path
        }
        else {
            send_eth_ipv4_tcp_rst(handle, p, 200, eth_dhost, eth_shost, ipv4_src_adr, ipv4_dst_adr, tcp_src_port, tcp_dst_port, tcp_seq + tcp_len, tcp_ack, 1, 0);          //original_path
            send_eth_ipv4_tcp_rst(handle, p, 200, eth_shost, eth_dhost, ipv4_dst_adr, ipv4_src_adr, tcp_dst_port, tcp_src_port, tcp_ack, tcp_seq + tcp_len, 0, 1);          //reverse_path
        }
        
        free(p);
    }

    return 0;
}