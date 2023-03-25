#ifndef MYTHREAD_H
#define MYTHREAD_H
#include <QThread>
#include <QMutex>
#define WPCAP
#define HAVE_REMOTE
#include <pcap.h>
#include <remote-ext.h>
#include <winsock.h>

#define PROTO_IP 0x0800
#define PROTO_ARP 0X0806
#define ETHERNET_SIZE 14
#define IP_RF 0x8000
#define IP_DF 0x4000
#define IP_MF 0x2000
#define IP_OFFMASK 0x1fff
#define TH_FIN 0X01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0X80
#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
#define IP_HL(ip)       ((ip)->ip_vhl & 0x0f)
#define TCP_HL(tcp)       ((tcp)->tcp_len & 0x0f)
#define IP_V(ip)        (((ip)->ip_vhl) >> 4)
#define PROTO_ICMP 1
#define PROTO_TCP 6
#define PROTO_UDP 17
#define TH_OFF(th) (((th)->th_offx2 & 0xf0) >> 4)

typedef struct ethernet_h
{
    u_char dest[6];
    u_char src[6];
    u_short type;
}ethhdr;

typedef struct arp_h{
    u_short htype;
    u_short prtype;
    u_char hsize;
    u_char prsize;
    u_short opcode;
    u_char senderMac[6];
    u_char senderIp[4];
    u_char destMac[6];
    u_char destIp[4];
}arphdr;

typedef struct ip_h{
    u_char ip_vhl;
    u_char tos;
    u_short ip_len;
    u_short identification;
    u_short flags_fo;
    u_char ttl;
    u_char proto;
    u_short hchecksum;
    u_char saddr[4];
    u_char daddr[4];
}iphdr;


typedef struct tcp_h{
    u_short srcPort;
    u_short destPort;
    u_int seq;
    u_int ack_sql;
    u_char th_offx2;
    u_char th_flags;
    u_short wnd_size;
    u_short checksum;
    u_short urg_ptr;
    u_char tcp_len;
}tcphdr;

typedef struct udp_h
{
    u_short srcPort;
    u_short destPort;
    u_short len;
    u_short crc;
}udphdr;

typedef struct icmp_h
{
    u_char type;
    u_char code;
    u_short chk_sum;
    u_short identification;
    u_short seq;
}icmphdr;

typedef struct headers
{
    char pktType[8];
    int time[6];
    int len;
    struct ethernet_h *ethh;
    struct arp_h *arph;
    struct ip_h *iph;
    struct icmp_h *icmph;
    struct udp_h *udph;
    struct tcp_h *tcph;
    u_char* apph;
    bool isHttp = false;
    int httpsize;
}datapkt;

typedef std::vector<datapkt *> datapktVec;
typedef std::vector<u_char *> dataVec;

class MyThread: public QThread
{
    Q_OBJECT
public:
    MyThread(pcap_t *handle, datapktVec &datapktLLink, dataVec &dataCharLLink, pcap_dumper_t *dump);
    void stop();
    int frame_details(const u_char *pkt, datapkt *data);
    int arp_details(const u_char *pkt, datapkt *data);
    int ip_details(const u_char *pkt, datapkt *data);
    int icmp_details(const u_char *pkt, datapkt *data);
    int tcp_details(const u_char *pkt, datapkt *data);
    int udp_details(const u_char *pkt, datapkt *data);
    int dns_details(const u_char *pkt, datapkt *data);
    int http_details(const u_char *pkt, datapkt *data);
protected:
    void run();
private:
    QMutex m_lock;
    volatile bool stopped;
    pcap_t *handle;
    datapktVec &packets;
    dataVec &data_char;
    pcap_dumper_t *dump;
    const u_char *pktInitialAddress;

signals:
    void Getpacket(QString timestr, QString srcMac, QString destMac, QString len, QString protoType, QString srcIP, QString dstIP);
};

#endif // MYTHREAD_H
