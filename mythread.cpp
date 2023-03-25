#include "mythread.h"
#include <QTextStream>
#include <QDebug>

MyThread::MyThread(pcap_t *handle, datapktVec& datapktLLink, dataVec& dataCharLLink, pcap_dumper_t *dump):
    packets(datapktLLink), data_char(dataCharLLink){
    stopped = false;
    this->handle = handle;
    this->dump = dump;
}

void MyThread::run(){
    int res;
    struct tm *ltime;
    time_t local_tv_sec;
    struct pcap_pkthdr *header;
    const u_char *pkt_data = NULL;
    u_char *ppkt_data;
    while(stopped != true && (res = pcap_next_ex(handle, &header, &pkt_data)) >= 0)
    {
        if(res == 0)
            continue;
        struct headers *data = (struct headers*)malloc(sizeof(struct headers));
        data->isHttp =false;
        memset(data, 0, sizeof(struct headers));

        data->len = header->len;

        if(frame_details(pkt_data, data) < 0)
            continue;

        if(dump != NULL)
        {
            pcap_dump((u_char *)dump, header, pkt_data);
        }

        ppkt_data = (u_char *)malloc(header->len * sizeof(u_char));
        memcpy(ppkt_data, pkt_data, header->len);

        packets.push_back(data);
        data_char.push_back(ppkt_data);
        local_tv_sec = header->ts.tv_sec;
        ltime = localtime(&local_tv_sec);
        data->time[0] = ltime->tm_year + 1900;
        data->time[1] = ltime->tm_mon + 1;
        data->time[2] = ltime->tm_mday;
        data->time[3] = ltime->tm_hour;
        data->time[4] = ltime->tm_min;
        data->time[5] = ltime->tm_sec;

        //get Timestamp
        QString timestr;
        QTextStream(&timestr) << data->time[0] << "/" << data->time[1] << "/" << data->time[2]
                                                << " " << data->time[3] << ":" << data->time[4]
                                                << ":" << data->time[5];
        QString pkt_len = QString::number(data->len);
        QString srcMac;
        char *buf = (char *)malloc(80 * sizeof(char));
        sprintf(buf, "%02x-%02x-%02x-%02x-%02x-%02x", data->ethh->src[0], data->ethh->src[1],
                data->ethh->src[2], data->ethh->src[3], data->ethh->src[4], data->ethh->src[5]);
        srcMac = QString(QLatin1String(buf));
        QString dstMac;
        sprintf(buf, "%02x-%02x-%02x-%02x-%02x-%02x", data->ethh->dest[0], data->ethh->dest[1],
                data->ethh->dest[2], data->ethh->dest[3], data->ethh->dest[4], data->ethh->dest[5]);
        dstMac = QString(QLatin1String(buf));
        QString protoType = QString(data->pktType);
        QString srcIP;
        if(data->ethh->type == 0x0806)  //
        {
            sprintf(buf, "%d.%d.%d.%d", data->arph->senderIp[0], data->arph->senderIp[1], data->arph->senderIp[2], data->arph->senderIp[3]);
            srcIP = QString(QLatin1String(buf));
        }
        else if(data->ethh->type == 0x0800) //IP
        {
            sprintf(buf, "%d.%d.%d.%d", data->iph->saddr[0], data->iph->saddr[1], data->iph->saddr[2], data->iph->saddr[3]);
            srcIP = QString(QLatin1String(buf));
        }

        QString dstIP;
        if(data->ethh->type == 0x0806)
        {
            sprintf(buf, "%d.%d.%d.%d", data->arph->destIp[0], data->arph->destIp[1], data->arph->destIp[2], data->arph->destIp[3]);
            dstIP = QString(QLatin1String(buf));
        }
        else if(data->ethh->type == 0x0800)
        {
            sprintf(buf, "%d.%d.%d.%d", data->iph->daddr[0], data->iph->daddr[1], data->iph->daddr[2], data->iph->daddr[3]);
            dstIP = QString(QLatin1String(buf));
        }
        emit Getpacket(timestr, srcMac, dstMac, pkt_len, protoType, srcIP, dstIP);

        free(buf);

    }
}

void MyThread::stop(){
    QMutexLocker locker(&m_lock);
    stopped = true;
}

int MyThread::frame_details(const u_char *pkt, datapkt *data){
    pktInitialAddress = pkt;
    struct ethernet_h *ethh = (struct ethernet_h *)pkt;
    data->ethh = (struct ethernet_h *)malloc(sizeof(struct ethernet_h));
    if(data->ethh == NULL){
        qDebug() << "failed to malloc ethh space." << endl;
        return -1;
    }
    for(int i = 0; i < 6; ++i)
    {
        data->ethh->dest[i] = ethh->dest[i];
        data->ethh->src[i] = ethh->src[i];
    }
    data->ethh->type = ntohs(ethh->type);

    int ret = 0;

    //analysis start
    switch(data->ethh->type)
    {
        case PROTO_IP:
            ret = ip_details((u_char *)pkt + 14, data);
            break;
        case PROTO_ARP:
            ret = arp_details((u_char *)pkt + 14, data);
            break;
        default:
            ret = -1;
            break;
    }
    return ret;

}

int MyThread::arp_details(const u_char *pkt, datapkt *data){
    struct arp_h *arph = (struct arp_h *)pkt;
    data->arph = (struct arp_h *)malloc(sizeof(struct arp_h));
    if(data->arph == NULL)
    {
        qDebug() << "failed to malloc arph space!" << endl;
        return -1;
    }
    for(int i = 0; i < 6; i++)
    {
        if(i < 4)
        {
            data->arph->senderIp[i] = arph->senderIp[i];
            data->arph->destIp[i] = arph->destIp[i];
        }
        data->arph->senderMac[i] = arph->senderMac[i];
        data->arph->destMac[i] = arph->destMac[i];
    }

    data->arph->htype = ntohs(arph->htype);
    data->arph->prtype = ntohs(arph->prtype);
    data->arph->hsize = arph->hsize;
    data->arph->prsize = arph->prsize;
    data->arph->opcode = ntohs(arph->opcode);

    strcpy(data->pktType, "ARP");
    return 1;
}

int MyThread::ip_details(const u_char* pkt,datapkt *data){
    struct ip_h *iph = (struct ip_h*)pkt;
    data->iph = (struct ip_h*)malloc(sizeof(struct ip_h));
    if(data->iph == NULL)
    {
        qDebug() << "failed to malloc ip header space!" << endl;
        return -1;
    }
    data->iph->hchecksum = ntohs(iph->hchecksum);

    for(int i = 0;i<4;i++)
    {
        data->iph->daddr[i] = iph->daddr[i];
        data->iph->saddr[i] = iph->saddr[i];
    }

    data->iph->tos = iph->tos;
    data->iph->ip_vhl = iph->ip_vhl;
    data->iph->ip_len = ntohs(iph->ip_len);
    data->iph->identification = ntohs(iph->identification);
    data->iph->flags_fo = ntohs(iph->flags_fo);
    data->iph->ttl = iph->ttl;
    data->iph->proto = iph->proto;

    u_int ipheader_len = IP_HL(data->iph) * 4;
    int ret = 0;
    switch(iph->proto)
    {
        case PROTO_ICMP:
            ret = icmp_details((u_char*)iph+ipheader_len,data);
            break;
        case PROTO_TCP:
            ret = tcp_details((u_char*)iph+ipheader_len,data);
            break;
        case PROTO_UDP:
            ret = udp_details((u_char*)iph+ipheader_len,data);
            break;
        default :
            ret = -1;
            break;
    }
    return ret;
}

int MyThread::icmp_details(const u_char *pkt, datapkt *data){
    struct icmp_h* icmph = (struct icmp_h*)pkt;
    data->icmph = (struct icmp_h*)malloc(sizeof(struct icmp_h));

    if(NULL == data->icmph)
        return -1;

    data->icmph->chk_sum = icmph->chk_sum;
    data->icmph->code = icmph->code;
    data->icmph->seq =ntohs(icmph->seq);
    data->icmph->type = icmph->type;
    data->icmph->identification = ntohs(icmph->identification);
    data->icmph->chk_sum = ntohs(icmph->chk_sum);
    strcpy(data->pktType,"ICMP");
    return 1;
}

int MyThread::tcp_details(const u_char *pkt, datapkt *data){
    struct tcp_h *tcphr = (struct tcp_h *)pkt;
    data->tcph = (struct tcp_h *)malloc(sizeof(struct tcp_h));
    if(data->tcph == NULL)
    {
        qDebug() << "failed to malloc tcp header space!" << endl;
        return -1;
    }

    data->tcph->srcPort = ntohs(tcphr->srcPort);
    data->tcph->destPort = ntohs(tcphr->destPort);
    data->tcph->seq =ntohl(tcphr->seq);
    data->tcph->ack_sql = ntohl(tcphr->ack_sql);
    data->tcph->th_flags = tcphr->th_flags;
    data->tcph->th_flags = tcphr->th_flags;
    data->tcph->wnd_size = ntohs(tcphr->wnd_size);
    data->tcph->checksum = ntohs(tcphr->checksum);
    data->tcph->urg_ptr = ntohs(tcphr->urg_ptr);

    if(data->tcph->srcPort == 80 || data->tcph->destPort == 80){
        http_details(pkt, data);
        return 1;
    }
    else{
        strcpy(data->pktType, "TCP");
    }
    return 1;
}

int MyThread::udp_details(const u_char *pkt, datapkt *data){
    struct udp_h *udphr = (struct udp_h *)pkt;
    data->udph = (struct udp_h *)malloc(sizeof(struct udp_h));
    data->udph->srcPort = ntohs(udphr->srcPort);
    data->udph->destPort = ntohs(udphr->destPort);
    data->udph->len = ntohs(udphr->len);
    data->udph->crc = ntohs(udphr->crc);

    if(data->udph->srcPort == 53 || data->udph->destPort == 53){
        dns_details(pkt,data);
        return 1;
    }
    strcpy(data->pktType,"UDP");
    return 1;
}

int MyThread::http_details(const u_char *pkt, datapkt *data){
    struct tcp_h *tcphr = (struct tcp_h *)pkt;
    u_char *httpdata = (u_char *)tcphr + TH_OFF(tcphr) * 4;
    const char *token[] = {"GET","POST","HTTP/1.1","HTTP/1.0"};
    u_char *httpHeader;
    for(int i = 0 ; i < 4 ; i ++){
        httpHeader = (u_char *)strstr((char *)httpdata,token[i]);
        if(httpHeader){
            strcpy(data->pktType, "HTTP");
            data->isHttp = true;
            int size = data->len - ((u_char *)httpdata - pktInitialAddress);
            data->httpsize = size;
            data->apph = (u_char *)malloc(size * sizeof(u_char));
            for(int j = 0; j < size; j++){
                data->apph[j] = httpdata[j];
            }
            return 1;
        }
    }
    strcpy(data->pktType, "TCP");
    return 1;
}

int MyThread::dns_details(const u_char *pkt, datapkt *data){
    strcpy(data->pktType, "DNS");
    return 1;
}
