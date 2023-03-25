#include "mainwindow.h"
#include "ui_mainwindow.h"
MainWindow::MainWindow(QWidget *parent) : QMainWindow(parent), ui(new Ui::MainWindow){
    this->setWindowTitle("WireFake: homework for UCAS 2023 Spring");
    ui->setupUi(this);
    RowCount =0;
    Tarcker_flag=0;
    mythread = NULL;
    ui->pkglistWidget->setColumnCount(8);
    ui->pkglistWidget->setColumnWidth(0, 50);
    ui->pkglistWidget->setColumnWidth(1, 150);
    ui->pkglistWidget->setColumnWidth(2, 200);
    ui->pkglistWidget->setColumnWidth(3, 200);
    ui->pkglistWidget->setColumnWidth(4, 50);
    ui->pkglistWidget->setColumnWidth(5, 50);
    ui->pkglistWidget->setColumnWidth(6, 200);
    ui->pkglistWidget->setColumnWidth(7, 200);
    //ui->pkglistWidget->horizontalHeader()->setStretchLastSection(true);
    ui->pkglistWidget->verticalHeader()->setDefaultSectionSize(30);
    ui->pkglistWidget->horizontalHeader()->setStyleSheet("QHeaderView::section{background-color:transparent;}");
    ui->pkglistWidget->setHorizontalHeaderLabels(QStringList() << tr("No.") << tr("Time")
                                              << tr("Source") << tr("Destination")
                                              << tr("Len") << tr("Prot.")
                                              << tr("Source IP") << tr("Destination IP"));
    //QColor color_line0 = QColor(84,84,84);
    //for(int i = 0; i < 8 ; i ++){
    //    ui->pkglistWidget->horizontalHeaderItem(i)->setBackgroundColor(color_line0);
    //}

    ui->pkglistWidget->setSelectionBehavior(QAbstractItemView::SelectRows);
    ui->pkglistWidget->setSelectionMode(QAbstractItemView::SingleSelection);
    ui->pkglistWidget->setEditTriggers(QAbstractItemView::NoEditTriggers);
    ui->pkglistWidget->verticalHeader()->setVisible(false);
    connect(ui->pkglistWidget, SIGNAL(cellClicked(int,int)), this, SLOT(PacketDetails(int,int)));

    ui->detailWidget->setColumnCount(1);
    ui->detailWidget->header()->setSectionResizeMode(QHeaderView::ResizeToContents);
    ui->detailWidget->header()->setStretchLastSection(false);
    ui->detailWidget->header()->setStyleSheet("QHeaderView::section{background-color:transparent;}");
    ui->stop->setEnabled(false);

    ui->tracker_start->setEnabled(true);
    ui->tracker_end->setEnabled(false);

    cap_init();
    for(dev=alldevs; dev; dev=dev->next){
        if(dev->description)
            ui->Nicselect->addItem(QString("%1").arg(dev->description));
    }
}

MainWindow::~MainWindow(){
    delete ui;
}

int MainWindow::cap_init(){
    devCount = 0;
    if(pcap_findalldevs_ex((char *)PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
        return -1;
    for(dev = alldevs; dev; dev = dev->next)
        devCount++;
    return 0;
}

int MainWindow::cap_start(){
    int interface_index = 0, count;
    u_int netmask;
    struct bpf_program fcode;
    interface_index = ui->Nicselect->currentIndex();
    if(interface_index == 0){
        QMessageBox::warning(this, "Sniffer", tr("select nic"), QMessageBox::Ok);
        return -1;
    }
    QString filterContent = ui->filterLineEdit->text();

    dev = alldevs;
    for(count = 0; count < interface_index - 1; count++){
        dev = dev->next;
        qDebug() << "debug information: " << dev->name << endl;
    }

    if((handle = pcap_open_live(dev->name, 65536,1,1000,errbuf)) == NULL){
        QMessageBox::warning(this, "open error", tr("change a device"), QMessageBox::Ok);
        pcap_freealldevs(alldevs);
        alldevs = NULL;
        return -1;
    }

    QByteArray ba = filterContent.toLatin1();
    char *filter = NULL;
    filter = ba.data();
    if(pcap_compile(handle, &fcode, filter, 1, 0) < 0)
    {
        QMessageBox::warning(this, "Sniff", tr("filter syntax error "));
        pcap_freealldevs(alldevs);
        alldevs = NULL;
        return -1;
    }


    if(pcap_setfilter(handle, &fcode) < 0)
    {
        QMessageBox::warning(this, "Sniff", tr("filter setting error "), QMessageBox::Ok);
        pcap_freealldevs(alldevs);
        alldevs = NULL;
        return -1;
    }

    QString path = QDir::currentPath();
    qDebug() << path << endl;
    QString direcPath = path + "//SavedData";
    QDir dir(direcPath);
    if(!dir.exists())
    {
        if(!dir.mkdir(direcPath))
        {
            QMessageBox::warning(this, "warning", tr("saving path error!"), QMessageBox::Ok);
            return -1;
        }
    }
    char thistime[30];
    struct tm *ltime;
    time_t nowtime;
    time(&nowtime);
    ltime = localtime(&nowtime);
    strftime(thistime,sizeof(thistime),"%Y%m%d %H%M%S",ltime);
    std::string str = direcPath.toStdString();
    strcpy(filepath, str.c_str());
    strcat(filepath, "//");
    strcat(filepath, thistime);
    strcat(filepath, ".pcap");      //pcap

    qDebug() << "data saved path is:" + QString(filepath) << endl;
    dump =  pcap_dump_open(handle, filepath);

    pcap_freealldevs(alldevs);
    alldevs = NULL;

    mythread = new MyThread(handle, packets, data_char, dump);
    connect(mythread, SIGNAL(Getpacket(QString,QString,QString,QString,QString,QString,QString)), this, SLOT(PacketList(QString,QString,QString,QString,QString,QString,QString)));
    mythread->start();
    return 1;
}

void MainWindow::on_start_clicked(){
    std::vector<datapkt *>::iterator it;
    for(it = packets.begin(); it != packets.end(); it++){
        free((*it)->ethh);
        free((*it)->arph);
        free((*it)->iph);
        free((*it)->icmph);
        free((*it)->udph);
        free((*it)->tcph);
        free((*it)->apph);
        free(*it);
    }
    std::vector<u_char *>::iterator kt;
    for(kt = data_char.begin(); kt != data_char.end(); kt++){
        free(*kt);
    }
    datapktVec().swap(packets);
    dataVec().swap(data_char);

    ui->detailWidget->clear();
    ui->HexWidget->clear();

    cap_init();

    mythread = NULL;

    if(cap_start() < 0)
        return;

    ui->pkglistWidget->clearContents();
    ui->pkglistWidget->setRowCount(0);
    ui->stop->setEnabled(true);
    ui->start->setEnabled(false);
}

void MainWindow::on_stop_clicked(){
    ui->start->setEnabled(true);
    ui->stop->setEnabled(false);
    mythread->stop();
    pcap_close(handle);
}

void MainWindow::on_tracker_start_clicked(){
    ui->tracker_end->setEnabled(true);
    ui->tracker_start->setEnabled(false);
    Tarcker_flag=1;
}

void MainWindow::on_tracker_end_clicked(){
    ui->tracker_end->setEnabled(false);
    ui->tracker_start->setEnabled(true);
    Tarcker_flag=0;
}

void MainWindow::PacketList(QString timestr, QString srcMac, QString destMac, QString len, QString protoType, QString srcIP, QString dstIP){
    RowCount = ui->pkglistWidget->rowCount();
    ui->pkglistWidget->insertRow(RowCount);
    QString orderNumber = QString::number(RowCount, 10);
    ui->pkglistWidget->setItem(RowCount, 0, new QTableWidgetItem(orderNumber));
    ui->pkglistWidget->setItem(RowCount, 1, new QTableWidgetItem(timestr));
    ui->pkglistWidget->setItem(RowCount, 2, new QTableWidgetItem(srcMac));
    ui->pkglistWidget->setItem(RowCount, 3, new QTableWidgetItem(destMac));
    ui->pkglistWidget->setItem(RowCount, 4, new QTableWidgetItem(len));
    ui->pkglistWidget->setItem(RowCount, 5, new QTableWidgetItem(protoType));
    ui->pkglistWidget->setItem(RowCount, 6, new QTableWidgetItem(srcIP));
    ui->pkglistWidget->setItem(RowCount, 7, new QTableWidgetItem(dstIP));

    if(RowCount > 1)
    {
        ui->pkglistWidget->scrollToItem(ui->pkglistWidget->item(RowCount, 0), QAbstractItemView::PositionAtBottom);
    }

    QColor color;
    if(protoType == "TCP" || protoType == "HTTP"){
        color = QColor(228,255,199);
    }
    else if(protoType == "UDP"){
        color = QColor(218,238,255);
    }
    else if(protoType == "ARP"){
        color = QColor(250,240,215);
    }
    else if(protoType == "ICMP"){
        color = QColor(252,224,255);
    }
    for(int i = 0; i < 8 ; i ++){
        ui->pkglistWidget->item(RowCount,i)->setBackgroundColor(color);
        ui->pkglistWidget->item(RowCount,i)->setTextAlignment(Qt::AlignHCenter | Qt::AlignVCenter);
    }
}

void MainWindow::PacketDetails(int row, int column){
    ui->detailWidget->clear();
    ui->HexWidget->clear();
    if(Tarcker_flag){
        PacketTracker(row,column);
    }

    struct headers *mem_data = (struct headers *)packets[row];
    u_char *print_data = (u_char *)data_char[row];
    int print_len = mem_data->len;
    PacketHex(print_data, print_len);

    QString showStr;
    char buf[100];
    sprintf(buf, "Frame %d", row + 1);
    showStr = QString(buf);

    QTreeWidgetItem *root = new QTreeWidgetItem(ui->detailWidget);
    root->setText(0, showStr);

    showStr = QString("EtherNet");
    QTreeWidgetItem *level1 = new QTreeWidgetItem(root);
    level1->setText(0, showStr);

    sprintf(buf, "%02x-%02x-%02x-%02x-%02x-%02x", mem_data->ethh->src[0], mem_data->ethh->src[1],
            mem_data->ethh->src[2], mem_data->ethh->src[3], mem_data->ethh->src[4], mem_data->ethh->src[5]);
    showStr = "Source: " + QString(buf);
    QTreeWidgetItem *srcEtherMac = new QTreeWidgetItem(level1);
    srcEtherMac->setText(0, showStr);

    sprintf(buf, "%02x-%02x-%02x-%02x-%02x-%02x", mem_data->ethh->dest[0], mem_data->ethh->dest[1],
            mem_data->ethh->dest[2], mem_data->ethh->dest[3], mem_data->ethh->dest[4], mem_data->ethh->dest[5]);
    showStr = "Destination: " + QString(buf);
    QTreeWidgetItem *destEtherMac = new QTreeWidgetItem(level1);
    destEtherMac->setText(0, showStr);

    sprintf(buf, "%04x", mem_data->ethh->type);
    showStr = "Type:0x" + QString(buf);
    QTreeWidgetItem *etherType = new QTreeWidgetItem(level1);
    etherType->setText(0, showStr);

    if(mem_data->ethh->type == 0x0806){
        showStr = QString("Address Resolution Protocol");
        QTreeWidgetItem *level2 = new QTreeWidgetItem(root);
        level2->setText(0, showStr);

        sprintf(buf, "Hardware Type: 0x%04x", mem_data->arph->htype);
        showStr = QString(buf);
        QTreeWidgetItem *arpHtype = new QTreeWidgetItem(level2);
        arpHtype->setText(0, showStr);

        sprintf(buf, "Protocol type: 0x%04x", mem_data->arph->prtype);
        showStr = QString(buf);
        QTreeWidgetItem *arpPrtype = new QTreeWidgetItem(level2);
        arpPrtype->setText(0, showStr);

        sprintf(buf, "Hardware Size: %d", mem_data->arph->hsize);
        showStr = QString(buf);
        QTreeWidgetItem *arpHsize = new QTreeWidgetItem(level2);
        arpHsize->setText(0, showStr);

        sprintf(buf, "Protocol Size: %d", mem_data->arph->prsize);
        showStr = QString(buf);
        QTreeWidgetItem *arpPrsize = new QTreeWidgetItem(level2);
        arpPrsize->setText(0, showStr);

        sprintf(buf, "Opcode: %d", mem_data->arph->opcode);
        showStr = QString(buf);
        QTreeWidgetItem *arpCode = new QTreeWidgetItem(level2);
        arpCode->setText(0, showStr);

        sprintf(buf, "%02x-%02x-%02x-%02x-%02x-%02x", mem_data->arph->senderMac[0], mem_data->arph->senderMac[1],
                mem_data->arph->senderMac[2], mem_data->arph->senderMac[3], mem_data->arph->senderMac[4], mem_data->arph->senderMac[5]);
        showStr = "Sender MAC address: " + QString(buf);
        QTreeWidgetItem *srcArpMac = new QTreeWidgetItem(level2);
        srcArpMac->setText(0, showStr);

        sprintf(buf, "%d.%d.%d.%d", mem_data->arph->senderIp[0], mem_data->arph->senderIp[1], mem_data->arph->senderIp[2]
                ,mem_data->arph->senderIp[3]);
        showStr = "Sender IP address: " + QString(buf);
        QTreeWidgetItem *srcArpIp = new QTreeWidgetItem(level2);
        srcArpIp->setText(0, showStr);

        sprintf(buf, "%02x-%02x-%02x-%02x-%02x-%02x", mem_data->arph->destMac[0], mem_data->arph->destMac[1],
                mem_data->arph->destMac[2], mem_data->arph->destMac[3], mem_data->arph->destMac[4], mem_data->arph->destMac[5]);
        showStr = "Target MAC address: " + QString(buf);
        QTreeWidgetItem *destArpMac = new QTreeWidgetItem(level2);
        destArpMac->setText(0, showStr);

        sprintf(buf, "%d.%d.%d.%d", mem_data->arph->destIp[0], mem_data->arph->destIp[1], mem_data->arph->destIp[2]
                ,mem_data->arph->destIp[3]);
        showStr = "Target IP address: " + QString(buf);
        QTreeWidgetItem *destArpIp = new QTreeWidgetItem(level2);
        destArpIp->setText(0, showStr);
    }
    else if(mem_data->ethh->type == 0x0800){
        showStr = QString("Internet Protocol Version 4");
        QTreeWidgetItem *level3 = new QTreeWidgetItem(root);
        level3->setText(0, showStr);

        sprintf(buf, "Version: %d", IP_V(mem_data->iph));
        showStr = QString(buf);
        QTreeWidgetItem *ipVersion = new QTreeWidgetItem(level3);
        ipVersion->setText(0, showStr);

        sprintf(buf, "Header Length: %d", IP_HL(mem_data->iph));
        showStr = QString(buf);
        QTreeWidgetItem *ipHeaderLen = new QTreeWidgetItem(level3);
        ipHeaderLen->setText(0, showStr);

        sprintf(buf, "Differentiated Services Field: %d", mem_data->iph->tos);
        showStr = QString(buf);
        QTreeWidgetItem *ipTos = new QTreeWidgetItem(level3);
        ipTos->setText(0, showStr);

        sprintf(buf, "Total length: %d", mem_data->iph->ip_len);
        showStr = QString(buf);
        QTreeWidgetItem *ipTotalLen = new QTreeWidgetItem(level3);
        ipTotalLen->setText(0, showStr);

        sprintf(buf, "Identification: 0x%04x", mem_data->iph->identification);
        showStr = QString(buf);
        QTreeWidgetItem *ipIdentify = new QTreeWidgetItem(level3);
        ipIdentify->setText(0, showStr);

        if((mem_data->iph->flags_fo & IP_RF) >> 15){
            sprintf(buf, "flags, Reserved Fragment Flag");
            showStr = QString(buf);
            QTreeWidgetItem *flag1 = new QTreeWidgetItem(level3);
            flag1->setText(0, showStr);
        }

        if((mem_data->iph->flags_fo & IP_DF) >> 14){
            sprintf(buf, "Flags, Don't fragment Flag)");
            showStr = QString(buf);
            QTreeWidgetItem *flag2 = new QTreeWidgetItem(level3);
            flag2->setText(0, showStr);
        }

        if((mem_data->iph->flags_fo & IP_MF) >> 13){
            sprintf(buf, "Flags, More Fragment Flag)");
            showStr = QString(buf);
            QTreeWidgetItem *flag3 = new QTreeWidgetItem(level3);
            flag3->setText(0, showStr);
        }

        sprintf(buf, "Fragment Offset: %d", mem_data->iph->flags_fo & IP_OFFMASK);
        showStr = QString(buf);
        QTreeWidgetItem *ipOffset = new QTreeWidgetItem(level3);
        ipOffset->setText(0, showStr);

        sprintf(buf, "Time to live: %d", mem_data->iph->ttl);
        showStr = QString(buf);
        QTreeWidgetItem *ipTTL = new QTreeWidgetItem(level3);
        ipTTL->setText(0, showStr);

        sprintf(buf, "Protocol: %d", mem_data->iph->proto);
        showStr = QString(buf);
        QTreeWidgetItem *ipProto = new QTreeWidgetItem(level3);
        ipProto->setText(0, showStr);

        sprintf(buf, "Header Checksum: 0x%04x", mem_data->iph->hchecksum);
        showStr = QString(buf);
        QTreeWidgetItem *ipHCheckSum = new QTreeWidgetItem(level3);
        ipHCheckSum->setText(0, showStr);

        sprintf(buf, "%d.%d.%d.%d", mem_data->iph->saddr[0], mem_data->iph->saddr[1], mem_data->iph->saddr[2]
                ,mem_data->iph->saddr[3]);
        showStr = "Source Address: " + QString(buf);
        QTreeWidgetItem *ipSrcIp = new QTreeWidgetItem(level3);
        ipSrcIp->setText(0, showStr);

        sprintf(buf, "%d.%d.%d.%d", mem_data->iph->daddr[0], mem_data->iph->daddr[1], mem_data->iph->daddr[2]
                ,mem_data->iph->daddr[3]);
        showStr = "Destination Address: " + QString(buf);
        QTreeWidgetItem *ipDestIp = new QTreeWidgetItem(level3);
        ipDestIp->setText(0, showStr);

        if(mem_data->iph->proto == PROTO_ICMP)  //ICMP协议
        {
            showStr = QString("Internet Control Message Protocol");
            QTreeWidgetItem *level4 = new QTreeWidgetItem(root);
            level4->setText(0, showStr);

            sprintf(buf, "Type: %d", mem_data->icmph->type);
            showStr = QString(buf);
            QTreeWidgetItem *icmpType = new QTreeWidgetItem(level4);
            icmpType->setText(0, showStr);

            sprintf(buf, "Code: %d", mem_data->icmph->code);
            showStr = QString(buf);
            QTreeWidgetItem *icmpCode = new QTreeWidgetItem(level4);
            icmpCode->setText(0, showStr);

            sprintf(buf, "Checksum: 0x%04x", mem_data->icmph->chk_sum);
            showStr = QString(buf);
            QTreeWidgetItem *icmpCheck = new QTreeWidgetItem(level4);
            icmpCheck->setText(0, showStr);

            sprintf(buf, "Flags: 0x%04x", mem_data->icmph->identification);
            showStr = QString(buf);
            QTreeWidgetItem *icmpIdentify = new QTreeWidgetItem(level4);
            icmpIdentify->setText(0, showStr);

            sprintf(buf, "Sequence Number: 0x%04x", mem_data->icmph->seq);
            showStr = QString(buf);
            QTreeWidgetItem *icmpSeq = new QTreeWidgetItem(level4);
            icmpSeq->setText(0, showStr);
        }
        else if(mem_data->iph->proto == PROTO_TCP)
        {
            showStr = QString("TCP");
            QTreeWidgetItem *level5 = new QTreeWidgetItem(root);
            level5->setText(0, showStr);

            sprintf(buf, "Source Port: %d", mem_data->tcph->srcPort);
            showStr = QString(buf);
            QTreeWidgetItem *tcpSrcPort = new QTreeWidgetItem(level5);
            tcpSrcPort->setText(0, showStr);

            sprintf(buf, "Destination: %d", mem_data->tcph->destPort);
            showStr = QString(buf);
            QTreeWidgetItem *tcpDestPort = new QTreeWidgetItem(level5);
            tcpDestPort->setText(0, showStr);

            sprintf(buf, "Sequence Number: 0x%08x", mem_data->tcph->seq);
            showStr = QString(buf);
            QTreeWidgetItem *tcpSeq = new QTreeWidgetItem(level5);
            tcpSeq->setText(0, showStr);

            sprintf(buf, "Acknowledgment Number: 0x%08x", mem_data->tcph->ack_sql);
            showStr = QString(buf);
            QTreeWidgetItem *tcpAck = new QTreeWidgetItem(level5);
            tcpAck->setText(0, showStr);

            sprintf(buf, "Header Length: %d", TH_OFF(mem_data->tcph));
            showStr = QString(buf);
            QTreeWidgetItem *tcpOFF = new QTreeWidgetItem(level5);
            tcpOFF->setText(0, showStr);

            sprintf(buf, "FLAG: 0x%02x", mem_data->tcph->th_flags);
            showStr = QString(buf);
            QTreeWidgetItem *tcpFlag = new QTreeWidgetItem(level5);
            tcpFlag->setText(0, showStr);

            if((mem_data->tcph->th_flags & TH_CWR) >> 7){
                sprintf(buf, "CWR");
                showStr = QString(buf);
                QTreeWidgetItem *cwrflag = new QTreeWidgetItem(tcpFlag);
                cwrflag->setText(0, showStr);
            }

            if((mem_data->tcph->th_flags & TH_ECE) >> 6){
                sprintf(buf, "ECE");
                showStr = QString(buf);
                QTreeWidgetItem *eceflag = new QTreeWidgetItem(tcpFlag);
                eceflag->setText(0, showStr);
            }

            if((mem_data->tcph->th_flags & TH_URG) >> 5){
                sprintf(buf, "URG");
                showStr = QString(buf);
                QTreeWidgetItem *urgflag = new QTreeWidgetItem(tcpFlag);
                urgflag->setText(0, showStr);
            }

            if((mem_data->tcph->th_flags & TH_ACK) >> 4){
                sprintf(buf, "ACK");
                showStr = QString(buf);
                QTreeWidgetItem *ackflag = new QTreeWidgetItem(tcpFlag);
                ackflag->setText(0, showStr);
            }

            if((mem_data->tcph->th_flags & TH_PUSH) >> 3){
                sprintf(buf, "PUSH");
                showStr = QString(buf);
                QTreeWidgetItem *pushflag = new QTreeWidgetItem(tcpFlag);
                pushflag->setText(0, showStr);
            }

            if((mem_data->tcph->th_flags & TH_RST) >> 2){
                sprintf(buf, "RST");
                showStr = QString(buf);
                QTreeWidgetItem *rstflag = new QTreeWidgetItem(tcpFlag);
                rstflag->setText(0, showStr);
            }

            if((mem_data->tcph->th_flags & TH_SYN) >> 1){
                sprintf(buf, "SYN");
                showStr = QString(buf);
                QTreeWidgetItem *synflag = new QTreeWidgetItem(tcpFlag);
                synflag->setText(0, showStr);
            }

            if((mem_data->tcph->th_flags & TH_FIN)){
                sprintf(buf, "FIN");
                showStr = QString(buf);
                QTreeWidgetItem *finflag = new QTreeWidgetItem(tcpFlag);
                finflag->setText(0, showStr);
            }

            sprintf(buf, "Window: %d", mem_data->tcph->wnd_size);
            showStr = QString(buf);
            QTreeWidgetItem *tcpWndSize = new QTreeWidgetItem(level5);
            tcpWndSize->setText(0, showStr);

            sprintf(buf, "Checksum: 0x%04x", mem_data->tcph->checksum);
            showStr = QString(buf);
            QTreeWidgetItem *tcpCheck = new QTreeWidgetItem(level5);
            tcpCheck->setText(0, showStr);

            sprintf(buf, "Urgent Pointer: %d", mem_data->tcph->urg_ptr);
            showStr = QString(buf);
            QTreeWidgetItem *tcpUrgPtr = new QTreeWidgetItem(level5);
            tcpUrgPtr->setText(0, showStr);

            if(mem_data->isHttp == true)
            {
                showStr = QString("HTTP Header");
                QTreeWidgetItem *level8 = new QTreeWidgetItem(root);
                level8->setText(0, showStr);

                QString content = "";
                u_char *httpps = mem_data->apph;

                qDebug() << QString(*httpps) << QString(*(httpps + 1)) << QString(*(httpps + 2)) << endl;

                u_char *httpps2 = NULL;

                const char *token[] = {"GET","POST","HTTP/1.1","HTTP/1.0"};
                for(int i = 0 ; i < 4 ; i ++){
                    httpps2 = (u_char *)strstr((char *)httpps,token[i]);
                    if(httpps2){
                        break;
                    }
                }
                int size = mem_data->httpsize - (httpps2 - httpps);

                for(int i = 0 ; i < size; i++){
                    if(httpps2[i] == 0x0d){
                        if(httpps2[i+1] == 0x0a && httpps2[i+2] == 0x0d && httpps2[i+3] == 0x0a){
                            content += "\\r\\n";
                            level8->addChild(new QTreeWidgetItem(level8,QStringList(content)));
                            level8->addChild(new QTreeWidgetItem(level8,QStringList("\\r\\n")));
                            break;
                        }
                        else if(httpps2[i+1] == 0x0a){
                            level8->addChild(new QTreeWidgetItem(level8,QStringList(content + "\\r\\n")));
                            content = "";
                            i ++;
                            continue;
                        }
                    }
                    content += httpps2[i];
                }
                level8->addChild(new QTreeWidgetItem(level8,QStringList("(Data)(Data)")));
            }
        }
        else if(mem_data->iph->proto == PROTO_UDP)  //UDP协议
        {
            showStr = QString("User Datagram Protocol");
            QTreeWidgetItem *level6 = new QTreeWidgetItem(root);
            level6->setText(0, showStr);

            sprintf(buf, "Source Port: %d", mem_data->udph->srcPort);
            showStr = QString(buf);
            QTreeWidgetItem *udpSrcPort = new QTreeWidgetItem(level6);
            udpSrcPort->setText(0, showStr);

            sprintf(buf, "Destination: %d", mem_data->udph->destPort);
            showStr = QString(buf);
            QTreeWidgetItem *udpDestPort = new QTreeWidgetItem(level6);
            udpDestPort->setText(0, showStr);

            sprintf(buf, "Length: %d", mem_data->udph->len);
            showStr = QString(buf);
            QTreeWidgetItem *udpLen = new QTreeWidgetItem(level6);
            udpLen->setText(0, showStr);

            sprintf(buf, "Checksum: 0x%04x", mem_data->udph->crc);
            showStr = QString(buf);
            QTreeWidgetItem *udpCrc = new QTreeWidgetItem(level6);
            udpCrc->setText(0, showStr);
        }
    }
}

void MainWindow::PacketHex(u_char *print_data, int print_len){
    QString tempnum,tempchar;
    QString oneline;
    int i;
    tempchar = "  ";
    oneline = "";
    for(i = 0 ; i < print_len ; i ++){
        if(i % 16 == 0){
            oneline += tempnum.sprintf("%04x  ",i);
        }
        oneline += tempnum.sprintf("%02x ",print_data[i]);
        if(isprint(print_data[i])){
            tempchar += print_data[i];
        }
        else{
            tempchar += ".";
        }
        if((i+1)%16 == 0){
            ui->HexWidget->append(oneline + tempchar);
            tempchar = "  ";
            oneline = "";
        }
    }
    i %= 16;
    for(; i < 16 ; i ++){
        oneline += "   ";
    }
    ui->HexWidget->append(oneline + tempchar);
}

void MainWindow::PacketTracker(int row, int column){
    struct headers *mem_data = (struct headers *)packets[row];
    u_char saddr[4];
    u_char daddr[4];
    u_short srcPort;
    u_short destPort;
    qDebug() << "isTCP? " << mem_data->pktType << strcmp(mem_data->pktType, "TCP") << endl;
    if(strcmp(mem_data->pktType, "TCP")==0){
        saddr[0]=mem_data->iph->saddr[0];
        saddr[1]=mem_data->iph->saddr[1];
        saddr[2]=mem_data->iph->saddr[2];
        saddr[3]=mem_data->iph->saddr[3];
        daddr[0]=mem_data->iph->daddr[0];
        daddr[1]=mem_data->iph->daddr[1];
        daddr[2]=mem_data->iph->daddr[2];
        daddr[3]=mem_data->iph->daddr[3];
        srcPort=mem_data->tcph->srcPort;
        destPort=mem_data->tcph->destPort;
        PacketFind(saddr,daddr,srcPort,destPort,1);
    }else if(strcmp(mem_data->pktType, "UDP")==0){
        saddr[0]=mem_data->iph->saddr[0];
        saddr[1]=mem_data->iph->saddr[1];
        saddr[2]=mem_data->iph->saddr[2];
        saddr[3]=mem_data->iph->saddr[3];
        daddr[0]=mem_data->iph->daddr[0];
        daddr[1]=mem_data->iph->daddr[1];
        daddr[2]=mem_data->iph->daddr[2];
        daddr[3]=mem_data->iph->daddr[3];
        srcPort=mem_data->udph->srcPort;
        destPort=mem_data->udph->destPort;
        PacketFind(saddr,daddr,srcPort,destPort,0);
    }
    return;

}

void MainWindow::PacketFind(u_char *saddr, u_char *daddr, u_short srcPort, u_short destPort, u_char t_or_u){
    qDebug() << srcPort << destPort << endl;
    if(t_or_u){
        for(int i=0;i<packets.size();i++){
            qDebug() << "tcpfind? " << endl;
            struct headers *mem_data = (struct headers *)packets[i];
            if(strcmp(mem_data->pktType, "TCP")!=0){
                continue;
            }
            if(saddr[0]==mem_data->iph->saddr[0]
                    && saddr[1]==mem_data->iph->saddr[1] \
                    && saddr[2]==mem_data->iph->saddr[2] \
                    && saddr[3]==mem_data->iph->saddr[3] \
                    && daddr[0]==mem_data->iph->daddr[0] \
                    && daddr[1]==mem_data->iph->daddr[1] \
                    && daddr[2]==mem_data->iph->daddr[2] \
                    && daddr[3]==mem_data->iph->daddr[3] \
                    && srcPort==mem_data->tcph->srcPort \
                    && destPort==mem_data->tcph->destPort){
                u_char *print_data = (u_char *)data_char[i];
                int print_len = mem_data->len;
                PacketTrackerPrint(print_data, print_len,0);
                continue;
            }
            if(saddr[0]==mem_data->iph->daddr[0]
                    && saddr[1]==mem_data->iph->daddr[1] \
                    && saddr[2]==mem_data->iph->daddr[2] \
                    && saddr[3]==mem_data->iph->daddr[3] \
                    && daddr[0]==mem_data->iph->saddr[0] \
                    && daddr[1]==mem_data->iph->saddr[1] \
                    && daddr[2]==mem_data->iph->saddr[2] \
                    && daddr[3]==mem_data->iph->saddr[3] \
                    && srcPort==mem_data->tcph->destPort \
                    && destPort==mem_data->tcph->srcPort){
                u_char *print_data = (u_char *)data_char[i];
                int print_len = mem_data->len;
                PacketTrackerPrint(print_data, print_len,1);
                continue;
            }
        }
    }else{
        for(int i=0;i<packets.size();i++){
            struct headers *mem_data = (struct headers *)packets[i];
            if(strcmp(mem_data->pktType, "UDP")!=0){
                continue;
            }
            if(saddr[0]==mem_data->iph->saddr[0]
                    && saddr[1]==mem_data->iph->saddr[1] \
                    && saddr[2]==mem_data->iph->saddr[2] \
                    && saddr[3]==mem_data->iph->saddr[3] \
                    && daddr[0]==mem_data->iph->daddr[0] \
                    && daddr[1]==mem_data->iph->daddr[1] \
                    && daddr[2]==mem_data->iph->daddr[2] \
                    && daddr[3]==mem_data->iph->daddr[3] \
                    && srcPort==mem_data->udph->srcPort \
                    && destPort==mem_data->udph->destPort){
                u_char *print_data = (u_char *)data_char[i];
                int print_len = mem_data->len;
                PacketTrackerPrint(print_data, print_len,0);
                continue;
            }
            if(saddr[0]==mem_data->iph->daddr[0]
                    && saddr[1]==mem_data->iph->daddr[1] \
                    && saddr[2]==mem_data->iph->daddr[2] \
                    && saddr[3]==mem_data->iph->daddr[3] \
                    && daddr[0]==mem_data->iph->saddr[0] \
                    && daddr[1]==mem_data->iph->saddr[1] \
                    && daddr[2]==mem_data->iph->saddr[2] \
                    && daddr[3]==mem_data->iph->saddr[3] \
                    && srcPort==mem_data->udph->destPort \
                    && destPort==mem_data->udph->srcPort){
                u_char *print_data = (u_char *)data_char[i];
                int print_len = mem_data->len;
                PacketTrackerPrint(print_data, print_len,1);
                continue;
            }
        }
    }

}

void MainWindow::PacketTrackerPrint(u_char *print_data, int print_len ,int color){
    QString tempnum,tempchar;
    QString oneline;
    int i;
    tempchar = "  ";
    for(i = 0 ; i < print_len ; i ++){
        if(isprint(print_data[i])){
            tempchar += print_data[i];
        }
        else{
            tempchar += ".";
        }
        if((i+1)%16 == 0){
            if(color)
                tempchar = "<font color=\"#FF0000\">"+tempchar+"</font> ";
            else
                tempchar = "<font color=\"#0000FF\">"+tempchar+"</font> ";
            ui->Tracker->append(tempchar);
            tempchar = "  ";
        }
    }
    i %= 16;
    for(; i < 16 ; i ++){
        oneline += "   ";
    }
    if(color)
        tempchar = "<font color=\"#FF0000\">"+tempchar+"</font> ";
    else
        tempchar = "<font color=\"#0000FF\">"+tempchar+"</font> ";
    ui->Tracker->append(tempchar);
}

