#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#define WPCAP
#define HAVE_REMOTE

#include <iostream>
#include <vector>
#include <pcap.h>
#include <remote-ext.h>
#include <winsock.h>
#include <mythread.h>
#include <QMainWindow>
#include <QMessageBox>
#include <QDebug>
#include <QTreeWidgetItem>
#include <QColor>
#include <QDir>
#include <QAction>
#include <QMenu>
#include <QIcon>
#include <QFileDialog>
#include <QFile>
#include <QCloseEvent>

namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = 0);
    ~MainWindow();
    int devCount;
    char errbuf[PCAP_ERRBUF_SIZE];
    char filepath[512];
    pcap_if_t *alldevs;
    pcap_if_t *dev;
    pcap_t *handle;
    pcap_dumper_t *dump;
    MyThread *mythread;
    datapktVec packets;
    dataVec data_char;
    int RowCount;
    int Tarcker_flag;



private slots:
    void on_start_clicked();
    void on_stop_clicked();
    void on_tracker_start_clicked();
    void on_tracker_end_clicked();
    void PacketList(QString timestr, QString srcMac, QString destMac, QString len, QString protoType, QString srcIP, QString dstIP);
    void PacketDetails(int row, int column);
    void PacketHex(u_char*, int len);
    void PacketTracker(int row, int column);
    void PacketFind(u_char *saddr, u_char *daddr, u_short srcPort, u_short destPort, u_char t_or_u);
    void PacketTrackerPrint(u_char *print_data, int print_len ,int color);
    int cap_init();
    int cap_start();

private:
    Ui::MainWindow *ui;

};

#endif // MAINWINDOW_H
