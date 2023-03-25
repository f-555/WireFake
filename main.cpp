#define _XKEYCHECK_H
#include "mainwindow.h"
#include <QApplication>
#pragma comment(lib,"wpcap.lib")
#pragma comment(lib,"ws2_32.lib")
int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    MainWindow w;
    w.show();
    return a.exec();
}
