#ifndef NETWORKCONTROLLER_H
#define NETWORKCONTROLLER_H

#include <QObject>
#include <QString>
#include <QDebug>

#include <sys/ioctl.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <net/if_arp.h>
#include <unistd.h>

#include <vector>
#include <string>
#include <iostream>

#include <pcap.h>

#include "../../include/mac.h"
#include "../../include/ethhdr.h"
#include "../../include/arphdr.hpp"
#include "../../include/iphdr.hpp"
#include "../../include/tcphdr.hpp"


class NetworkController : public QObject
{
    Q_OBJECT

#pragma pack(push, 1)
    struct EthArpPacket final {
        EthHdr eth_;
        ArpHdr arp_;
    };
#pragma pack(pop)

    typedef struct INTERFACE_INFO{
        QString interfaceName_;
        Mac mac_;

    }InterfaceInfo;

    typedef struct PCAP_RECV_DATA {
        pcap_pkthdr* header{};
        u_char* buf;
    }RecvData;

    std::vector<pcap_t*> pcaps_;
    std::vector<InterfaceInfo> interfaceInfos_;
    std::vector<RecvData> recvDatas_;

    void GetInterfaceInfo();
    bool OpenPcap(const int timeout = 1);

    Mac GetMac(const QString& interface, const QString targetIP);
    bool GetPacket(const QString& interface);

public:
    explicit NetworkController(QObject *parent = nullptr);
    ~NetworkController();

    std::vector<QString> GetInterfaces();

    bool ArpSpoofing(const QString interface, const QString senderIP,const QString targetIP);
    void ShowPacket(const QString interface,const uint16_t etherType, const QString ip, const IpHdr::PROTOCOL_ID_TYPE type);
signals:
};

#endif // NETWORKCONTROLLER_H
