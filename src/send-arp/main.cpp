#include <QString>

#include <vector>
#include <string>


#include "../../include/networkcontroller.h"

using namespace std;

vector<string> arguments;

void usage() {
    cout<<"syntax : send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]"<<endl;
    cout<<"sample : send-arp wlan0 192.168.10.2 192.168.10.1"<<endl;
}

bool parse(int argc, char* argv[]) {
    if(argc <= 1 || argc % 2 != 0) {
        usage();
        return false;
    }

    for(int i=1; i<argc; i++)
        arguments.push_back(string(argv[i]));

    return true;
}

int main(int argc, char *argv[])
{
    if(!parse(argc, argv)) return -1;

    NetworkController nc;

    string interface = arguments[0];

    for(int i=1; i<arguments.size(); i+=2)
        if(!nc.ArpSpoofing(interface.c_str(), arguments.at(i).c_str(), arguments.at(i+1).c_str())) return -1;
}
