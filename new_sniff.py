from scapy.all import *
from threading import Thread
import pandas
import time
import os,sys
from mac_vendor_lookup import MacLookup

args=sys.argv
if len(args)>=2 and args[1]=='U':
    print('MAC updating')
    mac = MacLookup()
    mac.update_vendors()
    print('Done MAC update')
# initialize the networks dataframe that will contain all access points nearby
networks = pandas.DataFrame(columns=["BSSID", "SSID", "Channel", "Crypto"])
# set the index BSSID (MAC address of the AP)
networks.set_index("BSSID", inplace=True)

packcnt={}

AP_p=[]
mac_list={}

def mac_lookup(mac):
    mac=str(str(mac)[:-3])
    if mac=='ff:ff:ff:ff:ff' or mac=='N':
        return ''
    else:
        if mac in mac_list:
            ret=mac_list[mac]
        else:
            ret=MacLookup().lookup(mac)
            mac_list[mac]=ret
        return(ret)

def callback(packet):

    if packet.haslayer(Dot11Beacon):
        # extract the MAC address of the network
        bssid = packet[Dot11].addr2
        AP_p.append(bssid)
        # get the name of it
        ssid = packet[Dot11Elt].info.decode()
        # extract network stats
        stats = packet[Dot11Beacon].network_stats()
        # get the channel of the AP
        channel = stats.get("channel")
        # get the crypto
        crypto = stats.get("crypto")
        networks.loc[bssid] = (ssid, channel, crypto)

    elif packet.haslayer(Dot11):

        srcmac=packet.getlayer(Dot11).addr2
        destmac=packet.getlayer(Dot11).addr1
        if srcmac in AP_p:

            if destmac not in packcnt:
                packcnt[destmac]={'up':0,'down':(packet.len),'dt':0}
            else:
                packcnt[destmac]['down']+=(packet.len)

        elif destmac in AP_p:

            if srcmac not in packcnt:
                packcnt[srcmac]={'up':(packet.len),'down':0,'dt':0}
            else:
                packcnt[srcmac]['up']+=(packet.len)
            
def print_all():
    while True:
        os.system("clear")
        print(networks)
        for i in list(packcnt):
            print(f"{i}[{mac_lookup(i)}] down:{packcnt[i]['down']} up:{packcnt[i]['up']}")

            if packcnt[i]['down']==0 and packcnt[i]['up']==0:
                packcnt[i]['dt']+=1
            else:
                packcnt[i]['dt']=0

            packcnt[i]['down']=0
            packcnt[i]['up']=0

            if packcnt[i]['dt']>=5:
                del packcnt[i]
        time.sleep(1)


def change_channel():
    ch = 1
    while True:
        os.system(f"iwconfig {interface} channel {ch}")
        # switch channel from 1 to 14 each 0.5s
        ch = ch % 14 + 1
        time.sleep(0.5)


if __name__ == "__main__":
    # interface name, check using iwconfig
    interface = "wlan1"
    # start the thread that prints all the networks
    printer = Thread(target=print_all)
    printer.daemon = True
    printer.start()
    # start the channel changer
    channel_changer = Thread(target=change_channel)
    channel_changer.daemon = True
    channel_changer.start()
    # start sniffing
    sniff(prn=callback, iface=interface)