from scapy.all import *
import threading
import os

ap_list = []
unknown_ap = []


class Sniff_Thread (threading.Thread):
    def __init__(self, iface, t):
        threading.Thread.__init__(self)
        self.iface = iface
        self.thread = t

    def run(self):
        if self.thread == 1:
            sniff(iface=self.iface, prn=list_hidden_ap)
        elif self.thread == 2:
            sniff(iface=self.iface, prn=uncover_ap)


def get_iface():
    no = 1
    ifaces = os.listdir("/sys/class/net")
    for iface in ifaces:
        print "["+str(no)+"] "+iface
        no += 1
    choice = raw_input("Enter Wireless Interface to Use: ")
    return ifaces[int(choice)-1]


def in_monitor(iface):
    chk = os.popen("iwconfig " + iface + " | grep Monitor").read()
    if chk == "":
        return False
    else:
        return True


def set_monitor(op, iface):
    os.system("sudo ifconfig " + iface + " down")
    if op == 1:
        os.system("sudo iw dev "+iface+" set type monitor")
    elif op == 0:
        os.system("sudo iw dev "+iface+" set type managed")
    else:
        print "Invalid choice"
    os.system("sudo ifconfig " + iface + " up")
    return in_monitor(iface)


def monitor_mode(iface):
    is_monitor = in_monitor(iface)

    if is_monitor:
        print "[+] Monitor mode enabled on " + iface
    else:
        while not is_monitor:
            print "[x] Monitor mode not enabled on " + iface + "\n[+] Enabling Monitor mode"
            is_monitor = set_monitor(1, iface)
            if is_monitor:
                print "[+] Monitor mode enabled on " + iface


def clean_up(iface):
    print "[+] Cleaning up the goodness :("
    set_monitor(0, iface)
    exit()


def uncover_ap(pkt):
    try:
        if pkt.info == "":
            unknown_ap.append(pkt.addr2)
    except:
        pass

    if pkt.type == 0 and pkt.subtype == 4 and pkt.addr2 in unknown_ap and pkt.addr2 not in ap_list:
        if pkt.info != "":
            print pkt.addr2 + " > " + pkt.addr3 + " : Subtype 4 : " + pkt.info
            ap_list.append(pkt.addr2)



iface = get_iface()
monitor_mode(iface)
sniff(iface=iface, prn=uncover_ap)

clean_up(iface)