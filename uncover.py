from datetime import datetime
from scapy.all import *
import threading
import hexdump
import Queue
import os


class SniffThread (threading.Thread):
    def __init__(self, iface, queue):
        self.iface = iface
        self.queue = queue
        self.ap_list = {}
        self.unknown_ap = []
        self.uncovered_ap = {}
        self.list = {}
        thread = threading.Thread(target=self.run, args=())
        thread.daemon = True
        thread.start()

        with open("unknown.txt", "a") as k:
            k.write(datetime.now().strftime('%Y-%m-%d %H:%M:%S') + "\n")

        with open("known.txt", "a") as k:
            k.write(datetime.now().strftime('%Y-%m-%d %H:%M:%S') + "\n")

        with open("uncovered.txt", "a") as k:
            k.write(datetime.now().strftime('%Y-%m-%d %H:%M:%S') + "\n")

        try:
            thread.join()
        except KeyboardInterrupt:
            print "HELLO"

    def uncover_ap(self, pkt):
        try:
            if pkt.type == 0:  # and pkt.subtype == 4 and pkt.addr2 in unknown_ap and pkt.addr2 not in ap_list:
                if pkt.subtype == 8:
                    if self.is_null(pkt.info):
                        if pkt.addr2 not in self.unknown_ap:
                            self.unknown_ap.append(pkt.addr2)
                            with open("unknown.txt", "a") as k:
                                k.write("MAC: " + pkt.addr2 + "\n")

                    elif not self.is_null(pkt.info):
                        if pkt.addr2 not in self.ap_list.keys():
                            self.ap_list[pkt.addr2] = pkt.info
                            with open("known.txt", "a") as k:
                                k.write("MAC: " + pkt.addr2 + " ESSID: " + pkt.info + "\n")

                elif pkt.subtype == 5:
                    if pkt.addr2 not in self.uncovered_ap.keys() and pkt.addr2 in self.unknown_ap:
                        print "MAC: " + pkt.addr2 + " ESSID: " + pkt.info
                        with open("uncovered.txt", "a") as k:
                            k.write("MAC: " + pkt.addr2 + " ESSID: " + pkt.info + "\n")
                        self.uncovered_ap[pkt.addr2] = pkt.info

            self.list['kap'] = self.ap_list
            self.list['ucap'] = self.uncovered_ap
            self.queue.put(self.list)

        except AttributeError:
            pass

        except KeyboardInterrupt:
            self._stop_event.set()

    def is_null(self, ssid):
        if not ssid or hexdump.dump(ssid) == "00 00 00 00 00 00 00" or ssid is None or ssid == "":
            return True
        else:
            return False

    def run(self):
        sniff(iface=self.iface, prn=self.uncover_ap)

    def stop(self):
        self._stop_event.set()


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


def main():
    interface = get_iface()
    monitor_mode(interface)
    queue = Queue.Queue()
    thread = SniffThread(interface, queue)
    try:
        pass
        '''while 1:
            ch = raw_input("\n[1] Print list of known APs\n[2] Print list of uncovered APs\n[3] Clear Screen\nEnter Choice: ")
            if ch == "1":
                ap_list = queue.get()
                print "\n============== LIST OF KNOWN APs =============="
                for addr in ap_list['kap'].keys():
                    print "MAC: " + addr + " ESSID: " + ap_list['kap'][addr]
            elif ch == "2":
                ap_list = queue.get()
                print "\n============== LIST OF UNCOVERED APs =============="   
                for addr in ap_list['ucap'].keys():
                    print "MAC: " + addr + " ESSID: " + ap_list['ucap'][addr]
            elif ch == "3":
                os.system("clear")
            else:
                print "[!] Invalid option try again"'''
    except KeyboardInterrupt:
        thread.stop()
        clean_up(interface)


if __name__ == "__main__":
    main()
