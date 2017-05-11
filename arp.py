import sys
from datetime import datetime
from scapy.all import srp, Ether, ARP, conf

try:
    interface = raw_input("[*] Enter Desired interface: ") #Get interface to scan
    ips = raw_input("[*] Enter Range of IPs to Scan for : ") #Get IP or IP range to scan
except KeyboardInterrupt:
    print ("\nkthxbi")
    sys.exit(1)

print ("\n[*] Scanning...")
start_time = datetime.now()


# Actually run the scan
conf.verb = 0
ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst = ips), timeout = 2, iface=interface, inter=0.1)

print ("MAC - IP")
macs = []
for snd, rcv in ans:
    macs.append(rcv.sprintf(r"%Ether.src%"))
    print (rcv.sprintf(r"%Ether.src% - %ARP.psrc%"))

#print macs
stop_time = datetime.now()
total_time = stop_time - start_time
print ("\n[*] Done in %s" %(total_time))

