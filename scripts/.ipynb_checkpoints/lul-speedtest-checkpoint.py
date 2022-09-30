from threading import Thread
import os, time
import subprocess as p
from scapy.all import *
import socket, dpkt
import pandas as pd
TEST_NAME = "mlab"
cmd_map = {'mlab': "ndt7-client",
           'ookla': 'speedtest'}
pcap_filter = {'mlab': 'port 443',
               'ookla': 'port 8080 or port 5060'}
def run_speedtest():
    cmd = cmd_map[TEST_NAME]
    proc =  p.Popen(cmd, shell=True, stdout=p.PIPE, stderr=p.PIPE)
    t = proc.wait()

IP_MAP = {}
IP_ADRR = ""
IS_RUNNING = True
def pkt_callback_fun(pkt):
    global IP_MAP
    (ip_src, ip_dst) = (pkt[IP].src, pkt[IP].dst)
    ip_server = ip_src if ip_dst == IP_ADDR else ip_dst
    if ip_server not in IP_MAP:
        IP_MAP[ip_server] = 1
    else:
        IP_MAP[ip_server] += 1

def start_ping(server_ip):
    global IS_RUNNING
    cmd = f'ping -c 1 {server_ip}'
    out_file = "ping_test.csv"
    f = open(out_file, 'w')
    while IS_RUNNING:
        proc = p.Popen(cmd, shell=True, stdout=p.PIPE, stderr=p.PIPE)
        content = proc.stdout.readlines()
        content = f'{time.time()},{content}'
        f.write(content)
        time.sleep(0.1)
    f.close()


def start_capture():
    cmd = "tcpdump -s 400 -f 'tcp' -w pkt.pcap"
    proc = p.Popen(cmd, shell=True)

def run_ping():
    global IP_ADDR
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    IP_ADDR = s.getsockname()[0]
    s.close()
    capture_filter = f'tcp and ({pcap_filter[TEST_NAME]})'
    capture = sniff(filter=capture_filter, prn=pkt_callback_fun,
                    store=0, count=1000)
    server_ip = max(IP_MAP, key=IP_MAP.get)
    start_ping(server_ip)

def kill_tcpdump():
    os.system("sudo pkill -KILL tcpdump")

def traceroute():
    max_i = 200
    i = 0
    os.system('traceroute -m 1 google.com > output.trt')
    while i < max_i:
        os.system("echo $(date +%s) >> output.trt")
        os.system('traceroute -m 1 -q 6 google.com >> output.trt')
        time.sleep(0.1)
        i += 1

def process_pcap():
    f = open('pkt.pcap', 'rb')
    pcap = dpkt.pcapng.Reader(f)
    flow_map = {}
    for ts, buf in pcap:
        eth = dpkt.ethernet.Ethernet(buf)
        ip = eth.data
        (src_ip, dst_ip) = (socket.inet_ntoa(ip.src), socket.inet_ntoa(ip.dst))
        flow_id = (src_ip, dst_ip)
        if not flow_id in flow_map:
            flow_map[flow_id] = {}
        ts_int = int(ts)
        if ts_int not in flow_map[flow_id]:
            flow_map[flow_id][ts_int] = 0
        flow_map[flow_id][ts_int] += ip.len
    return flow_map



th1 = Thread(target=run_speedtest)
th2 = Thread(target=run_ping)
th3 = Thread(target=start_capture)

#th3 = Thread(target=traceroute)
'''
th3.start()
th2.start()
th1.start()
th1.join()
IS_RUNNING=False
print(IP_MAP)
kill_tcpdump()
print("killing TCPDump")
'''
l = []
flow_map = process_pcap()
for flow_id in flow_map:
    for ts in flow_map[flow_id]:
        data = [flow_id, ts, flow_map[flow_id][ts]]
        l.append(data)

df = pd.DataFrame(l)
df.to_csv('processed.csv')
