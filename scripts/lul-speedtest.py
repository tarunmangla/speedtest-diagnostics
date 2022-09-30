from threading import Thread
import os, time
import subprocess as p
from scapy.all import *
import socket, dpkt
import pandas as pd
import ipaddress
import psutil

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
LOCAL_IPv4_ADRR = ""
LOCAL_IPv6_ADDR = ""
IS_RUNNING = True
SERVER_IP = ""
def pkt_callback_fun(pkt):
    global IP_MAP
    if IPv6 in pkt:
        (ip_src, ip_dst) = (pkt[IPv6].src, pkt[IPv6].dst)
        LOCAL_ADDR = LOCAL_IPv6_ADDR
    else:
        (ip_src, ip_dst) = (pkt[IP].src, pkt[IP].dst)
        LOCAL_ADDR = LOCAL_IPv4_ADDR
    ip_server = ip_src if ip_dst == LOCAL_ADDR else ip_dst
    if ip_server not in IP_MAP:
        IP_MAP[ip_server] = 1
    else:
        IP_MAP[ip_server] += 1

def start_ping(server_ip):
    global IS_RUNNING
    ip_address = ipaddress.ip_address(SERVER_IP)
    if isinstance(ip_address,ipaddress.IPv6Address):
        cmd = f'ping6 -c 1 {SERVER_IP}'
    else:
        cmd = f'ping6 -c 1 {SERVER_IP}'

    out_file = "ping_test.csv"
    f = open(out_file, 'w')
    while IS_RUNNING:
        print(cmd)
        proc = p.Popen(cmd, shell=True, stdout=p.PIPE, stderr=p.PIPE)
        content = proc.stdout.readlines()
        print(content)
        content = f'{time.time()},{content}'
        f.write(content)
        time.sleep(0.1)
    f.close()


def get_local_ipv6_address():
        """
        Get's local ipv6 address
        TODO: What if more than one interface present ?

        :return: IPv6 address as a string
        :rtype: string
        """
        try:
            s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
            s.connect(('2001:4860:4860::8888', 1))
            IP = s.getsockname()[0]
        except:
            IP = '::1'
        finally:
            if 's' in locals():
                s.close()
        return IP

def get_local_ipv4_address():
    """
    Get's local ipv4 address of the interface with the default gateway.
    Return '127.0.0.1' if no suitable interface is found

    :return: IPv4 address as a string
    :rtype: string
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('8.8.8.8', 1))
        IP = s.getsockname()[0]
    except:
        IP = '127.0.0.1'
    finally:
        s.close()
    return IP

def start_capture():
    while SERVER_IP == "":
        time.sleep(0.1)
    print(SERVER_IP)
    ip_address = ipaddress.ip_address(SERVER_IP)
    if isinstance(ip_address,ipaddress.IPv6Address):
        capture_filter = f'host {SERVER_IP}'
        fields = f"-e ipv6.src -e ipv6.dst -e ipv6.plen"
    else:
        capture_filter = f'ip=={SERVER_IP}'
        fields = f"-e ip.src -e ip.dst -e ip.len"
    cmd = f"tshark -f '{capture_filter}' -T fields -e frame.time_epoch {fields} -e\
        tcp.srcport -e tcp.dstport  > pkt.pcap"
    proc = p.Popen(cmd, shell=True)
    while IS_RUNNING:
        time.sleep(1)
    kill(proc.pid)



def run_ping():
    global LOCAL_IPv4_ADDR, LOCAL_IPv6_ADDR, SERVER_IP
    LOCAL_IPv4_ADDR = get_local_ipv4_address()
    LOCAL_IPv6_ADDR = get_local_ipv6_address()
    capture_filter = f'tcp and ({pcap_filter[TEST_NAME]})'
    capture = sniff(filter=capture_filter, prn=pkt_callback_fun,
                    store=0, count=1000)
    print(IP_MAP)
    server_ip = max(IP_MAP, key=IP_MAP.get)
    SERVER_IP = server_ip
    start_ping(server_ip)

def kill(proc_pid):
    process = psutil.Process(proc_pid)
    for proc in process.children(recursive=True):
        proc.kill()
    process.kill()


def traceroute():
    max_i = 200
    i = 0
    os.system('traceroute -m 1 google.com > output.trt')
    while i < max_i:
        os.system("echo $(date +%s) >> output.trt")
        os.system('traceroute -m 1 -q 6 google.com >> output.trt')
        time.sleep(0.1)
        i += 1

ntoa_map = {}

def process_csv_pcap():
    df = pd.read_csv('pkt.pcap')
    df['id'] = df.apply(lambda x: f'{x[1]}-{x[2]}', axis=1)
    df['ts_int'] = df[0].apply(lambda x: 250*int((1000*x)/250))
    df_grp = df.groupby(["ts_int", "id"]).agg({3: 'sum'}).reset_index()
    df_grp[3] = df_grp[3] * 8 / 1000
    df_down = df_grp[df_grp["id"].str.startswith(SERVER_IP)]
    df_up = df_grp[df_grp["id"].str.endswith(SERVER_IP)]
    df_merge = pd.merge(df_down, df_up, on="ts_int", suffixes=("_down", "_up"))
    df_merge["ratio"] = df_merge["3_down"] / df_merge["3_up"]
    ts_in = df_merge[df_merge["ratio"] <  1].min()





th1 = Thread(target=run_speedtest)
th2 = Thread(target=run_ping)
th3 = Thread(target=start_capture)

#th3 = Thread(target=traceroute)

th3.start()
th2.start()
th1.start()
th1.join()
IS_RUNNING=False
time.sleep(3)
'''
l = []
flow_map = process_pcap()
for flow_id in flow_map:
    for ts in flow_map[flow_id]:
        data = [flow_id, ts, flow_map[flow_id][ts]]
        l.append(data)

df = pd.DataFrame(l)
df.to_csv('processed.csv')
'''
