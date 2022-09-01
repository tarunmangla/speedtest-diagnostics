from threading import Thread
import os, time

def run_speedtest():
    print("running speedtest")
    os.system("speedtest > output.csv &")
    print("finished running speedtest")

def run_capture():
    os.system("sudo tcpdump  -i en0 -s 96 -w output.pcap &")

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

th1 = Thread(target=run_speedtest)
th2 = Thread(target=run_capture)
th3 = Thread(target=traceroute)
th3.start()
th2.start()
time.sleep(2)
th1.start()
th3.join()
kill_tcpdump()

