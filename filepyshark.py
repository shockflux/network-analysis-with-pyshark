import pyshark
import pandas as pd
import matplotlib.pyplot as plt

filename = input("Please enter filename with Extension csv/pcap example- file.csv or file.pcap:: ")

try:
    capture = pyshark.LiveCapture(interface="wlan0", output_file="{filename}")
    print("PROCESSING.... PRESS ctrl+c to STOP CAPTURING ")
    capture.sniff()
except KeyboardInterrupt:
    print(capture)
    if len(capture) > 10:
        capture1 = pyshark.FileCapture('{filename}')
        ip = []
        for pkt in capture1:
            if ("TCP" in pkt and "IP" in pkt):
                ip.append([pkt.ip.src, pkt.tcp.dstport])
                capture1.close()

                #print(pkt.ip.src, pkt.tcp.dstport)
            elif ("UDP" in pkt and "IP" in pkt):
                ip.append([pkt.ip.src, pkt.udp.dstport])
                capture1.close()
                #print(pkt.ip.src, pkt.udp.dstport)

        data1 = pd.DataFrame(ip, columns=['sourceip', 'port'])
        data1['port'] = data1['port'].astype(int)


        data1 = data1.groupby(['sourceip']).first().plot(kind='bar')
        plt.show()

        print(data1)
    else:
        print("[-] YOU HAVE LESS PACKETS TO PLOT THE GRAPH")
