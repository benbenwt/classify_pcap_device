#! coding=utf-8
import math
import pickle

from scapy.layers.inet import IPOption_Router_Alert
from scapy.packet import Raw
from scapy.utils import rdpcap

import pandas as pd

header = "ARP,LLC,EAPOL,IP,ICMP,ICMP6,TCP,UDP,TCP_w_size,HTTP,HTTPS,DHCP,BOOTP,SSDP,DNS,MDNS,NTP,IP_padding,IP_add_count,IP_ralert,Portcl_src,Portcl_dst,Pck_size,Pck_rawdata,payload_l,Entropy,Label,MAC"
header = header.split(",")

def get_result(pred):
    f = open('Result-RandomForest.txt', 'w')
    f.write('CLASS:' + '\n')
    for p in pred:
        f.write(str(p) + '\n')

def combine_mac_device(pred,mac_list):
    result=[]
    for p,m in zip(pred,mac_list):
        result.append([m,p])
    return pd.DataFrame(result,columns=["MAC","device_type"])

def pre_entropy(payload):
    characters = []
    for i in payload:
        characters.append(i)
    return shannon(characters)

def shannon(data):
    freq_dict={}
    for i in data:
        if i in freq_dict:
            freq_dict[i] += 1
        else:
            freq_dict[i] = 1
    entropy = 0.0
    logarithm_base = 2
    payload_size = len(data) #
    for key in freq_dict.keys():
        frequency = float(freq_dict[key])/payload_size
        if frequency > 0:
            entropy = entropy + frequency * math.log(frequency, logarithm_base)
    return -entropy

def port_class(port):
    if 0 <= port <= 1023:
        return 1
    elif  1024 <= port <= 49151 :
        return 2
    elif 49152 <=port <= 65535 :
        return 3
    else:
        return 0
# pcap_2feature: pcap->feature.
# predict_one: feature->label,mac.
# 1:n,one pcap to more mac address.

def pcap_2feature(path):

    dst_ip_list = {}
    MAC_list={}
    for i in MAC_list:
        dst_ip_list[i] = []

    pkt = rdpcap(path)
    print(pkt)
    features=[]
    for jj, j in enumerate(pkt):
        ip_add_count = 0
        layer_2_arp = 0
        layer_2_llc = 0

        layer_3_eapol = 0
        layer_3_ip = 0
        layer_3_icmp = 0
        layer_3_icmp6 = 0

        layer_4_tcp = 0
        layer_4_udp = 0
        layer_4_tcp_ws = 0

        layer_7_http = 0
        layer_7_https = 0
        layer_7_dhcp = 0
        layer_7_bootp = 0
        layer_7_ssdp = 0
        layer_7_dns = 0
        layer_7_mdns = 0
        layer_7_ntp = 0

        ip_padding = 0
        ip_ralert = 0

        port_class_src = 0
        port_class_dst = 0

        pck_size = 0
        pck_rawdata = 0
        entropy = 0

        layer_4_payload_l = 0

        try:
            pck_size = j.len
        except:
            pass

        try:
            if j['IP']:
                layer_3_ip = 1
            temp = str(j['IP'].dst)
            if(j.src not in dst_ip_list):
                dst_ip_list[j.src]=[]
            if temp not in dst_ip_list[j.src]:
                dst_ip_list[j.src].append(temp)
            ip_add_count = len(dst_ip_list[j.src])
            port_class_src = port_class(j['IP'].sport)
            port_class_dst = port_class(j['IP'].dport)
        except:
            pass

        temp = str(j.show)
        if "ICMPv6" in temp:
            layer_3_icmp6 = 1

        try:
            if j['IP'].ihl > 5:
                if IPOption_Router_Alert(j):
                    pad = str(IPOption_Router_Alert(j).show)
                    if "Padding" in pad:
                        ip_padding = 1
                    ip_ralert = 1
        except:
            pass

        if j.haslayer('ICMP'):
            layer_3_icmp = 1

        if j.haslayer(Raw):
            pck_rawdata = 1

        if j.haslayer('UDP'):

            layer_4_udp = 1
            if j['UDP'].sport == 68 or j['UDP'].sport == 67:
                layer_7_dhcp = 1
                layer_7_bootp = 1
            if j['UDP'].sport == 53 or j['UDP'].dport == 53:
                layer_7_dns = 1
            if j['UDP'].sport == 5353 or j['UDP'].dport == 5353:
                layer_7_mdns = 1
            if j['UDP'].sport == 1900 or j['UDP'].dport == 1900:
                layer_7_ssdp = 1
            if j['UDP'].sport == 123 or j['UDP'].dport == 123:
                layer_7_ntp = 1

        try:
            if j['UDP'].payload:
                layer_4_payload_l = len(j['UDP'].payload)
        except:
            pass

        if j.haslayer('TCP'):
            layer_4_tcp = 1
            layer_4_tcp_ws = j['TCP'].window
            if j['TCP'].sport == 80 or j['TCP'].dport == 80:
                layer_7_http = 1
            if j['TCP'].sport == 443 or j['TCP'].dport == 443:
                layer_7_https = 1
            try:
                if j['TCP'].payload:
                    layer_4_payload_l = len(j['TCP'].payload)
            except:
                pass

        if j.haslayer('ARP'):
            layer_2_arp = 1

        if j.haslayer('LLC'):
            layer_2_llc = 1

        if j.haslayer('EAPOL'):
            layer_3_eapol = 1
        try:
            entropy = pre_entropy(j[Raw].original)
        except:
            pass
        if(j.src in MAC_list):
            label = MAC_list[j.src]
        else:
            label=-1
        line = [layer_2_arp, layer_2_llc, layer_3_eapol, layer_3_ip, layer_3_icmp, layer_3_icmp6, layer_4_tcp,
                layer_4_udp, layer_4_tcp_ws, layer_7_http, layer_7_https, layer_7_dhcp, layer_7_bootp, layer_7_ssdp,
                layer_7_dns, layer_7_mdns, layer_7_ntp, ip_padding, ip_add_count, ip_ralert, port_class_src,
                port_class_dst, pck_size, pck_rawdata, layer_4_payload_l, entropy, label, j.src]
        features.append(line)
    return features

def predict_one(features):
    global header
    features_dataframe=pd.DataFrame(data=features,columns=header)
    mac_list = features_dataframe['MAC']
    X_test = features_dataframe[
        ['ARP', 'LLC', 'EAPOL', 'IP', 'ICMP', 'ICMP6', 'TCP', 'UDP', 'TCP_w_size', 'HTTP', 'HTTPS', 'DHCP', 'BOOTP',
         'SSDP', 'MDNS', 'DNS', 'NTP', 'IP_padding', 'IP_add_count', 'IP_ralert', 'Portcl_src', 'Portcl_dst',
         'Pck_size', 'Pck_rawdata', 'payload_l', 'Entropy']]

    with open('rfc.pkl', 'rb') as f:
        rfc=pickle.load(f)
    y_predict = rfc.predict(X_test)
    result=combine_mac_device(y_predict, mac_list)
#
    count_df=result.groupby(["MAC","device_type"]).agg({"device_type": "count"}).rename(columns={"device_type":"counts"}).reset_index(names=["MAC","device_type"])
    idx=count_df.groupby(["MAC"])["counts"].idxmax()
    result_df=count_df.iloc[idx].reset_index().drop(columns="index")
    return result_df
#    id  mac   device_type

def predict_pcap(path):
    features=pcap_2feature(path)
    result=predict_one(features)
    print(result)
    return result
if __name__ == '__main__':
    predict_pcap(r"D:\DevBackup\lab\platform\项目文档及提交指标\测试样本\pcap\2013-07-28-phishing-malware-traffic.pcap")


