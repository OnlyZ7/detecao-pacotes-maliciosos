import pandas as pd
from scapy.all import rdpcap, IP, TCP, UDP


def load_pcap_features(pcap_path):
    packets = rdpcap(pcap_path)
    features = []
    ignored = 0

    for idx, pkt in enumerate(packets):
        try:
            if IP in pkt:
                proto = None
                sport = dport = None
                flags = ''
                length = len(pkt)

                if TCP in pkt:
                    proto = 'TCP'
                    sport = pkt[TCP].sport
                    dport = pkt[TCP].dport
                    flags = str(pkt[TCP].flags)
                elif UDP in pkt:
                    proto = 'UDP'
                    sport = pkt[UDP].sport
                    dport = pkt[UDP].dport

                features.append({
                    'pkt_index': idx,           # mapeia para o PCAP original
                    'src_ip': pkt[IP].src,
                    'dst_ip': pkt[IP].dst,
                    'sport': sport,
                    'dport': dport,
                    'protocol': proto,
                    'length': length,
                    'flags': str(flags)
                })
        except Exception:
            ignored += 1
            continue

    return pd.DataFrame(features)