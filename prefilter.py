import pandas as pd
from scapy.all import rdpcap, wrpcap
from prefilter_config import PORT_WEIGHTS, UDP_AMP_PORTS, FLAGS_WEIGHTS, PROTO_BASE, \
    LENGTH_SMALL, LENGTH_LARGE, LEN_WEIGHT_SMALL, LEN_WEIGHT_LARGE


def _score_row(row):
    score = 0.0

    # protocolo
    proto = str(row.get('protocol', '')).upper()
    score += PROTO_BASE.get(proto, 0.0)

    # porta de destino
    dport = row.get('dport')
    if pd.notna(dport):
        try:
            dport = int(dport)
            score += PORT_WEIGHTS.get(dport, 0.0)
            if proto == 'UDP' and dport in UDP_AMP_PORTS:
                score += 2.0
        except (TypeError, ValueError):
            pass

    # flags TCP
    flags = str(row.get('flags', ''))
    if flags and flags.lower() != 'nan':
        fset = set(flags)
        if 'S' in fset and 'A' not in fset:
            score += FLAGS_WEIGHTS.get('SYN_ONLY', 0.0)
        if {'F','P','U'}.issubset(fset):
            score += FLAGS_WEIGHTS.get('XMAS', 0.0)
        if len(fset) == 0 or flags == '0':
            score += FLAGS_WEIGHTS.get('NULL', 0.0)

    # tamanho do pacote
    length = row.get('length')
    try:
        if length is not None:
            if length <= LENGTH_SMALL:
                score += LEN_WEIGHT_SMALL
            elif length >= LENGTH_LARGE:
                score += LEN_WEIGHT_LARGE
    except TypeError:
        pass

    return float(score)


def score_dataframe(df: pd.DataFrame) -> pd.DataFrame:
    out = df.copy()
    out['risk_score'] = out.apply(_score_row, axis=1)
    return out


def select_top_quantile(scored_df: pd.DataFrame, q: float):
    """Retorna df filtrado, máscara booleana e limiar de score."""
    threshold = scored_df['risk_score'].quantile(1 - q)
    mask = scored_df['risk_score'] >= threshold
    return scored_df[mask].copy(), mask, float(threshold)


def write_filtered_pcap(pcap_path: str, features_df: pd.DataFrame, mask: pd.Series, out_path: str) -> str:
    """
    Gera um PCAP contendo apenas os pacotes selecionados pelo pré-filtro.
    Requer a coluna 'pkt_index' em features_df.
    """
    packets = rdpcap(pcap_path)
    selected_idx = features_df.loc[mask, 'pkt_index'].tolist()
    selected_pkts = [packets[i] for i in selected_idx if i < len(packets)]
    wrpcap(out_path, selected_pkts)
    return out_path