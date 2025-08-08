import os
from config import PCAP_PATH, RESULTS_OUTPUT_DIR, TOP_QUANTILE
from data.loader import load_pcap_features
from prefilter import score_dataframe, select_top_quantile, write_filtered_pcap
from ndpi_processor import NDPIProcessor


def main():
    os.makedirs(RESULTS_OUTPUT_DIR, exist_ok=True)

    # 1) extrai features e pontua risco
    feats = load_pcap_features(PCAP_PATH)
    scored = score_dataframe(feats)

    # 2) seleciona top quantil para escalonar ao nDPI
    filtered_df, mask, thr = select_top_quantile(scored, q=TOP_QUANTILE)
    print(f"Pré-filtro: enviando {len(filtered_df)}/{len(scored)} pacotes (top {int(TOP_QUANTILE*100)}%), limiar={thr:.2f}")

    # 3) gera PCAP reduzido e roda nDPI
    reduced_pcap = os.path.join(RESULTS_OUTPUT_DIR, 'prefiltered.pcap')
    write_filtered_pcap(PCAP_PATH, scored, mask, reduced_pcap)

    proc = NDPIProcessor(pcap_path=reduced_pcap)
    raw, metrics = proc.run_ndpi()

    # 4) extrai estatística do nDPI
    threshold = proc.parse_output(raw)
    print("nDPI (prefiltrado) — total de pacotes maliciosos (estimado):", threshold)
    print("Métricas de recursos:", metrics)


if __name__ == '__main__':
    main()