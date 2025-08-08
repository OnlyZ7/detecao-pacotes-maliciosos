# 🛡️ Detecção de Atividades Maliciosas com nDPI (com Pré‑Filtro)

Este projeto executa **apenas o nDPI** (Deep Packet Inspection) em um **pipeline com pré‑processamento** para reduzir custo computacional. Em vez de enviar todo o tráfego para o nDPI, aplicamos um **pré‑filtro leve** que pontua o risco de cada pacote e envia apenas o **top quantil** (ex.: 30%) para inspeção profunda.

---

## 🔧 Arquitetura (visão geral)
1. **Extração de features leves** do PCAP (protocol, dport, flags, length, pkt_index)
2. **Pré‑filtro**: matriz de pesos → `risk_score` por pacote
3. **Seleção**: top `TOP_QUANTILE` dos pacotes (mais arriscados)
4. **PCAP reduzido** é gerado e usado como entrada do **nDPI**
5. **Parse do output** do `ndpiReader` para estatísticas (ex.: total "Unsafe"/"Dangerous")

---

## 📂 Estrutura do Projeto

```
deteccao-pacotes-maliciosos/
├── DPI/
│   └── nDPI/...                    # binário/fonte do ndpiReader
├── config.py                       # constantes (paths, timeouts, quantil)
├── data/
│   └── loader.py                   # extrai features do PCAP (inclui pkt_index)
├── prefilter_config.py             # matriz de pesos (regras) do pré‑processamento
├── prefilter.py                    # cálculo de risco + geração de PCAP filtrado
├── ndpi_processor.py               # executa ndpiReader e parseia saída
├── main.py                         # orquestra: loader → prefilter → nDPI
├── requirements.txt                # dependências Python
└── README.md
```

> **Observação**: a pasta de **resultados** (ex.: PCAP reduzido) é criada em runtime conforme `RESULTS_OUTPUT_DIR` do `config.py`.

---

## ⚙️ Configuração
Edite `config.py`:
```python
PCAP_PATH = "/caminho/para/seu.pcap"
NDPI_READER_BIN = "./DPI/nDPI/example/ndpiReader"  
NDPI_TIMEOUT_SECONDS = 15 * 60
RESULTS_OUTPUT_DIR = "/caminho/para/resultados"
TOP_QUANTILE = 0.30  
```

Ajuste `prefilter_config.py` para calibrar os **pesos** por portas, flags e tamanhos, conforme seu cenário.

---

## ▶️ Como Executar (PCAP estático)
1. **Instale dependências**:
   ```bash
   pip install -r requirements.txt
   ```
2. **Garanta o nDPI compilado** e configure `NDPI_READER_BIN` apontando para o `ndpiReader`.
3. **Rode**:
   ```bash
   python main.py
   ```

Saídas típicas no console:
- Quantos pacotes foram enviados ao nDPI (redução do volume)
- Limiar de score usado
- Estatística estimada de pacotes maliciosos via nDPI
- Métricas de recursos (CPU/Memory/Exec time)

Arquivos:
- `RESULTS_OUTPUT_DIR/prefiltered.pcap` — PCAP reduzido usado pelo nDPI

---

## 🧪 Pré‑Filtro (matriz de pesos)
- `prefilter_config.py` contém pesos iniciais conservadores (Telnet/RDP/SMB etc., padrões UDP de amplificação, flags SYN‑only/XMAS/NULL, tamanhos extremos).
- `TOP_QUANTILE` define a fração a ser escalada ao nDPI. **Recomendação inicial**: 0.30.
- Se possuir *ground‑truth*, avalie:
  - **Recall do pré‑filtro**: % de pacotes maliciosos que permanecem após o filtro
  - **Reduction ratio**: % de tráfego poupado do nDPI

---

## 🧭 Roadmap para Runtime (validação contínua)
> Não implementado ainda — apenas orientação para o futuro.
- **Micro‑batch** por tempo/volume (ex.: 1s ou 5k pacotes)
- **Janela deslizante** para estimar percentil de score on‑line
- **Geração de PCAPs reduzidos** por lote e execução do `ndpiReader` em cada lote
- Métricas de pipeline: pps, bytes/s, latência captura→nDPI, % redução

---

## 🧰 Requisitos
- Python 3.10+
- `ndpiReader` compilado e acessível em `NDPI_READER_BIN`
- Dependências Python (ver `requirements.txt`). Em alguns ambientes, a Scapy requer libpcap instalada.

---

## 🐞 Solução de Problemas
- **"ndpiReader: not found"** → verifique `NDPI_READER_BIN` e permissões de execução (`chmod +x`).
- **Permissões de captura ao vivo** (futuro) → geralmente requer `root`/`CAP_NET_RAW`.
- **WSL** → captura live é limitada; para testes com PCAP funciona normalmente.

---

## 📜 Licença
Projeto acadêmico, livre para uso educacional.
