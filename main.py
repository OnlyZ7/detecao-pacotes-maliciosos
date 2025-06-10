import time
import pandas as pd
from sklearn.metrics import accuracy_score, confusion_matrix
import psutil
import matplotlib.pyplot as plt
from scapy.all import rdpcap, IP, TCP, UDP
import subprocess
import json
import os

# === CONFIGURAÇÃO ===
pcap_path = "/home/arthur/projetos/pcaps/3-reduzido.pcap"
suricata_output_path = "/home/arthur/projetos/suricata_output"

# === FUNÇÃO DE EXTRAÇÃO ===
def load_pcap_features(pcap_path):
    print(f"[i] Lendo arquivo PCAP: {pcap_path}")
    packets = rdpcap(pcap_path)
    features = []
    ignored_count = 0

    for pkt in packets:
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
                    flags = pkt[TCP].flags
                elif UDP in pkt:
                    proto = 'UDP'
                    sport = pkt[UDP].sport
                    dport = pkt[UDP].dport

                features.append({
                    'src_ip': pkt[IP].src,
                    'dst_ip': pkt[IP].dst,
                    'sport': sport,
                    'dport': dport,
                    'protocol': proto,
                    'length': length,
                    'flags': str(flags)
                })
        except Exception as e:
            ignored_count += 1
            print(f"[!] Pacote ignorado: {e}")

    print(f"[✓] Total de pacotes processados: {len(features)}")
    print(f"[x] Total de pacotes ignorados: {ignored_count}")
    return pd.DataFrame(features)


# ========= Essa função é para base de validação de malwares ========
def load_labels_from_csv(features_df, csv_path):
    gt = pd.read_csv(csv_path)

    # Normaliza os nomes
    gt = gt.rename(columns={
        'Source IP': 'src_ip',
        'Destination IP': 'dst_ip',
        'Source Port': 'sport',
        'Destination Port': 'dport',
        'Protocol': 'protocol'
    })

    # Normaliza os valores
    gt['protocol'] = gt['protocol'].astype(str).str.upper()
    features_df['protocol'] = features_df['protocol'].astype(str).str.upper()

    # Marca se o pacote é ataque ou não
    gt['label'] = gt['Attack category'].apply(lambda x: 1 if x != 'Benign' else 0)

    # Faz o merge com inner join para manter só os pacotes encontrados no CSV
    merged = pd.merge(features_df, gt, on=['src_ip', 'dst_ip', 'sport', 'dport', 'protocol'], how='inner')

    # Retorna apenas os dados encontrados
    labels = merged['label'].astype(int)
    filtered_features = merged[features_df.columns]  # mantém as features na mesma ordem

    print(f"[✓] Labels carregados: {labels.sum()} maliciosos / {len(labels) - labels.sum()} benignos")
    print(f"[i] Total de amostras consideradas na validação: {len(labels)}")

    return filtered_features, labels

# === MODELO NDPI (via binário ndpiReader) ===
def load_ndpi_model():
    class NDPIModel:
        def predict(self, features):
            pcap_path = "/home/arthur/projetos/pcaps/3-reduzido.pcap"
            cmd = [
                "./nDPI/example/ndpiReader",
                "-i", pcap_path
            ]
            print("[●] Chamando ndpiReader...")
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, check=True, timeout=900)
                output = result.stdout
                print("[✓] nDPI finalizado")

                total_malicious_packets = 0
                target_categories = ["Unsafe", "Dangerous"]

                for line in output.splitlines():
                    line = line.strip()
                    for category in target_categories:
                        if line.startswith(category):
                            # Exemplo: "Unsafe              packets: 320992        bytes: ..."
                            try:
                                parts = line.split()
                                idx = parts.index("packets:")
                                pkt_count = int(parts[idx + 1])
                                total_malicious_packets += pkt_count
                            except (ValueError, IndexError):
                                continue

                threshold = total_malicious_packets
                predictions = [1 if i < threshold else 0 for i in range(len(features))]
                return predictions

            except subprocess.TimeoutExpired:
                print("[x] Tempo limite excedido para execução do ndpiReader (15 minutos).")
                return [0] * len(features)
            except subprocess.CalledProcessError as e:
                print("Erro ao executar ndpiReader:", e)
                return [0] * len(features)

    return NDPIModel()


# === MODELO SURICATA (usando alerts do eve.json) ===
def load_suricata_model():
    class SuricataModel:
        def predict(self, features):
            # Limpa saída anterior
            if os.path.exists(suricata_output_path):
                subprocess.run(["rm", "-rf", suricata_output_path])
            os.makedirs(suricata_output_path, exist_ok=True)

            subprocess.run(["suricata", "-r", pcap_path, "-l", suricata_output_path])

            alerts = [0] * len(features)
            try:
                with open(f"{suricata_output_path}/eve.json") as f:
                    alert_indices = set()
                    for line in f:
                        data = json.loads(line)
                        if data.get("event_type") == "alert":
                            alert_indices.add(len(alert_indices))  # Marca alertas
                    for i in list(alert_indices)[:len(features)]:
                        alerts[i] = 1
            except FileNotFoundError:
                pass
            return alerts
    return SuricataModel()

# === MODELO DE FILTRAGEM ESTÁTICA ===
def load_aoandon_model():
    class AoandonModel:
        def predict(self, features):
            return [1 if row['dport'] in [23, 3389] else 0 for _, row in features.iterrows()]
    return AoandonModel()

# === MONITORAMENTO DE SISTEMA ===
def track_system_resources(start_time):
    process = psutil.Process()
    memory_info = process.memory_info()
    cpu_percent = process.cpu_percent()
    memory_used = memory_info.rss / 1024 / 1024
    end_time = time.time()
    return {
        "cpu_usage": cpu_percent,
        "memory_usage": memory_used,
        "execution_time": end_time - start_time
    }

# === VALIDAÇÃO DOS MODELOS ===
def validate_model(model, test_data):
    start_time = time.time()
    predictions = model.predict(test_data['features'])
    accuracy = accuracy_score(test_data['labels'], predictions)
    cm = confusion_matrix(test_data['labels'], predictions)
    resources = track_system_resources(start_time)
    end_time = time.time()
    return accuracy, cm, resources, end_time - start_time

def validate_models(test_data):
    models = {
        "nDPI": load_ndpi_model(),
        "Suricata": load_suricata_model(),
        "Aoandon": load_aoandon_model()
    }

    results = {}

    print("[●] Iniciando validação com o modelo nDPI...")
    accuracy, cm, resources, exec_time = validate_model(models["nDPI"], test_data)
    results["nDPI"] = {
        "accuracy": accuracy,
        "confusion_matrix": cm,
        "cpu_usage": resources["cpu_usage"],
        "memory_usage": resources["memory_usage"],
        "execution_time": exec_time
    }
    print("[✓] Modelo nDPI finalizado")

    print("[●] Iniciando validação com o modelo Suricata...")
    accuracy, cm, resources, exec_time = validate_model(models["Suricata"], test_data)
    results["Suricata"] = {
        "accuracy": accuracy,
        "confusion_matrix": cm,
        "cpu_usage": resources["cpu_usage"],
        "memory_usage": resources["memory_usage"],
        "execution_time": exec_time
    }
    print("[✓] Modelo Suricata finalizado")

    print("[●] Iniciando validação com o modelo Aoandon...")
    accuracy, cm, resources, exec_time = validate_model(models["Aoandon"], test_data)
    results["Aoandon"] = {
        "accuracy": accuracy,
        "confusion_matrix": cm,
        "cpu_usage": resources["cpu_usage"],
        "memory_usage": resources["memory_usage"],
        "execution_time": exec_time
    }
    print("[✓] Modelo Aoandon finalizado")

    return results

# === EXECUÇÃO PRINCIPAL ===
features_df = load_pcap_features(pcap_path)
# Pra puxar a base da validação
ground_truth_csv_path = "/home/arthur/projetos/NUSW-NB15_GT.csv"
features_df, labels = load_labels_from_csv(features_df, ground_truth_csv_path)
test_data = {"features": features_df, "labels": labels}
validation_results = validate_models(test_data)

for model_name, result in validation_results.items():
    print(f"Modelo: {model_name}")
    print(f"Acurácia: {result['accuracy']}")
    print(f"Matriz de Confusão: \n{result['confusion_matrix']}")
    print(f"Uso de CPU: {result['cpu_usage']}%")
    print(f"Uso de Memória: {result['memory_usage']} MB")
    print(f"Tempo de Execução: {result['execution_time']} segundos")
    print("-" * 40)

# === GRÁFICOS ===
def plot_comparison(results):
    output_dir = "/home/arthur/projetos/resultados"
    os.makedirs(output_dir, exist_ok=True)

    models = list(results.keys())
    accuracies = [results[model]["accuracy"] for model in models]
    execution_times = [results[model]["execution_time"] for model in models]
    cpu_usages = [results[model]["cpu_usage"] for model in models]
    memory_usages = [results[model]["memory_usage"] for model in models]

    # Gráfico 1: Acurácia e Tempo de Execução
    fig, ax1 = plt.subplots(figsize=(10, 6))
    ax1.set_xlabel('Modelos')
    ax1.set_ylabel('Acurácia', color='tab:blue')
    ax1.bar(models, accuracies, color='tab:blue', alpha=0.6)
    ax1.tick_params(axis='y', labelcolor='tab:blue')

    ax2 = ax1.twinx()
    ax2.set_ylabel('Tempo de Execução (s)', color='tab:green')
    ax2.plot(models, execution_times, color='tab:green', marker='o')
    ax2.tick_params(axis='y', labelcolor='tab:green')

    plt.title('Comparação de Desempenho dos Modelos')
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, "desempenho_modelos.png"))
    plt.close(fig)

    # Gráfico 2: Uso de CPU e Memória
    fig2, ax3 = plt.subplots(figsize=(10, 6))
    ax3.set_xlabel('Modelos')
    ax3.set_ylabel('Uso de CPU (%)', color='tab:red')
    ax3.bar(models, cpu_usages, color='tab:red', alpha=0.6)
    ax3.tick_params(axis='y', labelcolor='tab:red')

    ax4 = ax3.twinx()
    ax4.set_ylabel('Uso de Memória (MB)', color='tab:purple')
    ax4.plot(models, memory_usages, color='tab:purple', marker='o')
    ax4.tick_params(axis='y', labelcolor='tab:purple')

    plt.title('Uso de Recursos dos Modelos')
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, "uso_recursos_modelos.png"))
    plt.close(fig2)

    print(f"[✓] Gráficos salvos em: {output_dir}")
