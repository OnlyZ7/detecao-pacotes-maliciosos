import subprocess, time, psutil
from config import NDPI_READER_BIN, NDPI_TIMEOUT_SECONDS, PCAP_PATH

class NDPIProcessor:
    def __init__(self, pcap_path=PCAP_PATH, timeout=NDPI_TIMEOUT_SECONDS):
        self.pcap_path = pcap_path
        self.timeout = timeout

    def run_ndpi(self):
        cmd = [NDPI_READER_BIN, '-i', self.pcap_path]
        start = time.time()
        proc = psutil.Process()
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, check=True, timeout=self.timeout)
            metrics = {
                'cpu_usage': proc.cpu_percent(),
                'memory_usage': proc.memory_info().rss / 1024**2,
                'execution_time': time.time() - start
            }
            return res.stdout, metrics
        except subprocess.TimeoutExpired:
            return "", {'cpu_usage': 0, 'memory_usage': 0, 'execution_time': self.timeout}

    def parse_output(self, output: str) -> int:
        total = 0
        for line in output.splitlines():
            line = line.strip()
            for cat in ("Unsafe", "Dangerous"):
                if line.startswith(cat) and 'packets:' in line:
                    parts = line.split()
                    try:
                        idx = parts.index('packets:')
                        total += int(parts[idx+1])
                    except Exception:
                        pass
        return total

    def classify_packets(self, num_packets: int, threshold: int):
        return [1 if i < threshold else 0 for i in range(num_packets)]
