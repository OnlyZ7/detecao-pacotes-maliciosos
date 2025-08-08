# portas comumente alvo/uso arriscado
PORT_WEIGHTS = {
    23: 3,    # Telnet
    2323: 3,  # Telnet alternativo (IoT)
    3389: 3,  # RDP
    445: 3,   # SMB
    5900: 2,  # VNC
    21: 2,    # FTP
    22: 1,    # SSH
    1433: 2,  # MS-SQL
    5060: 2,  # SIP
    8080: 1,
    8888: 1
}

# portas típicas de amplificação UDP
UDP_AMP_PORTS = {19, 53, 123, 1900, 500, 11211}

# pesos por flags TCP (interpretação simples)
FLAGS_WEIGHTS = {
    'SYN_ONLY': 2.0,     # S sem A
    'XMAS': 3.0,         # FPU
    'NULL': 3.0          # sem flags
}

# pesos por protocolo
PROTO_BASE = {'TCP': 0.0, 'UDP': 0.2}

# pesos por tamanho
LENGTH_SMALL = 60
LENGTH_LARGE = 1200
LEN_WEIGHT_SMALL = 0.5
LEN_WEIGHT_LARGE = 0.5