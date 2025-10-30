import os
import platform

os.environ["KERAS_BACKEND"] = "torch"

# Detectar SO 
is_windows = platform.system() == "Windows"
is_macos = platform.system() == "Darwin"

if is_macos:
    os.environ["PYTORCH_ENABLE_MPS_FALLBACK"] = "1"
    print("Setting MPS fallback to CPU for unsupported ops.")

import sys
import requests
from joblib import load
from scapy.all import sniff, IP, TCP, UDP, get_if_addr, get_if_list, conf
import datetime
from plyer import notification  # Para alertas desktop (pip install plyer)
import subprocess  # Para iptables
from flask import Flask, jsonify, render_template_string, request # Para dashboard simple (pip install flask)
from threading import Thread  # Para correr dashboard en background
import time
import numpy as np
from keras.saving import load_model
import warnings
import logging
from logging.handlers import RotatingFileHandler
from ipaddress import ip_address, ip_network

# Warnings ignore
warnings.filterwarnings("ignore", category=UserWarning)

# Configurar logger
logger = logging.getLogger('CiberVigIA')
handler = RotatingFileHandler('vigia_logs.txt', maxBytes=10*1024*1024, backupCount=5)
logger.addHandler(handler)
logger.setLevel(logging.INFO)

# Filtro dinámico de IPs cloud
def update_cloud_ips():
    try:
        response = requests.get('https://ip-ranges.amazonaws.com/ip-ranges.json', timeout=5)
        aws_ips = [prefix['ip_prefix'] for prefix in response.json()['prefixes']]
        response = requests.get('https://www.cloudflare.com/ips-v4', timeout=5)
        cloudflare_ips = response.text.split('\n')
        response = requests.get('https://download.microsoft.com/download/7/1/d/71d86715-5596-4529-9b13-da13a5de5b63/ServiceTags_Public_20251020.json')  # Ajusta fecha/semana
        data = response.json()
        azure_ips = [prefix['properties']['addressPrefixes'][0] for prefix in data['values'] if 'AzureCloud' in prefix['id']]
        return aws_ips + cloudflare_ips + azure_ips
    except Exception as e:
        print(f"Error actualizando IPs cloud: {e}")
        return ['104.16.0.0/12', '172.64.0.0/13', '44.192.0.0/10', '52.182.0.0/16', '20.36.0.0/14']  # Fallback
    
cloud_ips = update_cloud_ips()
def is_cloud_ip(ip):
    return any(ip_address(ip) in ip_network(cidr) for cidr in cloud_ips)

# Checar reputacion
def check_ip_reputation(ip):
    api_key = '8763e1179e5c8697674cd8dbcaada81579d853f69ef265c1b6a14ba7811d91c688b93b3d10cd0752'
    url = f'https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90'
    headers = {'Key': api_key, 'Accept': 'application/json'}
    response = requests.get(url, headers=headers)
    data = response.json()
    score = data['data']['abuseConfidenceScore']
    if score > 25:
        print(f"IP {ip} tiene score de abuso {score}")
        return True
    with open('whitelist.txt', 'a') as f:
        f.write(ip + '\n')
    return False

def get_active_interface():
    print("Interfaces disponibles:", get_if_list())
    return input("Selecciona interfaz (e.g., en0): ")

# Mensaje inicial para usuarios no técnicos
print("Bienvenido a CiberVigIA AI - Monitor de Red para Hogares y PyMEs")
print("1. Asegúrese de correr con sudo (Linux) o admin (Windows).")
print("2. Dashboard en http://localhost:5000 (abra en browser).")
print("3. Alertas automáticas para amenazas detectadas.")

# Auto-detección de interfaz
iface = get_active_interface()
ip = get_if_addr(conf.iface)

print(f"Interfaz activa: {iface}")
print(f"Dashboard: http://localhost:5000 (desde este equipo)")
print(f"Desde otros dispositivos: http://{ip}:5000")
                                                               
# Paso 1: Cargar modelo (de Fase 3)
# model = load('models/modelo_rf_cic.pkl')  - RF
def get_resource_path(relative_path):
    # Devuelve la ruta absoluta al recurso en el paquete .app o en el entorno de desarrollo.
    if hasattr(sys, '_MEIPASS'):
        # En el paquete .app, los archivos de datos están en Contents/Resources
        return os.path.join(sys._MEIPASS, relative_path)
    return os.path.join(os.path.abspath("."), relative_path)

# Carga los archivos utilizando la función get_resource_path
model_path = get_resource_path('models/modelo_lstm_nadam_cic.keras')
scaler_path = get_resource_path('models/scaler_cic.pkl')
le_path = get_resource_path('models/label_encoder_cic.pkl')

model = load_model(model_path)
scaler = load(scaler_path)
le = load(le_path)

# Lista de puertos sospechosos (de análisis previo)
def is_suspicious_port(dst_port, protocol):
    suspicious_ports = {
        'TCP': [
            20, 21, 22, 23, 25, 80, 110, 135, 137, 138, 139, 143,
            443, 445, 1433, 2049, 3306, 3389, 4444, 5432, 5900,
            8000, 8080, 8443, 9100, 10000
        ],
        'UDP': [
            7, 19, 53, 69, 123, 161, 162, 1900, 514, 520, 502
        ] + list(range(1024, 5000)) + list(range(49152, 65536))
    }

    return dst_port in suspicious_ports.get(protocol.upper(), [])

# Diccionario para trackear flujos y features (para todas las capturables de CIC)
flows = {}  # key: (src_ip, dst_ip, src_port, dst_port, proto), value: dict con todas las stats
alerts = []  # Lista para dashboard (timestamp, ip, puerto, predicción, features vector)

def packet_callback(packet):
    if not (packet.haslayer(IP) and (packet.haslayer(TCP) or packet.haslayer(UDP))):
        return

    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto = packet[IP].proto
        src_port = packet[TCP].sport if TCP in packet else packet[UDP].sport if UDP in packet else 0
        dst_port = packet[TCP].dport if TCP in packet else packet[UDP].dport if UDP in packet else 0
        key = (src_ip, dst_ip, src_port, dst_port, proto)

        # Cargar whitelist
        whitelist = []
        if os.path.exists('whitelist.txt'):
            with open('whitelist.txt', 'r') as f:
                whitelist = f.read().splitlines()

        if any([
            src_ip.startswith('127.'), dst_ip.startswith('127.'),
            src_ip.startswith('172.'), dst_ip.startswith('172.'),
            src_ip == dst_ip  # mismo host
        ]) or is_cloud_ip(src_ip) or is_cloud_ip(dst_ip) or src_ip in whitelist or dst_ip in whitelist:
            return

        current_time = time.time()
        packet_len = len(packet)
        fwd = src_ip < dst_ip  # Simplificado para dirección (ajusta si necesitas flow bidireccional preciso)

        if key not in flows:
            flows[key] = {
                'start_time': current_time,
                'last_time': current_time,
                'fwd_packets': 0,
                'bwd_packets': 0,
                'fwd_bytes': 0,
                'bwd_bytes': 0,
                'fwd_lengths': [],
                'bwd_lengths': [],
                'flow_iat': [],
                'fwd_iat': [],
                'bwd_iat': [],
                'fin_count': 0,
                'syn_count': 0,
                'rst_count': 0,
                'psh_count': 0,
                'ack_count': 0,
                'urg_count': 0,
                'cwe_count': 0,
                'ece_count': 0,
                'init_win_fwd': packet[TCP].window if TCP in packet and fwd else 0,
                'init_win_bwd': packet[TCP].window if TCP in packet and not fwd else 0,
                'act_data_pkt_fwd': 0,
                'min_seg_size_fwd': 0,  # Ajusta con seq/ack diffs si disponible
                'active_times': [],
                'idle_times': [],
                'last_packet_time': current_time,
                'is_idle': False,
                'current_active_start': None
            }

        # Actualiza flujo con todas las features capturables (parciales completas)
        flows[key]['last_time'] = current_time
        duration = current_time - flows[key]['start_time']

        # IAT (inter-arrival time)
        if flows[key]['flow_iat']:
            iat = current_time - flows[key]['last_packet_time']
            flows[key]['flow_iat'].append(iat)
            if fwd:
                flows[key]['fwd_iat'].append(iat)
            else:
                flows[key]['bwd_iat'].append(iat)
        flows[key]['last_packet_time'] = current_time

        # Packets y Bytes
        if fwd:
            flows[key]['fwd_packets'] += 1
            flows[key]['fwd_bytes'] += packet_len
            flows[key]['fwd_lengths'].append(packet_len)
            if len(packet.payload) > 0:
                flows[key]['act_data_pkt_fwd'] += 1
        else:
            flows[key]['bwd_packets'] += 1
            flows[key]['bwd_bytes'] += packet_len
            flows[key]['bwd_lengths'].append(packet_len)

        # Flags (si TCP)
        if TCP in packet:
            flags = str(packet[TCP].flags)
            if 'F' in flags: flows[key]['fin_count'] += 1
            if 'S' in flags: flows[key]['syn_count'] += 1
            if 'R' in flags: flows[key]['rst_count'] += 1
            if 'P' in flags: flows[key]['psh_count'] += 1
            if 'A' in flags: flows[key]['ack_count'] += 1
            if 'U' in flags: flows[key]['urg_count'] += 1
            if 'C' in flags: flows[key]['cwe_count'] += 1  # CWE si 'C'
            if 'E' in flags: flows[key]['ece_count'] += 1

        # Active/Idle (simplificado: idle si iat > threshold, e.g., 1 sec)
        threshold_idle = 1.0
        if iat > threshold_idle if 'iat' in locals() else False:
            if flows[key]['is_idle']:
                # Update idle
                idle_duration = iat
                flows[key]['idle_times'].append(idle_duration)
            else:
                # End active, start idle
                if flows[key]['current_active_start']:
                    active_duration = current_time - flows[key]['current_active_start']
                    flows[key]['active_times'].append(active_duration)
                flows[key]['is_idle'] = True
        else:
            if flows[key]['is_idle']:
                # End idle, start active
                flows[key]['is_idle'] = False
                flows[key]['current_active_start'] = current_time
            elif not flows[key]['current_active_start']:
                flows[key]['current_active_start'] = flows[key]['start_time']

        # Chequeo suspicious ports
        if packet.haslayer('TCP'):
            if is_suspicious_port(dst_port, 'TCP'):
                print(f"[{timestamp}] Pre-alerta: Puerto sospechoso detectado ({dst_port})")
        if packet.haslayer('UDP'):
            if is_suspicious_port(dst_port, 'UDP'):
                print(f"[{timestamp}] Pre-alerta: Puerto sospechoso detectado ({dst_port})")

        # Construir vector completo con todas las features capturables de CIC (78; ajusta orden a tu modelo entrenado)
        # Nota: Calcula stats on-the-fly; para parciales, usa 0 o aprox si no completo
        flow_iat_mean = np.mean(flows[key]['flow_iat']) if flows[key]['flow_iat'] else 0
        flow_iat_std = np.std(flows[key]['flow_iat']) if flows[key]['flow_iat'] else 0
        flow_iat_max = max(flows[key]['flow_iat']) if flows[key]['flow_iat'] else 0
        flow_iat_min = min(flows[key]['flow_iat']) if flows[key]['flow_iat'] else 0
        fwd_iat_total = sum(flows[key]['fwd_iat']) if flows[key]['fwd_iat'] else 0
        fwd_iat_mean = np.mean(flows[key]['fwd_iat']) if flows[key]['fwd_iat'] else 0
        fwd_iat_std = np.std(flows[key]['fwd_iat']) if flows[key]['fwd_iat'] else 0
        fwd_iat_max = max(flows[key]['fwd_iat']) if flows[key]['fwd_iat'] else 0
        fwd_iat_min = min(flows[key]['fwd_iat']) if flows[key]['fwd_iat'] else 0
        bwd_iat_total = sum(flows[key]['bwd_iat']) if flows[key]['bwd_iat'] else 0
        bwd_iat_mean = np.mean(flows[key]['bwd_iat']) if flows[key]['bwd_iat'] else 0
        bwd_iat_std = np.std(flows[key]['bwd_iat']) if flows[key]['bwd_iat'] else 0
        bwd_iat_max = max(flows[key]['bwd_iat']) if flows[key]['bwd_iat'] else 0
        bwd_iat_min = min(flows[key]['bwd_iat']) if flows[key]['bwd_iat'] else 0
        fwd_psh_flags = flows[key]['psh_count'] if 'fwd' else 0  # Simplificado
        bwd_psh_flags = flows[key]['psh_count'] if not 'fwd' else 0
        fwd_urg_flags = flows[key]['urg_count'] if 'fwd' else 0
        bwd_urg_flags = flows[key]['urg_count'] if not 'fwd' else 0
        fwd_header_length = flows[key]['fwd_packets'] * 40  # Aprox TCP/IP header (20 IP + 20 TCP)
        bwd_header_length = flows[key]['bwd_packets'] * 40
        fwd_packets_s = flows[key]['fwd_packets'] / duration if duration > 0 else 0
        bwd_packets_s = flows[key]['bwd_packets'] / duration if duration > 0 else 0
        min_packet_length = min(flows[key]['fwd_lengths'] + flows[key]['bwd_lengths']) if flows[key]['fwd_lengths'] or flows[key]['bwd_lengths'] else 0
        max_packet_length = max(flows[key]['fwd_lengths'] + flows[key]['bwd_lengths']) if flows[key]['fwd_lengths'] or flows[key]['bwd_lengths'] else 0
        packet_length_mean = np.mean(flows[key]['fwd_lengths'] + flows[key]['bwd_lengths']) if flows[key]['fwd_lengths'] or flows[key]['bwd_lengths'] else 0
        packet_length_std = np.std(flows[key]['fwd_lengths'] + flows[key]['bwd_lengths']) if flows[key]['fwd_lengths'] or flows[key]['bwd_lengths'] else 0
        packet_length_variance = np.var(flows[key]['fwd_lengths'] + flows[key]['bwd_lengths']) if flows[key]['fwd_lengths'] or flows[key]['bwd_lengths'] else 0
        fin_flag_count = flows[key]['fin_count']
        syn_flag_count = flows[key]['syn_count']
        rst_flag_count = flows[key]['rst_count']
        psh_flag_count = flows[key]['psh_count']
        ack_flag_count = flows[key]['ack_count']
        urg_flag_count = flows[key]['urg_count']
        cwe_flag_count = flows[key]['cwe_count']
        ece_flag_count = flows[key]['ece_count']
        down_up_ratio = flows[key]['bwd_bytes'] / flows[key]['fwd_bytes'] if flows[key]['fwd_bytes'] > 0 else 0
        average_packet_size = (flows[key]['fwd_bytes'] + flows[key]['bwd_bytes']) / (flows[key]['fwd_packets'] + flows[key]['bwd_packets']) if (flows[key]['fwd_packets'] + flows[key]['bwd_packets']) > 0 else 0
        avg_fwd_segment_size = flows[key]['fwd_bytes'] / flows[key]['fwd_packets'] if flows[key]['fwd_packets'] > 0 else 0
        avg_bwd_segment_size = flows[key]['bwd_bytes'] / flows[key]['bwd_packets'] if flows[key]['bwd_packets'] > 0 else 0
        fwd_header_length_1 = fwd_header_length  # Duplicado en CIC
        fwd_avg_bytes_bulk = 0  # Parcial
        fwd_avg_packets_bulk = 0
        fwd_avg_bulk_rate = 0
        bwd_avg_bytes_bulk = 0
        bwd_avg_packets_bulk = 0
        bwd_avg_bulk_rate = 0
        subflow_fwd_packets = flows[key]['fwd_packets']  # Simplificado
        subflow_fwd_bytes = flows[key]['fwd_bytes']
        subflow_bwd_packets = flows[key]['bwd_packets']
        subflow_bwd_bytes = flows[key]['bwd_bytes']
        init_win_bytes_forward = flows[key]['init_win_fwd']
        init_win_bytes_backward = flows[key]['init_win_bwd']
        act_data_pkt_fwd = flows[key]['act_data_pkt_fwd']
        min_seg_size_forward = flows[key]['min_seg_size_fwd']  # Parcial
        active_mean = np.mean(flows[key]['active_times']) if flows[key]['active_times'] else 0
        active_std = np.std(flows[key]['active_times']) if flows[key]['active_times'] else 0
        active_max = max(flows[key]['active_times']) if flows[key]['active_times'] else 0
        active_min = min(flows[key]['active_times']) if flows[key]['active_times'] else 0
        idle_mean = np.mean(flows[key]['idle_times']) if flows[key]['idle_times'] else 0
        idle_std = np.std(flows[key]['idle_times']) if flows[key]['idle_times'] else 0
        idle_max = max(flows[key]['idle_times']) if flows[key]['idle_times'] else 0
        idle_min = min(flows[key]['idle_times']) if flows[key]['idle_times'] else 0

        # Vector completo
        model_columns = [' Destination Port', ' Flow Duration', ' Total Fwd Packets', ' Total Backward Packets', 'Total Length of Fwd Packets', ' Total Length of Bwd Packets', ' Fwd Packet Length Max', ' Fwd Packet Length Min', ' Fwd Packet Length Mean', ' Fwd Packet Length Std', 'Bwd Packet Length Max', ' Bwd Packet Length Min', ' Bwd Packet Length Mean', ' Bwd Packet Length Std', 'Flow Bytes/s', ' Flow Packets/s', ' Flow IAT Mean', ' Flow IAT Std', ' Flow IAT Max', ' Flow IAT Min', 'Fwd IAT Total', ' Fwd IAT Mean', ' Fwd IAT Std', ' Fwd IAT Max', ' Fwd IAT Min', 'Bwd IAT Total', ' Bwd IAT Mean', ' Bwd IAT Std', ' Bwd IAT Max', ' Bwd IAT Min', 'Fwd PSH Flags', ' Bwd PSH Flags', ' Fwd URG Flags', ' Bwd URG Flags', ' Fwd Header Length', ' Bwd Header Length', 'Fwd Packets/s', ' Bwd Packets/s', ' Min Packet Length', ' Max Packet Length', ' Packet Length Mean', ' Packet Length Std', ' Packet Length Variance', 'FIN Flag Count', ' SYN Flag Count', ' RST Flag Count', ' PSH Flag Count', ' ACK Flag Count', ' URG Flag Count', ' CWE Flag Count', ' ECE Flag Count', ' Down/Up Ratio', ' Average Packet Size', ' Avg Fwd Segment Size', ' Avg Bwd Segment Size', ' Fwd Header Length.1', 'Fwd Avg Bytes/Bulk', ' Fwd Avg Packets/Bulk', ' Fwd Avg Bulk Rate', ' Bwd Avg Bytes/Bulk', ' Bwd Avg Packets/Bulk', 'Bwd Avg Bulk Rate', 'Subflow Fwd Packets', ' Subflow Fwd Bytes', ' Subflow Bwd Packets', ' Subflow Bwd Bytes', 'Init_Win_bytes_forward', ' Init_Win_bytes_backward', ' act_data_pkt_fwd', ' min_seg_size_forward', 'Active Mean', ' Active Std', ' Active Max', ' Active Min', 'Idle Mean', ' Idle Std', ' Idle Max', ' Idle Min']
        model_columns = [col.lstrip() for col in model_columns]
        vector = [
            dst_port, duration, flows[key]['fwd_packets'], flows[key]['bwd_packets'], flows[key]['fwd_bytes'], flows[key]['bwd_bytes'],
            max(flows[key]['fwd_lengths']) if flows[key]['fwd_lengths'] else 0, min(flows[key]['fwd_lengths']) if flows[key]['fwd_lengths'] else 0,
            np.mean(flows[key]['fwd_lengths']) if flows[key]['fwd_lengths'] else 0, np.std(flows[key]['fwd_lengths']) if flows[key]['fwd_lengths'] else 0,
            max(flows[key]['bwd_lengths']) if flows[key]['bwd_lengths'] else 0, min(flows[key]['bwd_lengths']) if flows[key]['bwd_lengths'] else 0,
            np.mean(flows[key]['bwd_lengths']) if flows[key]['bwd_lengths'] else 0, np.std(flows[key]['bwd_lengths']) if flows[key]['bwd_lengths'] else 0,
            (flows[key]['fwd_bytes'] + flows[key]['bwd_bytes']) / duration if duration > 0 else 0, (flows[key]['fwd_packets'] + flows[key]['bwd_packets']) / duration if duration > 0 else 0,
            flow_iat_mean, flow_iat_std, flow_iat_max, flow_iat_min, fwd_iat_total, fwd_iat_mean, fwd_iat_std, fwd_iat_max, fwd_iat_min,
            bwd_iat_total, bwd_iat_mean, bwd_iat_std, bwd_iat_max, bwd_iat_min, fwd_psh_flags, bwd_psh_flags, fwd_urg_flags, bwd_urg_flags,
            fwd_header_length, bwd_header_length, fwd_packets_s, bwd_packets_s, min_packet_length, max_packet_length, packet_length_mean,
            packet_length_std, packet_length_variance, fin_flag_count, syn_flag_count, rst_flag_count, psh_flag_count, ack_flag_count,
            urg_flag_count, cwe_flag_count, ece_flag_count, down_up_ratio, average_packet_size, avg_fwd_segment_size, avg_bwd_segment_size,
            fwd_header_length_1, fwd_avg_bytes_bulk, fwd_avg_packets_bulk, fwd_avg_bulk_rate, bwd_avg_bytes_bulk, bwd_avg_packets_bulk,
            bwd_avg_bulk_rate, subflow_fwd_packets, subflow_fwd_bytes, subflow_bwd_packets, subflow_bwd_bytes, init_win_bytes_forward,
            init_win_bytes_backward, act_data_pkt_fwd, min_seg_size_forward, active_mean, active_std, active_max, active_min,
            idle_mean, idle_std, idle_max, idle_min
        ]

        try:
            # Escalar vector
            vector_scaled = scaler.transform([vector])
            vector_reshaped = np.array(vector_scaled).reshape(1, 1, len(vector))

            # Predice
            pred_probs = model.predict(vector_reshaped, verbose=0)
            pred = le.inverse_transform([np.argmax(pred_probs, axis=1)[0]])[0]
        except Exception as e:
            print(f"Error en predicción: {e}")
            return
        
        omit = False

        if pred != 'BENIGN':

            if dst_port == 80 or dst_port == 443:
                alert_msg = f"Tráfico sospechoso: {src_ip} -> {dst_ip} | Puerto: {dst_port} | Buscando reputación..."
                print(alert_msg)
                if src_ip == ip:
                    reputation = check_ip_reputation(dst_ip)
                    print(reputation)
                    if reputation is False:
                        omit = True
                else:
                    reputation = check_ip_reputation(src_ip)
                    print(reputation)
                    if reputation is False:
                        omit = True

            if not omit:
                alert_msg = f"[{timestamp}] Tráfico sospechoso: {src_ip} -> {dst_ip} | Puerto: {dst_port} | Predicción: {pred}"
                alerts.append({'timestamp': timestamp, 'ip': f"{src_ip} -> {dst_ip}", 'port': dst_port, 'pred': pred, 'action': 'Bloqueo y Notificación' if src_ip != ip else 'Notificación'})

                # Solo bloquear si la IP de origen no es la IP local
                if src_ip != ip:
                    print(f"Bloqueando tráfico de la IP maliciosa: {src_ip}")
                    # Acción: Bloqueo, Notificación, Log
                    if platform.system() == 'Darwin':  # macOS
                        subprocess.run(
                            ['sudo', 'pfctl', '-f', '-', '-E'],
                            input=f"block in from {src_ip} to any".encode(),
                        )
                    elif platform.system() == 'Windows':
                        # Bloqueo con netsh en Windows
                        subprocess.run(['netsh', 'advfirewall', 'firewall', 'add', 'rule', 'name="CiberVigIA Block"', 'dir=in', 'action=block', 'remoteip=' + src_ip])
                    else:
                        # Bloqueo con iptables en Linux
                        subprocess.run(['sudo', 'iptables', '-A', 'INPUT', '-s', src_ip, '-j', 'DROP'])
                    
                    notification.notify(title='Alerta CiberVigIA', message=alert_msg, timeout=10)

                else:
                    # Aquí se registra que se detectó un paquete malicioso de la IP propia,
                    # pero no se bloqueó. Esto podría indicar un malware en tu propia máquina.
                    print(f"Alerta: Tráfico sospechoso detectado desde tu IP ({ip}). Revisa posibles apps maliciosas.")

                    notification.notify(title='Alerta CiberVigIA', message=f"Se detectó tráfico malicioso desde tu propia IP: {ip}", timeout=10)
                
                logger.info(alert_msg)


# Paso para correr dashboard Flask en background
app = Flask(__name__)

@app.route('/api/alerts')
def api_alerts():
    # Asume alerts es lista de dicts (actualiza tu alerts a [{ 'timestamp': ..., 'ip': ..., 'port': ..., 'pred': ..., 'action': ... }])
    return jsonify(alerts)

@app.route('/whitelist', methods=['POST'])
def whitelist_ip():
    ip = request.form['ip']
    with open('whitelist.txt', 'a') as f:
        f.write(ip + '\n')
    return jsonify({'status': f'IP {ip} añadida a whitelist'})

@app.route('/')
def dashboard():
    html = """
    <html>
    <head>
        <title>CiberVigIA Dashboard</title>
        <style>
            body { font-family: Arial, sans-serif; background-color: #f4f4f4; padding: 20px; }
            h1 { text-align: center; color: #333; }
            table { width: 100%; border-collapse: collapse; margin-top: 20px; }
            th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
            th { background-color: #4CAF50; color: white; }
            tr:nth-child(even) { background-color: #f2f2f2; }
            .alert { color: red; font-weight: bold; }
            .refresh-btn, .whitelist-form { text-align: center; margin-top: 10px; }
        </style>
        <script>
            function refreshPage() { location.reload(); }
            setInterval(refreshPage, 10000);
        </script>
    </head>
    <body>
        <h1>CiberVigIA Dashboard - Alertas en Tiempo Real</h1>
        <p>Monitor accesible para usuarios no técnicos. Muestra alertas de amenazas detectadas. Actualización cada 10 segundos.</p>
        <form class="whitelist-form" action="/whitelist" method="post">
            <input type="text" name="ip" placeholder="IP a confiar (e.g., 104.18.18.125)">
            <button type="submit">Añadir a Whitelist</button>
        </form>
        <table>
            <tr><th>Timestamp</th><th>IP Fuente -> IP Destino</th><th>Puerto</th><th>Predicción</th><th>Acción Tomada</th></tr>
            {% for alert in alerts %}
            <tr>
                <td>{{ alert.timestamp }}</td>
                <td class="alert">{{ alert.ip }}</td>
                <td>{{ alert.port }}</td>
                <td>{{ alert.pred }}</td>
                <td>{{ alert.action }}</td>
            </tr>
            {% endfor %}
        </table>
        <div class="refresh-btn">
            <button onclick="refreshPage()">Refresh Manual</button>
        </div>
    </body>
    </html>
    """
    return render_template_string(html, alerts=alerts)

def run_dashboard():
    app.run(host='0.0.0.0', port=5000)

# Main: Captura en tiempo real (sudo requerido)
if __name__ == "__main__":
    Thread(target=run_dashboard).start()  # Dashboard en background
    print("Prototipo corriendo.")
    sniff(iface=iface, filter="tcp or udp", prn=packet_callback, store=0)