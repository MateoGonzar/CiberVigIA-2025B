import joblib
from scapy.all import sniff, IP, TCP, UDP
import datetime
import pandas as pd
from plyer import notification  # Para alertas desktop (pip install plyer)
import subprocess  # Para iptables
from flask import Flask, render_template_string, request  # Para dashboard simple (pip install flask)
from threading import Thread  # Para correr dashboard en background
import time
import numpy as np
import warnings

warnings.filterwarnings("ignore", category=UserWarning)

# Paso 1: Cargar modelo (de Fase 3)
model = joblib.load('models/modelo_rf_cic.pkl')  

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
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto = packet[IP].proto
        src_port = packet[TCP].sport if TCP in packet else packet[UDP].sport if UDP in packet else 0
        dst_port = packet[TCP].dport if TCP in packet else packet[UDP].dport if UDP in packet else 0
        key = (src_ip, dst_ip, src_port, dst_port, proto)

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

        # Predice (asume vector coincide con model input
        vector_df = pd.DataFrame([vector], columns=model_columns[:len(vector)]) 
        pred = model.predict(vector_df)[0]
        print(pred)
        if pred != 'BENIGN':
            alert_msg = f"[{timestamp}] Tráfico sospechoso: {src_ip} -> {dst_ip} | Puerto: {dst_port} | Predicción: {pred}"
            print(alert_msg)
            alerts.append(alert_msg)

            # Acción: Bloqueo, Notificación, Log
            subprocess.call(['sudo', 'iptables', '-A', 'INPUT', '-s', src_ip, '-j', 'DROP'])
            notification.notify(title='Alerta CiberVigIA', message=alert_msg, timeout=10)
            with open('vigia_logs.txt', 'a') as f:
                f.write(alert_msg + '\n')

# Paso para correr dashboard Flask en background
app = Flask(__name__)

@app.route('/')
def dashboard():
    # HTML con tabla, colores y refresh auto (cada 10s con JS)
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
            .refresh-btn { text-align: center; margin-top: 10px; }
        </style>
        <script>
            function refreshPage() { location.reload(); }
            setInterval(refreshPage, 10000);  // Refresh auto cada 10s
        </script>
    </head>
    <body>
        <h1>CiberVigIA Dashboard - Alertas en Tiempo Real</h1>
        <p>Monitor accesible para usuarios no técnicos. Muestra alertas de amenazas detectadas, con explicaciones simples. Actualización automática cada 10 segundos.</p>
        <table>
            <tr><th>Timestamp</th><th>IP Fuente -> IP Destino</th><th>Puerto</th><th>Predicción</th><th>Acción Tomada</th></tr>
            {% for alert in alerts %}
            <tr>
                <td>{{ alert.split('|')[0] }}</td>
                <td class="alert">{{ alert.split('|')[1] }}</td>
                <td>{{ alert.split('|')[2] }}</td>
                <td>{{ alert.split('|')[3] }}</td>
                <td>Bloqueo IP y Notificación Enviada</td>
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
    print("Prototipo corriendo. Dashboard en http://localhost:5000")
    sniff(prn=packet_callback, store=0)  # Captura indefinida (ctrl+C para parar)