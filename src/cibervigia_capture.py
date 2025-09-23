from collections import defaultdict
from scapy.all import sniff, wrpcap, IP, TCP, UDP
import datetime  # Para timestamps en logs
import time

suspicious_ports = {
    'TCP': [20, 21, 22, 23, 25, 80, 110, 135, 137, 138, 139, 143, 443, 445, 1433, 2049, 3306, 3389, 4444, 5432, 5900, 8000, 8080, 8443, 9100, 10000],
    'UDP': [7, 19, 53, 69, 123, 161, 162, 1900, 514, 520, 502] + list(range(1024, 5000)) + list(range(49152, 65536))
}

attempts = defaultdict(list)

# Función callback para procesar cada paquete en tiempo real
def packet_callback(packet):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].proto  # 6 para TCP, 17 para UDP, etc.
        suspicious = False
        port = None

        if TCP in packet:
            port = packet[TCP].dport
            if port in suspicious_ports['TCP']:
                suspicious = True
        elif UDP in packet:
            port = packet[UDP].dport
            if port in suspicious_ports['UDP']:
                suspicious = True

        if suspicious:
            print(f"[{timestamp}] ALERTA: Tráfico sospechoso en puerto {port} - {src_ip} -> {dst_ip}")
            current_time = time.time()
            attempts[src_ip].append(current_time)
            # Limpiar intentos viejos (>60 seg)
            attempts[src_ip] = [t for t in attempts[src_ip] if current_time - t < 60]
            if len(attempts[src_ip]) > 5:  # Umbral para múltiples intentos
                print(f"ALERTA AVANZADA: Brute force sospechoso de {src_ip} en puerto {port} ({len(attempts[src_ip])} intentos en 60s)")

        # Loggear o imprimir en consola
        print(f"[{timestamp}] SRC: {src_ip} -> DST: {dst_ip} | Protocolo: {protocol} | Puerto: {port}")

    return packet  # Retornar para guardar

# Captura en tiempo real: count=100 para 100 paquetes; iface se va a necesitar
# Nota: Requiere privilegios de admin (sudo en Linux/Mac)
packets = sniff(prn=packet_callback, store=1, count=100)  # store=1 para guardar paquetes

# Guardar capturados en archivo .pcap
wrpcap('captura_trafico.pcap', packets)
print("Captura completada y guardada en 'captura_trafico.pcap'")