import threading
import random
import os
import csv
from scapy.all import *
from scapy.layers.dot11 import *
from datetime import datetime
from neo4j import GraphDatabase

# Conexión a Neo4j
uri = "bolt://localhost:7687"
username = "neo4j"
password = "secretgraph"
driver = GraphDatabase.driver(uri, auth=(username, password), database="neo4j")

# Crear la carpeta de logs si no existe
log_base_dir = "logs/"
os.makedirs(log_base_dir, exist_ok=True)

# Obtener la fecha actual para el nombre de la subcarpeta
log_sub_dir = os.path.join(log_base_dir, datetime.now().strftime("%Y-%m-%d"))
os.makedirs(log_sub_dir, exist_ok=True)

# Obtener la fecha y hora actuales para el nombre del archivo de log
log_filename = os.path.join(log_sub_dir, datetime.now().strftime("%Y-%m-%d_%H-%M-%S") + ".log")
csv_filename = "devices.csv"

def guardar_log(entry):
    # Obtener la fecha y hora actuales con segundos y décimas de segundo
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    log_entry = f"{timestamp} | {entry}"
    # Escribir en el archivo de log
    with open(log_filename, 'a') as log_file:
        log_file.write(log_entry + '\n')


# Función para guardar los datos en el CSV
def guardar_csv(mac_address, ssid, contador, rssi):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(csv_filename, mode='a', newline='') as csv_file:
        writer = csv.writer(csv_file)
        if csv_file.tell() == 0:
            writer.writerow(["Timestamp", "MAC", "SSID", "RSSI", "Contador"])
        writer.writerow([timestamp, mac_address, ssid, rssi, contador])





def add_device_to_neo4j(mac_address, ssid, rssi):
    try:
        with driver.session() as session:
            contador = session.execute_write(create_or_update_relationship, mac_address, ssid, rssi)
            return contador
    except Exception as e:
        print(f"Error al crear el dispositivo en neo4j: {e}")


def create_or_update_relationship(tx, mac_address, ssid, rssi):
    query = (
        "MERGE (m:MAC {mac: $mac_address}) "
        "MERGE (s:SSID {name: $ssid}) "
        "MERGE (m)-[r:BELONGS_TO]->(s) "
        "ON CREATE SET r.contador = 1, r.rssi = $rssi, r.last_updated = $timestamp "
        "ON MATCH SET r.contador = r.contador + 1, r.rssi = $rssi, r.last_updated = $timestamp "
        "RETURN r.contador as contador"
    )
    result = tx.run(query, mac_address=mac_address, ssid=ssid, rssi=rssi, timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    record = result.single()
    if record:
        return record["contador"]
    else:
        return 1


# Función para generar una dirección MAC aleatoria
def random_mac():
    return "02:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}".format(
        random.randint(0x00, 0x7f),
        random.randint(0x00, 0xff),
        random.randint(0x00, 0xff),
        random.randint(0x00, 0xff),
        random.randint(0x00, 0xff)
    )

# MAC del punto de acceso aleatoria
ap_mac = random_mac()

# Lista de threads de beacons
beacon_threads = []

# Función para manejar los paquetes de Probe Request
def handle_probe_request(pkt):
    if pkt.haslayer(Dot11ProbeReq):
        ssid = pkt.getlayer(Dot11ProbeReq).info.decode('utf-8')
        if ssid == "":
            log_entry = "Recibido Probe Request con SSID vacío, ignorando."
            guardar_log(log_entry)
            return
        mac_address = pkt.addr2
        rssi = pkt.dBm_AntSignal

        log_entry = f"Probe Request detectado: SSID={ssid}, MAC={mac_address}, RSSI={rssi} dBm"
        guardar_log(log_entry)
        contador = add_device_to_neo4j(mac_address, ssid, rssi)
        
        guardar_csv(mac_address, ssid, contador, rssi)
        print(f"Dispositivo detectado: SSID={ssid}, MAC={mac_address}, RSSI={rssi} dBm")
        
        # Iniciar un thread para enviar beacons y detener el anterior si existe
        stop_all_beacons()
        beacon_thread = threading.Thread(target=send_beacon_wpa2, args=(ssid, 6))
        beacon_threads.append(beacon_thread)
        beacon_thread.start()

        # Enviar probe response
        send_probe_response(ssid, mac_address)
        stop_all_beacons()  # Detener el envío de beacons después de enviar probe response


def send_beacon_wpa2(ssid, channel):
    # Crear el paquete básico de beacon
    beacon = (
        RadioTap() /
        Dot11(
            type=0,
            subtype=8,
            addr1="ff:ff:ff:ff:ff:ff",  # Broadcast
            addr2=ap_mac,               # Dirección de origen (MAC del punto de acceso)
            addr3=ap_mac                # Dirección del BSSID
        ) /
        Dot11Beacon(cap='ESS+privacy') /  # ESS indica red infraestructural, 'privacy' para cifrado
        Dot11Elt(ID='SSID', info=ssid) /
        Dot11Elt(ID='Rates', info=b'\x82\x84\x8b\x96\x24\x30\x48\x6c') /
        Dot11Elt(ID='DSset', info=chr(channel).encode())
    )

    # TODO Probar Red abierta

    # Agregar información sobre WPA2/RSN
    rsn_info = Dot11Elt(
        ID='RSNinfo',
        info=(
            b'\x01\x00'  # Version (WPA2)
            b'\x00\x0f\xac\x02'  # Grupo Cipher Suite (CCMP)
            b'\x02\x00'  # Número de pares de Cipher Suites (2)
            b'\x00\x0f\xac\x04'  # Unicast Cipher Suite (CCMP)
            b'\x00\x0f\xac\x02'  # Unicast Cipher Suite (TKIP)
            b'\x01\x00'  # Número de Authentication Suites (1)
            b'\x00\x0f\xac\x02'  # Authentication Suite (PSK)
            b'\x00\x00'  # RSN Capabilities (sin PMKID)
        )
    )

    # Agregar el RSN Information Element al paquete de beacon
    beacon = beacon / rsn_info

    log_entry = f"Enviando beacon para SSID={ssid} en el canal={channel}, AP MAC={ap_mac}"
    guardar_log(log_entry)
    # Enviar el paquete de beacon
    sendp(beacon, iface="wlp1s0mon", inter=0.1, loop=1, verbose=1) # Ver contador

def stop_all_beacons():
    global beacon_threads
    for thread in beacon_threads:
        if thread.is_alive():
            thread.do_run = False
    beacon_threads = []


def send_probe_response(ssid, mac_address):
    probe_response = (
        RadioTap() /
        Dot11(type=0, subtype=5, addr1=mac_address, addr2=ap_mac, addr3=mac_address) /
        Dot11ProbeResp(timestamp=0x0000000000000000, beacon_interval=100) /
        Dot11Elt(ID='SSID', info=ssid)
    )
    log_entry = f"Enviando probe response a MAC={mac_address} para SSID={ssid}"
    guardar_log(log_entry)
    sendp(probe_response, iface="wlp1s0mon", inter=1, loop=0)

# Función para escuchar paquetes de Probe Request
def start_sniffing():
    log_entry = "Iniciando la captura de Probe Requests..."
    guardar_log(log_entry)
    sniff(iface="wlp1s0mon", prn=handle_probe_request, store=0, filter="type mgt subtype probe-req")

# Crear hilos para enviar beacons y para escuchar Probe Requests
sniff_thread = threading.Thread(target=start_sniffing)

# Iniciar ambos hilos
sniff_thread.start()

# Esperar a que terminen 
sniff_thread.join()

