from scapy.all import ARP, Ether, srp, IP, ICMP, sr1
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import threading
import time
import platform
import os
import sys
import ctypes
from datetime import datetime
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph
from reportlab.lib.styles import getSampleStyleSheet
import json

def obtener_dispositivos_red(rango_red):
    # Construir un paquete ARP para escanear la red
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp = ARP(pdst=rango_red)
    paquete = ether / arp

    # Enviar el paquete y recibir las respuestas
    resultado = srp(paquete, timeout=2, verbose=0)[0]

    dispositivos = []
    for _, recibido in resultado:
        ttl = obtener_ttl(recibido.psrc)
        dispositivo = {
            'ip': recibido.psrc,
            'mac': recibido.hwsrc,
            'ttl': ttl,
            'os': identificar_sistema_operativo(ttl),
            'last_seen': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        dispositivos.append(dispositivo)

    return dispositivos

def obtener_ttl(ip):
    try:
        # Enviar un paquete ICMP para obtener el TTL
        respuesta = sr1(IP(dst=ip)/ICMP(), timeout=2, verbose=0)
        if respuesta is not None:
            return int(respuesta[IP].ttl)
        else:
            return None
    except Exception as e:
        print(f"Error obteniendo TTL para {ip}: {e}")
        return None

def identificar_sistema_operativo(ttl):
    if ttl is None:
        return 'Desconocido'
    elif ttl >= 128:
        return 'Windows'
    elif ttl >= 64:
        return 'Linux'
    else:
        return 'Otro'

def mostrar_dispositivos_gui(rango_red):
    root = tk.Tk()
    root.title("Network Traffic Analyzer")
    root.geometry("1000x700")

    style = ttk.Style()
    style.theme_use('clam')

    # Frame principal
    main_frame = ttk.Frame(root, padding="10")
    main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
    root.columnconfigure(0, weight=1)
    root.rowconfigure(0, weight=1)
    main_frame.columnconfigure(0, weight=1)
    main_frame.columnconfigure(1, weight=1)
    main_frame.rowconfigure(1, weight=1)

    # Controles superiores
    controls_frame = ttk.Frame(main_frame)
    controls_frame.grid(row=0, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=5)
    ttk.Button(controls_frame, text="Scan Network", command=lambda: threading.Thread(target=actualizar_dispositivos, daemon=True).start()).grid(row=0, column=0, padx=5)

    # Frame izquierdo para dispositivos detectados
    left_frame = ttk.LabelFrame(main_frame, text="Detected Devices", padding="5")
    left_frame.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), padx=5)
    left_frame.columnconfigure(0, weight=1)
    left_frame.rowconfigure(0, weight=1)

    # Treeview para dispositivos detectados
    columns = ('IP', 'MAC', 'TTL', 'OS', 'Last Seen')
    devices_tree = ttk.Treeview(left_frame, columns=columns, show='headings')

    # Configurar columnas
    devices_tree.heading('IP', text='IP Address')
    devices_tree.heading('MAC', text='MAC Address')
    devices_tree.heading('TTL', text='TTL')
    devices_tree.heading('OS', text='OS')
    devices_tree.heading('Last Seen', text='Last Seen')

    # Ajustar anchos de columna
    for col in columns:
        devices_tree.column(col, width=150)

    # Scrollbars para dispositivos detectados
    y_scroll = ttk.Scrollbar(left_frame, orient=tk.VERTICAL, command=devices_tree.yview)
    x_scroll = ttk.Scrollbar(left_frame, orient=tk.HORIZONTAL, command=devices_tree.xview)
    devices_tree.configure(yscrollcommand=y_scroll.set, xscrollcommand=x_scroll.set)

    # Grid para el árbol y scrollbars
    devices_tree.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
    y_scroll.grid(row=0, column=1, sticky=(tk.N, tk.S))
    x_scroll.grid(row=1, column=0, sticky=(tk.W, tk.E))

    dispositivos_actuales = {}

    def actualizar_dispositivos():
        while True:
            dispositivos_nuevos = obtener_dispositivos_red(rango_red)

            # Actualizar el diccionario de dispositivos actuales
            for dispositivo in dispositivos_nuevos:
                key = (dispositivo['ip'], dispositivo['mac'])
                dispositivos_actuales[key] = dispositivo

            # Limpiar la tabla y agregar los dispositivos actualizados
            for item in devices_tree.get_children():
                devices_tree.delete(item)

            for dispositivo in dispositivos_actuales.values():
                devices_tree.insert('', tk.END, values=(dispositivo['ip'], dispositivo['mac'], dispositivo['ttl'], dispositivo['os'], dispositivo['last_seen']))

            time.sleep(5)  # Escanear cada 5 segundos

    # Ejecutar el escaneo en un hilo separado para no bloquear la interfaz
    hilo_escaneo = threading.Thread(target=actualizar_dispositivos, daemon=True)
    hilo_escaneo.start()

    root.mainloop()

def imprimir_dispositivos(dispositivos):
    for dispositivo in dispositivos:
        print(f"IP: {dispositivo['ip']}, MAC: {dispositivo['mac']}, TTL: {dispositivo['ttl']}, OS: {dispositivo['os']}, Last Seen: {dispositivo['last_seen']}")

if __name__ == "__main__":
    rango_red = "192.168.1.0/24"  # Cambia esto al rango de red que quieres escanear
    mostrar_dispositivos_gui(rango_red)
