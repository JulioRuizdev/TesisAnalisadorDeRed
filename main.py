from scapy.all import ARP, Ether, srp, IP, ICMP, sr1
import tkinter as tk
from tkinter import ttk
import threading
import time

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
            'os': identificar_sistema_operativo(ttl)
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
    root.title("Dispositivos Conectados a la Red")

    tree = ttk.Treeview(root)
    tree['columns'] = ('IP', 'MAC', 'TTL', 'OS')

    tree.column('#0', width=0, stretch=tk.NO)
    tree.column('IP', anchor=tk.W, width=120)
    tree.column('MAC', anchor=tk.W, width=150)
    tree.column('TTL', anchor=tk.CENTER, width=50)
    tree.column('OS', anchor=tk.W, width=100)

    tree.heading('#0', text='', anchor=tk.W)
    tree.heading('IP', text='IP', anchor=tk.W)
    tree.heading('MAC', text='MAC', anchor=tk.W)
    tree.heading('TTL', text='TTL', anchor=tk.CENTER)
    tree.heading('OS', text='OS', anchor=tk.W)

    tree.pack(pady=20)

    dispositivos_actuales = {}

    def actualizar_dispositivos():
        while True:
            dispositivos_nuevos = obtener_dispositivos_red(rango_red)
            nuevos_dispositivos_set = set((d['ip'], d['mac']) for d in dispositivos_nuevos)

            # Actualizar el diccionario de dispositivos actuales
            for dispositivo in dispositivos_nuevos:
                if (dispositivo['ip'], dispositivo['mac']) not in dispositivos_actuales:
                    dispositivos_actuales[(dispositivo['ip'], dispositivo['mac'])] = dispositivo

            # Limpiar la tabla y agregar los dispositivos actualizados
            for item in tree.get_children():
                tree.delete(item)

            for dispositivo in dispositivos_actuales.values():
                tree.insert('', tk.END, values=(dispositivo['ip'], dispositivo['mac'], dispositivo['ttl'], dispositivo['os']))

            time.sleep(5)  # Escanear cada 5 segundos

    # Ejecutar el escaneo en un hilo separado para no bloquear la interfaz
    hilo_escaneo = threading.Thread(target=actualizar_dispositivos, daemon=True)
    hilo_escaneo.start()

    root.mainloop()

def imprimir_dispositivos(dispositivos):
    for dispositivo in dispositivos:
        print(f"IP: {dispositivo['ip']}, MAC: {dispositivo['mac']}, TTL: {dispositivo['ttl']}, OS: {dispositivo['os']}")

if __name__ == "__main__":
    rango_red = "192.168.1.0/24"  # Cambia esto al rango de red que quieres escanear
    mostrar_dispositivos_gui(rango_red)
