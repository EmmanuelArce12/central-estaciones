import tkinter as tk
from tkinter import messagebox, ttk
import sys
import os
import json
import requests
import subprocess
from bs4 import BeautifulSoup
from datetime import datetime, timedelta
import threading
import time
import random
import string

# --- CONFIGURACIÓN ---
URL_NUBE = "https://central-estaciones.onrender.com" # ⚠️ REEMPLAZA CON TU URL SI ES DISTINTA
CONFIG_FILE = "config.json"
BAT_FILE = "iniciar_servicio.bat"

# ==========================================
# 🕵️‍♂️ MODO SILENCIOSO (EL OBRERO)
# ==========================================
def obtener_config_nube(token):
    try:
        # Timeout corto para no bloquear si hay lag
        res = requests.post(f"{URL_NUBE}/api/agent/sync", headers={'X-API-TOKEN': token}, timeout=10)
        if res.status_code == 200:
            return res.json()
        elif res.status_code == 401:
            return "REVOKED"
    except: pass
    return None

def tarea_extraccion(token, config_vox):
    ip = config_vox.get('ip')
    user = config_vox.get('u')
    pwd = config_vox.get('p')
    
    if not ip or not user: return 

    # Conexión VOX
    base_url = f"http://{ip}/console"
    session = requests.Session()
    try:
        res = session.post(f"{base_url}/login/login/", data={'id_usuario': user, 'clave': pwd, 'autologin': '1', 'submit': 'Login'}, timeout=10)
        if "id_usuario" in res.text: return 
    except: return 

    # Barrido
    ahora = datetime.now()
    periodos = [(ahora.month, ahora.year), ((ahora.replace(day=1)-timedelta(days=1)).month, (ahora.replace(day=1)-timedelta(days=1)).year)]
    
    for mes, anio in periodos:
        try:
            res = session.post(f"{base_url}/reports/sales/", data={'reportId':'reportSales','filterType':'T','month':mes,'year':anio})
            soup = BeautifulSoup(res.text, 'html.parser')
            select = soup.find('select', {'name': 'period'})
            if select:
                for op in [o for o in select.find_all('option') if o.get('value')]:
                    tid, txt = op.get('value'), op.text.strip()
                    if "Actual" in txt or f"/{mes:02d}/" not in txt: continue
                    
                    res_d = session.post(f"{base_url}/reportSales/", data={'reportId':'reportSales','filterType':'T','month':mes,'year':anio,'period':tid,'search':'Buscar'})
                    monto = 0.0
                    for tr in BeautifulSoup(res_d.text, 'html.parser').find_all('tr'):
                        tds = tr.find_all('td')
                        if len(tds)>=2 and tds[0].text.strip()=="Contado":
                            try: monto=float(tds[1].text.strip().replace(".","").replace(",",".")); break
                            except: pass
                    
                    if monto > 0:
                        paquete = {"id_interno": tid, "estacion": "Agente", "monto": monto, "fecha": f"{anio}-{mes} ({txt})"}
                        requests.post(f"{URL_NUBE}/api/reportar", json=paquete, headers={'X-API-TOKEN': token})
        except: pass

def bucle_servicio():
    if not os.path.exists(CONFIG_FILE): return
    try:
        with open(CONFIG_FILE, 'r') as f: token = json.load(f).get('api_token')
    except: return

    if not token: return

    while True:
        data = obtener_config_nube(token)
        
        if data == "REVOKED":
            os.remove(CONFIG_FILE)
            sys.exit()
            
        if data and isinstance(data, dict):
            comando = data.get('command')
            config_vox = data.get('config')
            
            if comando == 'EXTRACT' and config_vox:
                tarea_extraccion(token, config_vox)
        
        # Esperamos 10 segundos entre consultas para no saturar
        time.sleep(10)

# ==========================================
# 📀 MODO INSTALADOR (GUI)
# ==========================================
class InstaladorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Agente VOX")
        self.root.geometry("400x350")
        
        self.codigo = tk.StringVar()
        self.status = tk.StringVar(value="Generando código...")
        
        # UI
        ttk.Label(root, text="VINCULACIÓN REQUERIDA", font=("Arial", 12, "bold"), foreground="red").pack(pady=20)
        ttk.Label(root, text="Dale este código a tu Administrador:").pack()
        
        self.lbl_code = ttk.Label(root, textvariable=self.codigo, font=("Courier", 30, "bold"), background="#eee")
        self.lbl_code.pack(pady=20, ipadx=10)
        
        self.lbl_code_note = ttk.Label(root, textvariable=self.status, foreground="blue")
        self.lbl_code_note.pack(pady=10)
        
        # Iniciar proceso
        self.generar_codigo()
        threading.Thread(target=self.esperar_vinculacion, daemon=True).start()

    def generar_codigo(self):
        chars = string.ascii_uppercase + string.digits
        code = ''.join(random.choices(chars, k=3)) + "-" + ''.join(random.choices(chars, k=2))
        self.codigo.set(code)
        self.status.set("Esperando autorización en la web...")

    def instalar_persistencia(self):
        # Crear .BAT y Tarea Programada
        exe_path = os.path.abspath(sys.executable if getattr(sys, 'frozen', False) else __file__)
        with open(BAT_FILE, 'w') as f:
            f.write(f'@echo off\ncd /d "{os.path.dirname(exe_path)}"\nstart "" "{exe_path}" --silent')

        cmd = f'schtasks /create /tn "AgenteVOX_Service" /tr "\'{os.path.abspath(BAT_FILE)}\'" /sc daily /st 07:00 /f'
        try: subprocess.run(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except: pass

    def esperar_vinculacion(self):
        while True:
            try:
                res = requests.post(f"{URL_NUBE}/api/handshake/poll", json={"code": self.codigo.get()})
                data = res.json()
                
                if data.get('status') == 'linked':
                    token = data.get('api_token')
                    
                    # Guardar
                    with open(CONFIG_FILE, 'w') as f: json.dump({"api_token": token}, f)
                    
                    # Instalar persistencia
                    self.instalar_persistencia()
                    
                    # Cambiar UI
                    self.root.after(0, self.mostrar_exito)
                    
                    # Arrancar servicio
                    threading.Thread(target=bucle_servicio, daemon=True).start()
                    return
            except: pass
            time.sleep(3)

    def mostrar_exito(self):
        for widget in self.root.winfo_children(): widget.destroy()
        ttk.Label(self.root, text="✅ SISTEMA ACTIVO", font=("Arial", 16, "bold"), foreground="green").pack(pady=40)
        ttk.Label(self.root, text="Vinculación exitosa.", font=("Arial", 10)).pack()
        ttk.Button(self.root, text="Minimizar", command=self.root.iconify).pack(pady=20)

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--silent":
        bucle_servicio()
    else:
        # Si ya existe config, arrancar en modo silencioso o mostrar estado
        if os.path.exists(CONFIG_FILE):
             bucle_servicio() 
        else:
            root = tk.Tk()
            app = InstaladorApp(root)
            root.mainloop()