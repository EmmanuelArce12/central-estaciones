import os
import secrets
import difflib
import pandas as pd
import json
import random
import io
import traceback # Nuevo para ver errores reales
import re
from collections import Counter
from sqlalchemy import func
from flask import Flask, request, jsonify, render_template, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, time, timedelta
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)

# --- CONFIGURACIÓN BASE DE DATOS ---
db_url = os.environ.get('DATABASE_URL', 'sqlite:///local.db')
if db_url and db_url.startswith("postgres://"):
    db_url = db_url.replace("postgres://", "postgresql://", 1)

app.config['SQLALCHEMY_DATABASE_URI'] = db_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'CLAVE_SUPER_SECRETA')

db = SQLAlchemy(app)
migrate = Migrate(app, db)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# ==========================================
# 🛠️ FUNCIONES AUXILIARES (BLOQUE CORREGIDO)
# ==========================================
# ==========================================
# 🛡️ CÁLCULO DE FECHAS SEGURO (A PRUEBA DE VACÍO)
# ==========================================
def get_rango_barrido_seguro():
    try:
        # 1. Intentar obtener el último reporte
        ultimo = Reporte.query.filter_by(user_id=current_user.id).order_by(Reporte.fecha_operativa.desc()).first()
        
        hoy = datetime.now().date()
        
        if ultimo and ultimo.fecha_operativa:
            try:
                # Si hay datos, empezamos desde la última fecha registrada
                inicio = datetime.strptime(ultimo.fecha_operativa, '%Y-%m-%d').date()
            except:
                # Si la fecha guardada es inválida, fallback
                inicio = datetime(2024, 11, 1).date()
        else:
            # 2. SI LA TABLA ESTÁ VACÍA (Tu caso actual)
            # Forzamos inicio el 1 de Noviembre 2024
            inicio = datetime(2024, 11, 1).date()
            
        # Truco: Siempre retrocedemos al día 1 de ESE mes para barrer completo
        # Ej: Si el último fue el 28/11, volvemos al 01/11 para re-chequear huecos
        inicio_mes = inicio.replace(day=1)
        
        # Formatear strings
        return inicio_mes.strftime('%Y-%m-%d'), hoy.strftime('%Y-%m-%d')

    except Exception as e:
        print(f"⚠️ Error fatal calculando fechas: {e}")
        # En el peor de los casos, devolvemos el mes actual completo
        inicio = datetime.now().date().replace(day=1)
        return inicio.strftime('%Y-%m-%d'), datetime.now().strftime('%Y-%m-%d')
def calcular_info_operativa(fecha_hora_str):
    """Calcula fecha operativa y turno basándose en la hora (IMPORTANTE: Para CSVs de Tiradas)"""
    try:
        dt = pd.to_datetime(fecha_hora_str)
        hora = dt.hour
        fecha_op = dt.date()
        turno = "Noche"
        # Reglas de negocio fijas para asignar turno base
        if 6 <= hora < 14: turno = "Mañana"
        elif 14 <= hora < 22: turno = "Tarde"
        else:
            # Si es madrugada (antes de las 6), cuenta como Noche del día anterior
            if hora < 6: fecha_op = fecha_op - timedelta(days=1)
        return fecha_op.strftime('%Y-%m-%d'), turno
    except: 
        return datetime.now().strftime('%Y-%m-%d'), "Sin Asignar"

def procesar_datos_turno_texto(s):
    """Plan B: Usar regex sobre el texto si el ID falla (Para VOX)"""
    try:
        if not s: return None, None, None, None
        fecha_obj = datetime.now().date()
        
        # Busca patrones DD/MM/YYYY o YYYY/MM/DD
        match = re.search(r'(\d{2,4})[/-](\d{1,2})[/-](\d{2,4})', s)
        if match:
            partes = match.groups()
            if len(partes[0]) == 4: # YYYY-MM-DD
                fecha_obj = datetime(int(partes[0]), int(partes[1]), int(partes[2])).date()
            else: # DD/MM/YYYY
                fecha_obj = datetime(int(partes[2]), int(partes[1]), int(partes[0])).date()
            
        fecha_sql = fecha_obj.strftime('%Y-%m-%d')
        
        s_lower = s.lower()
        turno = "Sin Asignar"
        if "turno 1" in s_lower or "mañana" in s_lower: turno = "Mañana"
        elif "turno 2" in s_lower or "tarde" in s_lower: turno = "Tarde"
        elif "turno 3" in s_lower or "noche" in s_lower: turno = "Noche"
        
        # Horarios ficticios para relleno
        now = datetime.now()
        return fecha_sql, turno, now, now
    except: return None, None, None, None

def procesar_info_desde_id(id_vox, texto_original=""):
    """
    Plan A: Extrae la información EXACTA usando el ID de VOX (Para VOX).
    Formato ID: AAAAMMDDHHMMSSAAAAMMDDHHMMSS (Inicio + Fin)
    """
    try:
        # Si el ID es muy corto o nulo, usamos el texto como respaldo
        if not id_vox or len(str(id_vox)) < 20:
            return procesar_datos_turno_texto(texto_original)

        id_str = str(id_vox).strip()
        
        # El ID son 2 fechas pegadas (14 chars cada una)
        str_inicio = id_str[:14]
        str_fin = id_str[14:]
        
        # Intentamos parsear con el formato compacto
        dt_apertura = datetime.strptime(str_inicio, "%Y%m%d%H%M%S")
        dt_cierre = datetime.strptime(str_fin, "%Y%m%d%H%M%S")
        
        # Fecha Operativa: Generalmente es la fecha de cierre. 
        # Si cierra de madrugada (antes de las 06:00), pertenece al día anterior.
        fecha_obj = dt_cierre.date()
        if dt_cierre.hour < 6:
            fecha_obj = fecha_obj - timedelta(days=1)
            
        fecha_sql = fecha_obj.strftime('%Y-%m-%d')
        
        # Calcular Turno por hora de CIERRE
        h = dt_cierre.hour
        turno = "Noche"
        if 6 <= h < 14: turno = "Mañana"
        elif 14 <= h < 22: turno = "Tarde"
        
        return fecha_sql, turno, dt_cierre, dt_apertura

    except Exception as e:
        print(f"❌ Error decodificando ID {id_vox}: {e}")
        # Si falla el ID, intentamos leer el texto normal
        return procesar_datos_turno_texto(texto_original)# ==========================================
# 🗃️ MODELOS DE DATOS
# ==========================================

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), default='estacion', nullable=False)
    
    channels = db.relationship('Channel', backref='usuario', lazy=True, cascade="all, delete-orphan")
    cliente_info = db.relationship('Cliente', backref='usuario', uselist=False, cascade="all, delete-orphan")
    # Relaciones de datos
    reportes = db.relationship('Reporte', backref='usuario', lazy=True, cascade="all, delete-orphan")
    tiradas = db.relationship('Tirada', backref='usuario', lazy=True, cascade="all, delete-orphan")
    ventas_vendedor = db.relationship('VentaVendedor', backref='usuario', lazy=True, cascade="all, delete-orphan")

    def set_password(self, p): self.password_hash = generate_password_hash(p)
    def check_password(self, p): return check_password_hash(self.password_hash, p)
    @property
    def is_superadmin(self): return self.role == 'superadmin'

class Channel(db.Model):
    __tablename__ = 'channels'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    tipo = db.Column(db.String(20), nullable=False)
    nombre = db.Column(db.String(50), nullable=False)
    token = db.Column(db.String(100), unique=True, nullable=True)
    code = db.Column(db.String(20), nullable=True)
    status = db.Column(db.String(20), default='offline')
    last_check = db.Column(db.DateTime)
    comando = db.Column(db.String(50), nullable=True)
    config_data = db.Column(db.Text, nullable=True) 

class Cliente(db.Model):
    __tablename__ = 'clientes'
    id = db.Column(db.Integer, primary_key=True)
    nombre_fantasia = db.Column(db.String(100))
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), unique=True)

class Reporte(db.Model):
    __tablename__ = 'reportes'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    id_interno = db.Column(db.String(50))
    estacion = db.Column(db.String(100))
    fecha_completa = db.Column(db.String(100))
    monto = db.Column(db.Float)
    fecha_operativa = db.Column(db.String(20))
    turno = db.Column(db.String(20))
    hora_cierre = db.Column(db.DateTime)
    hora_apertura = db.Column(db.DateTime)

class VentaVendedor(db.Model):
    __tablename__ = 'ventas_vendedor'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    fecha = db.Column(db.String(20))
    vendedor = db.Column(db.String(100))
    combustible = db.Column(db.String(100)) 
    litros = db.Column(db.Float)
    precio = db.Column(db.Float)            
    monto = db.Column(db.Float)
    primer_horario = db.Column(db.String(50)) 
    tipo_pago = db.Column(db.String(50))      
    duracion_seg = db.Column(db.Float)        

class Tirada(db.Model):
    __tablename__ = 'tiradas'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    fecha_operativa = db.Column(db.String(50)) 
    vendedor = db.Column(db.String(100))
    vendedor_raw = db.Column(db.String(100))
    dni = db.Column(db.String(50))
    transaccion = db.Column(db.String(50))
    sector = db.Column(db.String(100))
    monto = db.Column(db.Float)
    hora = db.Column(db.String(20))
    turno = db.Column(db.String(50))
    # Billetes
    b2000 = db.Column(db.Integer, default=0)
    b1000 = db.Column(db.Integer, default=0)
    b500 = db.Column(db.Integer, default=0)
    b200 = db.Column(db.Integer, default=0)
    b100 = db.Column(db.Integer, default=0)
    cant_billetes = db.Column(db.Integer, default=0)
    detalle_extra = db.Column(db.String(255)) 

with app.app_context():
    try: db.create_all()
    except Exception as e: print(f"⚠️ Advertencia DB: {e}")

@login_manager.user_loader
def load_user(uid): return User.query.get(int(uid))

# ==========================================
# 🌐 RUTAS WEB
# ==========================================

@app.route('/')
def root():
    if current_user.is_authenticated:
        return redirect(url_for('panel_superadmin')) if current_user.is_superadmin else redirect(url_for('panel_estacion'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form.get('username')).first()
        if user and user.check_password(request.form.get('password')):
            login_user(user); return redirect(url_for('root'))
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# --- PANEL SUPERADMIN ---
@app.route('/admin/dashboard', methods=['GET', 'POST'])
@login_required
def panel_superadmin():
    if not current_user.is_superadmin: return "Acceso Denegado"
    msg = ""
    if request.method == 'POST':
        if 'create_user' in request.form:
            u = request.form.get('username'); p = request.form.get('password')
            if User.query.filter_by(username=u).first(): msg = "❌ Usuario existe."
            else:
                nu = User(username=u, role='estacion'); nu.set_password(p)
                db.session.add(nu); db.session.commit()
                db.session.add(Cliente(nombre_fantasia=request.form.get('nombre'), user_id=nu.id))
                db.session.commit()
                msg = "✅ Estación creada."
        elif 'add_channel' in request.form:
            uid = request.form.get('user_id')
            db.session.add(Channel(user_id=uid, tipo=request.form.get('tipo'), nombre=request.form.get('nombre')))
            db.session.commit()
            msg = "✅ Canal agregado."
        elif 'link_channel' in request.form:
            ch = Channel.query.get(request.form.get('channel_id'))
            code = request.form.get('pairing_code').strip().upper()
            if ch and code:
                ch.code = code; ch.status = 'waiting'; db.session.commit()
                msg = f"🔗 Esperando conexión."
        elif 'delete_channel' in request.form:
            db.session.delete(Channel.query.get(request.form.get('channel_id'))); db.session.commit()
        elif 'revoke_channel' in request.form:
            ch = Channel.query.get(request.form.get('channel_id'))
            if ch: ch.token = None; ch.status = 'offline'; ch.code = None; db.session.commit()
        elif 'clean_database' in request.form:
            try: db.session.query(Tirada).delete(); db.session.commit(); msg = "✅ Base limpia."
            except: db.session.rollback()
    return render_template('admin_dashboard.html', users=User.query.all(), msg=msg)

@app.route('/admin/eliminar-estacion/<int:id>', methods=['POST'])
@login_required
def eliminar_estacion(id):
    if not current_user.is_superadmin: return "Acceso Denegado"
    db.session.delete(User.query.get_or_404(id)); db.session.commit()
    return redirect(url_for('panel_superadmin'))

@app.route('/admin/api/status-all')
@login_required
def admin_status_all():
    if not current_user.is_superadmin: return jsonify([])
    data = []
    ahora = datetime.now()
    for u in User.query.all():
        channels_data = []
        for ch in u.channels:
            st = ch.status
            if ch.last_check and (ahora - ch.last_check).total_seconds() > 120: st = 'offline'
            channels_data.append({"id": ch.id, "nombre": ch.nombre, "tipo": ch.tipo, "status": st, "token": ch.token, "code": ch.code, "last_check": ch.last_check.strftime('%H:%M') if ch.last_check else "-"})
        data.append({"id": u.id, "username": u.username, "cliente": u.cliente_info.nombre_fantasia if u.cliente_info else "-", "channels": channels_data})
    return jsonify(data)

# ---------------------------------------------------------
# 2. TAREA AUTOMÁTICA (Misma lógica de barrido)
# ---------------------------------------------------------
@app.route('/api/agent/trigger-auto', methods=['POST'])
def trigger_auto_agente():
    token = request.headers.get('X-API-TOKEN')
    ch = Channel.query.filter_by(token=token).first()
    
    if not ch or ch.tipo != 'VOX': 
        return jsonify({"status": "error", "msg": "Token invalido"}), 401
    
    # LÓGICA DE BARRIDO DE SEGURIDAD (Igual que arriba)
    hoy = datetime.now().date()
    primer_dia_este_mes = hoy.replace(day=1)
    ultimo_dia_mes_anterior = primer_dia_este_mes - timedelta(days=1)
    primer_dia_mes_anterior = ultimo_dia_mes_anterior.replace(day=1)
    
    rango_inicio = primer_dia_mes_anterior.strftime('%Y-%m-%d')
    rango_fin = hoy.strftime('%Y-%m-%d')
    
    # Guardar orden
    ch.comando = 'EXTRACT'
    
    import json
    conf = {}
    if ch.config_data:
        try: conf = json.loads(ch.config_data)
        except: pass
    
    conf['rango_inicio'] = rango_inicio
    conf['rango_fin'] = rango_fin
    
    ch.config_data = json.dumps(conf)
    db.session.commit()
    
    print(f"🤖 AUTO-SCHEDULER ({ch.nombre}): Barrido desde {rango_inicio}")
    
    return jsonify({"status": "ok", "msg": "Barrido programado"})
# ==========================================
# 📡 APIS COMUNICACIÓN
# ==========================================

@app.route('/api/handshake/tiradas', methods=['POST']) 
@app.route('/api/handshake/poll', methods=['POST'])
def handshake_generic():
    code = request.json.get('code', '').strip().upper()
    ch = Channel.query.filter_by(code=code).first()
    if ch:
        if not ch.token: ch.token = secrets.token_hex(32)
        ch.code = None; ch.status = 'online'; ch.last_check = datetime.now()
        db.session.commit()
        return jsonify({"status": "linked", "api_token": ch.token}), 200
    return jsonify({"status": "waiting"}), 200

@app.route('/api/tiradas/sync', methods=['POST'])
@app.route('/api/agent/sync', methods=['POST'])
def sync_generic():
    token = request.headers.get('X-API-TOKEN')
    ch = Channel.query.filter_by(token=token).first()
    
    if not ch: return jsonify({"status": "revoked"}), 401
    
    ch.status = 'online'
    ch.last_check = datetime.now()
    
    resp = {"status": "ok", "command": ch.comando}
    
    # Recuperamos la configuración (donde guardamos la fecha) para enviarla
    import json
    conf = {}
    if ch.config_data:
        try: conf = json.loads(ch.config_data)
        except: pass
    
    resp['config'] = conf # Aquí viaja 'filtro_fecha' hacia el agente
    
    # Lógica de limpieza automática solo para VOX (Tiradas espera a fin_tarea)
    if ch.tipo == 'VOX' and ch.comando == 'EXTRACT': 
        ch.comando = None

    db.session.commit()
    return jsonify(resp), 200

# 3. AGREGAR NUEVA RUTA: FIN TAREA (Para que el agente avise cuando terminó)
@app.route('/api/fin-tarea', methods=['POST'])
def fin_tarea_tiradas():
    token = request.headers.get('X-API-TOKEN')
    ch = Channel.query.filter_by(token=token).first()
    if ch:
        ch.comando = None # Apagamos la orden/botón en la web
        db.session.commit()
    return jsonify({"status": "ok"})
# ==========================================
# [NUEVO] API OPTIMIZACIÓN: VERIFICAR IDs EXISTENTES
# ==========================================
# ==========================================
# [MODIFICADO] API OPTIMIZACIÓN: CHECK IDs
# ==========================================
@app.route('/api/check-existing-ids', methods=['POST'])
def check_existing_ids_vox():
    token = request.headers.get('X-API-TOKEN')
    ch = Channel.query.filter_by(token=token).first()
    if not ch: return jsonify({"status": "error"}), 401
    
    data = request.json or {}
    incoming_ids = data.get('ids', [])
    
    # 1. ACTUALIZAR VISUALMENTE QUE ESTAMOS VERIFICANDO
    if ESTADO_CARGA["activo"]:
        ESTADO_CARGA["mensaje"] = f"🔎 Verificando {len(incoming_ids)} registros en base de datos..."
        # No sumamos porcentaje aún, pero informamos la acción
    
    try:
        user_id = ch.user_id
        existing_reports = db.session.query(Reporte.id_interno)\
            .filter(Reporte.user_id == user_id, Reporte.id_interno.in_(incoming_ids))\
            .all()
        existing_ids_set = set(r[0] for r in existing_reports)
        missing_ids = [id_val for id_val in incoming_ids if id_val not in existing_ids_set]
        
        return jsonify({"missing_ids": missing_ids})
    except Exception as e:
        return jsonify({"missing_ids": incoming_ids})
# ==========================================
# [NUEVO] API PROGRESO RÁPIDO (Para los que saltamos)
# ==========================================
# EN APP.PY (Reemplaza la función existente)
# ==========================================
# [MODIFICADO] API PROGRESO RÁPIDO (SALTOS)
# ==========================================
@app.route('/api/progreso-rapido', methods=['POST'])
def progreso_rapido_api():
    token = request.headers.get('X-API-TOKEN')
    if not Channel.query.filter_by(token=token).first(): return jsonify({}), 401
    
    data = request.json or {}
    cantidad_saltada = data.get('cantidad', 0)
    
    if ESTADO_CARGA["activo"] and cantidad_saltada > 0:
        # Sumamos al procesado porque verificar y saltar TAMBIÉN es trabajo hecho
        ESTADO_CARGA["procesados"] += cantidad_saltada
        
        # Mensaje específico para que el usuario entienda por qué subió la barra
        ESTADO_CARGA["mensaje"] = f"⚡ Verificados {cantidad_saltada} registros existentes (Saltando...)"
        
        print(f"⏩ Progreso: Saltados {cantidad_saltada} registros.")
        
    return jsonify({"status": "ok"})
@app.route('/api/reportar', methods=['POST'])
def api_reportar_vox():
    try:
        # 1. VERIFICAR TOKEN
        tk = request.headers.get('X-API-TOKEN')
        ch = Channel.query.filter_by(token=tk).first()
        if not ch: return jsonify({"status":"error"}), 401
        
        n = request.json
        nid = str(n.get('id_interno'))
        u_id = ch.user_id 
        
        # 2. FILTRO DE DUPLICADOS
        # Si ya existe, NO guardamos, pero SÍ sumamos al contador de progreso
        # para que la barra avance y no se quede trabada.
        if Reporte.query.filter_by(id_interno=nid, user_id=u_id).first(): 
            if ESTADO_CARGA["activo"]:
                ESTADO_CARGA["procesados"] += 1
            print(f"   ⚠️ ID {nid} ya existe. Ignorando.")
            return jsonify({"status":"ignorado"}), 200
        
        # 3. PROCESAMIENTO DE FECHAS (Usando el ID para máxima precisión)
        # Llama a la función 'procesar_info_desde_id' que agregamos antes
        f_op, turno, dt_cierre, dt_apertura = procesar_info_desde_id(nid, n.get('fecha'))
        
        if not f_op: 
            return jsonify({"status":"error_fecha"}), 400
        
        # 4. GUARDAR EN BASE DE DATOS
        r = Reporte(
            user_id=u_id, 
            id_interno=nid, 
            estacion=n.get('estacion'),
            fecha_completa=n.get('fecha'), 
            monto=n.get('monto'),
            fecha_operativa=f_op, 
            turno=turno, 
            hora_cierre=dt_cierre, 
            hora_apertura=dt_apertura
        )
        db.session.add(r)
        db.session.commit()
        
        # 5. ACTUALIZAR BARRA DE PROGRESO
        if ESTADO_CARGA["activo"]:
            ESTADO_CARGA["procesados"] += 1
            ESTADO_CARGA["mensaje"] = f"Cargado: {f_op} ({turno})"
        
        print(f"   ✅ GUARDADO: {f_op} ({turno}) - ${n.get('monto')}")
        return jsonify({"status":"exito"}), 200

    except Exception as e:
        print(f"🔥 ERROR API REPORTAR: {e}")
        # En caso de error, no frenamos todo, solo reportamos fallo
        return jsonify({"status":"error", "msg": str(e)}), 500
# ==========================================
# CORRECCIÓN EN APP.PY - ESTADO FINAL FORZADO
# ==========================================
# ==========================================
# CORRECCIÓN EN APP.PY: RUTAS UNIFICADAS
# ==========================================
@app.route('/api/fin-tarea', methods=['POST'])
def fin_tarea_unificada():
    try:
        # 1. Apagar la orden en Base de Datos (Para que el agente deje de trabajar)
        token = request.headers.get('X-API-TOKEN')
        if token:
            ch = Channel.query.filter_by(token=token).first()
            if ch:
                ch.comando = None
                db.session.commit()

        # 2. Apagar la Barra Visual (Para que el HTML muestre 100%)
        ESTADO_CARGA["activo"] = False
        ESTADO_CARGA["mensaje"] = "✅ Carga Completa"
        
        # Forzamos matemáticamente el 100%
        if ESTADO_CARGA["total_estimado"] > 0:
            ESTADO_CARGA["procesados"] = ESTADO_CARGA["total_estimado"]
        else:
            ESTADO_CARGA["procesados"] = 1
            ESTADO_CARGA["total_estimado"] = 1
            
        print("🏁 FIN TAREA RECIBIDO: Barra liberada al 100%.")
        return jsonify({"status": "ok"})
        
    except Exception as e:
        print(f"🔥 Error en fin-tarea: {e}")
        return jsonify({"status": "error"}), 500
@app.route('/api/estado-progreso')
@login_required
def estado_progreso():
    # Calculamos porcentaje
    pct = int((ESTADO_CARGA["procesados"] / ESTADO_CARGA["total_estimado"]) * 100)
    if pct > 100: pct = 99 # Mantener en 99 hasta que llegue el fin-tarea
    if not ESTADO_CARGA["activo"] and ESTADO_CARGA["mensaje"] == "✅ Carga Completa": pct = 100
        
    return jsonify({
        "activo": ESTADO_CARGA["activo"],
        "porcentaje": pct,
        "mensaje": ESTADO_CARGA["mensaje"]
    })
@app.route('/api/ping-ui')
@login_required
def ping_ui():
    ch = next((c for c in current_user.channels if c.tipo == 'VOX'), None)
    st = 'offline'; cmd_pendiente = False
    if ch:
        st = ch.status
        if ch.last_check and (datetime.now() - ch.last_check).total_seconds() > 120: st = 'offline'
        cmd_pendiente = (ch.comando == 'EXTRACT')
    return jsonify({"st": st, "cmd": cmd_pendiente})

# 5. RECEPCIÓN ARCHIVOS (TIRADAS) - [MEJORADO: Filtros + CSV Robusto]
# 5. RECEPCIÓN ARCHIVOS (TIRADAS) - [FILTRO DE VENDEDORES + UNION NOMBRE/APELLIDO]
@app.route('/api/recepcion-tiradas', methods=['POST'])
def api_recepcion_tiradas():
    token = request.headers.get('X-API-TOKEN')
    ch = Channel.query.filter_by(token=token).first()
    
    if not ch or ch.tipo != 'TIRADAS': 
        return jsonify({"status": "error", "msg": "Token invalido"}), 401
    
    user = ch.usuario 
    if 'archivo' not in request.files: return jsonify({"status": "error"}), 400
    archivo = request.files['archivo']
    
    try:
        import io
        contenido = archivo.read()
        df = None
        
        # 1. LECTURA ROBUSTA (Saltar líneas rotas para evitar error 500)
        for sep in [',', ';', '\t', r'\s+']:
            try:
                s = io.BytesIO(contenido)
                temp = pd.read_csv(s, sep=sep, engine='python', on_bad_lines='skip')
                cols = [c.lower().strip() for c in temp.columns]
                if 'nombre' in cols and ('total bolsa' in cols or 'total dep.' in cols): 
                    df = temp; break
            except: continue
            
        if df is None: df = pd.read_csv(io.BytesIO(contenido), on_bad_lines='skip')

        # 2. LIMPIEZA COLUMNAS
        df.columns = df.columns.astype(str).str.strip()
        def get_col(keys): return next((c for c in df.columns if any(k.lower() in c.lower() for k in keys)), None)
        
        c_nom = get_col(['nombre', 'vendedor'])
        c_monto = get_col(['total bolsa', 'total dep'])
        c_fecha = get_col(['fecha', 'hora'])
        c_dni = get_col(['dni']) # Aquí viene el APELLIDO
        c_trans = get_col(['transaccion', 'transacción'])

        if not c_monto or not c_nom: 
            return jsonify({"status": "error", "msg": "Faltan columnas clave"}), 400

        fecha_hoy = datetime.now().strftime('%Y-%m-%d')
        count = 0
        
        for _, row in df.iterrows():
            try:
                # A. FILTRAR PLAYA / SHOP (Los dejamos afuera)
                nom_raw = str(row[c_nom]).strip()
                nom_lower = nom_raw.lower()
                
                # Si el nombre contiene "playa" o "shop" o "lubri", lo saltamos
                if 'playa' in nom_lower or 'shop' in nom_lower or 'lubri' in nom_lower:
                    continue 

                # B. UNIR NOMBRE + APELLIDO
                apellido = str(row[c_dni]).strip() if c_dni else ""
                # Limpiamos "nan" si pandas leyó vacío
                if apellido.lower() == 'nan': apellido = ""
                
                # Formato final: "Juan Perez"
                nombre_final = f"{nom_raw} {apellido}".strip()

                # C. FECHA Y HORA
                fecha_str_csv = str(row[c_fecha]) if c_fecha else str(datetime.now())
                fecha_op, turno_calc = calcular_info_operativa(fecha_str_csv)
                
                h_str = "-"
                try: h_str = pd.to_datetime(fecha_str_csv).strftime('%H:%M:%S')
                except: pass

                # D. EVITAR DUPLICADOS (ID Transacción)
                id_trans = str(row[c_trans]) if c_trans else f"AUTO-{random.randint(10000,99999)}"
                if c_trans and Tirada.query.filter_by(user_id=user.id, transaccion=id_trans).first():
                    continue

                # E. MONTO
                val = float(str(row[c_monto]).replace('$','').replace('.','').replace(',','.'))

                # F. GUARDAR
                t = Tirada(
                    user_id=user.id, 
                    fecha_operativa=fecha_op, 
                    turno=turno_calc, # Preliminar (la vista decide el final)
                    vendedor=nombre_final, # Nombre Completo
                    vendedor_raw=nom_raw,
                    monto=val, 
                    hora=h_str,
                    dni=apellido,
                    transaccion=id_trans,
                    sector="-" # Ignoramos sector como pediste
                )
                db.session.add(t)
                count += 1
            except: pass
        
        ch.comando = None
        db.session.commit()
        return jsonify({"status": "ok", "count": count}), 200

    except Exception as e: 
        return jsonify({"status": "error", "msg": str(e)}), 500
@app.route('/estacion/panel')
@login_required
def panel_estacion():
    if current_user.is_superadmin: return redirect(url_for('panel_superadmin'))
    return render_template('station_dashboard.html', user=current_user)

@app.route('/estacion/ver-reportes')
@login_required
def ver_reportes_html():
    return render_template('index.html', usuario=current_user.username)

# ==========================================
# 📊 CONTROL DE PROGRESO GLOBAL (Simple en memoria para este caso)
# ==========================================
# En un sistema multi-usuario idealmente esto iría en Redis o DB, 
# pero para tu uso (una estación principal) esto funciona perfecto.
ESTADO_CARGA = {
    "activo": False,
    "total_estimado": 1, # Evitar división por cero
    "procesados": 0,
    "mensaje": "Esperando...",
    "inicio": None
}

# ==========================================
# 🗓️ API ESTADO CALENDARIO (COLORES)
# ==========================================
@app.route('/api/estado-calendario')
@login_required
def estado_calendario():
    # Buscamos todos los reportes del usuario
    reportes = db.session.query(Reporte.fecha_operativa, Reporte.turno).filter_by(user_id=current_user.id).all()
    
    # Agrupamos en memoria
    # Estructura: { "2025-11-28": {"Mañana", "Noche"}, ... }
    dias = {}
    for r in reportes:
        if not r.fecha_operativa: continue
        if r.fecha_operativa not in dias: dias[r.fecha_operativa] = set()
        dias[r.fecha_operativa].add(r.turno)
    
    resultado = []
    hoy = datetime.now().date().strftime('%Y-%m-%d')
    
    for fecha, turnos in dias.items():
        cantidad = len(turnos)
        estado = "rojo"
        
        # Lógica de colores
        if cantidad >= 3:
            estado = "verde" # Completo
        elif 0 < cantidad < 3:
            # Si es HOY, no lo marcamos como incompleto (amarillo) todavía, lo dejamos neutro o azul
            if fecha == hoy: estado = "azul" 
            else: estado = "amarillo" # Incompleto histórico
            
        resultado.append({"fecha": fecha, "estado": estado})
        
    return jsonify(resultado)

# ==========================================
# 🔄 LANZAR ORDEN (CON FECHA PERSONALIZABLE)
# ==========================================
# ==========================================
# ➕ API: AJUSTAR ESTIMACIÓN (Lógica Matemática)
# ==========================================
@app.route('/api/ajustar-estimacion', methods=['POST'])
@login_required
def ajustar_estimacion():
    try:
        data = request.json
        nuevos_encontrados = data.get('cantidad', 0)
        
        if ESTADO_CARGA["activo"]:
            # Si el agente dice que encontró X registros, ajustamos la meta.
            # Caso 1: Inicio de carga (estimado dummy vs real)
            if ESTADO_CARGA["total_estimado"] == 1000: # Valor inicial dummy
                ESTADO_CARGA["total_estimado"] = max(ESTADO_CARGA["procesados"] + nuevos_encontrados, 1)
            else:
                # Caso 2: Cambio de mes (acumular)
                ESTADO_CARGA["total_estimado"] += nuevos_encontrados
            
            print(f"📊 Barra ajustada: Meta es {ESTADO_CARGA['total_estimado']} reportes.")
            
        return jsonify({"status": "ok"})
    except: return jsonify({"status": "error"}), 500
# ==========================================
# 🛑 API: DETENER CARGA
# ==========================================
@app.route('/api/detener-carga', methods=['POST'])
@login_required
def detener_carga():
    ESTADO_CARGA["activo"] = False
    ESTADO_CARGA["mensaje"] = "🛑 Detenido por usuario"
    
    # Limpiamos la orden para que el agente pare
    for ch in current_user.channels:
        if ch.tipo == 'VOX': ch.comando = None
            
    db.session.commit()
    print("🛑 Carga detenida manualmente.")
    return jsonify({"status": "ok"})

# ==========================================
# 🔄 LANZAR ORDEN (MODIFICADO: INICIO CON ESTIMACIÓN BAJA)
# ==========================================
@app.route('/api/lanzar-orden', methods=['POST'])
# ==========================================
# 🔄 LANZAR ORDEN (Valor Inicial Dummy Alto)
# ==========================================
@app.route('/api/lanzar-orden', methods=['POST'])
@login_required
def lanzar_vox():
    try:
        data = request.json or {}
        fecha_manual = data.get('fecha_inicio')
        
        if fecha_manual:
            rango_inicio = fecha_manual
            rango_fin = datetime.now().strftime('%Y-%m-%d')
        else:
            rango_inicio, rango_fin = get_rango_barrido_seguro()
        
        ESTADO_CARGA["activo"] = True
        ESTADO_CARGA["procesados"] = 0
        # Ponemos 1000 para que la barra empiece en 0% y no salte hasta que el agente cuente
        ESTADO_CARGA["total_estimado"] = 1000 
        ESTADO_CARGA["mensaje"] = f"Iniciando: {rango_inicio}..."
        
        print(f"🔄 ORDEN: {rango_inicio} al {rango_fin}")

        for ch in current_user.channels:
            if ch.tipo == 'VOX': 
                ch.comando = 'EXTRACT'
                import json
                conf = {}
                if ch.config_data:
                    try: conf = json.loads(ch.config_data)
                    except: pass
                
                conf['rango_inicio'] = rango_inicio
                conf['rango_fin'] = rango_fin
                ch.config_data = json.dumps(conf)

        db.session.commit()
        return jsonify({"status": "ok"})

    except Exception as e:
        print(f"🔥 Error 500: {e}")
        return jsonify({"status": "error", "msg": str(e)}), 500
# ==========================================
# 🚀 CORRECCIÓN: AGREGAR RUTAS (@app.route)
# ==========================================

@app.route('/api/lanzar-tiradas', methods=['POST']) # <--- FALTABA ESTO
@login_required
def lanzar_tiradas():
    # Recibimos la fecha del frontend
    data = request.json or {}
    fecha_filtro = data.get('fecha_inicio', '2025-01-01') 

    for ch in current_user.channels:
        # Usamos .upper() para evitar problemas de mayúsculas/minúsculas
        if ch.tipo and ch.tipo.upper() == 'TIRADAS': 
            ch.comando = 'UPLOAD_TIRADAS'
            
            import json
            conf = {}
            if ch.config_data:
                try: conf = json.loads(ch.config_data)
                except: pass
            
            conf['filtro_fecha'] = fecha_filtro
            # CORREGIDO: Decía 'jso<n.dumps' (error de dedo)
            ch.config_data = json.dumps(conf)

    db.session.commit()
    return jsonify({"status": "ok"})

@app.route('/api/estado-tiradas') # <--- FALTABA ESTO PARA EL ERROR 404
@login_required
def estado_tiradas():
    online = False
    last = "-"
    cmd_pendiente = False
    
    for ch in current_user.channels:
        if ch.tipo and ch.tipo.upper() == 'TIRADAS':
            # Consideramos online si reportó en los últimos 10 minutos
            if ch.last_check and (datetime.now() - ch.last_check).total_seconds() < 600:
                online = True
                last = ch.last_check.strftime("%H:%M:%S")
            
            # Verificamos si está ocupado trabajando
            if ch.comando == 'UPLOAD_TIRADAS':
                cmd_pendiente = True
                
    return jsonify({"online": online, "ultima_vez": last, "comando_pendiente": cmd_pendiente})
@app.route('/estacion/config-vox', methods=['GET', 'POST'])
@login_required
def config_vox():
    ch = next((c for c in current_user.channels if c.tipo == 'VOX'), None)
    if not ch:
        ch = Channel(user_id=current_user.id, tipo='VOX', nombre='VOX Principal'); db.session.add(ch); db.session.commit()
    msg = ""
    import json
    if request.method == 'POST':
        try:
            nuevos_datos = {'ip': request.form.get('ip'), 'u': request.form.get('u'), 'p': request.form.get('p')}
            ch.config_data = json.dumps(nuevos_datos); db.session.commit(); msg = "✅ Configuración guardada."
        except: msg = "❌ Error al guardar"
    datos_guardados = {}
    if ch.config_data:
        try: datos_guardados = json.loads(ch.config_data)
        except: pass
    class CredsFake:
        vox_ip = datos_guardados.get('ip', ''); vox_usuario = datos_guardados.get('u', ''); vox_clave = datos_guardados.get('p', '')
    is_online = (ch.status == 'online')
    last_seen = ch.last_check.strftime("%H:%M:%S") if ch.last_check else "Nunca"
    return render_template('configurar_vox.html', cred=CredsFake(), msg=msg, is_online=is_online, last_seen=last_seen, user=current_user)

@app.route('/api/resumen-dia/<string:fecha>')
@login_required
def api_res(fecha):
    reps = Reporte.query.filter_by(fecha_operativa=fecha, user_id=current_user.id).all()
    agrupado = {}
    for r in reps:
        if r.turno not in agrupado: agrupado[r.turno] = { "monto": 0.0, "apertura": r.hora_apertura, "cierre": r.hora_cierre, "count": 0 }
        agrupado[r.turno]["monto"] += r.monto; agrupado[r.turno]["count"] += 1
        if r.hora_apertura and (not agrupado[r.turno]["apertura"] or r.hora_apertura < agrupado[r.turno]["apertura"]): agrupado[r.turno]["apertura"] = r.hora_apertura
        if r.hora_cierre and (not agrupado[r.turno]["cierre"] or r.hora_cierre > agrupado[r.turno]["cierre"]): agrupado[r.turno]["cierre"] = r.hora_cierre
    salida = []
    for turno in ["Mañana", "Tarde", "Noche"]:
        if turno in agrupado:
            d = agrupado[turno]; ini = d["apertura"].strftime("%H:%M:%S") if d["apertura"] else "??"; fin = d["cierre"].strftime("%H:%M:%S") if d["cierre"] else "??"
            salida.append({ "turno": turno, "monto": d["monto"], "cantidad_cierres": d["count"], "horario_real": f"{ini} a {fin}" })
    return jsonify(salida)
@app.route('/estacion/ventas-vendedor', methods=['GET'])
@login_required
def ver_ventas_vendedor():

    from datetime import time, datetime, timedelta
    
    fecha = request.args.get('fecha', datetime.now().strftime('%Y-%m-%d'))

    # HORARIOS TEÓRICOS (solo para elegir el cierre correcto)
    TEORICO = {
        "Mañana": time(14, 0, 0),
        "Tarde": time(22, 0, 0),
        "Noche": time(6, 0, 0)
    }

    # -----------------------------------------
    # 1) OBTENER REPORTES VOX
    # -----------------------------------------
    reportes = Reporte.query.filter_by(
        user_id=current_user.id,
        fecha_operativa=fecha
    ).all()

    lista_reportes_dia = []
    totales_vox = {"Mañana": 0.0, "Tarde": 0.0, "Noche": 0.0}

    for r in reportes:
        if r.turno in totales_vox and r.hora_apertura and r.hora_cierre:
            totales_vox[r.turno] += (r.monto or 0.0)
            lista_reportes_dia.append({
                "turno": r.turno,
                "ap": r.hora_apertura,
                "ci": r.hora_cierre
            })

    # -----------------------------------------
    # 2) FUNCIONES PARA DEFINIR TURNOS REALES
    # -----------------------------------------

    def distancia_a_teorico(hora_real, hora_teorica):
        """Retorna la diferencia absoluta en segundos."""
        dt_real = datetime.combine(datetime.today(), hora_real)
        dt_teo = datetime.combine(datetime.today(), hora_teorica)
        return abs((dt_real - dt_teo).total_seconds())

    def elegir_cierre(turno, cierres):
        """Elegir el cierre más cercano al horario teórico."""
        if not cierres:
            return None
        return min(cierres, key=lambda h: distancia_a_teorico(h.time(), TEORICO[turno]))

    def elegir_apertura(turno, aperturas):
        """Para consistencia, aunque la apertura suele ser única."""
        if not aperturas:
            return None
        return min(aperturas)

    # -----------------------------------------
    # 3) ARMAR TURNOS REALES VOX
    # -----------------------------------------
    aperturas = {"Mañana": [], "Tarde": [], "Noche": []}
    cierres   = {"Mañana": [], "Tarde": [], "Noche": []}

    for r in lista_reportes_dia:
        aperturas[r["turno"]].append(r["ap"])
        cierres[r["turno"]].append(r["ci"])

    rangos = {}

    # MAÑANA
    ap_m = elegir_apertura("Mañana", aperturas["Mañana"])
    ci_m = elegir_cierre("Mañana", cierres["Mañana"])
    if ap_m and ci_m:
        rangos["Mañana"] = (ap_m, ci_m)

    # TARDE
    ap_t = elegir_apertura("Tarde", aperturas["Tarde"])
    ci_t = elegir_cierre("Tarde", cierres["Tarde"])
    if ap_t and ci_t:
        rangos["Tarde"] = (ap_t, ci_t)

    # NOCHE
    # Apertura = cierre de la tarde
    if ci_t:
        ap_n = ci_t
    else:
        ap_n = None

    # Cierre = cercano a 06:00 teórico
    ci_n = elegir_cierre("Noche", cierres["Noche"])

    if ap_n and ci_n:
        # Si cruzamos medianoche, aseguramos que cierre sea día siguiente
        if ci_n <= ap_n:
            ci_n = ci_n + timedelta(days=1)

        rangos["Noche"] = (ap_n, ci_n)

    # Ordenar turnos por apertura para asignación
    rangos_ordenados = sorted(
        [(t, ap, ci) for t, (ap, ci) in rangos.items()],
        key=lambda x: x[1]
    )

    # -----------------------------------------
    # 4) ASIGNAR TURNO A CADA VENTA
    # -----------------------------------------
    ventas = VentaVendedor.query.filter_by(
        user_id=current_user.id,
        fecha=fecha
    ).all()

    res = {"Mañana": [], "Tarde": [], "Noche": [], "Sin Asignar": []}

    t_l = 0
    t_p = 0

    def asignar_turno(dt_venta):
        """Asignación estricta por rango real VOX."""
        for turno, ap, ci in rangos_ordenados:
            if ap <= dt_venta <= ci:
                return turno

        # SI NO ENCAJA EXACTO:
        for idx, (turno, ap, ci) in enumerate(rangos_ordenados):

            if dt_venta > ci:
                if idx + 1 < len(rangos_ordenados):
                    return rangos_ordenados[idx + 1][0]
                else:
                    return rangos_ordenados[0][0]

            if dt_venta < ap:
                if idx - 1 >= 0:
                    return rangos_ordenados[idx - 1][0]
                else:
                    return rangos_ordenados[-1][0]

        return "Sin Asignar"

    # PROCESAR VENTAS
    for v in ventas:
        t_l += v.litros
        t_p += v.monto

        try:
            dt_venta = datetime.strptime(
                f"{v.fecha} {v.primer_horario}",
                "%Y-%m-%d %H:%M:%S"
            )
        except:
            res["Sin Asignar"].append(v)
            continue

        turno = asignar_turno(dt_venta)
        if turno not in res:
            turno = "Sin Asignar"

        res[turno].append(v)

    # -----------------------------------------
    # 5) COMPARATIVA (VOX vs VENDEDORES)
    # -----------------------------------------
    comparativa = {}

    for t in ["Mañana", "Tarde", "Noche"]:

        total_yer = sum(
            v.monto for v in res[t]
            if "yer" in str(v.tipo_pago or "").lower()
        )

        total_no_yer = sum(
            v.monto for v in res[t]
            if "yer" not in str(v.tipo_pago or "").lower()
        )

        diff = totales_vox[t] - total_no_yer
        coincide = abs(diff) < 10

        comparativa[t] = {
            "vox": totales_vox[t],
            "vendedores_contado": total_no_yer,
            "total_yer": total_yer,
            "diferencia": diff,
            "coincide": coincide
        }

    # -----------------------------------------
    # 6) ENVIAR A PANTALLA
    # -----------------------------------------
  
    return render_template(
        "ventas_vendedor.html",
        ventas_por_turno=res,
        fecha=fecha,
        t_litros=t_l,
        t_plata=t_p,
        limites=rangos,
        user=current_user,
        comparativa=comparativa
    )

    
from sqlalchemy import insert
from datetime import timedelta
import pandas as pd
import traceback

@app.route("/subir_ventas_vendedor", methods=["POST"])
@login_required
def subir_ventas_vendedor():

    if "archivo" not in request.files:
        flash("No se seleccionó archivo.", "error")
        return redirect(url_for("ver_ventas_vendedor"))

    archivo = request.files["archivo"]

    if archivo.filename == "":
        flash("Archivo no válido.", "error")
        return redirect(url_for("ver_ventas_vendedor"))

    # ============================================================
    # 1) LEER ARCHIVO COMPLETO SIN AFECTAR RAM
    # ============================================================
    if archivo.filename.lower().endswith(".csv"):
        try:
            df_raw = pd.read_csv(archivo, header=None, engine="c")
        except:
            archivo.seek(0)
            df_raw = pd.read_csv(archivo, sep=";", header=None, engine="python")
    else:
        df_raw = pd.read_excel(archivo, header=None)

    # ============================================================
    # 2) DETECTAR AUTOMÁTICAMENTE LA FILA DE CABECERA
    # ============================================================
    fila_tabla = -1

    for i, row in df_raw.iterrows():
        valores = [str(c).strip().lower() for c in row]

        tiene_vendedor = any("vendedor" in v for v in valores)
        tiene_importe = any(
            ("importe" in v) or ("monto" in v) or ("total" in v)
            for v in valores
        )

        if tiene_vendedor and tiene_importe:
            fila_tabla = i
            break

    if fila_tabla == -1:
        flash("❌ No se encontró la cabecera de ventas (falta 'Vendedor' o 'Importe').", "error")
        return redirect(url_for("ver_ventas_vendedor"))

    # ============================================================
    # 3) CREAR DF DEFINITIVO USANDO ESA CABECERA
    # ============================================================
    df = df_raw.iloc[fila_tabla + 1:].copy()

    df.columns = (
        df_raw.iloc[fila_tabla]
        .astype(str).str.strip().str.lower().str.replace(" ", "_")
    )

    # ============================================================
    # 4) MAPEO DE COLUMNAS A NOMBRES ESTÁNDAR
    # ============================================================
    map_cols = {}
    for c in df.columns:
        if "fecha" in c: map_cols[c] = "Fecha"
        elif "hora" in c: map_cols[c] = "Hora"
        elif "vendedor" in c: map_cols[c] = "Vendedor"
        elif "producto" in c or "comb" in c: map_cols[c] = "Combustible"
        elif "vol" in c or "litro" in c: map_cols[c] = "Litros"
        elif "importe" in c or "monto" in c or "total" in c: map_cols[c] = "Importe"
        elif "precio" in c: map_cols[c] = "Precio"
        elif "dur" in c: map_cols[c] = "DuracionSeg"
        elif "tipo" in c and "pago" in c: map_cols[c] = "TipoPago"

    df = df.rename(columns=map_cols)

    if "Vendedor" not in df.columns or "Importe" not in df.columns:
        flash("❌ Archivo inválido: faltan columnas obligatorias.", "error")
        return redirect(url_for("ver_ventas_vendedor"))

    # ============================================================
    # 5) ARMAR FECHA + HORA REAL (Fecha_DT) y primer_horario
    # ============================================================
    if "Hora" in df.columns:
        s_fecha = df["Fecha"].astype(str)
        s_hora = df["Hora"].astype(str)

        df["Fecha_DT"] = pd.to_datetime(
            s_fecha + " " + s_hora,
            dayfirst=True,
            errors="coerce"
        )
    else:
        df["Fecha_DT"] = pd.to_datetime(df["Fecha"], dayfirst=True, errors="coerce")

    df = df.dropna(subset=["Fecha_DT"])
    df["Fecha_Str"] = df["Fecha_DT"].dt.strftime("%Y-%m-%d")
    df["primer_horario"] = df["Fecha_DT"].dt.strftime("%H:%M:%S")

    # ============================================================
    # 6) LIMPIEZA NUMÉRICA
    # ============================================================
    for col in ["Litros", "Importe", "Precio", "DuracionSeg"]:
        if col not in df.columns:
            df[col] = 0
        else:
            df[col] = (
                df[col].astype(str)
                .str.replace("$", "")
                .str.replace(",", "")
                .str.replace(".", "", regex=False)
                .str.strip()
            )

            df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0)

    if "TipoPago" not in df.columns:
        df["TipoPago"] = ""

    # ============================================================
    # 7) ARMAR CAMPOS PARA LA TABLA ventas_vendedor
    # ============================================================
    df["user_id"] = current_user.id
    df["fecha"] = df["Fecha_Str"]
    df["vendedor"] = df["Vendedor"]
    df["combustible"] = df.get("Combustible", "")
    df["litros"] = df["Litros"]
    df["monto"] = df["Importe"]
    df["precio"] = df["Precio"]
    df["tipo_pago"] = df["TipoPago"]
    df["duracion_seg"] = df["DuracionSeg"]

    campos_sql = [
        "user_id", "fecha", "vendedor", "combustible",
        "litros", "monto", "precio",
        "primer_horario", "tipo_pago", "duracion_seg"
    ]

    data_to_insert = df[campos_sql].to_dict("records")

    # ============================================================
    # 8) INSERTAR TODO EN LA BASE
    # ============================================================
    db.session.bulk_insert_mappings(VentaVendedor, data_to_insert)
    db.session.commit()

    flash("✔ Archivo procesado exitosamente.", "success")
    return redirect(url_for("ver_ventas_vendedor"))
@app.route('/estacion/tiradas', methods=['GET'])
@login_required
def ver_tiradas_web(): 
    fecha = request.args.get('fecha', datetime.now().strftime('%Y-%m-%d'))
    
    # 1. TRAER TODAS LAS TIRADAS DEL DÍA
    tiradas = Tirada.query.filter_by(user_id=current_user.id, fecha_operativa=fecha).all()
    total_plata = sum([t.monto for t in tiradas])
    
    # 2. LÓGICA INTELIGENTE DE REASIGNACIÓN DE TURNOS
    # Agrupamos temporalmente por vendedor para analizar su comportamiento
    tiradas_por_vendedor = {}
    for t in tiradas:
        if t.vendedor not in tiradas_por_vendedor: tiradas_por_vendedor[t.vendedor] = []
        tiradas_por_vendedor[t.vendedor].append(t)
    
    # Definimos límites horarios estrictos para referencia
    def get_turno_estricto(hora_str):
        try:
            h = datetime.strptime(hora_str, "%H:%M:%S").hour
            if 6 <= h < 14: return "Mañana"
            elif 14 <= h < 22: return "Tarde"
            else: return "Noche"
        except: return "Sin Asignar"

    # Procesamos cada vendedor
    for vendedor, lista_tiradas in tiradas_por_vendedor.items():
        # A. Calculamos el turno "estricto" de cada tirada
        turnos_detectados = []
        for t in lista_tiradas:
            t.turno_calc = get_turno_estricto(t.hora) # Atributo temporal
            turnos_detectados.append(t.turno_calc)
        
        # B. Encontramos el Turno Dominante (donde hizo más tiradas)
        if not turnos_detectados: continue
        conteo = Counter(turnos_detectados)
        turno_dominante = conteo.most_common(1)[0][0] # El más repetido (ej: "Mañana")
        
        # C. Aplicamos corrección (Tolerance Window)
        # Si el turno dominante es Mañana, y tiene una tirada en Tarde a las 14:10, la pasamos a Mañana.
        for t in lista_tiradas:
            # Si el turno calculado es distinto al dominante
            if t.turno_calc != turno_dominante:
                try:
                    h_obj = datetime.strptime(t.hora, "%H:%M:%S")
                    h_val = h_obj.hour + (h_obj.minute / 60.0)
                    
                    # CASO: Es Mañana pero se pasó a Tarde (ej: 14:15)
                    if turno_dominante == "Mañana" and t.turno_calc == "Tarde":
                        # Si es antes de las 15:00 (1 hora de tolerancia), lo traemos a Mañana
                        if h_val < 15.0: 
                            t.turno_calc = "Mañana"
                            
                    # CASO: Es Tarde pero se pasó a Noche (ej: 22:15)
                    elif turno_dominante == "Tarde" and t.turno_calc == "Noche":
                        if h_val < 23.0: 
                            t.turno_calc = "Tarde"
                            
                    # CASO: Es Noche pero parece Mañana (ej: 06:10 am antes de irse)
                    elif turno_dominante == "Noche" and t.turno_calc == "Mañana":
                        if h_val < 7.0: 
                            t.turno_calc = "Noche"
                except: pass

    # 3. CONSTRUIR ESTRUCTURA FINAL PARA JINJA
    # Ahora agrupamos usando el 'turno_calc' ya corregido
    datos_agrupados = { "Mañana": [], "Tarde": [], "Noche": [], "Sin Asignar": [] }
    
    for t in tiradas:
        # Usamos el turno calculado si existe, sino el de la base, sino Noche
        turno_final = getattr(t, 'turno_calc', t.turno or "Noche")
        if turno_final not in datos_agrupados: turno_final = "Sin Asignar"
        datos_agrupados[turno_final].append(t)

    return render_template('tiradas.html', 
                           tiradas_por_turno=datos_agrupados, 
                           fecha=fecha, 
                           t_plata=total_plata, 
                           t_sobres=len(tiradas))
if __name__ == '__main__': 
    app.run(host='0.0.0.0', port=10000)