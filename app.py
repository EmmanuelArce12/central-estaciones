import os
import secrets
import difflib
import pandas as pd
import json
import random
import io
import traceback # Nuevo para ver errores reales
from collections import Counter
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
# 🛠️ FUNCIONES AUXILIARES
# ==========================================

def calcular_info_operativa(fecha_hora_str):
    """Calcula fecha operativa y turno basándose en la hora"""
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

def procesar_datos_turno(s):
    """Procesa strings complejos del reporte VOX"""
    try:
        if '(' not in s:
            return calcular_info_operativa(s) + (None, None)

        contenido = s.split('(')[1].replace(')', '') 
        partes = contenido.split(' - ')
        str_apertura = partes[0].strip()
        str_cierre = partes[1].strip()
        
        for fmt in ["%Y/%m/%d %H:%M:%S", "%d/%m/%Y %H:%M:%S"]:
            try:
                dt_apertura = datetime.strptime(str_apertura, fmt)
                dt_cierre = datetime.strptime(str_cierre, fmt)
                break
            except: continue
        
        h = dt_cierre.hour
        fecha_obj = dt_cierre.date()
        turno = "Noche"
        
        if 6 <= h < 14: turno = "Mañana"
        elif 14 <= h < 22: turno = "Tarde"
        else:
            if h < 6: fecha_obj = fecha_obj - timedelta(days=1)
        
        return fecha_obj.strftime("%Y-%m-%d"), turno, dt_cierre, dt_apertura
    except: 
        return datetime.now().strftime("%Y-%m-%d"), "Error", datetime.now(), datetime.now()

# ==========================================
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
@app.route('/api/reportar', methods=['POST'])
def api_reportar_vox():
    try:
        tk = request.headers.get('X-API-TOKEN')
        ch = Channel.query.filter_by(token=tk).first()
        if not ch or ch.tipo != 'VOX': return jsonify({"status":"error", "msg":"Token invalido"}), 401
        n = request.json; nid = n.get('id_interno'); u_id = ch.user_id 
        if Reporte.query.filter_by(id_interno=nid, user_id=u.id).first(): return jsonify({"status":"ignorado"}), 200
        f_op, turno, dt_cierre, dt_apertura = procesar_datos_turno(n.get('fecha'))
        if not f_op: return jsonify({"status":"error_fecha"}), 400
        r = Reporte(user_id=u_id, id_interno=nid, estacion=n.get('estacion'), fecha_completa=n.get('fecha'), monto=n.get('monto'), fecha_operativa=f_op, turno=turno, hora_cierre=dt_cierre, hora_apertura=dt_apertura)
        db.session.add(r); db.session.commit()
        return jsonify({"status":"exito"}), 200
    except Exception as e: return jsonify({"status":"error", "msg": str(e)}), 500

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

@app.route('/api/lanzar-orden', methods=['POST'])
@login_required
def lanzar_vox():
    for ch in current_user.channels:
        if ch.tipo == 'VOX': ch.comando = 'EXTRACT'
    db.session.commit()
    return jsonify({"status": "ok"})

@app.route('/api/lanzar-tiradas', methods=['POST'])
# A. MODIFICAR: LANZAR TIRADAS (Ahora recibe fecha de filtro)
# 1. MODIFICAR: LANZAR ORDEN (Ahora guarda la fecha que eliges en el calendario)
@app.route('/api/lanzar-tiradas', methods=['POST'])
@login_required
def lanzar_tiradas():
    # Recibimos la fecha del frontend (si no envían nada, usa 2025-01-01)
    data = request.json or {}
    fecha_filtro = data.get('fecha_inicio', '2025-01-01')

    for ch in current_user.channels:
        if ch.tipo == 'TIRADAS': 
            ch.comando = 'UPLOAD_TIRADAS'
            
            # Guardamos la fecha en la configuración del canal
            import json
            conf = {}
            if ch.config_data:
                try: conf = json.loads(ch.config_data)
                except: pass
            
            conf['filtro_fecha'] = fecha_filtro
            ch.config_data = json.dumps(conf)

    db.session.commit()
    return jsonify({"status": "ok"})@app.route('/api/estado-tiradas')
@login_required
def estado_tiradas():
    online = False
    last = "-"
    for ch in current_user.channels:
        if ch.tipo == 'TIRADAS':
            if ch.last_check and (datetime.now() - ch.last_check).total_seconds() < 600:
                online = True
                last = ch.last_check.strftime("%H:%M:%S")
    return jsonify({"online": online, "ultima_vez": last})

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
    fecha = request.args.get('fecha', datetime.now().strftime('%Y-%m-%d'))
    reportes = Reporte.query.filter_by(user_id=current_user.id, fecha_operativa=fecha).all()
    limites = { "Mañana": {"inicio": None, "fin": None}, "Tarde": {"inicio": None, "fin": None}, "Noche": {"inicio": None, "fin": None} }
    for r in reportes:
        if r.turno in limites:
            if r.hora_apertura:
                t = r.hora_apertura.time()
                if limites[r.turno]["inicio"] is None or t < limites[r.turno]["inicio"]: limites[r.turno]["inicio"] = t
            if r.hora_cierre:
                t = r.hora_cierre.time()
                if limites[r.turno]["fin"] is None or t > limites[r.turno]["fin"]: limites[r.turno]["fin"] = t
    ventas = VentaVendedor.query.filter_by(user_id=current_user.id, fecha=fecha).all()
    res = { "Mañana": [], "Tarde": [], "Noche": [], "Sin Asignar": [] }
    t_l = 0; t_p = 0
    for v in ventas:
        t_l += v.litros; t_p += v.monto; assigned = False
        try: h = datetime.strptime(v.primer_horario, "%H:%M:%S").time()
        except: res["Sin Asignar"].append(v); continue
        for t, l in limites.items():
            if l["inicio"] and l["fin"]:
                if (l["inicio"] < l["fin"] and l["inicio"] <= h <= l["fin"]) or (l["inicio"] > l["fin"] and (h >= l["inicio"] or h <= l["fin"])):
                    res[t].append(v); assigned = True; break
        if not assigned:
            hr = h.hour
            if 6 <= hr < 14: res["Mañana"].append(v)
            elif 14 <= hr < 22: res["Tarde"].append(v)
            else: res["Noche"].append(v)
    return render_template('ventas_vendedor.html', ventas_por_turno=res, fecha=fecha, t_litros=t_l, t_plata=t_p, limites=limites, user=current_user)

@app.route('/estacion/subir-ventas-vendedor', methods=['POST'])
@login_required
def subir_ventas_vendedor():
    if 'archivo' not in request.files: return redirect(url_for('ver_ventas_vendedor'))
    archivo = request.files['archivo']
    if archivo.filename == '': return redirect(url_for('ver_ventas_vendedor'))

    try:
        df_raw = pd.read_excel(archivo, header=None)
        fila_tabla = -1
        for i, row in df_raw.iterrows():
            if row.astype(str).str.contains('Vendedor').any() and row.astype(str).str.contains('Importe').any():
                fila_tabla = i; break

        if fila_tabla == -1: flash("Error: Formato no reconocido", "error"); return redirect(url_for('ver_ventas_vendedor'))

        df = df_raw.iloc[fila_tabla + 1:].copy()
        df.columns = df_raw.iloc[fila_tabla]
        df.columns = df.columns.astype(str).str.strip().str.title()
        
        # Mapeo flexible
        map_cols = {}
        for c in df.columns:
            if 'Fecha' in c: map_cols[c] = 'Fecha'
            if 'Vendedor' in c: map_cols[c] = 'Vendedor'
            if 'Producto' in c: map_cols[c] = 'Combustible'
            if 'Vol' in c: map_cols[c] = 'Litros'
            if 'Importe' in c: map_cols[c] = 'Importe'
            if 'Precio' in c: map_cols[c] = 'Precio'
            if 'Duracion' in c or 'Duración' in c: map_cols[c] = 'DuracionSeg'
            if 'Tipo' in c: map_cols[c] = 'TipoPago'

        df = df.rename(columns=map_cols)
        df = df.dropna(subset=["Vendedor"])
        
        df['Fecha_DT'] = pd.to_datetime(df['Fecha'], dayfirst=True, errors='coerce')
        if df['Fecha_DT'].dropna().empty: flash("Sin fechas válidas", "error"); return redirect(url_for('ver_ventas_vendedor'))
        
        fecha_auto = df['Fecha_DT'].dropna().dt.date.mode()[0].strftime('%Y-%m-%d')
        
        def safe_float(x):
            try: return float(str(x).replace('.','').replace(',','.'))
            except: return 0.0

        for col in ['Litros', 'Importe', 'Precio', 'DuracionSeg']:
            if col in df.columns: df[col] = df[col].apply(safe_float)

        agregaciones = { 'Fecha': 'first', 'Litros': 'sum', 'Importe': 'sum' }
        if 'Precio' in df.columns: agregaciones['Precio'] = 'first'
        if 'TipoPago' in df.columns: agregaciones['TipoPago'] = 'first'
        if 'DuracionSeg' in df.columns: agregaciones['DuracionSeg'] = 'sum'

        resumen = df.sort_values('Fecha_DT').groupby(['Vendedor', 'Combustible']).agg(agregaciones).reset_index()
        
        VentaVendedor.query.filter_by(user_id=current_user.id, fecha=fecha_auto).delete()
        
        for _, row in resumen.iterrows():
            hora = pd.to_datetime(row['Fecha']).strftime('%H:%M:%S') if pd.notnull(row['Fecha']) else "-"
            
            db.session.add(VentaVendedor(
                user_id=current_user.id, fecha=fecha_auto, vendedor=row['Vendedor'], combustible=row['Combustible'],
                litros=row['Litros'], monto=row['Importe'], precio=row.get('Precio',0), primer_horario=hora,
                tipo_pago=str(row.get('TipoPago','-')), duracion_seg=row.get('DuracionSeg',0)
            ))
        
        db.session.commit()
        return redirect(url_for('ver_ventas_vendedor', fecha=fecha_auto))

    except Exception as e:
        flash(f"Error: {e}", "error"); return redirect(url_for('ver_ventas_vendedor'))

# --- MÓDULO TIRADAS (CANAL 2) ---

# --- VISTA TIRADAS (LÓGICA INTELIGENTE DE TURNOS) ---
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