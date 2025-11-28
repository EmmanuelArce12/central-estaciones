import os
import secrets
import difflib
import pandas as pd
import json
import random
from flask import Flask, request, jsonify, render_template, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, time, timedelta
from dotenv import load_dotenv

# Cargar variables de entorno
load_dotenv()

app = Flask(__name__)

# --- CONFIGURACIÓN ---
db_url = os.environ.get('DATABASE_URL', 'sqlite:///local.db')
if db_url and db_url.startswith("postgres://"):
    db_url = db_url.replace("postgres://", "postgresql://", 1)

app.config['SQLALCHEMY_DATABASE_URI'] = db_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'CLAVE_DEFAULT_SEGURA')

db = SQLAlchemy(app)
migrate = Migrate(app, db)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# --- FUNCIONES AUXILIARES ---
def calcular_info_operativa(fecha_hora_str):
    try:
        dt = pd.to_datetime(fecha_hora_str)
        hora = dt.hour
        fecha_op = dt.date()
        turno = "Noche"
        if 6 <= hora < 14: turno = "Mañana"
        elif 14 <= hora < 22: turno = "Tarde"
        else:
            if hora < 6: fecha_op = fecha_op - timedelta(days=1)
        return fecha_op.strftime('%Y-%m-%d'), turno
    except: return datetime.now().strftime('%Y-%m-%d'), "Sin Asignar"

# --- MODELOS ---

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), default='estacion', nullable=False)
    
    # RELACIÓN: Un usuario tiene MUCHOS canales
    channels = db.relationship('Channel', backref='usuario', lazy=True, cascade="all, delete-orphan")
    
    # Relaciones de datos
    cliente_info = db.relationship('Cliente', backref='usuario', uselist=False, cascade="all, delete-orphan")
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
    
    tipo = db.Column(db.String(20), nullable=False)   # 'VOX' o 'TIRADAS'
    nombre = db.Column(db.String(50), nullable=False) # Ej: "Caja 1", "Surtidores"
    
    token = db.Column(db.String(100), unique=True, nullable=True)
    code = db.Column(db.String(20), nullable=True)
    status = db.Column(db.String(20), default='offline')
    last_check = db.Column(db.DateTime)
    comando = db.Column(db.String(50), nullable=True)
    
    # Para guardar IP/User/Pass del VOX en formato JSON
    config_data = db.Column(db.Text, nullable=True) 

class Cliente(db.Model):
    __tablename__ = 'clientes'
    id = db.Column(db.Integer, primary_key=True)
    nombre_fantasia = db.Column(db.String(100))
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), unique=True)

# (Este modelo queda obsoleto con Channels, pero lo dejamos para no romper migraciones si existen datos viejos)
class CredencialVox(db.Model):
    __tablename__ = 'credenciales_vox'
    id = db.Column(db.Integer, primary_key=True)
    vox_ip = db.Column(db.String(50))
    vox_usuario = db.Column(db.String(50))
    vox_clave = db.Column(db.String(50))
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

# --- RUTAS WEB ---

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
        # 1. CREAR ESTACIÓN (Crea canales por defecto)
        if 'create_user' in request.form:
            u = request.form.get('username'); p = request.form.get('password')
            if User.query.filter_by(username=u).first(): msg = "❌ Usuario existe."
            else:
                nu = User(username=u, role='estacion'); nu.set_password(p)
                db.session.add(nu); db.session.commit()
                db.session.add(Cliente(nombre_fantasia=request.form.get('nombre'), user_id=nu.id))
                # Canales Base
                db.session.add(Channel(user_id=nu.id, tipo='VOX', nombre='VOX Principal'))
                db.session.add(Channel(user_id=nu.id, tipo='TIRADAS', nombre='Caja Principal'))
                db.session.commit()
                msg = "✅ Estación creada."

        # 2. AGREGAR NUEVO CANAL (+)
        elif 'add_channel' in request.form:
            uid = request.form.get('user_id')
            db.session.add(Channel(user_id=uid, tipo=request.form.get('tipo'), nombre=request.form.get('nombre')))
            db.session.commit()
            msg = "✅ Canal agregado."

        # 3. VINCULAR CANAL ESPECÍFICO
        elif 'link_channel' in request.form:
            ch = Channel.query.get(request.form.get('channel_id'))
            code = request.form.get('pairing_code').strip().upper()
            if ch and code:
                ch.code = code; ch.status = 'waiting'; db.session.commit()
                msg = f"🔗 Esperando conexión en {ch.nombre}"

        # 4. BORRAR CANAL
        elif 'delete_channel' in request.form:
            db.session.delete(Channel.query.get(request.form.get('channel_id')))
            db.session.commit()

        # 5. DESVINCULAR (Revocar)
        elif 'revoke_channel' in request.form:
            ch = Channel.query.get(request.form.get('channel_id'))
            if ch: ch.token = None; ch.status = 'offline'; ch.code = None; db.session.commit()

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
            
            channels_data.append({
                "id": ch.id,
                "nombre": ch.nombre,
                "tipo": ch.tipo,
                "status": st,
                "token": ch.token,
                "code": ch.code,
                "last_check": ch.last_check.strftime('%H:%M') if ch.last_check else "-"
            })
            
        data.append({
            "id": u.id,
            "username": u.username,
            "cliente": u.cliente_info.nombre_fantasia if u.cliente_info else "-",
            "channels": channels_data
        })
    return jsonify(data)

# --- APIS UNIFICADAS (ROUTER INTELIGENTE DE CANALES) ---

# 1. HANDSHAKE GENÉRICO (Sirve para VOX, TIRADAS y futuros canales)
@app.route('/api/handshake/tiradas', methods=['POST']) 
@app.route('/api/handshake/poll', methods=['POST'])
def handshake_generic():
    code = request.json.get('code', '').strip().upper()
    # Buscamos qué canal tiene este código
    ch = Channel.query.filter_by(code=code).first()
    
    if ch:
        if not ch.token: ch.token = secrets.token_hex(32)
        ch.code = None; ch.status = 'online'; ch.last_check = datetime.now()
        db.session.commit()
        return jsonify({"status": "linked", "api_token": ch.token}), 200
    
    return jsonify({"status": "waiting"}), 200

# 2. SYNC / LATIDO (Sirve para VOX y TIRADAS)
@app.route('/api/tiradas/sync', methods=['POST'])
@app.route('/api/agent/sync', methods=['POST'])
def sync_generic():
    token = request.headers.get('X-API-TOKEN')
    ch = Channel.query.filter_by(token=token).first()
    
    if not ch: return jsonify({"status": "revoked"}), 401
    
    ch.status = 'online'; ch.last_check = datetime.now()
    resp = {"status": "ok", "command": ch.comando}
    
    # Si es VOX, inyectamos credenciales si hay
    if ch.tipo == 'VOX':
        if ch.comando == 'EXTRACT': ch.comando = None
        import json
        conf = json.loads(ch.config_data) if ch.config_data else {}
        resp['config'] = {"ip": conf.get('ip'), "u": conf.get('u'), "p": conf.get('p')}
    
    db.session.commit()
    return jsonify(resp), 200

# 3. RECEPCIÓN ARCHIVOS
@app.route('/api/recepcion-tiradas', methods=['POST'])
def api_recepcion_tiradas():
    token = request.headers.get('X-API-TOKEN')
    ch = Channel.query.filter_by(token=token).first()
    
    if not ch or ch.tipo != 'TIRADAS': 
        return jsonify({"status": "error", "msg": "Token invalido o canal incorrecto"}), 401
    
    user = ch.usuario 
    
    if 'archivo' not in request.files: return jsonify({"status": "error"}), 400
    archivo = request.files['archivo']
    
    try:
        import io
        contenido = archivo.read()
        df = None
        
        # Intentar separadores
        for sep in [',', ';', '\t', '\s+']:
            try:
                s = io.BytesIO(contenido)
                temp = pd.read_csv(s, sep=sep, engine='python') if sep=='\s+' else pd.read_csv(s, sep=sep)
                cols = [c.lower().strip() for c in temp.columns]
                if 'nombre' in cols and ('total bolsa' in cols or 'total dep.' in cols): df = temp; break
            except: continue
            
        if df is None: df = pd.read_csv(io.BytesIO(contenido))

        # Limpieza
        df.columns = df.columns.astype(str).str.strip()
        
        def get_col(keys): return next((c for c in df.columns if any(k.lower() in c.lower() for k in keys)), None)
        
        c_nom = get_col(['nombre', 'vendedor'])
        c_monto = get_col(['total bolsa', 'total dep'])
        c_fecha = get_col(['fecha', 'hora'])
        c_sector = get_col(['sector'])
        c_dni = get_col(['dni'])
        c_trans = get_col(['transaccion', 'transacción'])

        if not c_monto or not c_nom: return jsonify({"status": "error", "msg": "Columnas faltantes"}), 400

        fecha_hoy = datetime.now().strftime('%Y-%m-%d')
        # Fuzzy Match
        ventas_exist = VentaVendedor.query.filter_by(user_id=user.id, fecha=fecha_hoy).all()
        oficiales = list(set([v.vendedor for v in ventas_exist]))
        import difflib
        
        count = 0
        for _, row in df.iterrows():
            try:
                # 1. CALCULAR FECHA Y TURNO REAL
                fecha_str_csv = str(row[c_fecha]) if c_fecha else str(datetime.now())
                fecha_op, turno_calc = calcular_info_operativa(fecha_str_csv)
                
                id_trans = str(row[c_trans]) if c_trans else f"AUTO-{random.randint(10000,99999)}"
                
                # Evitar duplicados
                if c_trans and Tirada.query.filter_by(user_id=user.id, transaccion=id_trans).first():
                    continue

                nom_raw = str(row[c_nom]).strip()
                nom_fin = nom_raw
                if oficiales:
                    m = difflib.get_close_matches(nom_raw, oficiales, n=1, cutoff=0.4)
                    if m: nom_fin = m[0]

                val = float(str(row[c_monto]).replace('$','').replace(',','.'))
                
                h_str = "-"
                try: h_str = pd.to_datetime(fecha_str_csv).strftime('%H:%M:%S')
                except: pass

                def get_int(key):
                    c = get_col([key])
                    if c:
                        try: return int(float(str(row[c]).replace(',','.')))
                        except: return 0
                    return 0

                t = Tirada(
                    user_id=user.id, fecha_operativa=fecha_op, turno=turno_calc,
                    vendedor=nom_fin, vendedor_raw=nom_raw,
                    monto=val, hora=h_str,
                    dni=str(row[c_dni]) if c_dni else "-",
                    transaccion=id_trans,
                    sector=str(row[c_sector]) if c_sector else "-",
                    
                    b2000=get_int('2000'), b1000=get_int('1000'), b500=get_int('500'),
                    b200=get_int('200'), b100=get_int('100'), cant_billetes=get_int('cant')
                )
                db.session.add(t); count += 1
            except: pass
        
        ch.comando = None
        db.session.commit()
        return jsonify({"status": "ok", "count": count}), 200

    except Exception as e: return jsonify({"status": "error", "msg": str(e)}), 500

# --- VISTAS CLIENTE (ESTACIÓN) ---

@app.route('/estacion/panel')
@login_required
def panel_estacion():
    if current_user.is_superadmin: return redirect(url_for('panel_superadmin'))
    return render_template('station_dashboard.html', user=current_user)

@app.route('/api/lanzar-orden', methods=['POST']) # VOX
@login_required
def lanzar_vox():
    for ch in current_user.channels:
        if ch.tipo == 'VOX': ch.comando = 'EXTRACT'
    db.session.commit()
    return jsonify({"status": "ok"})

@app.route('/api/lanzar-tiradas', methods=['POST']) # TIRADAS
@login_required
def lanzar_tiradas():
    for ch in current_user.channels:
        if ch.tipo == 'TIRADAS': ch.comando = 'UPLOAD_TIRADAS'
    db.session.commit()
    return jsonify({"status": "ok"})

@app.route('/api/estado-tiradas')
@login_required
def estado_tiradas():
    online = False
    last = "-"
    for ch in current_user.channels:
        if ch.tipo == 'TIRADAS':
            if ch.last_check and (datetime.now() - ch.last_check).total_seconds() < 120:
                online = True
                last = ch.last_check.strftime("%H:%M:%S")
    return jsonify({"online": online, "ultima_vez": last})

@app.route('/estacion/config-vox', methods=['GET', 'POST'])
@login_required
def config_vox():
    ch = next((c for c in current_user.channels if c.tipo == 'VOX'), None)
    if not ch: # Auto-fix si no tiene canal
        ch = Channel(user_id=current_user.id, tipo='VOX', nombre='VOX Principal')
        db.session.add(ch); db.session.commit()

    import json
    data = json.loads(ch.config_data) if ch.config_data else {}
    
    if request.method == 'POST':
        new_data = {'ip': request.form.get('ip'), 'u': request.form.get('u'), 'p': request.form.get('p')}
        ch.config_data = json.dumps(new_data)
        ch.comando = 'EXTRACT'
        db.session.commit()
        
    class DummyCred:
        vox_ip = data.get('ip', '')
        vox_usuario = data.get('u', '')
        vox_clave = data.get('p', '')
    
    return render_template('configurar_vox.html', cred=DummyCred(), user=current_user)

# --- VENTAS VENDEDOR Y REPORTES (Siguen igual, pero verificadas) ---
@app.route('/api/resumen-dia/<string:fecha>')
@login_required
def api_res(fecha):
    reps = Reporte.query.filter_by(fecha_operativa=fecha, user_id=current_user.id).all()
    agrupado = {}
    for r in reps:
        if r.turno not in agrupado: agrupado[r.turno] = { "monto": 0.0, "apertura": r.hora_apertura, "cierre": r.hora_cierre, "count": 0 }
        agrupado[r.turno]["monto"] += r.monto
        agrupado[r.turno]["count"] += 1
        if r.hora_apertura and (not agrupado[r.turno]["apertura"] or r.hora_apertura < agrupado[r.turno]["apertura"]): agrupado[r.turno]["apertura"] = r.hora_apertura
        if r.hora_cierre and (not agrupado[r.turno]["cierre"] or r.hora_cierre > agrupado[r.turno]["cierre"]): agrupado[r.turno]["cierre"] = r.hora_cierre
    salida = []
    for turno in ["Mañana", "Tarde", "Noche"]:
        if turno in agrupado:
            d = agrupado[turno]
            ini = d["apertura"].strftime("%H:%M:%S") if d["apertura"] else "??"
            fin = d["cierre"].strftime("%H:%M:%S") if d["cierre"] else "??"
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

@app.route('/estacion/tiradas', methods=['GET'])
@login_required
def ver_tiradas():
    fecha = request.args.get('fecha', datetime.now().strftime('%Y-%m-%d'))
    tiradas = Tirada.query.filter_by(user_id=current_user.id, fecha_operativa=fecha).all()
    total_plata = sum([t.monto for t in tiradas])
    return render_template('tiradas.html', tiradas=tiradas, fecha=fecha, t_plata=total_plata, t_sobres=len(tiradas))

@app.route('/estacion/subir-tiradas', methods=['POST'])
@login_required
def subir_tiradas():
    # Esta ruta es para subida manual desde el navegador
    # Para simplificar, redirigimos, pero aquí se podría implementar la lectura de CSV manual
    # usando la misma lógica que la API pero con current_user.id
    if 'archivo' not in request.files: return redirect(url_for('ver_tiradas'))
    return redirect(url_for('ver_tiradas'))

# 1. API DE RECEPCIÓN (Usa token_tiradas)
@app.route('/api/recepcion-tiradas', methods=['POST'])
def api_recepcion_tiradas():
    print("🔵 [API] Recibiendo archivo de tirada...")
    
    token = request.headers.get('X-API-TOKEN')
    user = User.query.filter_by(token_tiradas=token).first()
    
    if not user: 
        print(f"❌ Token rechazado: {token}")
        return jsonify({"status": "error", "msg": "Token invalido"}), 401

    if 'archivo' not in request.files: return jsonify({"status": "error", "msg": "Sin archivo"}), 400
    archivo = request.files['archivo']
    
    try:
        # 1. LECTURA FLEXIBLE DEL CSV
        import io
        contenido = archivo.read()
        df = None
        
        # Probamos separadores comunes (Tu archivo parece usar tabulaciones o espacios múltiples)
        for sep in [',', ';', '\t', '\s+']:
            try:
                stream = io.BytesIO(contenido)
                # engine='python' ayuda con separadores complejos
                df_temp = pd.read_csv(stream, sep=sep, engine='python') if sep == '\s+' else pd.read_csv(stream, sep=sep)
                
                # Verificamos si encontró columnas clave
                cols = [c.lower().strip() for c in df_temp.columns]
                if 'nombre' in cols and ('total bolsa' in cols or 'total dep.' in cols):
                    df = df_temp
                    print(f"✅ Separador detectado: '{sep}'")
                    break
            except: continue
            
        if df is None:
            # Último intento: lectura default
            stream = io.BytesIO(contenido)
            df = pd.read_csv(stream)

        # 2. LIMPIEZA DE NOMBRES DE COLUMNA (Quitar espacios extra)
        df.columns = df.columns.astype(str).str.strip()
        print(f"🔍 Columnas encontradas: {list(df.columns)}")

        # 3. MAPEO EXACTO PARA TU ARCHIVO
        # Buscamos la columna que contenga "Nombre" (para Vendedor)
        col_vend = next((c for c in df.columns if 'Nombre' in c), None)
        
        # Buscamos la columna que contenga "Total Bolsa" o "Total dep." (para Monto)
        col_monto = next((c for c in df.columns if 'Total Bolsa' in c or 'Total dep.' in c), None)
        
        # Buscamos Fecha/Hora
        col_fecha_hora = next((c for c in df.columns if 'Fecha' in c and 'Hora' in c), None)
        
        # Buscamos Sector (para turno)
        col_sector = next((c for c in df.columns if 'Sector' in c), None)

        if not col_monto or not col_vend:
            msg = f"No se encontraron columnas. Buscamos 'Nombre' y 'Total Bolsa'. Vimos: {list(df.columns)}"
            print(f"❌ {msg}")
            return jsonify({"status": "error", "msg": msg}), 400

        # 4. PROCESAMIENTO
        fecha_hoy = datetime.now().strftime('%Y-%m-%d')
        
        # Preparamos comparación de nombres
        ventas_existentes = VentaVendedor.query.filter_by(user_id=user.id, fecha=fecha_hoy).all()
        nombres_oficiales = list(set([v.vendedor for v in ventas_existentes]))

        count = 0
        import difflib

        for _, row in df.iterrows():
            try:
                # OBTENER DATOS
                nombre_csv = str(row[col_vend]).strip()
                
                # Limpieza de Monto
                val_str = str(row[col_monto]).replace('$','').replace(',','.') # 10000 -> 10000.0
                try: val = float(val_str)
                except: val = 0.0

                # Obtener Hora desde la columna combinada "2022-09-21 04:43:21"
                hora_str = "-"
                if col_fecha_hora and pd.notnull(row[col_fecha_hora]):
                    try:
                        # Intentamos parsear la fecha completa y sacar la hora
                        dt = pd.to_datetime(row[col_fecha_hora])
                        hora_str = dt.strftime('%H:%M:%S')
                        # Opcional: Usar la fecha del archivo en vez de 'hoy' si quisieras
                        # fecha_hoy = dt.strftime('%Y-%m-%d') 
                    except: pass

                # Fuzzy Match de Nombre
                nombre_final = nombre_csv
                if nombres_oficiales:
                    matches = difflib.get_close_matches(nombre_csv, nombres_oficiales, n=1, cutoff=0.4)
                    if matches: nombre_final = matches[0]

                # Guardar en DB
                db.session.add(Tirada(
                    user_id=user.id,
                    fecha_operativa=fecha_hoy,
                    vendedor=nombre_final,
                    vendedor_raw=nombre_csv,
                    monto=val,
                    hora=hora_str,
                    turno=str(row[col_sector]) if col_sector else "-", # Guardamos "Playa Turno Noche" aquí
                    sector="-", 
                    detalle_extra="Importado Autom."
                ))
                count += 1
            except Exception as e:
                print(f"⚠️ Error fila: {e}")

        user.comando_tiradas = None 
        db.session.commit()
        print(f"💾 Guardadas {count} tiradas.")
        return jsonify({"status": "ok", "count": count}), 200

    except Exception as e:
        print(f"🔥 Error Servidor: {e}")
        return jsonify({"status": "error", "msg": str(e)}), 500# 2. LANZAR ORDEN (Boton Naranja)
@app.route('/api/lanzar-tiradas', methods=['POST'])
@login_required
def lanzar_orden_tiradas():
    current_user.comando_tiradas = 'UPLOAD_TIRADAS'
    db.session.commit()
    return jsonify({"status": "ok"})

# 3. SEMÁFORO Y ESTADO
@app.route('/api/estado-tiradas')
@login_required
def estado_tiradas():
    is_online = False
    if current_user.last_check_tiradas:
        delta = datetime.now() - current_user.last_check_tiradas
        if delta.total_seconds() < 120: is_online = True
            
    return jsonify({
        "online": is_online,
        "comando_pendiente": current_user.comando_tiradas == 'UPLOAD_TIRADAS',
        "ultima_vez": current_user.last_check_tiradas.strftime("%H:%M:%S") if current_user.last_check_tiradas else "-"
    })

# 4. HANDSHAKE (Vinculación)
@app.route('/api/handshake/tiradas', methods=['POST'])
def handshake_tiradas():
    code = request.json.get('code', '').strip().upper()
    user = User.query.filter_by(code_tiradas=code).first()
    
    if user:
        if not user.token_tiradas: user.token_tiradas = secrets.token_hex(32)
        user.code_tiradas = None; user.status_tiradas = 'online'
        user.last_check_tiradas = datetime.now()
        db.session.commit()
        return jsonify({"status": "linked", "api_token": user.token_tiradas}), 200
    return jsonify({"status": "waiting"}), 200

# 5. LATIDO (Sync)
@app.route('/api/tiradas/sync', methods=['POST'])
def tiradas_sync():
    token = request.headers.get('X-API-TOKEN')
    user = User.query.filter_by(token_tiradas=token).first()
    
    if not user: return jsonify({"status": "revoked"}), 401
    
    user.status_tiradas = 'online'
    user.last_check_tiradas = datetime.now()
    db.session.commit()
    return jsonify({"status": "ok", "command": user.comando_tiradas}), 200

if __name__ == '__main__': 
    app.run(host='0.0.0.0', port=10000)