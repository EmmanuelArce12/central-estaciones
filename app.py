import os
import secrets
import difflib
import pandas as pd
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

# --- MODELOS ---

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), default='estacion', nullable=False)
    
    # --- CANAL 1: VOX (Surtidores) ---
    api_token = db.Column(db.String(100), unique=True, nullable=True)
    device_pairing_code = db.Column(db.String(20), nullable=True)
    status_conexion = db.Column(db.String(20), default='offline')
    comando_pendiente = db.Column(db.String(50), nullable=True)
    last_check = db.Column(db.DateTime)
    
    # --- CANAL 2: TIRADAS (Sobres/CSV) ---
    token_tiradas = db.Column(db.String(100), unique=True, nullable=True) # Token exclusivo Tiradas
    code_tiradas = db.Column(db.String(20), nullable=True)                # Código de vinculación
    status_tiradas = db.Column(db.String(20), default='offline')          # Estado PC Tiradas
    last_check_tiradas = db.Column(db.DateTime)                           # Latido PC Tiradas
    comando_tiradas = db.Column(db.String(50), nullable=True)             # Ordenes (Subir ahora)

    # --- RELACIONES ---
    cliente_info = db.relationship('Cliente', backref='usuario', uselist=False, cascade="all, delete-orphan")
    credenciales_vox = db.relationship('CredencialVox', backref='usuario', uselist=False, cascade="all, delete-orphan")
    reportes = db.relationship('Reporte', backref='usuario', lazy=True, cascade="all, delete-orphan")
    
    # Relación con Tiradas
    tiradas = db.relationship('Tirada', backref='usuario', lazy=True, cascade="all, delete-orphan")
    ventas_vendedor = db.relationship('VentaVendedor', backref='usuario', lazy=True, cascade="all, delete-orphan")

    def set_password(self, p): self.password_hash = generate_password_hash(p)
    def check_password(self, p): return check_password_hash(self.password_hash, p)
    @property
    def is_superadmin(self): return self.role == 'superadmin'

class Cliente(db.Model):
    __tablename__ = 'clientes'
    id = db.Column(db.Integer, primary_key=True)
    nombre_fantasia = db.Column(db.String(100))
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), unique=True)

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
    fecha_operativa = db.Column(db.String(20)) 
    vendedor = db.Column(db.String(100))      
    vendedor_raw = db.Column(db.String(100))  
    monto = db.Column(db.Float)
    hora = db.Column(db.String(20))
    turno = db.Column(db.String(50))
    sector = db.Column(db.String(50))
    detalle_extra = db.Column(db.String(200)) 

# --- INICIALIZACIÓN ---
with app.app_context():
    try:
        db.create_all()
    except Exception as e:
        print(f"⚠️ Advertencia DB: {e}")

@login_manager.user_loader
def load_user(uid): 
    return User.query.get(int(uid))

# --- PARSEO DE FECHAS ---
def procesar_datos_turno(s):
    try:
        contenido = s.split('(')[1].replace(')', '') 
        partes = contenido.split(' - ')
        str_apertura = partes[0].strip()
        str_cierre = partes[1].strip()
        
        dt_apertura = datetime.strptime(str_apertura, "%Y/%m/%d %H:%M:%S")
        dt_cierre = datetime.strptime(str_cierre, "%Y/%m/%d %H:%M:%S")
        
        h = dt_cierre.hour
        fecha_obj = dt_cierre.date()
        turno = "Noche"
        
        if 6 <= h < 14: turno = "Mañana"
        elif 14 <= h < 22: turno = "Tarde"
        else:
            if h < 6: fecha_obj = fecha_obj - timedelta(days=1)
        
        return fecha_obj.strftime("%Y-%m-%d"), turno, dt_cierre, dt_apertura
    except Exception as e: 
        print(f"Error parseando fecha: {s} -> {e}")
        return None, None, None, None

# --- VISTAS BÁSICAS ---

@app.route('/')
def root():
    if current_user.is_authenticated:
        return redirect(url_for('panel_superadmin')) if current_user.is_superadmin else redirect(url_for('panel_estacion'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = ""
    if request.method == 'POST':
        u = request.form.get('username')
        p = request.form.get('password')
        user = User.query.filter_by(username=u).first()
        if user and user.check_password(p):
            login_user(user)
            return redirect(url_for('root'))
        else:
            error = "Credenciales incorrectas."
    return render_template('login.html', error=error)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# --- VISTAS ADMIN ---

@app.route('/admin/dashboard', methods=['GET', 'POST'])
@login_required
def panel_superadmin():
    if not current_user.is_superadmin: return "Acceso Denegado"
    msg = ""
    
    if request.method == 'POST':
        # 1. CREAR USUARIO
        if 'create_user' in request.form:
            u = request.form.get('username'); p = request.form.get('password')
            n = request.form.get('nombre'); r = request.form.get('role')
            if User.query.filter_by(username=u).first():
                msg = "❌ El usuario ya existe."
            else:
                nu = User(username=u, role=r); nu.set_password(p)
                db.session.add(nu); db.session.commit()
                if r == 'estacion':
                    nc = Cliente(nombre_fantasia=n, user_id=nu.id); db.session.add(nc)
                    cv = CredencialVox(user_id=nu.id, vox_ip="", vox_usuario="", vox_clave=""); db.session.add(cv)
                    db.session.commit()
                msg = "✅ Usuario creado."

        # 2. VINCULAR CANAL 1 (VOX)
        elif 'link_pc' in request.form:
            code = request.form.get('pairing_code', '').strip().upper()
            u = User.query.get(request.form.get('user_id'))
            if u and code:
                u.device_pairing_code = code; u.status_conexion = "waiting"; db.session.commit()
                msg = f"🔗 Esperando PC VOX: {code}"

        # 3. VINCULAR CANAL 2 (TIRADAS)
        elif 'link_tiradas' in request.form:
            code = request.form.get('pairing_code', '').strip().upper()
            u = User.query.get(request.form.get('user_id'))
            if u and code:
                u.code_tiradas = code
                u.status_tiradas = "waiting"
                db.session.commit()
                msg = f"🔗 Esperando PC Tiradas: {code}"

        # 4. DESVINCULAR SOLO VOX (Canal 1) <-- NUEVO
        elif 'revoke_vox' in request.form:
            u = User.query.get(request.form.get('user_id'))
            if u: 
                u.api_token = None
                u.status_conexion = "offline"
                u.device_pairing_code = None
                db.session.commit()
                msg = "🚫 PC VOX desvinculada."

        # 5. DESVINCULAR SOLO TIRADAS (Canal 2) <-- NUEVO
        elif 'revoke_tiradas' in request.form:
            u = User.query.get(request.form.get('user_id'))
            if u:
                u.token_tiradas = None
                u.status_tiradas = "offline"
                u.code_tiradas = None
                db.session.commit()
                msg = "🚫 PC Tiradas desvinculada."

    users = User.query.all()
    return render_template('admin_dashboard.html', users=users, msg=msg)
@app.route('/admin/eliminar-estacion/<int:id>', methods=['POST'])
@login_required
def eliminar_estacion(id):
    if not current_user.is_superadmin: return "Acceso Denegado"
    user = User.query.get_or_404(id)
    if user.id == current_user.id: return "Error"
    db.session.delete(user); db.session.commit()
    return redirect(url_for('panel_superadmin'))

@app.route('/admin/api/status-all')
@login_required
def admin_status_all():
    if not current_user.is_superadmin: return jsonify([])
    users = User.query.all()
    data = []
    ahora = datetime.now()
    for u in users:
        # Estado Canal 1
        st = u.status_conexion
        if u.last_check and (ahora - u.last_check).total_seconds() > 120: st = 'offline'
        
        # Estado Canal 2
        st_tiradas = u.status_tiradas
        if u.last_check_tiradas and (ahora - u.last_check_tiradas).total_seconds() > 120: st_tiradas = 'offline'

        data.append({
            "id": u.id, 
            "username": u.username,
            "cliente": u.cliente_info.nombre_fantasia if u.cliente_info else "Sin Nombre",
            "status": st, 
            "code": u.device_pairing_code, 
            "token": u.api_token, 
            "last_check": u.last_check.strftime('%d/%m %H:%M') if u.last_check else "Nunca",
            # Datos Canal 2
            "status_tiradas": st_tiradas,
            "token_tiradas": u.token_tiradas,
            "code_tiradas": u.code_tiradas,
            "last_check_tiradas": u.last_check_tiradas.strftime('%H:%M') if u.last_check_tiradas else '-'
        })
    return jsonify(data)

# --- VISTAS ESTACIÓN ---

@app.route('/estacion/panel')
@login_required
def panel_estacion():
    if current_user.is_superadmin: return redirect(url_for('panel_superadmin'))
    return render_template('station_dashboard.html', user=current_user)

@app.route('/estacion/config-vox', methods=['GET', 'POST'])
@login_required
def config_vox():
    msg = ""
    cred = CredencialVox.query.filter_by(user_id=current_user.id).first()
    
    is_online = False; last_seen = "Nunca"
    if current_user.last_check:
        diff = datetime.now() - current_user.last_check
        if diff.total_seconds() < 60: is_online = True
        last_seen = current_user.last_check.strftime("%H:%M:%S")

    if request.method == 'POST':
        try:
            if not cred: cred = CredencialVox(user_id=current_user.id); db.session.add(cred)
            cred.vox_ip = request.form.get('ip')
            cred.vox_usuario = request.form.get('u')
            cred.vox_clave = request.form.get('p')
            current_user.comando_pendiente = 'EXTRACT'
            db.session.add(current_user); db.session.commit()
            msg = "✅ Configuración enviada." if is_online else "⚠️ Guardado (PC Desconectada)."
        except Exception as e: db.session.rollback(); msg = f"❌ Error: {e}"

    if not cred: cred = CredencialVox(vox_ip="", vox_usuario="", vox_clave="")
    return render_template('configurar_vox.html', cred=cred, msg=msg, user=current_user, is_online=is_online, last_seen=last_seen)

@app.route('/estacion/ver-reportes')
@login_required
def ver_reportes_html():
    return render_template('index.html', usuario=current_user.username)

# --- APIS CANAL 1 (VOX) ---

@app.route('/api/handshake/poll', methods=['POST'])
def handshake_poll():
    code = request.json.get('code', '').strip().upper()
    if not code: return jsonify({"status": "waiting"}), 200
    user = User.query.filter_by(device_pairing_code=code).first()
    if user:
        if not user.api_token: user.api_token = secrets.token_hex(32)
        user.device_pairing_code = None; user.status_conexion = 'online'
        user.last_check = datetime.now(); user.comando_pendiente = 'EXTRACT'
        db.session.commit()
        return jsonify({"status": "linked", "api_token": user.api_token}), 200
    return jsonify({"status": "waiting"}), 200

@app.route('/api/agent/sync', methods=['POST'])
def agent_sync():
    token = request.headers.get('X-API-TOKEN')
    user = User.query.filter_by(api_token=token).first()
    if not user: return jsonify({"status": "revoked"}), 401
    
    user.status_conexion = 'online'
    user.last_check = datetime.now()
    
    cmd = user.comando_pendiente
    # Limpiamos EXTRACT, pero si es de tiradas no deberia estar aqui
    if cmd == 'EXTRACT': 
        user.comando_pendiente = None
    
    conf = {}
    if user.credenciales_vox:
        conf = {"ip": user.credenciales_vox.vox_ip, "u": user.credenciales_vox.vox_usuario, "p": user.credenciales_vox.vox_clave}
        
    db.session.commit()
    return jsonify({"status": "ok", "command": cmd, "config": conf}), 200

@app.route('/api/reportar', methods=['POST'])
def rep():
    try:
        tk = request.headers.get('X-API-TOKEN')
        u = User.query.filter_by(api_token=tk).first()
        if not u: return jsonify({"status":"error"}), 401
        
        n = request.json
        nid = n.get('id_interno')
        
        if Reporte.query.filter_by(id_interno=nid, user_id=u.id).first(): 
            return jsonify({"status":"ignorado"}), 200
            
        f_op, turno, dt_cierre, dt_apertura = procesar_datos_turno(n.get('fecha'))
        if not f_op: return jsonify({"status":"error_fecha"}), 400

        r = Reporte(
            user_id=u.id, id_interno=nid, estacion=n.get('estacion'), 
            fecha_completa=n.get('fecha'), monto=n.get('monto'), 
            fecha_operativa=f_op, turno=turno, 
            hora_cierre=dt_cierre, hora_apertura=dt_apertura
        )
        db.session.add(r)
        db.session.commit()
        return jsonify({"status":"exito"}), 200
    except Exception as e: 
        return jsonify({"status":"error"}), 500

@app.route('/api/ping-ui')
@login_required
def ping(): 
    st = 'online'
    if current_user.last_check and (datetime.now() - current_user.last_check).total_seconds() > 60: st = 'offline'
    return jsonify({"st": st, "cmd": current_user.comando_pendiente == 'EXTRACT'})

@app.route('/api/lanzar-orden', methods=['POST'])
@login_required
def lanzar():
    current_user.comando_pendiente = 'EXTRACT'; db.session.commit()
    return jsonify({"status": "ok"})

@app.route('/api/resumen-dia/<string:fecha>')
@login_required
def api_res(fecha):
    reps = Reporte.query.filter_by(fecha_operativa=fecha, user_id=current_user.id).all()
    agrupado = {}
    
    for r in reps:
        if r.turno not in agrupado:
            agrupado[r.turno] = { "monto": 0.0, "apertura": r.hora_apertura, "cierre": r.hora_cierre, "count": 0 }
        agrupado[r.turno]["monto"] += r.monto
        agrupado[r.turno]["count"] += 1
        
        if r.hora_apertura and (not agrupado[r.turno]["apertura"] or r.hora_apertura < agrupado[r.turno]["apertura"]):
            agrupado[r.turno]["apertura"] = r.hora_apertura
        if r.hora_cierre and (not agrupado[r.turno]["cierre"] or r.hora_cierre > agrupado[r.turno]["cierre"]):
            agrupado[r.turno]["cierre"] = r.hora_cierre

    salida = []
    for turno in ["Mañana", "Tarde", "Noche"]:
        if turno in agrupado:
            d = agrupado[turno]
            ini = d["apertura"].strftime("%H:%M:%S") if d["apertura"] else "??"
            fin = d["cierre"].strftime("%H:%M:%S") if d["cierre"] else "??"
            salida.append({ "turno": turno, "monto": d["monto"], "cantidad_cierres": d["count"], "horario_real": f"{ini} a {fin}" })
        
    return jsonify(salida)

# --- MÓDULO VENTAS VENDEDOR ---

@app.route('/estacion/ventas-vendedor', methods=['GET'])
@login_required
def ver_ventas_vendedor():
    fecha = request.args.get('fecha', datetime.now().strftime('%Y-%m-%d'))
    reportes = Reporte.query.filter_by(user_id=current_user.id, fecha_operativa=fecha).all()
    
    limites_turnos = { "Mañana": {"inicio": None, "fin": None}, "Tarde": {"inicio": None, "fin": None}, "Noche": {"inicio": None, "fin": None} }
    
    for r in reportes:
        if r.turno in limites_turnos:
            if r.hora_apertura:
                t_ini = r.hora_apertura.time()
                if limites_turnos[r.turno]["inicio"] is None or t_ini < limites_turnos[r.turno]["inicio"]: limites_turnos[r.turno]["inicio"] = t_ini
            if r.hora_cierre:
                t_fin = r.hora_cierre.time()
                if limites_turnos[r.turno]["fin"] is None or t_fin > limites_turnos[r.turno]["fin"]: limites_turnos[r.turno]["fin"] = t_fin

    ventas = VentaVendedor.query.filter_by(user_id=current_user.id, fecha=fecha).all()
    ventas_por_turno = { "Mañana": [], "Tarde": [], "Noche": [], "Sin Asignar": [] }
    total_litros = 0; total_plata = 0

    for v in ventas:
        total_litros += v.litros; total_plata += v.monto; asignado = False
        try:
            if not v.primer_horario or v.primer_horario == '-': raise ValueError
            hora_venta = datetime.strptime(v.primer_horario, "%H:%M:%S").time()
        except:
            ventas_por_turno["Sin Asignar"].append(v); continue

        for nombre_turno, limites in limites_turnos.items():
            ini, fin = limites["inicio"], limites["fin"]
            if ini and fin:
                if (ini < fin and ini <= hora_venta <= fin) or (ini > fin and (hora_venta >= ini or hora_venta <= fin)):
                    ventas_por_turno[nombre_turno].append(v); asignado = True; break
        
        if not asignado:
            h = hora_venta.hour
            if 6 <= h < 14: ventas_por_turno["Mañana"].append(v)
            elif 14 <= h < 22: ventas_por_turno["Tarde"].append(v)
            else: ventas_por_turno["Noche"].append(v)

    return render_template('ventas_vendedor.html', ventas_por_turno=ventas_por_turno, fecha=fecha, t_litros=total_litros, t_plata=total_plata, limites=limites_turnos, user=current_user)

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
    token = request.headers.get('X-API-TOKEN')
    user = User.query.filter_by(token_tiradas=token).first() # BUSCAR POR TOKEN TIRADAS
    
    if not user: return jsonify({"status": "error", "msg": "Token invalido"}), 401
    if 'archivo' not in request.files: return jsonify({"status": "error", "msg": "Sin archivo"}), 400
    
    archivo = request.files['archivo']
    try:
        try:
            df = pd.read_csv(archivo)
            if len(df.columns) < 2: df = pd.read_csv(archivo, sep=';')
        except: return jsonify({"status": "error", "msg": "Formato CSV invalido"}), 400

        df.columns = df.columns.astype(str).str.lower().str.strip()
        
        # Mapeo flexible de columnas
        col_monto = next((c for c in df.columns if 'monto' in c or 'importe' in c), None)
        col_vend = next((c for c in df.columns if 'vendedor' in c or 'nombre' in c), None)
        col_hora = next((c for c in df.columns if 'hora' in c), None)
        col_turno = next((c for c in df.columns if 'turno' in c), None)
        col_sector = next((c for c in df.columns if 'sector' in c), None)

        if not col_monto or not col_vend: return jsonify({"status": "error", "msg": "Faltan columnas Vendedor/Monto"}), 400

        fecha_hoy = datetime.now().strftime('%Y-%m-%d')
        
        # Buscar coincidencias de nombre
        ventas_existentes = VentaVendedor.query.filter_by(user_id=user.id, fecha=fecha_hoy).all()
        nombres_oficiales = list(set([v.vendedor for v in ventas_existentes]))

        Tirada.query.filter_by(user_id=user.id, fecha_operativa=fecha_hoy).delete()

        count = 0
        for _, row in df.iterrows():
            nombre_csv = str(row[col_vend]).strip()
            nombre_final = nombre_csv
            if nombres_oficiales:
                matches = difflib.get_close_matches(nombre_csv, nombres_oficiales, n=1, cutoff=0.4)
                if matches: nombre_final = matches[0]

            try: val = float(str(row[col_monto]).replace('$','').replace('.','').replace(',','.'))
            except: val = 0.0

            db.session.add(Tirada(
                user_id=user.id, fecha_operativa=fecha_hoy, vendedor=nombre_final, vendedor_raw=nombre_csv,
                monto=val, hora=str(row[col_hora]) if col_hora else "-",
                turno=str(row[col_turno]) if col_turno else "-", sector=str(row[col_sector]) if col_sector else "-"
            ))
            count += 1
        
        user.comando_tiradas = None # Limpiar orden
        db.session.commit()
        return jsonify({"status": "ok", "count": count}), 200

    except Exception as e: return jsonify({"status": "error", "msg": str(e)}), 500

# 2. LANZAR ORDEN (Boton Naranja)
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