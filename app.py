import os
import secrets
import difflib # <--- IMPORTANTE: Agregar esto para buscar nombres parecidos
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
    api_token = db.Column(db.String(100), unique=True, nullable=True)
    device_pairing_code = db.Column(db.String(20), nullable=True)
    status_conexion = db.Column(db.String(20), default='offline')
    comando_pendiente = db.Column(db.String(50), nullable=True)
    last_check = db.Column(db.DateTime)
    
    cliente_info = db.relationship('Cliente', backref='usuario', uselist=False, cascade="all, delete-orphan")
    credenciales_vox = db.relationship('CredencialVox', backref='usuario', uselist=False, cascade="all, delete-orphan")
    reportes = db.relationship('Reporte', backref='usuario', lazy=True, cascade="all, delete-orphan")

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

# --- MODELO ACTUALIZADO (Con nuevos campos) ---
class VentaVendedor(db.Model):
    __tablename__ = 'ventas_vendedor'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    fecha = db.Column(db.String(20))
    vendedor = db.Column(db.String(100))
    combustible = db.Column(db.String(100)) # Nuevo
    litros = db.Column(db.Float)
    precio = db.Column(db.Float)            # Nuevo
    monto = db.Column(db.Float)
    primer_horario = db.Column(db.String(50)) # Nuevo
    tipo_pago = db.Column(db.String(50))      # Nuevo
    duracion_seg = db.Column(db.Float)        # Nuevo# --- INICIALIZACIÓN ---
class Tirada(db.Model):
    __tablename__ = 'tiradas'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    fecha_operativa = db.Column(db.String(20)) 
    vendedor = db.Column(db.String(100))      # Nombre ya corregido/normalizado
    vendedor_raw = db.Column(db.String(100))  # Nombre original del CSV (por si acaso)
    monto = db.Column(db.Float)
    hora = db.Column(db.String(20))
    turno = db.Column(db.String(50))
    sector = db.Column(db.String(50))
    detalle_extra = db.Column(db.String(200)) # Cualquier otra nota del CSV
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

# --- VISTAS ---

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

@app.route('/admin/dashboard', methods=['GET', 'POST'])
@login_required
def panel_superadmin():
    if not current_user.is_superadmin: return "Acceso Denegado"
    msg = ""
    if request.method == 'POST':
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
        elif 'link_pc' in request.form:
            code = request.form.get('pairing_code', '').strip().upper()
            u = User.query.get(request.form.get('user_id'))
            if u and code:
                u.device_pairing_code = code; u.status_conexion = "waiting"; db.session.commit()
                msg = f"🔗 Esperando PC: {code}"
        elif 'revoke' in request.form:
            u = User.query.get(request.form.get('user_id'))
            if u: u.api_token = None; u.status_conexion = "offline"; u.device_pairing_code = None; db.session.commit(); msg = "🚫 Revocado."
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

# --- APIS ---

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
    
    ahora = datetime.now()
    if not user.last_check or (ahora - user.last_check).total_seconds() > 30:
        user.status_conexion = 'online'; user.last_check = ahora; db.session.commit()
    
    cmd = user.comando_pendiente
    if cmd: user.comando_pendiente = None; db.session.commit()
    
    conf = {}
    if user.credenciales_vox:
        conf = {"ip": user.credenciales_vox.vox_ip, "u": user.credenciales_vox.vox_usuario, "p": user.credenciales_vox.vox_clave}
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
            user_id=u.id, 
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
        return jsonify({"status":"exito"}), 200
    except Exception as e: 
        print(e)
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

# --- API RESUMEN (MODIFICADA: Orden Fijo y Datos Completos) ---
# --- EN APP.PY (Agregar junto a las otras APIs) ---

# 1. BOTÓN GATILLO: El usuario presiona "Solicitar ingreso" en la web
@app.route('/api/lanzar-tiradas', methods=['POST'])
@login_required
def lanzar_orden_tiradas():
    # Cambiamos el comando pendiente. El agente leerá esto en su próximo "latido".
    current_user.comando_pendiente = 'UPLOAD_TIRADAS'
    db.session.commit()
    return jsonify({"status": "ok"})

# 2. API RECEPCIÓN: El agente envía el archivo aquí
# --- EN APP.PY ---

# 1. API DE RECEPCIÓN (Aquí ocurre la ASOCIACIÓN DEL ID)
@app.route('/api/recepcion-tiradas', methods=['POST'])
def api_recepcion_tiradas():
    # A. Recibimos el Token del Agente
    token = request.headers.get('X-API-TOKEN')
    
    # B. BUSCAMOS AL DUEÑO DEL TOKEN (Aquí se hace la asociación)
    user = User.query.filter_by(api_token=token).first()
    
    if not user: 
        return jsonify({"status": "error", "msg": "Token invalido"}), 401

    if 'archivo' not in request.files:
        return jsonify({"status": "error", "msg": "Sin archivo"}), 400

    archivo = request.files['archivo']
    try:
        import difflib # Importamos aquí o arriba
        
        # Leer CSV
        try:
            df = pd.read_csv(archivo)
            if len(df.columns) < 2: df = pd.read_csv(archivo, sep=';')
        except:
            return jsonify({"status": "error", "msg": "Formato CSV invalido"}), 400

        # Normalizar columnas
        df.columns = df.columns.astype(str).str.lower().str.strip()
        col_monto = next((c for c in df.columns if 'monto' in c or 'importe' in c), None)
        col_vend = next((c for c in df.columns if 'vendedor' in c or 'playero' in c or 'nombre' in c), None)
        # ... (resto de detección de columnas igual) ...
        col_hora = next((c for c in df.columns if 'hora' in c), None)
        col_turno = next((c for c in df.columns if 'turno' in c), None)
        col_sector = next((c for c in df.columns if 'sector' in c), None)

        if not col_monto or not col_vend:
            return jsonify({"status": "error", "msg": "Columnas faltantes"}), 400

        # Lógica de Nombres
        fecha_hoy = datetime.now().strftime('%Y-%m-%d')
        ventas_existentes = VentaVendedor.query.filter_by(user_id=user.id, fecha=fecha_hoy).all()
        nombres_oficiales = list(set([v.vendedor for v in ventas_existentes]))

        # Limpieza previa del día para evitar duplicados
        Tirada.query.filter_by(user_id=user.id, fecha_operativa=fecha_hoy).delete()

        count = 0
        for _, row in df.iterrows():
            nombre_csv = str(row[col_vend]).strip()
            nombre_final = nombre_csv
            if nombres_oficiales:
                matches = difflib.get_close_matches(nombre_csv, nombres_oficiales, n=1, cutoff=0.4)
                if matches: nombre_final = matches[0]

            try:
                monto_val = float(str(row[col_monto]).replace('$','').replace('.','').replace(',','.'))
            except: monto_val = 0.0

            nueva = Tirada(
                user_id=user.id, # <--- ¡AQUÍ SE GUARDA LA ASOCIACIÓN! Usamos el ID del usuario encontrado por Token.
                fecha_operativa=fecha_hoy,
                vendedor=nombre_final,
                vendedor_raw=nombre_csv,
                monto=monto_val,
                hora=str(row[col_hora]) if col_hora else "-",
                turno=str(row[col_turno]) if col_turno else "-",
                sector=str(row[col_sector]) if col_sector else "-"
            )
            db.session.add(nueva)
            count += 1
        
        db.session.commit()
        return jsonify({"status": "ok", "count": count}), 200

    except Exception as e:
        return jsonify({"status": "error", "msg": str(e)}), 500

# 2. API DE ESTADO (Para el Semáforo en el Frontend)
@app.route('/api/estado-tiradas')
@login_required
def estado_tiradas():
    is_online = False
    # Si hubo señal hace menos de 60 segundos, está ONLINE
    if current_user.last_check:
        delta = datetime.now() - current_user.last_check
        if delta.total_seconds() < 60:
            is_online = True
            
    return jsonify({
        "online": is_online,
        "comando_pendiente": current_user.comando_pendiente == 'UPLOAD_TIRADAS',
        "ultima_vez": current_user.last_check.strftime("%H:%M:%S") if current_user.last_check else "-"
    })@app.route('/api/resumen-dia/<string:fecha>')
@login_required
def api_res(fecha):
    reps = Reporte.query.filter_by(fecha_operativa=fecha, user_id=current_user.id).all()
    
    agrupado = {}
    
    # 1. Agrupar datos
    for r in reps:
        if r.turno not in agrupado:
            agrupado[r.turno] = {
                "monto": 0.0, 
                "apertura": r.hora_apertura, 
                "cierre": r.hora_cierre, 
                "count": 0
            }
        
        agrupado[r.turno]["monto"] += r.monto
        agrupado[r.turno]["count"] += 1
        
        # Actualizar extremos
        if r.hora_apertura < agrupado[r.turno]["apertura"]:
            agrupado[r.turno]["apertura"] = r.hora_apertura
        if r.hora_cierre > agrupado[r.turno]["cierre"]:
            agrupado[r.turno]["cierre"] = r.hora_cierre

    # 2. Generar lista ordenada (Mañana -> Tarde -> Noche)
    salida = []
    orden_turnos = ["Mañana", "Tarde", "Noche"]

    for turno in orden_turnos:
        if turno in agrupado:
            datos = agrupado[turno]
            ini = datos["apertura"].strftime("%H:%M:%S") if datos["apertura"] else "??"
            fin = datos["cierre"].strftime("%H:%M:%S") if datos["cierre"] else "??"
            
            salida.append({
                "turno": turno,
                "monto": datos["monto"],
                "cantidad_cierres": datos["count"],
                "horario_real": f"{ini} a {fin}" 
            })
        
    return jsonify(salida)

@app.route('/admin/api/status-all')
@login_required
def admin_status_all():
    if not current_user.is_superadmin: return jsonify([])
    users = User.query.all()
    data = []
    ahora = datetime.now()
    for u in users:
        st = u.status_conexion
        # Consideramos offline si no hubo latido en 120 segundos
        if u.last_check and (ahora - u.last_check).total_seconds() > 120: st = 'offline'
        
        # AGREGAMOS "token": u.api_token PARA QUE EL FRONT LO MUESTRE
        data.append({
            "id": u.id, 
            "username": u.username,
            "cliente": u.cliente_info.nombre_fantasia if u.cliente_info else "Sin Nombre",
            "status": st, 
            "code": u.device_pairing_code, 
            "token": u.api_token if u.api_token else None, # <--- ESTO ES NUEVO
            "last_check": u.last_check.strftime('%d/%m %H:%M') if u.last_check else "Nunca"
        })
    return jsonify(data)
# --- HERRAMIENTA CLI ---
@app.cli.command("reparar-horarios")
def reparar_horarios_db():
    """Recalcula horarios de apertura/cierre basados en el texto crudo del VOX."""
    print("🔧 Iniciando reparación de base de datos...")
    reportes = Reporte.query.all(); count = 0; errores = 0
    for r in reportes:
        if r.fecha_completa:
            try:
                contenido = r.fecha_completa.split('(')[1].replace(')', '') 
                partes = contenido.split(' - ')
                dt_inicio = datetime.strptime(partes[0].strip(), "%Y/%m/%d %H:%M:%S")
                dt_fin = datetime.strptime(partes[1].strip(), "%Y/%m/%d %H:%M:%S")
                r.hora_apertura = dt_inicio; r.hora_cierre = dt_fin
                count += 1
            except: errores += 1
    db.session.commit()
    print(f"✅ FINALIZADO: {count} ok, {errores} errores.")
# --- MÓDULO VENTAS POR VENDEDOR ---
# --- ESTA ES LA PARTE QUE FALTA ---
@app.route('/estacion/ventas-vendedor', methods=['GET'])
@login_required
def ver_ventas_vendedor():
    fecha = request.args.get('fecha', datetime.now().strftime('%Y-%m-%d'))
    
    # 1. Obtener las reglas de juego (Horarios de los turnos) desde Reportes
    reportes = Reporte.query.filter_by(user_id=current_user.id, fecha_operativa=fecha).all()
    
    # Estructura para saber a qué hora abrió y cerró realmente cada turno ese día
    limites_turnos = {
        "Mañana": {"inicio": None, "fin": None},
        "Tarde": {"inicio": None, "fin": None},
        "Noche": {"inicio": None, "fin": None}
    }
    
    for r in reportes:
        if r.turno in limites_turnos:
            # Buscamos los extremos (si hubo varios cierres, tomamos el rango total)
            if r.hora_apertura:
                t_ini = r.hora_apertura.time()
                if limites_turnos[r.turno]["inicio"] is None or t_ini < limites_turnos[r.turno]["inicio"]:
                    limites_turnos[r.turno]["inicio"] = t_ini
            
            if r.hora_cierre:
                t_fin = r.hora_cierre.time()
                if limites_turnos[r.turno]["fin"] is None or t_fin > limites_turnos[r.turno]["fin"]:
                    limites_turnos[r.turno]["fin"] = t_fin

    # 2. Traer las ventas cargadas del Excel
    ventas = VentaVendedor.query.filter_by(user_id=current_user.id, fecha=fecha).all()
    
    # 3. Clasificación: Crear las cajas para cada turno
    ventas_por_turno = {
        "Mañana": [],
        "Tarde": [],
        "Noche": [],
        "Sin Asignar": [] # Por si alguno queda fuera de rango
    }
    
    total_litros = 0
    total_plata = 0

    for v in ventas:
        total_litros += v.litros
        total_plata += v.monto
        asignado = False
        
        try:
            # Convertimos el horario del vendedor a objeto time para comparar
            if not v.primer_horario or v.primer_horario == '-':
                raise ValueError("Sin hora")
            hora_venta = datetime.strptime(v.primer_horario, "%H:%M:%S").time()
        except:
            ventas_por_turno["Sin Asignar"].append(v)
            continue

        # El Gran Filtro: Probamos si entra en algún turno detectado
        for nombre_turno, limites in limites_turnos.items():
            ini = limites["inicio"]
            fin = limites["fin"]
            
            if ini and fin:
                # Caso Normal (Ej: Mañana 06:00 a 14:00) -> La hora debe estar en el medio
                if ini < fin:
                    if ini <= hora_venta <= fin:
                        ventas_por_turno[nombre_turno].append(v)
                        asignado = True
                        break
                # Caso Noche/Cruce (Ej: 22:00 a 06:00) -> La hora es mayor al inicio O menor al fin
                else:
                    if hora_venta >= ini or hora_venta <= fin:
                        ventas_por_turno[nombre_turno].append(v)
                        asignado = True
                        break
        
        # Si no coincidió con los horarios exactos del reporte (o no hay reporte), usamos lógica por defecto
        if not asignado:
            h = hora_venta.hour
            if 6 <= h < 14: ventas_por_turno["Mañana"].append(v)
            elif 14 <= h < 22: ventas_por_turno["Tarde"].append(v)
            else: ventas_por_turno["Noche"].append(v)

    return render_template('ventas_vendedor.html', 
                           ventas_por_turno=ventas_por_turno, 
                           fecha=fecha, 
                           t_litros=total_litros, 
                           t_plata=total_plata,
                           limites=limites_turnos,
                           user=current_user)# ----------------------------------
@app.route('/estacion/subir-ventas-vendedor', methods=['POST'])
@login_required
def subir_ventas_vendedor():
    if 'archivo' not in request.files:
        return redirect(url_for('ver_ventas_vendedor'))
    
    archivo = request.files['archivo']
    
    if archivo.filename == '':
        return redirect(url_for('ver_ventas_vendedor'))

    try:
        # 1. Leer Excel sin encabezados
        df_raw = pd.read_excel(archivo, header=None)

        # 2. Buscar fila de cabecera
        fila_tabla = -1
        for i, row in df_raw.iterrows():
            fila_texto = row.astype(str).str.lower().str.strip()
            if (fila_texto.str.contains('vendedor').any() and 
                fila_texto.str.contains('producto').any() and 
                fila_texto.str.contains('vol').any() and 
                fila_texto.str.contains('importe').any()):
                fila_tabla = i
                break

        if fila_tabla == -1:
            flash("❌ No se pudo detectar la tabla real de ventas.", "error")
            return redirect(url_for('ver_ventas_vendedor'))

        # 3. Construir DataFrame
        df = df_raw.iloc[fila_tabla + 1:].copy()
        df.columns = df_raw.iloc[fila_tabla]
        df.columns = df.columns.astype(str).str.strip().str.lower()

        # 4. Mapeo de columnas
        try:
            col_fecha = [c for c in df.columns if 'fecha' in c][0]
            col_vendedor = [c for c in df.columns if 'vendedor' in c][0]
            col_producto = [c for c in df.columns if 'producto' in c][0]
            col_litros = [c for c in df.columns if 'vol' in c][0]
            col_importe = [c for c in df.columns if 'importe' in c][0]
            col_precio = next((c for c in df.columns if 'precio' in c), None)
            col_duracion = next((c for c in df.columns if 'duración' in c or 'duracion' in c), None)
            col_pago = next((c for c in df.columns if 'tipo' in c), None)
        except IndexError:
            flash("❌ El Excel no tiene las columnas requeridas (Fecha, Vendedor, Producto...).", "error")
            return redirect(url_for('ver_ventas_vendedor'))

        # Renombrar
        cols_to_keep = { col_fecha: "Fecha", col_vendedor: "Vendedor", col_producto: "Combustible", col_litros: "Litros", col_importe: "Importe" }
        if col_precio: cols_to_keep[col_precio] = "Precio"
        if col_duracion: cols_to_keep[col_duracion] = "DuracionSeg"
        if col_pago: cols_to_keep[col_pago] = "TipoPago"

        df = df[list(cols_to_keep.keys())].rename(columns=cols_to_keep)
        df = df.dropna(subset=["Vendedor"])

        # --- 5. DETECCIÓN AUTOMÁTICA DE FECHA ---
        # Convertimos la columna Fecha a objetos datetime
        # dayfirst=True es importante para fechas tipo 27/11/2025
        df['Fecha_DT'] = pd.to_datetime(df['Fecha'], dayfirst=True, errors='coerce')
        
        # Eliminamos filas donde la fecha no se pudo leer
        fechas_validas = df['Fecha_DT'].dropna()
        
        if fechas_validas.empty:
            flash("❌ No se encontraron fechas válidas en el archivo para asignar el día.", "error")
            return redirect(url_for('ver_ventas_vendedor'))

        # CALCULAMOS LA FECHA DOMINANTE (Moda)
        # Esto sirve por si hay turnos noche que cruzan las 00:00 hs.
        # El sistema asignará el reporte al día que tenga más registros.
        fecha_auto = fechas_validas.dt.date.mode()[0].strftime('%Y-%m-%d')
        
        # --- VERIFICAR EXISTENCIA ---
        existe = VentaVendedor.query.filter_by(user_id=current_user.id, fecha=fecha_auto).first()
        if existe:
            flash(f"⚠️ Aviso: Ya existían datos del {fecha_auto}. Se han actualizado.", "warning")
        else:
            flash(f"✅ Archivo procesado. Se detectó la fecha: {fecha_auto}", "success")

        # 6. Limpieza numérica
        def limpiar_numero(val):
            if isinstance(val, (int, float)): return float(val)
            val = str(val).strip()
            if val in ["", "-", "nan", "none"]: return 0.0
            val = val.replace(".", "").replace(",", ".")
            try: return float(val)
            except: return 0.0

        for col in ["Litros", "Importe", "Precio", "DuracionSeg"]:
            if col in df.columns: df[col] = df[col].apply(limpiar_numero)

        # 7. Agrupación
        agregaciones = { "Fecha": "first", "Litros": "sum", "Importe": "sum" }
        if "Precio" in df.columns: agregaciones["Precio"] = "first" # O mean
        if "TipoPago" in df.columns: agregaciones["TipoPago"] = "first"
        if "DuracionSeg" in df.columns: agregaciones["DuracionSeg"] = "sum"

        resumen = df.sort_values("Fecha_DT").groupby(["Vendedor", "Combustible"]).agg(agregaciones).reset_index()

        # 8. Guardar (Usando fecha_auto)
        VentaVendedor.query.filter_by(user_id=current_user.id, fecha=fecha_auto).delete()

        for _, row in resumen.iterrows():
            hora_str = "-"
            try:
                if pd.notnull(row['Fecha']):
                    ts = pd.to_datetime(row['Fecha'])
                    hora_str = ts.strftime('%H:%M:%S')
            except: pass

            nueva = VentaVendedor(
                user_id=current_user.id,
                fecha=fecha_auto, # <--- USAMOS LA FECHA DETECTADA
                vendedor=row['Vendedor'],
                combustible=row['Combustible'],
                litros=round(row['Litros'], 2),
                monto=round(row['Importe'], 2),
                precio=round(row.get('Precio', 0), 2),
                primer_horario=hora_str,
                tipo_pago=str(row.get('TipoPago', '-')),
                duracion_seg=row.get('DuracionSeg', 0)
            )
            db.session.add(nueva)

        db.session.commit()
        # REDIRIGIMOS AL USUARIO A LA FECHA DETECTADA
        return redirect(url_for('ver_ventas_vendedor', fecha=fecha_auto))

    except Exception as e:
        print("Error técnico:", e)
        flash(f"Error procesando: {str(e)}", "error")
        return redirect(url_for('ver_ventas_vendedor'))
# --- RUTAS PARA TIRADAS (SOBRES) ---

@app.route('/estacion/tiradas', methods=['GET'])
@login_required
def ver_tiradas():
    fecha = request.args.get('fecha', datetime.now().strftime('%Y-%m-%d'))
    
    # Obtenemos las tiradas
    tiradas = Tirada.query.filter_by(user_id=current_user.id, fecha_operativa=fecha).all()
    
    # Totales generales para las tarjetas de arriba
    total_plata = sum([t.monto for t in tiradas])
    total_sobres = len(tiradas)

    return render_template('tiradas.html', 
                           tiradas=tiradas, 
                           fecha=fecha, 
                           t_plata=total_plata, 
                           t_sobres=total_sobres)

@app.route('/estacion/subir-tiradas', methods=['POST'])
@login_required
def subir_tiradas():
    if 'archivo' not in request.files: return redirect(url_for('ver_tiradas'))
    archivo = request.files['archivo']
    if not archivo.filename: return redirect(url_for('ver_tiradas'))

    try:
        # 1. Leer CSV (Probamos coma y punto y coma)
        try:
            df = pd.read_csv(archivo)
            if len(df.columns) < 2: # Si falló el separador
                archivo.seek(0)
                df = pd.read_csv(archivo, sep=';')
        except:
            flash("❌ Error leyendo el CSV. Verifique el formato.", "error")
            return redirect(url_for('ver_tiradas'))

        # Normalizar nombres de columnas
        df.columns = df.columns.astype(str).str.lower().str.strip()
        
        # Intentar detectar columnas clave
        col_monto = next((c for c in df.columns if 'monto' in c or 'importe' in c or 'valor' in c), None)
        col_vend = next((c for c in df.columns if 'vendedor' in c or 'playero' in c or 'nombre' in c), None)
        col_hora = next((c for c in df.columns if 'hora' in c), None)
        col_turno = next((c for c in df.columns if 'turno' in c), None)
        col_sector = next((c for c in df.columns if 'sector' in c), None) # Opcional

        if not col_monto or not col_vend:
            flash("❌ El CSV debe tener al menos columnas de 'Vendedor' y 'Monto'.", "error")
            return redirect(url_for('ver_tiradas'))

        # 2. Obtener lista de vendedores "oficiales" (los que vendieron combustible ese día)
        # Esto sirve para la "Similitud"
        fecha_hoy = request.form.get('fecha_manual', datetime.now().strftime('%Y-%m-%d'))
        
        ventas_existentes = VentaVendedor.query.filter_by(user_id=current_user.id, fecha=fecha_hoy).all()
        nombres_oficiales = list(set([v.vendedor for v in ventas_existentes])) # Lista única: ['Ruben Arce', 'Maria L']

        # Limpiar tiradas viejas de esa fecha para no duplicar al resubir
        Tirada.query.filter_by(user_id=current_user.id, fecha_operativa=fecha_hoy).delete()

        count = 0
        for _, row in df.iterrows():
            nombre_csv = str(row[col_vend]).strip()
            
            # --- LÓGICA DE SIMILITUD (FUZZY MATCHING) ---
            nombre_final = nombre_csv 
            if nombres_oficiales:
                # Busca el nombre más parecido en la lista oficial
                # cutoff=0.4 significa que con un 40% de similitud ya lo toma (es flexible)
                matches = difflib.get_close_matches(nombre_csv, nombres_oficiales, n=1, cutoff=0.4)
                if matches:
                    nombre_final = matches[0] # Usamos el nombre oficial (Ej: Cambia "Arce R" por "Ruben Arce")

            # Procesar monto
            try:
                monto_raw = str(row[col_monto]).replace('$','').replace('.','').replace(',','.')
                monto_val = float(monto_raw)
            except: monto_val = 0.0

            nueva = Tirada(
                user_id=current_user.id,
                fecha_operativa=fecha_hoy,
                vendedor=nombre_final,      # Nombre Corregido
                vendedor_raw=nombre_csv,    # Nombre Original
                monto=monto_val,
                hora=str(row[col_hora]) if col_hora else "-",
                turno=str(row[col_turno]) if col_turno else "-",
                sector=str(row[col_sector]) if col_sector else "-"
            )
            db.session.add(nueva)
            count += 1

        db.session.commit()
        flash(f"✅ Se procesaron {count} tiradas para el {fecha_hoy}. Nombres unificados.", "success")
        return redirect(url_for('ver_tiradas', fecha=fecha_hoy))

    except Exception as e:
        print(e)
        flash(f"Error técnico: {e}", "error")
        return redirect(url_for('ver_tiradas'))
if __name__ == '__main__': 
    app.run(host='0.0.0.0', port=10000)