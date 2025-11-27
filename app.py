import os
import secrets
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
    hora_apertura = db.Column(db.DateTime) # <--- NUEVA COLUMNA

# --- INICIALIZACIÓN ---
with app.app_context():
    try:
        db.create_all()
    except Exception as e:
        print(f"⚠️ Advertencia DB: {e}")

@login_manager.user_loader
def load_user(uid): 
    return User.query.get(int(uid))

def procesar_datos_turno(s):
    # Devuelve: fecha_str, turno, datetime_cierre, datetime_apertura
    try:
        p = s.split(' - '); cr = p[1].replace(')', '').strip()
        dt_cierre = datetime.strptime(cr, "%Y/%m/%d %H:%M:%S")
        
        h = dt_cierre.hour
        fecha_obj = dt_cierre.date()
        turno = "Noche"
        
        # Lógica de Turnos
        if 6 <= h < 14: 
            turno = "Mañana"
            # Apertura Mañana: Ese mismo día a las 06:00
            dt_apertura = datetime.combine(fecha_obj, time(6, 0, 0))
            
        elif 14 <= h < 22: 
            turno = "Tarde"
            # Apertura Tarde: Ese mismo día a las 14:00
            dt_apertura = datetime.combine(fecha_obj, time(14, 0, 0))
            
        else:
            # Turno Noche (22:00 a 06:00)
            # Si es madrugada (ej: 00:01), pertenece a la fecha operativa de ayer
            if h < 6: 
                fecha_obj = fecha_obj - timedelta(days=1)
            
            # Apertura Noche: Fecha operativa a las 22:00
            dt_apertura = datetime.combine(fecha_obj, time(22, 0, 0))

        return fecha_obj.strftime("%Y-%m-%d"), turno, dt_cierre, dt_apertura
    except: 
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
    
    # Semáforo online
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

# --- MODIFICADO: CALCULA APERTURA Y CIERRE ---
@app.route('/api/reportar', methods=['POST'])
def rep():
    try:
        tk = request.headers.get('X-API-TOKEN')
        u = User.query.filter_by(api_token=tk).first()
        if not u: return jsonify({"status":"error"}), 401
        
        n = request.json
        nid = n.get('id_interno')
        
        # Si ya existe, ignoramos
        if Reporte.query.filter_by(id_interno=nid, user_id=u.id).first(): 
            return jsonify({"status":"ignorado"}), 200
            
        # Calculamos Apertura y Cierre
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
            hora_apertura=dt_apertura # <--- Guardamos la apertura calculada
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

# --- MODIFICADO: DEVUELVE APERTURA Y CIERRE AL FRONTEND ---
@app.route('/api/resumen-dia/<string:fecha>')
@login_required
def api_res(fecha):
    reps = Reporte.query.filter_by(fecha_operativa=fecha, user_id=current_user.id).all()
    
    salida = []
    # Agrupamos por si hubiera múltiples cierres en un mismo turno (raro, pero posible)
    # Mostramos la apertura del primero y cierre del último.
    agrupado = {}
    
    for r in reps:
        if r.turno not in agrupado:
            agrupado[r.turno] = {
                "monto": 0.0, 
                "apertura": r.hora_apertura, # Apertura teórica
                "cierre": r.hora_cierre,     # Cierre real
                "count": 0
            }
        
        agrupado[r.turno]["monto"] += r.monto
        agrupado[r.turno]["count"] += 1
        # Si hubiera más de uno, nos quedamos con el cierre más tardío
        if r.hora_cierre > agrupado[r.turno]["cierre"]:
            agrupado[r.turno]["cierre"] = r.hora_cierre

    for turno, datos in agrupado.items():
        # Formateamos bonito
        ini = datos["apertura"].strftime("%H:%M") if datos["apertura"] else "??"
        fin = datos["cierre"].strftime("%H:%M") if datos["cierre"] else "??"
        
        salida.append({
            "turno": turno,
            "monto": datos["monto"],
            "cantidad_cierres": datos["count"],
            "horario_real": f"{ini} a {fin}" # <--- ESTO ES LO QUE VERÁS EN EL HTML
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
        if u.last_check and (ahora - u.last_check).total_seconds() > 120: st = 'offline'
        data.append({"id": u.id, "status": st, "code": u.device_pairing_code, "last_check": u.last_check.strftime('%d/%m %H:%M') if u.last_check else "Nunca"})
    return jsonify(data)

if __name__ == '__main__': 
    app.run(host='0.0.0.0', port=10000)