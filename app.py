import os
import secrets
from flask import Flask, request, jsonify, render_template, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
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

# --- INICIALIZACIÓN ---
with app.app_context():
    try:
        db.create_all()
    except Exception as e:
        print(f"⚠️ Advertencia DB: {e}")

@login_manager.user_loader
def load_user(uid): 
    return User.query.get(int(uid))

def procesar_fecha_turno(s):
    try:
        p = s.split(' - '); cr = p[1].replace(')', '').strip()
        dt = datetime.strptime(cr, "%Y/%m/%d %H:%M:%S")
        h=dt.hour; f=dt.date(); t="Noche"
        if 6<=h<14: t="Mañana"
        elif 14<=h<22: t="Tarde"
        else:
            if h<6: f=f-timedelta(days=1)
        return f.strftime("%Y-%m-%d"), t, dt
    except: 
        return None, None, None

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
            u = request.form.get('username')
            p = request.form.get('password')
            n = request.form.get('nombre')
            r = request.form.get('role')
            
            if User.query.filter_by(username=u).first():
                msg = "❌ El usuario ya existe."
            else:
                nu = User(username=u, role=r)
                nu.set_password(p)
                db.session.add(nu)
                db.session.commit()
                
                if r == 'estacion':
                    # Crear Cliente
                    nc = Cliente(nombre_fantasia=n, user_id=nu.id)
                    db.session.add(nc)
                    # Crear Credencial VOX vacía (EVITA ERROR 500)
                    cv = CredencialVox(user_id=nu.id, vox_ip="", vox_usuario="", vox_clave="")
                    db.session.add(cv)
                    
                    db.session.commit()
                msg = "✅ Usuario creado correctamente."
                
        elif 'link_pc' in request.form:
            code_input = request.form.get('pairing_code', '').strip().upper()
            user_id = request.form.get('user_id')
            user = User.query.get(user_id)
            if user and code_input:
                user.device_pairing_code = code_input
                user.status_conexion = "waiting" 
                db.session.commit()
                msg = f"🔗 Esperando conexión con código: {code_input}"

        elif 'revoke' in request.form:
            u = User.query.get(request.form.get('user_id'))
            if u: 
                u.api_token = None
                u.status_conexion = "offline"
                u.device_pairing_code = None
                db.session.commit()
                msg = "🚫 Vinculación revocada."

    users = User.query.all()
    return render_template('admin_dashboard.html', users=users, msg=msg)

@app.route('/admin/eliminar-estacion/<int:id>', methods=['POST'])
@login_required
def eliminar_estacion(id):
    if not current_user.is_superadmin: return "Acceso Denegado"
    user_to_delete = User.query.get_or_404(id)
    if user_to_delete.id == current_user.id: return "No puedes borrarte a ti mismo."
    try:
        db.session.delete(user_to_delete)
        db.session.commit()
        return redirect(url_for('panel_superadmin'))
    except Exception as e: return f"Error al eliminar: {str(e)}"

@app.route('/estacion/panel')
@login_required
def panel_estacion():
    if current_user.is_superadmin: return redirect(url_for('panel_superadmin'))
    btn_txt = "⬇️ EXTRAER REPORTE AHORA"
    is_loading = False
    if current_user.comando_pendiente == 'EXTRACT': 
        btn_txt = "⏳ Enviando orden..."
        is_loading = True
    return render_template('station_dashboard.html', user=current_user, btn_txt=btn_txt, is_loading=is_loading)

# --- FUNCIÓN CORREGIDA FINAL ---
@app.route('/estacion/config-vox', methods=['GET', 'POST'])
@login_required
def config_vox():
    msg = ""
    cred = CredencialVox.query.filter_by(user_id=current_user.id).first()

    # --- LÓGICA DEL SEMÁFORO ---
    # Si la PC habló hace menos de 60 segundos, está ONLINE.
    is_online = False
    last_seen = "Nunca"
    
    if current_user.last_check:
        diferencia = datetime.now() - current_user.last_check
        if diferencia.total_seconds() < 60: # 60 segundos de tolerancia
            is_online = True
        last_seen = current_user.last_check.strftime("%H:%M:%S")
    # ---------------------------

    if request.method == 'POST':
        try:
            ip = request.form.get('ip')
            u = request.form.get('u')
            p = request.form.get('p')
            
            if not cred: 
                cred = CredencialVox(user_id=current_user.id)
                db.session.add(cred) 
            
            cred.vox_ip = ip
            cred.vox_usuario = u
            cred.vox_clave = p
            
            # Solo si está online tiene sentido enviar la orden
            current_user.comando_pendiente = 'EXTRACT' 
            
            db.session.add(current_user)
            db.session.commit()
            
            if is_online:
                msg = "✅ Datos enviados. La PC los ha recibido."
            else:
                msg = "⚠️ Datos guardados, pero la PC parece desconectada."
                
        except Exception as e:
            db.session.rollback()
            msg = f"❌ Error: {str(e)}"

    if not cred:
        cred = CredencialVox(vox_ip="", vox_usuario="", vox_clave="")

    return render_template('configurar_vox.html', cred=cred, msg=msg, user=current_user, is_online=is_online, last_seen=last_seen)
@app.route('/estacion/ver-reportes')
@login_required
def ver_reportes_html():
    return render_template('index.html', usuario=current_user.username)

# --- APIS (ORIGINALES) ---

@app.route('/api/handshake/poll', methods=['POST'])
def handshake_poll():
    code_raw = request.json.get('code', '')
    if not code_raw: return jsonify({"status": "waiting"}), 200
    code = code_raw.strip().upper()
    
    user = User.query.filter_by(device_pairing_code=code).first()
    if user:
        if not user.api_token: user.api_token = secrets.token_hex(32)
        token_real = user.api_token
        
        user.device_pairing_code = None 
        user.status_conexion = 'online'
        user.last_check = datetime.now()
        user.comando_pendiente = 'EXTRACT'
        
        db.session.commit()
        return jsonify({"status": "linked", "api_token": token_real}), 200
    return jsonify({"status": "waiting"}), 200

@app.route('/api/agent/sync', methods=['POST'])
def agent_sync():
    token = request.headers.get('X-API-TOKEN')
    user = User.query.filter_by(api_token=token).first()
    
    if not user: return jsonify({"status": "revoked"}), 401
    
    ahora = datetime.now()
    if not user.last_check or (ahora - user.last_check).total_seconds() > 60:
        user.status_conexion = 'online'
        user.last_check = ahora
        db.session.commit()
    
    cmd = user.comando_pendiente
    if cmd: 
        user.comando_pendiente = None
        db.session.commit()
    
    conf = {}
    if user.credenciales_vox:
        conf = {
            "ip": user.credenciales_vox.vox_ip, 
            "u": user.credenciales_vox.vox_usuario, 
            "p": user.credenciales_vox.vox_clave
        }
        
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
            
        f,t,d = procesar_fecha_turno(n.get('fecha'))
        
        r = Reporte(
            user_id=u.id, 
            id_interno=nid, 
            estacion=n.get('estacion'), 
            fecha_completa=n.get('fecha'), 
            monto=n.get('monto'), 
            fecha_operativa=f, 
            turno=t, 
            hora_cierre=d
        )
        db.session.add(r)
        db.session.commit()
        return jsonify({"status":"exito"}), 200
    except: return jsonify({"status":"error"}), 500

@app.route('/api/ping-ui')
@login_required
def ping(): 
    est = current_user.status_conexion
    if current_user.last_check and datetime.now() - current_user.last_check > timedelta(minutes=2):
        est = 'offline'
    return jsonify({"st": est, "cmd": current_user.comando_pendiente == 'EXTRACT'})

@app.route('/api/lanzar-orden', methods=['POST'])
@login_required
def lanzar():
    current_user.comando_pendiente = 'EXTRACT'
    db.session.commit()
    return redirect(url_for('panel_estacion'))

@app.route('/api/resumen-dia/<string:fecha>')
@login_required
def api_res(fecha):
    reps = Reporte.query.filter_by(fecha_operativa=fecha, user_id=current_user.id).all()
    
    # Estructura para acumular datos
    res = {
        "Mañana": {"monto": 0.0, "min_time": None, "max_time": None},
        "Tarde": {"monto": 0.0, "min_time": None, "max_time": None},
        "Noche": {"monto": 0.0, "min_time": None, "max_time": None}
    }
    
    for r in reps:
        if r.turno in res: 
            # Sumar monto
            res[r.turno]["monto"] += r.monto
            
            # Calcular Apertura (Hora más temprana encontrada)
            if res[r.turno]["min_time"] is None or r.hora_cierre < res[r.turno]["min_time"]:
                res[r.turno]["min_time"] = r.hora_cierre
                
            # Calcular Cierre (Hora más tardía encontrada)
            if res[r.turno]["max_time"] is None or r.hora_cierre > res[r.turno]["max_time"]:
                res[r.turno]["max_time"] = r.hora_cierre

    # Formatear salida para el JSON
    salida = []
    for turno, datos in res.items():
        horario_txt = "Sin datos"
        if datos["min_time"] and datos["max_time"]:
            apertura = datos["min_time"].strftime("%H:%M:%S")
            cierre = datos["max_time"].strftime("%H:%M:%S")
            horario_txt = f"{apertura} a {cierre}"
            
        salida.append({
            "turno": turno,
            "monto": datos["monto"],
            "horario_real": horario_txt
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
        estado = u.status_conexion
        if u.last_check and (ahora - u.last_check).total_seconds() > 120: 
            estado = 'offline'
        
        fecha = "Nunca"
        if u.last_check: 
            fecha = u.last_check.strftime('%d/%m %H:%M:%S')
            
        data.append({
            "id": u.id, 
            "status": estado, 
            "code": u.device_pairing_code, 
            "last_check": fecha
        })
    return jsonify(data)

if __name__ == '__main__': 
    app.run(host='0.0.0.0', port=10000)