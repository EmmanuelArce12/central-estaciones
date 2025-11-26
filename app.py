import os
import secrets
from flask import Flask, request, jsonify, render_template, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta

app = Flask(__name__)

# --- CONFIGURACIÓN ---
db_url = os.environ.get('DATABASE_URL', 'sqlite:///local.db')
if db_url and db_url.startswith("postgres://"):
    db_url = db_url.replace("postgres://", "postgresql://", 1)

app.config['SQLALCHEMY_DATABASE_URI'] = db_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'CLAVE_SUPER_SECRETA'

db = SQLAlchemy(app)
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
    
    # SISTEMA DE VINCULACIÓN
    api_token = db.Column(db.String(100), unique=True, nullable=True) # Llave Maestra
    device_pairing_code = db.Column(db.String(20), nullable=True)     # Código temporal (ej: XJ9-22)
    
    # ESTADO
    status_conexion = db.Column(db.String(20), default='offline')
    last_check = db.Column(db.DateTime)
    
    # DATOS VOX (Se guardan aquí para enviarlos a la PC cuando se conecte)
    vox_ip = db.Column(db.String(50))
    vox_user = db.Column(db.String(50))
    vox_pass = db.Column(db.String(50))

    cliente_info = db.relationship('Cliente', backref='usuario', uselist=False)
    reportes = db.relationship('Reporte', backref='usuario', lazy=True)

    def set_password(self, p): self.password_hash = generate_password_hash(p)
    def check_password(self, p): return check_password_hash(self.password_hash, p)
    @property
    def is_superadmin(self): return self.role == 'superadmin'

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

@login_manager.user_loader
def load_user(uid): return User.query.get(int(uid))

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
    except: return None,None,None

# --- RUTAS ---
@app.route('/')
def root():
    if current_user.is_authenticated:
        return redirect(url_for('panel_superadmin')) if current_user.is_superadmin else redirect(url_for('panel_estacion'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = ""
    if request.method == 'POST':
        u = request.form.get('username'); p = request.form.get('password')
        user = User.query.filter_by(username=u).first()
        if user and user.check_password(p): login_user(user); return redirect(url_for('root'))
        else: error = "Credenciales incorrectas."
    return f"""<style>body{{font-family:sans-serif;background:#eef2f3;display:flex;justify-content:center;align-items:center;height:100vh}}form{{background:white;padding:40px;border-radius:15px;box-shadow:0 10px 25px #00000010;width:300px;text-align:center}}input{{width:100%;padding:12px;margin:10px 0;border:1px solid #ccc;border-radius:8px}}button{{width:100%;padding:12px;background:#007bff;color:white;border:none;border-radius:8px;cursor:pointer}}</style><form method="POST"><h2>🔒 Portal</h2><input name="username" placeholder="User" required><input type="password" name="password" placeholder="Pass" required><button>Entrar</button><p style="color:red">{error}</p></form>"""

@app.route('/logout')
@login_required
def logout(): logout_user(); return redirect(url_for('login'))

@app.route('/admin/dashboard', methods=['GET', 'POST'])
@login_required
def panel_superadmin():
    if not current_user.is_superadmin: return "Acceso Denegado"
    msg = ""
    
    # CREAR USUARIO
    if request.method == 'POST' and 'create_user' in request.form:
        u = request.form.get('username'); p = request.form.get('password'); n = request.form.get('nombre'); r = request.form.get('role')
        if User.query.filter_by(username=u).first(): msg = "❌ Existe."
        else:
            nu = User(username=u, role=r); nu.set_password(p); db.session.add(nu); db.session.commit()
            if r == 'estacion': nc = Cliente(nombre_fantasia=n, user_id=nu.id); db.session.add(nc); db.session.commit()
            msg = "✅ Creado."

    # VINCULAR PC (HANDSHAKE ADMIN)
    if request.method == 'POST' and 'link_pc' in request.form:
        user_id = request.form.get('user_id')
        code = request.form.get('pairing_code')
        user = User.query.get(user_id)
        if user:
            user.device_pairing_code = code # Guardamos el código que nos dio el técnico
            # Generamos el token definitivo
            user.api_token = secrets.token_hex(24)
            db.session.commit()
            msg = f"✅ PC Vinculada a {user.username}. Esperando que el script confirme."

    # REVOCAR ACCESO
    if request.method == 'POST' and 'revoke' in request.form:
        user_id = request.form.get('user_id')
        user = User.query.get(user_id)
        if user:
            user.api_token = None
            user.device_pairing_code = None
            user.status_conexion = "offline"
            db.session.commit()
            msg = f"🚫 Acceso revocado a {user.username}."

    users = User.query.all(); l = ""
    for u in users:
        if u.role == 'superadmin': continue
        st = "🟢 Online" if u.status_conexion=='online' else "🔴 Offline"
        nom = u.cliente_info.nombre_fantasia if u.cliente_info else "-"
        
        # Control de Vinculación
        if u.api_token:
            control_html = f"""
            <div style="color:green;font-size:0.8rem">🔑 Vinculado (Token Activo)</div>
            <form method="POST" style="display:inline"><input type="hidden" name="user_id" value="{u.id}"><input type="hidden" name="revoke" value="1"><button style="background:#dc3545;padding:5px;font-size:0.7rem">🚫 Revocar PC</button></form>
            """
        else:
            control_html = f"""
            <form method="POST" style="margin-top:5px">
                <input type="hidden" name="user_id" value="{u.id}">
                <input type="hidden" name="link_pc" value="1">
                <input type="text" name="pairing_code" placeholder="Código de PC (ej: ABC-123)" style="width:150px;padding:5px" required>
                <button style="padding:5px;font-size:0.7rem;background:#6c5ce7">🔗 Vincular</button>
            </form>
            """

        l += f"""
        <li style='padding:15px;border-bottom:1px solid #eee;background:white;margin-bottom:10px;border-radius:8px'>
            <div style="display:flex;justify-content:space-between">
                <div>🏢 <b>{u.username}</b> ({nom})</div>
                <div>{st}</div>
            </div>
            {control_html}
        </li>"""

    return f"""
    <style>body{{font-family:sans-serif;padding:30px;background:#f4f7f6;max-width:800px;margin:0 auto}}.card{{background:white;padding:20px;border-radius:10px;margin-bottom:20px;box-shadow:0 2px 5px #00000010}}input,select{{padding:8px;margin:5px}}button{{padding:8px 15px;background:green;color:white;border:none;border-radius:5px;cursor:pointer}}</style>
    <a href="/logout" style="float:right;color:red">Salir</a><h1>SuperAdmin Panel</h1>
    <p style="color:blue;font-weight:bold">{msg}</p>
    
    <div class="card">
        <h3>➕ Nueva Estación</h3>
        <form method="POST">
            <input type="hidden" name="create_user" value="1">
            <input name="username" placeholder="Usuario Login" required>
            <input name="password" type="password" placeholder="Clave Login" required>
            <input name="nombre" placeholder="Nombre Fantasía">
            <input type="hidden" name="role" value="estacion">
            <button>Crear</button>
        </form>
    </div>
    
    <h3>📋 Estaciones y Vinculaciones</h3>
    <ul style="list-style:none;padding:0">{l}</ul>
    """

# --- PANEL ESTACIÓN (CLIENTE) ---
@app.route('/estacion/panel', methods=['GET', 'POST'])
@login_required
def panel_estacion():
    if current_user.is_superadmin: return redirect(url_for('panel_superadmin'))
    
    msg = ""
    if request.method == 'POST':
        current_user.vox_ip = request.form.get('ip')
        current_user.vox_user = request.form.get('u')
        current_user.vox_pass = request.form.get('p')
        db.session.commit()
        msg = "✅ Datos VOX Guardados."

    return f"""
    <style>body{{font-family:sans-serif;text-align:center;background:#f0f2f5;padding:20px}}.card{{background:white;padding:30px;border-radius:10px;max-width:500px;margin:0 auto;box-shadow:0 5px 15px #00000010}}input{{display:block;width:90%;margin:10px auto;padding:10px;border:1px solid #ccc;border-radius:5px}}button{{padding:12px 30px;background:#007bff;color:white;border:none;border-radius:5px;width:95%}}a{{color:#666;text-decoration:none}}</style>
    <h1>Hola, {current_user.username}</h1>
    
    <div class="card">
        <h3>⚙️ Configuración Técnica VOX</h3>
        <p style="font-size:0.9rem;color:#666">Estos datos se enviarán automáticamente a tu PC vinculada.</p>
        <form method="POST">
            <label style="display:block;text-align:left;margin-left:15px">IP Servidor VOX</label>
            <input name="ip" value="{current_user.vox_ip or '10.6.235.229'}">
            <label style="display:block;text-align:left;margin-left:15px">Usuario VOX</label>
            <input name="u" value="{current_user.vox_user or ''}">
            <label style="display:block;text-align:left;margin-left:15px">Contraseña VOX</label>
            <input name="p" type="password" value="{current_user.vox_pass or ''}">
            <button>Guardar Configuración</button>
        </form>
        <p style="color:green">{msg}</p>
    </div>
    <br>
    <a href="/estacion/ver-reportes" style="font-weight:bold;color:#2c3e50">📊 Ir a Gráficos y Reportes</a>
    <br><br><a href="/logout" style="color:red">Cerrar Sesión</a>
    """

@app.route('/estacion/ver-reportes')
@login_required
def ver_reportes_html(): return render_template('index.html', usuario=current_user.username)

# --- 🤝 HANDSHAKE API (EL CORAZÓN DEL SISTEMA) 🤝 ---

@app.route('/api/handshake/poll', methods=['POST'])
def handshake_poll():
    # El script manda su código temporal (ej: XJ9-22)
    code = request.json.get('code')
    
    # Buscamos si algún usuario tiene ese código asignado por el Admin
    user = User.query.filter_by(device_pairing_code=code).first()
    
    if user and user.api_token:
        # ¡MATCH! El admin ya lo vinculó.
        # Entregamos el token definitivo y borramos el código temporal
        token_real = user.api_token
        user.device_pairing_code = None # Ya no se usa
        db.session.commit()
        return jsonify({"status": "linked", "api_token": token_real}), 200
    
    return jsonify({"status": "waiting"}), 200

# --- API AGENTE (YA VINCULADO) ---

@app.route('/api/agent/sync', methods=['POST'])
def agent_sync():
    token = request.headers.get('X-API-TOKEN')
    user = User.query.filter_by(api_token=token).first()
    
    if not user:
        return jsonify({"status": "revoked"}), 401 # Orden de autodestrucción si el token fue borrado
        
    # Heartbeat
    user.status_conexion = 'online'
    user.last_check = datetime.now()
    db.session.commit()
    
    # Entregamos configuración VOX
    return jsonify({
        "status": "ok",
        "config": {
            "ip": user.vox_ip,
            "u": user.vox_user,
            "p": user.vox_pass
        }
    }), 200

@app.route('/api/reportar', methods=['POST'])
def reportar():
    try:
        token = request.headers.get('X-API-TOKEN')
        user = User.query.filter_by(api_token=token).first()
        if not user: return jsonify({"status":"error"}), 401
        
        n = request.json; nid = n.get('id_interno')
        if Reporte.query.filter_by(id_interno=nid, user_id=user.id).first(): return jsonify({"status":"ignorado"}), 200
        
        f,t,d = procesar_fecha_turno(n.get('fecha'))
        r = Reporte(user_id=user.id, id_interno=nid, estacion=n.get('estacion'), fecha_completa=n.get('fecha'), monto=n.get('monto'), fecha_operativa=f, turno=t, hora_cierre=d)
        db.session.add(r); db.session.commit()
        return jsonify({"status":"exito"}), 200
    except Exception as e: return jsonify({"status":"error","msg":str(e)}), 500

# --- API GRAFICOS ---
@app.route('/api/resumen-dia/<string:fecha>')
@login_required
def api_res(fecha):
    # Si es admin ve todo? No, dejemos que vea vacío o implementamos logica luego.
    # Si es estación, ve lo suyo
    uid = current_user.id
    reps = Reporte.query.filter_by(fecha_operativa=fecha, user_id=uid).all()
    res = {k: {"monto":0.0,"horario":"-","cierres":0} for k in ["Mañana","Tarde","Noche"]}
    for r in reps:
        if r.turno in res: res[r.turno]["monto"]+=r.monto; res[r.turno]["cierres"]+=1
    return jsonify([{"turno":k, "monto":v["monto"]} for k,v in res.items()])

def auto_setup():
    try:
        with app.app_context():
            db.create_all()
            if not User.query.filter_by(username='admin').first():
                a = User(username='admin', role='superadmin'); a.set_password('admin123'); db.session.add(a); db.session.commit()
    except: pass
auto_setup()

if __name__ == '__main__': app.run(host='0.0.0.0', port=10000)
