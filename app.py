import os
import secrets
from flask import Flask, request, jsonify, render_template, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta

app = Flask(__name__)

# --- CONFIGURACIÓN DB ---
db_url = os.environ.get('DATABASE_URL', 'sqlite:///local.db')
if db_url and db_url.startswith("postgres://"):
    db_url = db_url.replace("postgres://", "postgresql://", 1)

app.config['SQLALCHEMY_DATABASE_URI'] = db_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'CLAVE_SUPER_SECRETA_PRODUCCION'

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
    
    # Token Único para el Agente .EXE
    api_token = db.Column(db.String(100), unique=True, nullable=True)
    
    # Estado de la conexión del Agente
    status_conexion = db.Column(db.String(20), default='offline')
    comando_pendiente = db.Column(db.String(50), nullable=True) # Ej: 'EXTRACT'
    last_check = db.Column(db.DateTime)
    
    # Relaciones
    cliente_info = db.relationship('Cliente', backref='usuario', uselist=False)
    credenciales_vox = db.relationship('CredencialVox', backref='usuario', uselist=False)
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
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

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

# --- RUTAS DE NAVEGACIÓN ---

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
    
    # CREAR USUARIO CON TOKEN
    if request.method == 'POST' and 'create_user' in request.form:
        u = request.form.get('username'); p = request.form.get('password'); n = request.form.get('nombre'); r = request.form.get('role')
        if User.query.filter_by(username=u).first(): msg = "❌ Existe."
        else:
            # Generamos Token Fijo al crear
            token_nuevo = "TK-" + secrets.token_hex(6)
            nu = User(username=u, role=r, api_token=token_nuevo); nu.set_password(p); db.session.add(nu); db.session.commit()
            if r == 'estacion': nc = Cliente(nombre_fantasia=n, user_id=nu.id); db.session.add(nc); db.session.commit()
            msg = f"✅ Creado. Token: {token_nuevo}"

    users = User.query.all(); l = ""
    for u in users:
        if u.role == 'superadmin': continue
        st = "🟢 Online" if u.status_conexion=='online' else "🔴 Offline"
        nom = u.cliente_info.nombre_fantasia if u.cliente_info else "-"
        l += f"<li style='padding:10px;border-bottom:1px solid #eee;background:white;margin:5px;border-radius:5px'><b>{u.username}</b> ({nom})<br><small>Token: {u.api_token}</small><div style='float:right'>{st}</div></li>"

    return f"""<style>body{{font-family:sans-serif;padding:30px;background:#f4f7f6;max-width:800px;margin:0 auto}}.card{{background:white;padding:20px;border-radius:10px;margin-bottom:20px}}input,select{{padding:5px;margin:5px}}button{{padding:5px 15px;background:green;color:white;border:none;border-radius:5px;cursor:pointer}}</style><a href="/logout" style="float:right">Salir</a><h1>SuperAdmin</h1><p style="color:blue">{msg}</p><div class="card"><h3>➕ Nueva Estación</h3><form method="POST"><input type="hidden" name="create_user" value="1"><input name="username" placeholder="Usuario" required><input name="password" placeholder="Clave"><input name="nombre" placeholder="Fantasia"><select name="role"><option value="estacion">Estación</option></select><button>Crear</button></form></div><div class="card"><h3>📡 Gestión</h3><ul style="list-style:none;padding:0">{l}</ul></div>"""

@app.route('/estacion/panel')
@login_required
def panel_estacion():
    if current_user.is_superadmin: return redirect(url_for('panel_superadmin'))
    
    # Botón de extracción manual
    btn_txt = "⬇️ FORZAR EXTRACCIÓN AHORA"
    btn_style = "background:#007bff"
    if current_user.comando_pendiente == 'EXTRACT': 
        btn_txt = "⏳ Enviando orden..."
        btn_style = "background:gray;cursor:wait"

    st = current_user.status_conexion
    icon = "🟢 Conectado" if st=='online' else "🔴 Desconectado"
    cls = "ok" if st=='online' else "err"

    return f"""
    <style>body{{font-family:sans-serif;background:#f0f2f5;padding:20px;text-align:center}}.btn{{display:block;width:100%;padding:20px;margin:15px 0;background:white;border:none;border-radius:12px;text-align:left;text-decoration:none;color:#333;box-shadow:0 4px 6px #00000005}}.tag{{float:right;padding:5px 10px;border-radius:15px;background:#eee;font-size:0.8rem}}.ok{{background:#d4edda;color:green}}.err{{background:#f8d7da;color:red}}.act{{color:white;font-weight:bold;text-align:center}}</style>
    <script>setInterval(()=>{{fetch('/api/ping-ui').then(r=>r.json()).then(d=>{{if(d.st!=='{st}'||d.cmd!=={( 'true' if current_user.comando_pendiente else 'false' )})location.reload()}})}},3000)</script>
    <div style="max-width:600px;margin:0 auto">
        <h1>Hola, {current_user.username}</h1>
        <p>Estado PC: <span class="tag {cls}">{icon}</span></p>
        
        <div style="background:#333;color:white;padding:10px;border-radius:5px;margin-bottom:20px;font-family:monospace">
            TOKEN INSTALADOR: <b>{current_user.api_token}</b>
        </div>
        
        <a href="/estacion/config-vox" class="btn">⚙️ Configurar Credenciales VOX</a>
        
        <form method="POST" action="/api/lanzar-orden">
            <button class="btn act" style="{btn_style}">{btn_txt}</button>
        </form>

        <a href="/estacion/ver-reportes" class="btn">📊 Ver Gráficos</a>
        <br><a href="/logout">Salir</a>
    </div>
    """

@app.route('/estacion/config-vox', methods=['GET', 'POST'])
@login_required
def config_vox():
    msg = ""
    if request.method == 'POST':
        ip = request.form.get('ip'); u = request.form.get('u'); p = request.form.get('p')
        
        c = CredencialVox.query.filter_by(user_id=current_user.id).first()
        if not c: c = CredencialVox(user_id=current_user.id)
        
        c.vox_ip = ip; c.vox_usuario = u; c.vox_clave = p
        db.session.add(c); db.session.commit()
        msg = "✅ Guardado. El agente recibirá estos datos en breve."
    
    c = current_user.credenciales_vox
    val_ip = c.vox_ip if c else "10.6.235.229"
    val_u = c.vox_usuario if c else ""; val_p = c.vox_clave if c else ""
    
    return f"""<style>body{{font-family:sans-serif;padding:40px;text-align:center}}input{{display:block;width:300px;margin:10px auto;padding:10px}}button{{padding:10px 30px;background:#007bff;color:white;border:none;border-radius:5px}}</style><h1>Configurar VOX</h1><form method="POST"><label>IP Local</label><input name="ip" value="{val_ip}"><label>Usuario VOX</label><input name="u" value="{val_u}"><label>Clave VOX</label><input type="password" name="p" value="{val_p}"><button>Guardar</button></form><p style="color:green">{msg}</p><br><a href="/">Volver</a>"""

@app.route('/estacion/ver-reportes')
@login_required
def ver_reportes_html(): return render_template('index.html', usuario=current_user.username)

# --- APIS PARA EL AGENTE ---

@app.route('/api/agent/sync', methods=['POST'])
def agent_sync():
    token = request.headers.get('X-API-TOKEN')
    user = User.query.filter_by(api_token=token).first()
    
    if not user: return jsonify({"status": "revoked"}), 401
    
    # Heartbeat
    user.status_conexion = 'online'
    user.last_check = datetime.now()
    
    # Comandos
    cmd = user.comando_pendiente
    if cmd: user.comando_pendiente = None
    db.session.commit()
    
    # Config VOX para entregar al agente
    conf = {}
    if user.credenciales_vox:
        conf = {"ip": user.credenciales_vox.vox_ip, "u": user.credenciales_vox.vox_usuario, "p": user.credenciales_vox.vox_clave}

    return jsonify({"status": "ok", "command": cmd, "config": conf}), 200

@app.route('/api/reportar', methods=['POST'])
def rep():
    try:
        tk = request.headers.get('X-API-TOKEN'); u = User.query.filter_by(api_token=tk).first()
        if not u: return jsonify({"status":"error"}), 401
        n = request.json; nid = n.get('id_interno')
        if Reporte.query.filter_by(id_interno=nid, user_id=u.id).first(): return jsonify({"status":"ignorado"}),200
        f,t,d = procesar_fecha_turno(n.get('fecha'))
        r = Reporte(user_id=u.id, id_interno=nid, estacion=n.get('estacion'), fecha_completa=n.get('fecha'), monto=n.get('monto'), fecha_operativa=f, turno=t, hora_cierre=d)
        db.session.add(r); db.session.commit()
        return jsonify({"status":"exito"}),200
    except Exception as e: return jsonify({"status":"error"}),500

# API UI
@app.route('/api/ping-ui')
@login_required
def ping(): return jsonify({"st": current_user.status_conexion, "cmd": current_user.comando_pendiente == 'EXTRACT'})

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
    res = {k: {"monto":0.0,"horario":"-","cierres":0} for k in ["Mañana","Tarde","Noche"]}
    for r in reps:
        if r.turno in res: res[r.turno]["monto"]+=r.monto; res[r.turno]["cierres"]+=1
    return jsonify([{"turno":k, "monto":v["monto"], "cantidad_cierres":v["cierres"]} for k,v in res.items()])

def auto_setup():
    try:
        with app.app_context():
            db.create_all()
            if not User.query.filter_by(username='admin').first():
                a = User(username='admin', role='superadmin', api_token='MASTER'); a.set_password('admin123'); db.session.add(a); db.session.commit()
    except: pass
auto_setup()

if __name__ == '__main__': app.run(host='0.0.0.0', port=10000)