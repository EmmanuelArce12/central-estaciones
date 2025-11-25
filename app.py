import os
import secrets
from flask import Flask, request, jsonify, render_template, redirect, url_for
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
app.config['SECRET_KEY'] = 'SECRET_KEY'

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
    
    # EL TOKEN ÚNICO (Nace con el usuario)
    station_token = db.Column(db.String(100), unique=True, nullable=True)
    
    # Estado y Comandos
    status_conexion = db.Column(db.String(20), default='offline')
    comando_pendiente = db.Column(db.String(50), nullable=True) # Ej: 'EXTRACT'
    last_check = db.Column(db.DateTime)
    
    # Datos VOX (Guardados en el Usuario para simplificar)
    vox_ip = db.Column(db.String(50))
    vox_user = db.Column(db.String(50))
    vox_pass = db.Column(db.String(50))

    cliente_info = db.relationship('Cliente', backref='usuario', uselist=False)

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
    if request.method == 'POST':
        u = request.form.get('username'); p = request.form.get('password'); n = request.form.get('nombre'); r = request.form.get('role')
        if User.query.filter_by(username=u).first(): msg = "❌ Existe."
        else:
            # Generamos Token FIJO al crear
            token = "ST-" + secrets.token_hex(4)
            nu = User(username=u, role=r, station_token=token); nu.set_password(p); db.session.add(nu); db.session.commit()
            if r == 'estacion': nc = Cliente(nombre_fantasia=n, user_id=nu.id); db.session.add(nc); db.session.commit()
            msg = f"✅ Creado. Token: {token}"
    
    users = User.query.all(); l = ""
    for u in users:
        st = "🟢" if u.status_conexion=='online' else "🔴"
        nm = u.cliente_info.nombre_fantasia if u.cliente_info else "-"
        l += f"<li style='padding:10px;border-bottom:1px solid #eee'>{st} <b>{u.username}</b> ({nm}) - Token: <code>{u.station_token}</code></li>"
    return f"""<style>body{{font-family:sans-serif;padding:30px;max-width:800px;margin:0 auto}}.card{{background:white;padding:20px;border-radius:10px;margin-bottom:20px;box-shadow:0 2px 5px #00000010}}input,select{{padding:8px;margin:5px}}button{{padding:8px 15px;background:green;color:white;border:none;border-radius:5px}}</style><a href="/logout">Salir</a><h1>SuperAdmin</h1><div class="card"><h3>➕ Nuevo</h3><form method="POST"><input name="username" placeholder="User" required><input name="password" type="password" placeholder="Pass" required><input name="nombre" placeholder="Negocio"><select name="role"><option value="estacion">Estación</option><option value="superadmin">Admin</option></select><button>Crear</button></form><p>{msg}</p></div><div class="card"><ul>{l}</ul></div>"""

@app.route('/estacion/panel')
@login_required
def panel_estacion():
    if current_user.is_superadmin: return redirect(url_for('panel_superadmin'))
    st = current_user.status_conexion
    icon = "✅ PC Conectada" if st=='online' else "🔴 PC Desconectada"
    cls = "ok" if st=='online' else "err"
    
    # Botón de extracción
    btn_txt = "⬇️ EXTRAER REPORTE AHORA"
    if current_user.comando_pendiente == 'EXTRACT': btn_txt = "⏳ Enviando orden..."

    return f"""
    <style>body{{font-family:sans-serif;background:#f0f2f5;padding:20px;text-align:center}}.btn{{display:block;width:100%;padding:20px;margin:15px 0;background:white;border:none;border-radius:12px;text-align:left;text-decoration:none;color:#333;box-shadow:0 4px 6px #00000005}}.tag{{float:right;padding:5px 10px;border-radius:15px;background:#eee;font-size:0.8rem}}.ok{{background:#d4edda;color:green}}.err{{background:#f8d7da;color:red}}.act{{background:#007bff;color:white;font-weight:bold;text-align:center}}.token{{background:#333;color:#fff;padding:15px;border-radius:8px;font-family:monospace;margin-bottom:20px}}</style>
    <script>setInterval(()=>{{fetch('/api/ping-ui').then(r=>r.json()).then(d=>{{if(d.st!=='{st}'||d.cmd!=={( 'true' if current_user.comando_pendiente else 'false' )})location.reload()}})}},3000)</script>
    <div style="max-width:600px;margin:0 auto">
        <h1>Hola, {current_user.username}</h1>
        
        <div class="token">
            🔑 TOKEN DE INSTALACIÓN:<br>
            <span style="font-size:1.5em">{current_user.station_token}</span>
        </div>

        <p>Estado PC: <span class="tag {cls}">{icon}</span></p>
        
        <a href="/estacion/config-vox" class="btn">⚙️ Configurar Datos VOX (IP/User/Pass)</a>
        
        <form method="POST" action="/api/lanzar-orden">
            <button class="btn act">{btn_txt}</button>
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
        current_user.vox_ip = request.form.get('ip')
        current_user.vox_user = request.form.get('u')
        current_user.vox_pass = request.form.get('p')
        db.session.commit()
        msg = "✅ Guardado."
    return f"""<style>body{{font-family:sans-serif;padding:40px;text-align:center}}input{{display:block;width:300px;margin:10px auto;padding:10px}}button{{padding:10px 30px}}</style><h1>Datos VOX</h1><form method="POST"><label>IP Local</label><input name="ip" value="{current_user.vox_ip or ''}"><label>Usuario</label><input name="u" value="{current_user.vox_user or ''}"><label>Clave</label><input name="p" type="password" value="{current_user.vox_pass or ''}"><button>Guardar</button></form><p style="color:green">{msg}</p><br><a href="/">Volver</a>"""

@app.route('/estacion/ver-reportes')
@login_required
def ver_reportes_html(): return render_template('index.html', usuario=current_user.username)

# --- APIS PARA EL SCRIPT (AGENT) ---

@app.route('/api/agent/poll', methods=['POST'])
def agent_poll():
    # El script manda su token
    token = request.json.get('token')
    user = User.query.filter_by(station_token=token).first()
    
    if not user: return jsonify({"error": "Token invalido"}), 403
    
    # Actualizamos "visto por ultima vez"
    user.status_conexion = 'online'
    user.last_check = datetime.now()
    
    # Verificamos si hay ordenes
    cmd = user.comando_pendiente
    if cmd:
        user.comando_pendiente = None # Limpiamos orden
    
    db.session.commit()
    
    return jsonify({
        "command": cmd,
        "config": {
            "ip": user.vox_ip,
            "user": user.vox_user,
            "pass": user.vox_pass
        }
    }), 200

@app.route('/api/agent/report', methods=['POST'])
def agent_report():
    token = request.json.get('token')
    user = User.query.filter_by(station_token=token).first()
    if not user: return jsonify({"error": "Token invalido"}), 403
    
    n = request.json
    nid = n.get('id_interno')
    if Reporte.query.filter_by(id_interno=nid, user_id=user.id).first():
        return jsonify({"status": "ignorado"}), 200
        
    f,t,d = procesar_fecha_turno(n.get('fecha'))
    r = Reporte(user_id=user.id, id_interno=nid, estacion=n.get('estacion'), fecha_completa=n.get('fecha'), monto=n.get('monto'), fecha_operativa=f, turno=t, hora_cierre=d)
    db.session.add(r); db.session.commit()
    return jsonify({"status":"exito"}), 200

# --- APIS INTERNAS ---
@app.route('/api/lanzar-orden', methods=['POST'])
@login_required
def lanzar():
    current_user.comando_pendiente = 'EXTRACT'
    db.session.commit()
    return redirect(url_for('panel_estacion'))

@app.route('/api/ping-ui')
@login_required
def ping(): return jsonify({"st": current_user.status_conexion, "cmd": current_user.comando_pendiente == 'EXTRACT'})

@app.route('/api/resumen-dia/<string:fecha>')
@login_required
def api_res(fecha):
    reps = Reporte.query.filter_by(fecha_operativa=fecha, user_id=current_user.id).all()
    # ... (Lógica de resumen igual que antes, resumida aqui) ...
    res = {k: {"monto":0.0,"horario":"-","cierres":0} for k in ["Mañana","Tarde","Noche"]}
    for r in reps:
        if r.turno in res: res[r.turno]["monto"]+=r.monto; res[r.turno]["cierres"]+=1
    return jsonify([{"turno":k, "monto":v["monto"], "cantidad_cierres":v["cierres"]} for k,v in res.items()])

def auto_setup():
    try:
        with app.app_context():
            db.create_all()
            if not User.query.filter_by(username='admin').first():
                u = User(username='admin', role='superadmin'); u.set_password('admin123'); db.session.add(u); db.session.commit()
    except: pass
auto_setup()

if __name__ == '__main__': app.run(host='0.0.0.0', port=10000)
