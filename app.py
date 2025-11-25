import os
import secrets # Para generar tokens seguros
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
app.config['SECRET_KEY'] = 'CLAVE_SUPER_SECRETA_INDESCIFRABLE'

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
    
    # 🔐 NUEVO: Token de API único para el script
    api_token = db.Column(db.String(100), unique=True, nullable=True) 

    cliente_info = db.relationship('Cliente', backref='usuario', uselist=False)
    credenciales_vox = db.relationship('CredencialVox', backref='usuario', uselist=False)
    status_conexion = db.Column(db.String(20), default='pendiente')
    last_check = db.Column(db.DateTime)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    @property
    def is_superadmin(self):
        return self.role == 'superadmin'

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

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- LÓGICA FECHAS ---
def procesar_fecha_turno(fecha_hora_str):
    try:
        partes = fecha_hora_str.split(' - ')
        if len(partes) < 2: return None, None, None
        cierre_raw = partes[1].replace(')', '').strip()
        dt = datetime.strptime(cierre_raw, "%Y/%m/%d %H:%M:%S")
        hora = dt.hour
        fecha_op = dt.date()
        turno = "Noche"
        if 6 <= hora < 14: turno = "Mañana"
        elif 14 <= hora < 22: turno = "Tarde"
        else:
            if hora < 6: fecha_op = fecha_op - timedelta(days=1)
        return fecha_op.strftime("%Y-%m-%d"), turno, dt
    except: return None, None, None

# --- VISTAS ---

@app.route('/')
def root():
    if current_user.is_authenticated:
        if current_user.is_superadmin: return redirect(url_for('panel_superadmin'))
        return redirect(url_for('panel_estacion'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = ""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('root'))
        else:
            error = "Credenciales incorrectas."
    return f"""
    <style>body{{font-family:sans-serif;background:#eef2f3;display:flex;justify-content:center;align-items:center;height:100vh}}form{{background:white;padding:40px;border-radius:15px;box-shadow:0 10px 25px rgba(0,0,0,0.1);width:300px;text-align:center}}input{{width:100%;padding:12px;margin:10px 0;border:1px solid #ccc;border-radius:8px}}button{{width:100%;padding:12px;background:#007bff;color:white;border:none;border-radius:8px;cursor:pointer}}</style>
    <form method="POST"><h2>🔒 Portal</h2><input type="text" name="username" placeholder="Usuario" required><input type="password" name="password" placeholder="Contraseña" required><button type="submit">Ingresar</button><p style="color:red">{error}</p></form>
    """

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/admin/dashboard', methods=['GET', 'POST'])
@login_required
def panel_superadmin():
    if not current_user.is_superadmin: return "⛔ ACCESO DENEGADO."
    mensaje = ""
    if request.method == 'POST':
        u_user = request.form.get('username')
        u_pass = request.form.get('password')
        c_nombre = request.form.get('nombre_fantasia')
        u_role = request.form.get('role')
        if User.query.filter_by(username=u_user).first():
            mensaje = "❌ Usuario existente."
        else:
            # Generamos TOKEN automático
            token_seguro = secrets.token_hex(16) # Genera string aleatorio de 32 caracteres
            
            nuevo_user = User(username=u_user, role=u_role, api_token=token_seguro)
            nuevo_user.set_password(u_pass)
            db.session.add(nuevo_user)
            db.session.commit()
            if u_role == 'estacion':
                nuevo_cliente = Cliente(nombre_fantasia=c_nombre, user_id=nuevo_user.id)
                db.session.add(nuevo_cliente)
                db.session.commit()
            mensaje = f"✅ Usuario '{u_user}' creado."

    usuarios = User.query.all()
    lista = ""
    for u in usuarios:
        rol_txt = "👑 SUPER" if u.role == 'superadmin' else "🏢 ESTACIÓN"
        nom = u.cliente_info.nombre_fantasia if u.cliente_info else "-"
        estado = "⚪"
        if u.status_conexion == 'ok': estado = "🟢 Online"
        elif u.status_conexion == 'error': estado = "🔴 Error"
        lista += f"<li style='padding:10px;border-bottom:1px solid #eee'>{rol_txt}: <b>{u.username}</b> ({nom}) - {estado}</li>"

    return f"""
    <style>body{{font-family:sans-serif;padding:30px;background:#f8f9fa;max-width:800px;margin:0 auto}}.card{{background:white;padding:25px;border-radius:10px;box-shadow:0 2px 10px rgba(0,0,0,0.05);margin-bottom:20px}}input,select{{padding:10px;margin:5px}}button{{padding:10px 20px;background:#28a745;color:white;border:none;border-radius:5px;cursor:pointer}}a{{float:right;color:#dc3545;text-decoration:none;font-weight:bold}}</style>
    <a href="/logout">Salir</a><h1>Panel Super Usuario</h1>
    <div class="card"><h3>➕ Alta Nuevo Usuario</h3><form method="POST"><input type="text" name="username" placeholder="Usuario Login" required><input type="password" name="password" placeholder="Contraseña" required><input type="text" name="nombre_fantasia" placeholder="Nombre Negocio"><select name="role"><option value="estacion">Rol: Estación</option><option value="superadmin">Rol: SuperAdmin</option></select><button type="submit">Crear</button></form><p style="color:blue">{mensaje}</p></div>
    <div class="card"><h3>📋 Usuarios</h3><ul style="list-style:none;padding:0">{lista}</ul></div>
    """

@app.route('/estacion/panel')
@login_required
def panel_estacion():
    if current_user.is_superadmin: return redirect(url_for('panel_superadmin'))
    nom = current_user.cliente_info.nombre_fantasia if current_user.cliente_info else current_user.username
    
    estado_conex = current_user.status_conexion
    icono_estado = "⚪ Pendiente"
    clase_estado = ""
    if estado_conex == 'ok': 
        icono_estado = "✅ Conectado OK"; clase_estado = "ok"
    elif estado_conex == 'error': 
        icono_estado = "❌ Error Conexión"; clase_estado = "error"

    tiene_creds = "Configurar"
    if current_user.credenciales_vox: tiene_creds = "Modificar"

    # Mostramos el TOKEN para copiar
    token_visible = current_user.api_token or "No generado"

    return f"""
    <style>body{{font-family:'Segoe UI',sans-serif;background:#f0f2f5;padding:20px;text-align:center}}.container{{max-width:600px;margin:0 auto}}.btn-grande{{display:block;width:100%;padding:20px;margin:15px 0;background:white;border:none;border-radius:12px;box-shadow:0 4px 6px rgba(0,0,0,0.05);text-align:left;cursor:pointer;text-decoration:none;color:#333;font-size:1.1rem;transition:0.2s}}.btn-grande:hover{{transform:translateY(-3px)}}.estado{{float:right;font-size:0.9rem;padding:5px 10px;border-radius:20px;background:#eee}}.estado.ok{{background:#d4edda;color:#155724}}.estado.error{{background:#f8d7da;color:#721c24}}.token-box{{background:#2c3e50;color:white;padding:15px;border-radius:8px;margin-bottom:20px;word-break:break-all;font-family:monospace}}</style>
    <div class="container">
        <h1>Hola, {nom} 👋</h1>
        
        <div class="token-box">
            <small>🔑 TU TOKEN DE SEGURIDAD (Copiar en config.json):</small><br>
            <b>{token_visible}</b>
        </div>

        <p>Panel de Configuración</p>
        
        <a href="/estacion/config-vox" class="btn-grande">
            📡 Configurar Conexión VOX
            <span class="estado {clase_estado}">{icono_estado}</span>
            <div style="font-size:0.8rem;color:gray;margin-top:5px">{tiene_creds} Datos</div>
        </a>
        <a href="#" class="btn-grande">💳 Mercado Pago y Extranet</a>
        <a href="#" class="btn-grande">📝 Corrección de Planillas</a>
        <a href="/estacion/ver-reportes" class="btn-grande" style="background:#2c3e50;color:white">📊 Ver Gráficos</a>
        <br><a href="/logout" style="color:#c0392b">Cerrar Sesión</a>
    </div>
    """

@app.route('/estacion/config-vox', methods=['GET', 'POST'])
@login_required
def config_vox():
    if request.method == 'POST':
        u_ip = request.form.get('vox_ip'); u_vox = request.form.get('vox_user'); p_vox = request.form.get('vox_pass')
        cred = CredencialVox.query.filter_by(user_id=current_user.id).first()
        if not cred: cred = CredencialVox(user_id=current_user.id)
        cred.vox_ip = u_ip; cred.vox_usuario = u_vox; cred.vox_clave = p_vox
        current_user.status_conexion = 'pendiente' # Reseteamos estado
        db.session.add(cred); db.session.commit()
        return redirect(url_for('config_vox'))

    cred = current_user.credenciales_vox
    val_ip = cred.vox_ip if cred else "10.6.235.229"
    val_u = cred.vox_usuario if cred else ""; val_p = cred.vox_clave if cred else ""
    
    st = current_user.status_conexion
    status_html = ""
    if st == 'pendiente':
        status_html = """<div class="status-box pending">🟡 <b>Esperando conexión...</b><br>Ejecuta el script en tu PC con el TOKEN configurado.<br><span id="loader">⏳ Buscando señal...</span></div>"""
    elif st == 'ok':
        status_html = """<div class="status-box success">✅ <b>¡Conexión Exitosa!</b></div>"""
    elif st == 'error':
        status_html = """<div class="status-box error">❌ <b>Error de Conexión</b></div>"""

    return f"""
    <!DOCTYPE html><html><head><style>body{{font-family:'Segoe UI',sans-serif;background:#f4f7f6;padding:20px;text-align:center}}.card{{background:white;padding:40px;border-radius:15px;box-shadow:0 10px 25px rgba(0,0,0,0.1);max-width:400px;margin:0 auto;text-align:left}}input{{width:100%;padding:12px;margin:8px 0;border:1px solid #ccc;border-radius:8px;box-sizing:border-box}}label{{font-weight:bold;color:#555;font-size:0.9rem}}button{{width:100%;padding:12px;background:#007bff;color:white;border:none;border-radius:8px;cursor:pointer;font-size:1rem;margin-top:15px}}button:hover{{background:#0056b3}}.status-box{{margin-top:20px;padding:15px;border-radius:8px;text-align:center;font-size:0.9rem}}.pending{{background:#fff3cd;color:#856404;border:1px solid #ffeeba}}.success{{background:#d4edda;color:#155724;border:1px solid #c3e6cb}}.error{{background:#f8d7da;color:#721c24;border:1px solid #f5c6cb}}a{{display:block;text-align:center;margin-top:20px;color:#666}}</style><script>setInterval(function(){{fetch('/api/check-status-usuario?token={current_user.api_token}').then(r=>r.json()).then(d=>{{if(d.status==='ok'){{document.getElementById('status-container').innerHTML='<div class="status-box success">✅ <b>¡Conectado!</b><br>Redireccionando...</div>';setTimeout(()=>window.location.reload(),2000)}}else if(d.status==='error'){{if(!document.querySelector('.error'))window.location.reload()}} }})}},3000);</script></head><body><h1>📡 Configuración VOX</h1><div class="card"><form method="POST"><label>IP Servidor VOX</label><input type="text" name="vox_ip" value="{val_ip}" required><label>Usuario VOX</label><input type="text" name="vox_user" value="{val_u}" required><label>Contraseña VOX</label><input type="password" name="vox_pass" value="{val_p}" required><button type="submit">💾 Guardar y Probar Conexión</button></form><div id="status-container">{status_html}</div><a href="/">Volver al Panel</a></div></body></html>
    """

@app.route('/estacion/ver-reportes')
@login_required
def ver_reportes_html(): return render_template('index.html', usuario=current_user.username)

# --- API CHECK STATUS (INTERNA) ---
@app.route('/api/check-status-usuario')
def check_status_user():
    # Verificamos por TOKEN en la URL (para simplificar el JS) o sesión
    token = request.args.get('token')
    user = None
    if current_user.is_authenticated: user = current_user
    elif token: user = User.query.filter_by(api_token=token).first()
    
    if user: return jsonify({"status": user.status_conexion})
    return jsonify({"status": "unknown"})

# --- APIS PROTEGIDAS (TOKEN REQUERIDO) ---

def verificar_token():
    """Verifica que el request traiga el token válido"""
    token = request.headers.get('X-API-TOKEN')
    if not token: return None
    return User.query.filter_by(api_token=token).first()

@app.route('/api/obtener-credenciales', methods=['POST'])
def api_credenciales():
    user = verificar_token()
    if not user: return jsonify({"error": "Token invalido"}), 403
    
    if user.credenciales_vox:
        return jsonify({
            "vox_ip": user.credenciales_vox.vox_ip,
            "vox_usuario": user.credenciales_vox.vox_usuario, 
            "vox_clave": user.credenciales_vox.vox_clave
        }), 200
    return jsonify({"error": "No configurado"}), 404

@app.route('/api/estado-conexion', methods=['POST'])
def api_estado():
    user = verificar_token()
    if not user: return jsonify({"error": "Token invalido"}), 403
    
    data = request.json
    status = data.get('status')
    user.status_conexion = status
    user.last_check = datetime.now()
    db.session.commit()
    return jsonify({"msg": "OK"}), 200

@app.route('/api/reportar', methods=['POST'])
def recibir_reporte():
    try:
        user = verificar_token()
        if not user: return jsonify({"error": "Token invalido"}), 403

        nuevo = request.json
        nid = nuevo.get('id_interno')
        if Reporte.query.filter_by(id_interno=nid, user_id=user.id).first():
            return jsonify({"status": "ignorado"}), 200
        
        fecha_str = nuevo.get('fecha')
        f_op, turno, dt_cierre = procesar_fecha_turno(fecha_str)
        rep = Reporte(
            user_id=user.id, id_interno=nid, estacion=nuevo.get('estacion'), fecha_completa=fecha_str,
            monto=nuevo.get('monto'), fecha_operativa=f_op, turno=turno, hora_cierre=dt_cierre
        )
        db.session.add(rep)
        db.session.commit()
        return jsonify({"status": "exito"}), 200
    except Exception as e:
        return jsonify({"status": "error", "msg": str(e)}), 500

# --- AUTO SETUP ---
def auto_setup():
    try:
        with app.app_context():
            db.create_all()
            if not User.query.filter_by(username='admin').first():
                a = User(username='admin', role='superadmin', api_token='ADMIN_TOKEN_MASTER')
                a.set_password('admin123')
                db.session.add(a)
                db.session.commit()
    except: pass
auto_setup()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=10000)
