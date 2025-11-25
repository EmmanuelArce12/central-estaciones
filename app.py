import os
from flask import Flask, request, jsonify, render_template, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta

app = Flask(__name__)

# --- CONFIGURACIÓN ---
# Detecta la base de datos de Render. Si no hay, usa una local.
# Fix para Render: SQLAlchemy espera 'postgresql://', pero Render da 'postgres://'
db_url = os.environ.get('DATABASE_URL', 'sqlite:///local.db')
if db_url.startswith("postgres://"):
    db_url = db_url.replace("postgres://", "postgresql://", 1)

app.config['SQLALCHEMY_DATABASE_URI'] = db_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'CLAVE_SUPER_SECRETA_INDESCIFRABLE'

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# --- MODELOS DE BASE DE DATOS ---

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    # Roles: 'superadmin' (Tú), 'estacion' (Clientes)
    role = db.Column(db.String(20), default='estacion', nullable=False)
    
    # Relación con datos del cliente
    cliente_info = db.relationship('Cliente', backref='usuario', uselist=False)

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
    nombre_fantasia = db.Column(db.String(100)) # Ej: "Estación Laferrere"
    direccion = db.Column(db.String(200), nullable=True)
    telefono = db.Column(db.String(50), nullable=True)
    # Vinculamos este perfil de negocio a un usuario de login
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), unique=True)

class Reporte(db.Model):
    __tablename__ = 'reportes'
    id = db.Column(db.Integer, primary_key=True)
    id_interno = db.Column(db.String(50), unique=True)
    estacion = db.Column(db.String(100))
    fecha_completa = db.Column(db.String(100))
    monto = db.Column(db.Float)
    fecha_operativa = db.Column(db.String(20))
    turno = db.Column(db.String(20))
    hora_cierre = db.Column(db.DateTime)

# --- LOGIN MANAGER ---
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- LÓGICA DE NEGOCIO (FECHAS) ---
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

# --- RUTAS DE NAVEGACIÓN ---

@app.route('/')
def root():
    # El portero: decide a dónde vas según quién eres
    if current_user.is_authenticated:
        if current_user.is_superadmin:
            return redirect(url_for('panel_superadmin'))
        else:
            return render_template('index.html', usuario=current_user.username)
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
            error = "Usuario o contraseña incorrectos."

    # Formulario Login minimalista
    return f"""
    <style>body{{font-family:sans-serif;background:#eef2f3;display:flex;justify-content:center;align-items:center;height:100vh}}form{{background:white;padding:40px;border-radius:15px;box-shadow:0 10px 25px rgba(0,0,0,0.1);width:300px;text-align:center}}input{{width:100%;padding:12px;margin:10px 0;border:1px solid #ccc;border-radius:8px;box-sizing:border-box}}button{{width:100%;padding:12px;background:#007bff;color:white;border:none;border-radius:8px;cursor:pointer;font-weight:bold}}button:hover{{background:#0056b3}}.error{{color:red;margin-top:10px}}</style>
    <form method="POST">
        <h2>🔒 Acceso Seguro</h2>
        <input type="text" name="username" placeholder="Usuario" required>
        <input type="password" name="password" placeholder="Contraseña" required>
        <button type="submit">Ingresar</button>
        <p class="error">{error}</p>
    </form>
    """

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# --- 👑 PANEL SUPER ADMIN ---
@app.route('/admin/dashboard', methods=['GET', 'POST'])
@login_required
def panel_superadmin():
    if not current_user.is_superadmin:
        return "⛔ ACCESO DENEGADO. Área restringida."

    mensaje = ""
    if request.method == 'POST':
        # Crear Estación (Usuario + Cliente)
        u_user = request.form.get('username')
        u_pass = request.form.get('password')
        c_nombre = request.form.get('nombre_fantasia')
        
        if User.query.filter_by(username=u_user).first():
            mensaje = "❌ El usuario ya existe."
        else:
            # 1. Crear Usuario
            nuevo_user = User(username=u_user, role='estacion')
            nuevo_user.set_password(u_pass)
            db.session.add(nuevo_user)
            db.session.commit()
            
            # 2. Crear Cliente
            nuevo_cliente = Cliente(nombre_fantasia=c_nombre, user_id=nuevo_user.id)
            db.session.add(nuevo_cliente)
            db.session.commit()
            mensaje = f"✅ Estación '{c_nombre}' creada con éxito."

    # Listar estaciones
    usuarios = User.query.all()
    lista = ""
    for u in usuarios:
        rol = "👑 ADMIN" if u.is_superadmin else "🏢 ESTACIÓN"
        nombre_negocio = u.cliente_info.nombre_fantasia if u.cliente_info else "Sistema"
        lista += f"<li style='padding:10px;border-bottom:1px solid #eee'>{rol}: <b>{u.username}</b> ({nombre_negocio})</li>"

    return f"""
    <style>body{{font-family:sans-serif;padding:30px;background:#f8f9fa;max-width:800px;margin:0 auto}}h1{{color:#333}}.card{{background:white;padding:25px;border-radius:10px;box-shadow:0 2px 10px rgba(0,0,0,0.05);margin-bottom:20px}}input{{padding:10px;border:1px solid #ddd;border-radius:5px;margin:5px}}button{{padding:10px 20px;background:#28a745;color:white;border:none;border-radius:5px;cursor:pointer}}a{{float:right;color:#dc3545;text-decoration:none;font-weight:bold}}</style>
    
    <a href="/logout">Cerrar Sesión</a>
    <h1>Panel de Super Usuario</h1>
    
    <div class="card">
        <h3>➕ Alta de Nueva Estación</h3>
        <form method="POST">
            <input type="text" name="username" placeholder="Usuario Login" required>
            <input type="password" name="password" placeholder="Contraseña" required>
            <input type="text" name="nombre_fantasia" placeholder="Nombre del Negocio" required>
            <br><br>
            <button type="submit">Crear Estación</button>
        </form>
        <p style="font-weight:bold;color:#007bff">{mensaje}</p>
    </div>

    <div class="card">
        <h3>📋 Estaciones Activas</h3>
        <ul style="list-style:none;padding:0">{lista}</ul>
    </div>
    """

# --- APIS ---
@app.route('/api/reportar', methods=['POST'])
def recibir_reporte():
    try:
        nuevo = request.json
        nid = nuevo.get('id_interno')
        
        # Filtro duplicados
        if Reporte.query.filter_by(id_interno=nid).first():
            return jsonify({"status": "ignorado"}), 200
        
        fecha_str = nuevo.get('fecha')
        f_op, turno, dt_cierre = procesar_fecha_turno(fecha_str)
        
        # Guardar
        rep = Reporte(
            id_interno=nid, estacion=nuevo.get('estacion'), fecha_completa=fecha_str,
            monto=nuevo.get('monto'), fecha_operativa=f_op, turno=turno, hora_cierre=dt_cierre
        )
        db.session.add(rep)
        db.session.commit()
        return jsonify({"status": "exito"}), 200
    except Exception as e:
        return jsonify({"status": "error", "msg": str(e)}), 500

@app.route('/api/resumen-dia/<string:fecha_seleccionada>')
@login_required
def api_resumen(fecha_seleccionada):
    reportes = Reporte.query.filter_by(fecha_operativa=fecha_seleccionada).all()
    resumen = { "Mañana": {"monto":0.0,"horario":"-","cierres":0,"fin":None}, "Tarde": {"monto":0.0,"horario":"-","cierres":0,"fin":None}, "Noche": {"monto":0.0,"horario":"-","cierres":0,"fin":None} }
    
    for r in reportes:
        t = r.turno
        if t in resumen:
            resumen[t]["monto"] += r.monto
            resumen[t]["cierres"] += 1
            if resumen[t]["fin"] is None or r.hora_cierre > resumen[t]["fin"]:
                resumen[t]["fin"] = r.hora_cierre
                resumen[t]["horario"] = r.hora_cierre.strftime("%H:%M")
    
    rta = []
    for t in ["Mañana","Tarde","Noche"]:
        d = resumen[t]
        rta.append({"turno":t,"monto":d["monto"],"horario":d["horario"],"cantidad_cierres":d["cantidad_cierres"]})
    return jsonify(rta)


# --- INICIALIZADOR AUTOMÁTICO AL ARRANCAR ---
# Esto crea las tablas y el admin en cuanto Render prende el servidor.
def auto_setup():
    with app.app_context():
        db.create_all()
        # Verificar si existe superadmin
        if not User.query.filter_by(username='admin').first():
            print("⚙️ SETUP INICIAL: Creando SuperAdmin...")
            admin = User(username='admin', role='superadmin')
            admin.set_password('admin123')
            db.session.add(admin)
            db.session.commit()
            print("✅ SuperAdmin creado.")

# Ejecutamos el setup
auto_setup()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=10000)
