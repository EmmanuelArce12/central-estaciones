import os
from flask import Flask, request, jsonify, render_template, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

# --- CONFIGURACIÓN DE SEGURIDAD Y BASE DE DATOS ---
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///local.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'ESTO_DEBE_SER_SECRETO_Y_LARGO' # Token de seguridad para sesiones

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# --- MODELOS (TABLAS DEFINITIVAS) ---

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    # ROLES: 'superadmin' (Tú), 'admin' (Gerentes), 'estacion' (Solo ver gráficos)
    role = db.Column(db.String(20), default='estacion', nullable=False)
    
    # Relación: Un usuario puede tener datos de cliente asociados
    cliente_info = db.relationship('Cliente', backref='usuario', uselist=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    # Helpers para verificar roles
    @property
    def is_superadmin(self):
        return self.role == 'superadmin'

class Cliente(db.Model):
    __tablename__ = 'clientes'
    id = db.Column(db.Integer, primary_key=True)
    nombre_fantasia = db.Column(db.String(100)) # Ej: Estación Laferrere
    direccion = db.Column(db.String(200))
    telefono = db.Column(db.String(50))
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), unique=True) # Vinculo con el login

# (Dejamos la tabla de reportes preparada para que no de error el script, pero no la usamos hoy)
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

# --- SISTEMA DE LOGIN ---

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- RUTAS DE ACCESO ---

@app.route('/')
def index_redirect():
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
            # Redirección inteligente según rol
            if user.is_superadmin:
                return redirect(url_for('panel_superadmin'))
            return redirect(url_for('index_redirect'))
        else:
            error = "Credenciales inválidas."

    return f"""
    <style>body{{font-family:'Segoe UI',sans-serif;background:#f4f7f6;display:flex;justify-content:center;align-items:center;height:100vh}}form{{background:white;padding:40px;border-radius:12px;box-shadow:0 5px 15px rgba(0,0,0,0.1);width:320px;text-align:center}}input{{width:100%;padding:12px;margin:10px 0;border:1px solid #ddd;border-radius:8px;box-sizing:border-box}}button{{width:100%;padding:12px;background:#007bff;color:white;border:none;border-radius:8px;cursor:pointer;font-weight:600;font-size:16px}}button:hover{{background:#0056b3}}.error{{color:#e74c3c;margin-top:10px}}</style>
    <form method="POST">
        <h2 style="color:#333;margin-bottom:20px">🔐 Portal Seguro</h2>
        <input type="text" name="username" placeholder="Usuario" required>
        <input type="password" name="password" placeholder="Contraseña" required>
        <button type="submit">Iniciar Sesión</button>
        <p class="error">{error}</p>
    </form>
    """

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# --- 👑 PANEL SUPER ADMIN (Gestión de Usuarios y Clientes) ---
@app.route('/admin/dashboard', methods=['GET', 'POST'])
@login_required
def panel_superadmin():
    if not current_user.is_superadmin:
        return "⛔ ACCESO DENEGADO"

    mensaje = ""
    if request.method == 'POST':
        # Lógica para crear NUEVA ESTACIÓN (Usuario + Cliente)
        u_user = request.form.get('username')
        u_pass = request.form.get('password')
        c_nombre = request.form.get('nombre_fantasia')
        
        if User.query.filter_by(username=u_user).first():
            mensaje = "❌ El usuario ya existe."
        else:
            # 1. Crear Usuario Login
            nuevo_user = User(username=u_user, role='estacion')
            nuevo_user.set_password(u_pass)
            db.session.add(nuevo_user)
            db.session.commit() # Commit para obtener el ID
            
            # 2. Crear Perfil de Cliente vinculado
            nuevo_cliente = Cliente(nombre_fantasia=c_nombre, user_id=nuevo_user.id)
            db.session.add(nuevo_cliente)
            db.session.commit()
            
            mensaje = f"✅ Estación '{c_nombre}' creada con usuario '{u_user}'."

    # Listar datos para ver en el panel
    usuarios = User.query.all()
    lista_html = ""
    for u in usuarios:
        rol_icono = "👑" if u.role == 'superadmin' else "🏢"
        cliente_nom = u.cliente_info.nombre_fantasia if u.cliente_info else "Sin datos de cliente"
        lista_html += f"<li>{rol_icono} <b>{u.username}</b> - {cliente_nom} <span style='font-size:0.8em;color:gray'>({u.role})</span></li>"

    return f"""
    <style>body{{font-family:'Segoe UI',sans-serif;padding:40px;background:#f9f9f9;max-width:900px;margin:0 auto}}h1{{color:#2c3e50}}.card{{background:white;padding:25px;border-radius:10px;box-shadow:0 2px 10px rgba(0,0,0,0.05);margin-bottom:25px}}input,select{{padding:10px;border:1px solid #ccc;border-radius:5px;margin-right:10px}}button{{padding:10px 20px;background:#27ae60;color:white;border:none;border-radius:5px;cursor:pointer}}a{{color:#c0392b;text-decoration:none;font-weight:bold;float:right}}</style>
    
    <a href="/logout">Cerrar Sesión</a>
    <h1>👑 Panel de Super Administración</h1>
    
    <div class="card">
        <h3>➕ Alta de Nueva Estación</h3>
        <p style="color:#666;font-size:0.9em">Esto creará el usuario para el Login y el perfil del cliente.</p>
        <form method="POST" style="display:flex;gap:10px;flex-wrap:wrap">
            <input type="text" name="username" placeholder="Usuario Login (ej: laferrere)" required>
            <input type="password" name="password" placeholder="Contraseña" required>
            <input type="text" name="nombre_fantasia" placeholder="Nombre Fantasía (ej: Est. Laferrere)" required>
            <button type="submit">Crear Estación</button>
        </form>
        <p style="font-weight:bold;color:#2980b9">{mensaje}</p>
    </div>

    <div class="card">
        <h3>📋 Estaciones y Usuarios Activos</h3>
        <ul>{lista_html}</ul>
    </div>
    """

# --- INICIALIZADOR SEGURO (Solo corre una vez si hace falta) ---
def inicializar_sistema():
    with app.app_context():
        # Crea las tablas SOLO si no existen. NO BORRA NADA.
        db.create_all()
        
        # Verifica si existe el Super Admin, si no, lo crea.
        if not User.query.filter_by(username='admin').first():
            print("⚙️ Creando Super Admin por primera vez...")
            admin = User(username='admin', role='superadmin')
            admin.set_password('admin123')
            db.session.add(admin)
            db.session.commit()
            print("✅ Super Admin creado.")

# API Reportar (Mantenemos para que no se rompa el script de la PC)
@app.route('/api/reportar', methods=['POST'])
def recibir_reporte():
    # ... (Misma lógica de antes) ...
    return jsonify({"status": "exito"}), 200

# API Resumen (Mantenemos para el Front)
@app.route('/api/resumen-dia/<string:fecha_seleccionada>')
@login_required
def api_resumen(fecha_seleccionada):
    # ... (Misma lógica de antes) ...
    return jsonify([]) 


if __name__ == '__main__':
    # Ejecutamos el inicializador al arrancar
    inicializar_sistema()
    app.run(host='0.0.0.0', port=10000)
