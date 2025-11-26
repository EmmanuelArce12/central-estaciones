import os
from flask import Flask, request, jsonify, render_template, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta

app = Flask(__name__)

# --- CONFIGURACIÓN ---
# Detecta automáticamente la DB de Render o Supabase
db_url = os.environ.get('DATABASE_URL', 'sqlite:///local.db')
# Parche para compatibilidad con Supabase/Render (postgres:// -> postgresql://)
if db_url and db_url.startswith("postgres://"):
    db_url = db_url.replace("postgres://", "postgresql://", 1)

app.config['SQLALCHEMY_DATABASE_URI'] = db_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'CLAVE_SUPER_SECRETA_INDESCIFRABLE'

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# --- CLAVE MAESTRA PARA EL INSTALADOR .EXE ---
# Esta clave debe ser IGUAL en este archivo y en tu script de Python/Exe
API_KEY_MAESTRA = "CLAVE_MAESTRA_INSTALADOR" 

# --- MODELOS DE BASE DE DATOS ---

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), default='estacion', nullable=False)
    
    # Relaciones
    cliente_info = db.relationship('Cliente', backref='usuario', uselist=False)
    # Relación con reportes (Un usuario puede tener muchos reportes)
    reportes = db.relationship('Reporte', backref='usuario', lazy=True)

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

class Reporte(db.Model):
    __tablename__ = 'reportes'
    id = db.Column(db.Integer, primary_key=True)
    # Vinculamos el reporte a un usuario (dueño)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    
    id_interno = db.Column(db.String(50)) # ID del turno en VOX
    estacion = db.Column(db.String(100))  # Nombre texto (ej: "Estación Morón")
    fecha_completa = db.Column(db.String(100)) # String original
    monto = db.Column(db.Float)
    
    # Datos procesados para gráficos
    fecha_operativa = db.Column(db.String(20))
    turno = db.Column(db.String(20))
    hora_cierre = db.Column(db.DateTime)
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- LÓGICA DE FECHAS ---
def procesar_fecha_turno(fecha_hora_str):
    try:
        # Formato esperado: "2025-11 (2025/11/24 06:00:00 - 2025/11/24 14:00:00)"
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
            # Si es madrugada (ej: 2 AM), pertenece a la noche anterior
            if hora < 6: fecha_op = fecha_op - timedelta(days=1)
        
        return fecha_op.strftime("%Y-%m-%d"), turno, dt
    except: return None, None, None

# --- RUTAS WEB (FRONTEND) ---

@app.route('/')
def root():
    if current_user.is_authenticated:
        if current_user.is_superadmin:
            return redirect(url_for('panel_superadmin'))
        else:
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
    <form method="POST"><h2>🔒 Acceso Sistema</h2><input type="text" name="username" placeholder="Usuario" required><input type="password" name="password" placeholder="Contraseña" required><button type="submit">Ingresar</button><p style="color:red">{error}</p></form>
    """

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# --- PANEL SUPER ADMIN ---
@app.route('/admin/dashboard', methods=['GET', 'POST'])
@login_required
def panel_superadmin():
    if not current_user.is_superadmin: return "⛔ Acceso Denegado"
    
    mensaje = ""
    if request.method == 'POST':
        u_user = request.form.get('username')
        u_pass = request.form.get('password')
        c_nombre = request.form.get('nombre_fantasia')
        u_role = request.form.get('role')
        
        if User.query.filter_by(username=u_user).first():
            mensaje = "❌ El usuario ya existe."
        else:
            # Crear Usuario
            nuevo_user = User(username=u_user, role=u_role)
            nuevo_user.set_password(u_pass)
            db.session.add(nuevo_user)
            db.session.commit()
            
            # Si es estación, creamos perfil de cliente
            if u_role == 'estacion':
                nuevo_cliente = Cliente(nombre_fantasia=c_nombre, user_id=nuevo_user.id)
                db.session.add(nuevo_cliente)
                db.session.commit()
            
            mensaje = f"✅ Usuario '{u_user}' creado."

    usuarios = User.query.all()
    lista = ""
    for u in usuarios:
        rol_txt = "👑 ADMIN" if u.is_superadmin else "🏢 ESTACIÓN"
        nom = u.cliente_info.nombre_fantasia if u.cliente_info else "-"
        lista += f"<li style='padding:10px;border-bottom:1px solid #eee'>{rol_txt}: <b>{u.username}</b> ({nom})</li>"

    return f"""
    <style>body{{font-family:sans-serif;padding:30px;background:#f8f9fa;max-width:800px;margin:0 auto}}.card{{background:white;padding:25px;border-radius:10px;box-shadow:0 2px 10px rgba(0,0,0,0.05);margin-bottom:20px}}input,select{{padding:10px;margin:5px}}button{{padding:10px 20px;background:#28a745;color:white;border:none;border-radius:5px;cursor:pointer}}a{{float:right;color:#dc3545;text-decoration:none;font-weight:bold}}</style>
    <a href="/logout">Cerrar Sesión</a><h1>Panel Super Usuario</h1>
    <div class="card"><h3>➕ Alta Nuevo Usuario</h3><form method="POST"><input type="text" name="username" placeholder="Usuario Login (ej: laferrere)" required><input type="password" name="password" placeholder="Contraseña" required><input type="text" name="nombre_fantasia" placeholder="Nombre Negocio"><select name="role"><option value="estacion">Rol: Estación</option><option value="superadmin">Rol: SuperAdmin</option></select><button type="submit">Crear</button></form><p style="color:blue">{mensaje}</p></div>
    <div class="card"><h3>📋 Usuarios Activos</h3><ul style="list-style:none;padding:0">{lista}</ul></div>
    """

# --- PANEL ESTACIÓN (Solo visualización) ---
@app.route('/estacion/panel')
@login_required
def panel_estacion():
    if current_user.is_superadmin: return redirect(url_for('panel_superadmin'))
    return render_template('index.html', usuario=current_user.username)

# --- API QUE ALIMENTA LOS GRÁFICOS (FRONTEND) ---
@app.route('/api/resumen-dia/<string:fecha_seleccionada>')
@login_required
def api_resumen(fecha_seleccionada):
    # Filtramos reportes SOLO de este usuario para privacidad
    reportes = Reporte.query.filter_by(fecha_operativa=fecha_seleccionada, user_id=current_user.id).all()
    
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


# ============================================================
# 🔥 API DE INGRESO DIRECTO (PARA EL INSTALADOR .EXE) 🔥
# ============================================================
@app.route('/api/ingreso-directo', methods=['POST'])
def ingreso_directo():
    try:
        data = request.json
        
        # 1. Verificamos Clave Maestra
        if data.get('api_key') != API_KEY_MAESTRA:
            return jsonify({"status": "error", "msg": "Unauthorized"}), 401

        # 2. Verificamos datos mínimos
        estacion_nombre = data.get('estacion') # Viene del input "Nombre" del .exe
        monto = data.get('monto')
        nid = data.get('id_interno')
        
        if not estacion_nombre or not monto:
            return jsonify({"status": "error", "msg": "Faltan datos"}), 400

        # 3. Asignación Inteligente de Usuario
        # Buscamos si existe un usuario con el mismo nombre que puso en el instalador
        # Si no existe, se lo asignamos al ADMIN (ID 1) para no perder el dato.
        
        owner = User.query.filter_by(username=estacion_nombre).first()
        if not owner:
            # Fallback: Asignar al admin
            owner = User.query.get(1) 
            if not owner: 
                # Caso extremo: No hay ni admin, creamos uno fantasma o fallamos
                return jsonify({"status": "error", "msg": "No existe usuario destino"}), 404

        # 4. Verificar Duplicados (Para no cargar 2 veces lo mismo)
        existe = Reporte.query.filter_by(id_interno=nid, user_id=owner.id).first()
        if existe:
            return jsonify({"status": "ignorado", "msg": "Reporte ya existe"}), 200

        # 5. Procesar Fechas
        f_op, turno, dt_cierre = procesar_fecha_turno(data.get('fecha_texto'))
        
        # 6. Guardar en Base de Datos
        nuevo_reporte = Reporte(
            user_id=owner.id,
            estacion=estacion_nombre,
            id_interno=nid,
            fecha_completa=data.get('fecha_texto'),
            monto=float(monto),
            fecha_operativa=f_op,
            turno=turno,
            hora_cierre=dt_cierre
        )
        
        db.session.add(nuevo_reporte)
        db.session.commit()
        
        return jsonify({"status": "exito", "owner": owner.username}), 200
        
    except Exception as e:
        return jsonify({"status": "error", "msg": str(e)}), 500


# --- INICIALIZADOR AUTOMÁTICO ---
def auto_setup():
    try:
        with app.app_context():
            db.create_all()
            if not User.query.filter_by(username='admin').first():
                print("⚙️ Creando SuperAdmin...")
                admin = User(username='admin', role='superadmin')
                admin.set_password('admin123')
                db.session.add(admin)
                db.session.commit()
                print("✅ SuperAdmin creado.")
    except Exception as e:
        print(f"⚠️ Setup Warning: {e}")

# Ejecutar setup
auto_setup()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=10000)
