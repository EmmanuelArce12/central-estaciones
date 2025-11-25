import os
from flask import Flask, request, jsonify, render_template, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta

app = Flask(__name__)

# --- CONFIGURACIÓN ---
# Leemos la URL de la base de datos desde Render. Si no existe (local), usa un archivo sqlite.
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///local.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'clave_secreta_super_segura' # Necesario para el login

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login' # Si no estás logueado, te manda aquí

# --- MODELOS (TABLAS DE LA BASE DE DATOS) ---

# Tabla de Usuarios (Para el Login)
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)

# Tabla de Reportes (Para los datos de la VOX)
class Reporte(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    id_interno = db.Column(db.String(50), unique=True) # ID único del turno VOX
    estacion = db.Column(db.String(100))
    fecha_completa = db.Column(db.String(100)) # String original "YYYY-MM (Turno)"
    monto = db.Column(db.Float)
    
    # Datos procesados para filtros
    fecha_operativa = db.Column(db.String(20)) # YYYY-MM-DD
    turno = db.Column(db.String(20))           # Mañana/Tarde/Noche
    hora_cierre = db.Column(db.DateTime)       # Para ordenar

# --- SISTEMA DE LOGIN ---

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- LÓGICA DE FECHAS (Tu función original optimizada) ---
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

# --- RUTAS ---

@app.route('/')
@login_required # <--- ¡CANDADO! Solo entra si está logueado
def home():
    return render_template('index.html', usuario=current_user.username)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('home'))
        else:
            return "<h1>❌ Usuario o contraseña incorrectos</h1><a href='/login'>Intentar de nuevo</a>"
            
    # Formulario simple de login (Integrado aquí para no crear otro archivo HTML hoy)
    return """
    <style>body{font-family:sans-serif;display:flex;justify-content:center;align-items:center;height:100vh;background:#f0f2f5}form{background:white;padding:2rem;border-radius:10px;box-shadow:0 4px 10px rgba(0,0,0,0.1);text-align:center}input{display:block;margin:10px 0;padding:10px;width:100%}button{background:#2980b9;color:white;border:none;padding:10px;width:100%;border-radius:5px;cursor:pointer}</style>
    <form method="POST">
        <h2>🔐 Acceso Gerencial</h2>
        <input type="text" name="username" placeholder="Usuario" required>
        <input type="password" name="password" placeholder="Contraseña" required>
        <button type="submit">Ingresar</button>
    </form>
    """

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# --- CREAR EL PRIMER USUARIO (Ruta Secreta de Instalación) ---
@app.route('/setup-admin')
def setup():
    # Solo ejecutar esto una vez para crear tu usuario
    db.create_all() # Crea las tablas si no existen
    
    if not User.query.filter_by(username='admin').first():
        hashed_pw = generate_password_hash('admin123', method='pbkdf2:sha256')
        nuevo_user = User(username='admin', password=hashed_pw)
        db.session.add(nuevo_user)
        db.session.commit()
        return "✅ Usuario 'admin' creado con clave 'admin123'. ¡Ahora ve a /login!"
    return "El usuario ya existe."

# --- API REPORTES (Modificada para Base de Datos) ---
@app.route('/api/reportar', methods=['POST'])
def recibir_reporte():
    db.create_all() # Asegura que la tabla exista
    nuevo = request.json
    nid = nuevo.get('id_interno')
    
    # 1. Buscamos en la DB si ya existe
    if Reporte.query.filter_by(id_interno=nid).first():
        return jsonify({"status": "ignorado"}), 200
    
    # 2. Procesamos datos
    fecha_str = nuevo.get('fecha') # "2025-11 (2025...)"
    f_op, turno, dt_cierre = procesar_fecha_turno(fecha_str)
    
    # 3. Guardamos en DB
    nuevo_reporte = Reporte(
        id_interno=nid,
        estacion=nuevo.get('estacion'),
        fecha_completa=fecha_str,
        monto=nuevo.get('monto'),
        fecha_operativa=f_op,
        turno=turno,
        hora_cierre=dt_cierre
    )
    db.session.add(nuevo_reporte)
    db.session.commit()
    
    print(f"💾 Guardado en DB: {nuevo.get('estacion')} - ${nuevo.get('monto')}")
    return jsonify({"status": "exito"}), 200

@app.route('/api/resumen-dia/<string:fecha_seleccionada>')
@login_required # Protegemos la API también
def api_resumen(fecha_seleccionada):
    # Buscamos en la DB solo los reportes de esa fecha
    reportes = Reporte.query.filter_by(fecha_operativa=fecha_seleccionada).all()
    
    resumen = {
        "Mañana": {"monto": 0.0, "horario": "-", "cierres": 0, "fin": None},
        "Tarde":  {"monto": 0.0, "horario": "-", "cierres": 0, "fin": None},
        "Noche":  {"monto": 0.0, "horario": "-", "cierres": 0, "fin": None}
    }

    for r in reportes:
        t = r.turno
        if t in resumen:
            resumen[t]["monto"] += r.monto
            resumen[t]["cierres"] += 1
            # Lógica de horario
            if resumen[t]["fin"] is None or r.hora_cierre > resumen[t]["fin"]:
                resumen[t]["fin"] = r.hora_cierre
                resumen[t]["horario"] = r.hora_cierre.strftime("%H:%M")

    # Formateo final
    respuesta_final = []
    for turno in ["Mañana", "Tarde", "Noche"]:
        data = resumen[turno]
        respuesta_final.append({
            "turno": turno,
            "monto": data["monto"],
            "horario": data["horario"],
            "cantidad_cierres": data["cierres"]
        })

    return jsonify(respuesta_final)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(host='0.0.0.0', port=10000)
