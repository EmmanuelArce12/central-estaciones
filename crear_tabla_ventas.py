import os
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import text

# ==========================================
# ⚠️ PEGA AQUÍ TU DATABASE_URL DE RENDER/SUPABASE
# ==========================================
URL_REMOTA = "postgresql://postgres.kqicfbsdjrwelcmqbpjy:MHN9f6b45xWyB2Pa@aws-1-sa-east-1.pooler.supabase.com:6543/postgres"

if URL_REMOTA.startswith("postgres://"):
    URL_REMOTA = URL_REMOTA.replace("postgres://", "postgresql://", 1)

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = URL_REMOTA
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

def crear_tabla():
    print("🌍 Conectando a la base de datos remota...")
    
    # Definimos el SQL crudo para ser precisos y no depender de modelos locales
    sql_crear_tabla = """
    CREATE TABLE IF NOT EXISTS ventas_vendedor (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        fecha VARCHAR(20),
        vendedor VARCHAR(100),
        litros FLOAT,
        monto FLOAT
    );
    """
    
    with app.app_context():
        try:
            # Ejecutamos la orden SQL
            db.session.execute(text(sql_crear_tabla))
            db.session.commit()
            print("✅ ¡ÉXITO! La tabla 'ventas_vendedor' ha sido creada (o ya existía).")
            print("   Tus usuarios y reportes anteriores están 100% seguros.")
        except Exception as e:
            print(f"❌ Error al crear tabla: {e}")
            db.session.rollback()

if __name__ == "__main__":
    crear_tabla()