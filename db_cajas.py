import os
import psycopg2
from psycopg2.extras import RealDictCursor
from dotenv import load_dotenv

# Cargar variables de entorno
load_dotenv()

def get_cajas_connection():
    """
    Devuelve una conexión a la base CAJAS (Google Cloud SQL)
    """
    return psycopg2.connect(
        host=os.getenv("CAJAS_DB_HOST"),
        port=os.getenv("CAJAS_DB_PORT"),
        dbname=os.getenv("CAJAS_DB_NAME"),
        user=os.getenv("CAJAS_DB_USER"),
        password=os.getenv("CAJAS_DB_PASSWORD"),
        sslmode="disable"  # Cloud SQL usa IP pública, está OK así
    )


def ejecutar_query(sql, params=None):
    """
    Ejecuta una consulta y devuelve resultados (SELECT)
    """
    conn = get_cajas_connection()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(sql, params)
            return cur.fetchall()
    finally:
        conn.close()
