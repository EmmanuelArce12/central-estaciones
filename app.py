from flask import Flask, request, jsonify

app = Flask(__name__)

# Memoria temporal (Lista de diccionarios)
reportes_recibidos = []

@app.route('/')
def home():
    # Diseño simple con CSS para que se vea mejor
    html = """
    <style>
        body { font-family: sans-serif; max-width: 800px; margin: 2rem auto; padding: 0 1rem; }
        .card { border: 1px solid #ddd; padding: 1rem; margin-bottom: 1rem; border-radius: 8px; box-shadow: 2px 2px 5px rgba(0,0,0,0.1); }
        .header { background: #f4f4f4; padding: 5px 10px; border-radius: 4px; font-weight: bold; }
        .money { color: green; font-weight: bold; font-size: 1.2rem; }
        h1 { color: #333; border-bottom: 2px solid #333; padding-bottom: 10px; }
    </style>
    <h1>📡 Panel de Control - Estaciones</h1>
    <h3>Últimos reportes recibidos:</h3>
    """
    
    if not reportes_recibidos:
        html += "<p>⏳ Esperando datos...</p>"
    
    for r in reportes_recibidos:
        # Recuperamos datos, usando .get() para evitar errores si falta algún campo
        estacion = r.get('estacion', 'Desconocida')
        fecha = r.get('fecha', '-')
        monto = r.get('monto', 0)
        id_int = r.get('id_interno', 'N/A')
        
        html += f"""
        <div class="card">
            <div class="header">🏢 {estacion} <span style="float:right; font-size:0.8rem; color:#666">ID: {id_int}</span></div>
            <p>📅 Fecha/Turno: {fecha}</p>
            <p class="money">💰 $ {monto:,.2f}</p>
        </div>
        """
    return html

@app.route('/api/reportar', methods=['POST'])
def recibir_reporte():
    nuevo_dato = request.json
    nuevo_id = nuevo_dato.get('id_interno')
    
    # --- FILTRO ANTI-DUPLICADOS ---
    # Revisamos si ya existe ese ID en nuestra lista
    for reporte in reportes_recibidos:
        if reporte.get('id_interno') == nuevo_id:
            print(f"♻️ Dato repetido recibido ({nuevo_id}), ignorando.")
            return jsonify({"status": "ignorado", "mensaje": "Ya existia"}), 200
            
    # Si no existe, lo agregamos al principio
    print(f"📥 Nuevo reporte aceptado: {nuevo_dato.get('estacion')}")
    reportes_recibidos.insert(0, nuevo_dato)
    
    return jsonify({"status": "exito", "mensaje": "Guardado"}), 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=10000)
