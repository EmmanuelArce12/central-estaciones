from flask import Flask, request, jsonify, render_template
from datetime import datetime, timedelta

app = Flask(__name__)

# --- MEMORIA TEMPORAL (Pronto lo cambiaremos por Base de Datos) ---
reportes_recibidos = []

def determinar_turno(fecha_hora_str):
    """
    Recibe "2025-11-24 (2025/11/24 13:43:59 - 2025/11/24 21:46:20)"
    Devuelve: fecha_operativa (YYYY-MM-DD), turno (Mañana/Tarde/Noche), horario_cierre
    """
    try:
        # Extraemos solo la parte del cierre final para calcular la hora
        # El formato que manda el script es: "YYYY-MM (Apertura - Cierre)"
        # Buscamos el último paréntesis y tomamos la fecha de cierre
        partes = fecha_hora_str.split(' - ')
        if len(partes) < 2: return None, None, None
        
        cierre_raw = partes[1].replace(')', '').strip() # Ej: 2025/11/24 21:46:20
        dt = datetime.strptime(cierre_raw, "%Y/%m/%d %H:%M:%S")
        
        hora = dt.hour
        fecha_operativa = dt.date()
        turno = "Noche" # Default

        if 6 <= hora < 14:
            turno = "Mañana"
        elif 14 <= hora < 22:
            turno = "Tarde"
        else:
            turno = "Noche"
            # Si cierra a las 2 AM del dia 25, pertenece a la Noche del 24
            if hora < 6:
                fecha_operativa = fecha_operativa - timedelta(days=1)
        
        return fecha_operativa.strftime("%Y-%m-%d"), turno, dt
    except Exception as e:
        print(f"Error parseando fecha: {e}")
        return None, None, None

@app.route('/')
def home():
    # Ahora carga tu archivo HTML bonito
    return render_template('index.html')

# --- API QUE USA TU HTML PARA DIBUJAR LOS GRAFICOS ---
@app.route('/api/resumen-dia/<string:fecha_seleccionada>')
def api_resumen(fecha_seleccionada):
    # Estructura vacía
    resumen = {
        "Mañana": {"monto": 0.0, "inicio": None, "fin": None, "cierres": 0},
        "Tarde":  {"monto": 0.0, "inicio": None, "fin": None, "cierres": 0},
        "Noche":  {"monto": 0.0, "inicio": None, "fin": None, "cierres": 0}
    }

    # Recorremos la memoria buscando datos de esa fecha
    for r in reportes_recibidos:
        fecha_str_completa = r.get('fecha') # Viene del script recolector
        monto = r.get('monto', 0)

        fecha_op, turno, dt_cierre = determinar_turno(fecha_str_completa)
        
        if fecha_op == fecha_seleccionada and turno:
            datos_turno = resumen[turno]
            datos_turno["monto"] += monto
            datos_turno["cierres"] += 1
            
            # Guardamos el horario de cierre más reciente para mostrar
            if datos_turno["fin"] is None or dt_cierre > datos_turno["fin"]:
                datos_turno["fin"] = dt_cierre
                # Simulamos apertura (esto se podría mejorar trayendo el dato real)
                datos_turno["horario_txt"] = dt_cierre.strftime("%H:%M")

    # Convertimos al formato de lista que espera tu HTML
    respuesta_final = []
    orden = ["Mañana", "Tarde", "Noche"]
    
    for nombre_turno in orden:
        data = resumen[nombre_turno]
        respuesta_final.append({
            "turno": nombre_turno,
            "monto": data["monto"],
            "horario": data.get("horario_txt", "Sin datos") if data["cierres"] > 0 else "-",
            "cantidad_cierres": data["cierres"]
        })

    return jsonify(respuesta_final)

# --- API PARA RECIBIR DATOS DE LAS ESTACIONES ---
@app.route('/api/reportar', methods=['POST'])
def recibir_reporte():
    nuevo = request.json
    nid = nuevo.get('id_interno')
    
    # Filtro anti-duplicados
    for r in reportes_recibidos:
        if r.get('id_interno') == nid:
            return jsonify({"status": "ignorado"}), 200
            
    reportes_recibidos.insert(0, nuevo)
    print(f"📥 Recibido: {nuevo.get('estacion')} - $ {nuevo.get('monto')}")
    return jsonify({"status": "exito"}), 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=10000)
