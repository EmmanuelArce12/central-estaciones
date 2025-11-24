from flask import Flask, request, jsonify

app = Flask(__name__)

# Memoria temporal
reportes_recibidos = []

@app.route('/')
def home():
    html = "<h1>📡 Central de Monitoreo de Estaciones</h1>"
    html += "<h3>Últimos reportes recibidos:</h3><ul>"
    for r in reportes_recibidos:
        html += f"<li>🏢 <b>{r['estacion']}</b>: $ {r['monto']} (Fecha: {r['fecha']})</li>"
    html += "</ul>"
    return html

@app.route('/api/reportar', methods=['POST'])
def recibir_reporte():
    datos = request.json
    # Aquí simulamos recibir los datos
    print(f"📥 Recibido reporte de: {datos.get('estacion')}")
    reportes_recibidos.insert(0, datos)
    return jsonify({"status": "exito", "mensaje": "Reporte guardado en la nube"}), 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=10000)
