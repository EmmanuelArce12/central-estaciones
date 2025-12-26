#!/bin/bash
echo "⬇️ 1. Bajando cambios de GIT..."
git fetch --all
git reset --hard origin/main

echo "📦 2. Instalando librerías..."
./venv/bin/pip install -r requirements.txt

echo "🗄️ 3. Ajustando Base de Datos..."
./venv/bin/flask db upgrade

echo "🔄 4. Reiniciando Servidor..."
sudo systemctl daemon-reload
sudo systemctl restart central-estaciones.service

# Si no usas systemctl (servicio), descomenta la linea de abajo y comenta la de arriba:
# sudo pkill -f python3 && sudo nohup python3 app.py > log_salida.txt 2>&1 &

echo "✅ ¡Listo! Sistema actualizado."
