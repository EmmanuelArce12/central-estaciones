# --- API PÚBLICA PARA EL AGENTE EXE ---
@app.route('/api/ingreso-directo', methods=['POST'])
def ingreso_directo():
    try:
        data = request.json
        # Validamos Token Maestro (Opcional, para que no cualquiera mande datos)
        if data.get('api_key') != 'CLAVE_MAESTRA_INSTALADOR': 
            return jsonify({"status": "error", "msg": "Unauthorized"}), 401

        # Verificar si ya existe el reporte
        nid = data.get('id_interno')
        estacion_nombre = data.get('estacion')
        
        # Buscamos usuario dueño (O creamos uno genérico si prefieres)
        # Para simplificar, buscaremos al usuario por el nombre de la estación
        # Ojo: Aquí asumimos que el nombre de la estación coincide con un usuario
        # Si quieres simplificar, guarda el nombre de la estación como texto en el reporte y listo.
        
        existe = Reporte.query.filter_by(id_interno=nid, estacion=estacion_nombre).first()
        if existe:
            return jsonify({"status": "ignorado"}), 200

        # Procesar fecha
        f_op, turno, dt_cierre = procesar_fecha_turno(data.get('fecha_texto'))
        
        # Guardar
        # NOTA: Aquí asignamos user_id=1 (Admin) por defecto o buscamos uno.
        # Para este modelo simple, asignaremos al Admin para que tú veas todo.
        admin_user = User.query.filter_by(username='admin').first()
        
        nuevo = Reporte(
            user_id=admin_user.id, # Asignamos al Admin para centralizar
            id_interno=nid,
            estacion=estacion_nombre,
            fecha_completa=data.get('fecha_texto'),
            monto=float(data.get('monto')),
            fecha_operativa=f_op,
            turno=turno,
            hora_cierre=dt_cierre
        )
        
        db.session.add(nuevo)
        db.session.commit()
        return jsonify({"status": "exito"}), 200
        
    except Exception as e:
        return jsonify({"status": "error", "msg": str(e)}), 500
