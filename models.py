from datetime import date, datetime
from app import db

# -----------------------------
# CAJA
# -----------------------------
class Caja(db.Model):
    __tablename__ = 'cajas'

    id = db.Column(db.Integer, primary_key=True)

    vendedor_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    estacion_id = db.Column(db.Integer, db.ForeignKey('estacion.id'), nullable=False)

    fecha = db.Column(db.Date, default=date.today, nullable=False)
    turno = db.Column(db.String(20), nullable=False)   # mañana / tarde / noche
    sector = db.Column(db.String(50), nullable=False)  # sin_gnc / con_gnc / gnc

    estado = db.Column(db.String(20), default='borrador')

    datos = db.Column(db.JSON)

    creada_en = db.Column(db.DateTime, default=datetime.utcnow)
    enviada_en = db.Column(db.DateTime)
    corregida_en = db.Column(db.DateTime)

    vendedor = db.relationship('User', foreign_keys=[vendedor_id])

# -----------------------------
# COMENTARIOS DE CAJA
# -----------------------------
class CajaComentario(db.Model):
    __tablename__ = 'caja_comentarios'

    id = db.Column(db.Integer, primary_key=True)
    caja_id = db.Column(db.Integer, db.ForeignKey('cajas.id'), nullable=False)
    autor_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    comentario = db.Column(db.Text, nullable=False)
    creado_en = db.Column(db.DateTime, default=datetime.utcnow)

    caja = db.relationship('Caja', backref='comentarios')
    autor = db.relationship('User')
