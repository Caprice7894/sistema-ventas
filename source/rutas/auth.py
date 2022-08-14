import functools
import json

import jwt

from flask import (
    Blueprint, g, redirect, request, url_for, escape, current_app
)

from datetime import datetime, timedelta

from werkzeug.security import check_password_hash, generate_password_hash

from source.db import get_db

bp = Blueprint('auth', __name__, url_prefix='/auth')
@bp.route('/register', methods=['POST'])
def register():
    if request.method == 'POST':
        if not request.headers.get('authorization'):
            return {'error': 'NO ESTAS AUTHORIZADO PARA REALIZAR ESTA OPERACIóN'}, 403
        db = get_db()
        nombre = escape(request.form['nombre'])
        password = escape(request.form['password'])
        telefono = escape(request.form['telefono'])

        error = None

        if nombre is None:
            error = "EL NOMBRE NO DEBE ESTAR VACIO"
        elif password is None:
            error = "LA CONTRASEÑA NO DEBE ESTAR VACIA"
        elif telefono is None:
            error = 'EL NUMERO DE TELEFONO NO DEBE ESTAR VACIO'

        if error is not None:
            return {'error': error}

        password = generate_password_hash(password, 'pbkdf2:sha256', 4)
        try:
            db.execute(
                'INSERT INTO usuarios(nombre, password, telefono) VALUES (?,?,?)',
                (nombre, password, telefono)
            )

            db.commit()
            usuario = db.execute(
                'SELECT id FROM usuarios ORDER BY id DESC LIMIT 1'
            ).fetchone()

            db.execute(
                'INSERT INTO usuario_role(usuario_id) VALUES (?)',
                (usuario['id'], )
            )
            db.commit()

            usuario = db.execute(
                'SELECT usuario_id as id, role FROM usuario_role WHERE usuario_id = ? ORDER BY usuario_id DESC LIMIT 1',
                (usuario['id'], )
            ).fetchone()

        except db.IntegrityError:
            error = 'ALGO HA IDO MAL DURANTE EL REGISTRO'

        return {'jwt': jwt.encode(
            {
                'user_id':usuario['id'],
                'user_role':usuario['role'],
                'exp': str(datetime.utcnow() + timedelta(seconds=60))
            },
            current_app.config['SECRET_KEY']
        )}


    return {'error': 'ONLY RECIEVE POST METHOD'}
