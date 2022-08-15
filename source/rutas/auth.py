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

        return 

    return {'error': 'ONLY RECIEVE POST METHOD'}

@bp.route('/login', methods=['POST'])
def login():
    if request.method == 'POST':
        telefono = request.form['telefono']
        password = request.form['password']
        db = get_db()
        error = None

        if telefono is None:
            error = 'EL CAMPO TELEFONO ES REQUERIDO.'
        elif password is None:
            error = 'EL CAMPO CONTRASEÑA ES REQUERIDO.'

        if error is not None:
            return {'error': error}, 400

        telefono = escape(telefono)
        password = escape(password)

        try:
            usuario = db.execute(
                'SELECT id, nombre, password, role FROM usuarios u LEFT JOIN usuario_role WHERE u.id = usuario_id AND u.telefono = ?',
                (telefono,)
            ).fetchone()
        except db.IntegrityError:
            error = 'ALGO HA FALLADO.'

        if usuario is None:
            error = 'TELEFONO INCORRECTO.'
        elif not check_password_hash(usuario['password'], password):
            error = 'CONTRASEÑA INCORRECTA.'

        if error is not None:
            return {'error', error}, 400

        exp_date = str(datetime.now() + timedelta(hours=20))
        token = jwt.encode(
            {
                'exp': exp_date,
                'usuario_id': usuario['id'],
                'usuario_role': usuario['role']
            },
            current_app.config['SECRET_KEY']
        )

        return {
            'nombre': usuario['nombre'],
            'token': token,
            'expiracion': exp_date
        }


def login_required(func):
    @functools.wraps(func)
    def wrapped_view(**kwargs):
        token = request.headers.get('token')
        if not token:
            return {'error': 'NO ESTAS AUTORIZADO', 'redirect': url_for('auth.login')}, 401
        try:
            data = jwt.decode(token, current_app.config['SECRET_KEY'])
        except:
            return {'error':'TOKEN INVALIDO'}, 403
        return func(**kwargs)
    return wrapped_view
