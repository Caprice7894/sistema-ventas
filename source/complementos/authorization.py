import functools
import json
import jwt
from flask import (
    request, current_app, g
)

def login_required(func):
    @functools.wraps(func)
    def wrapped_view(**kwargs):
        token = request.headers.get('token')
        print(current_app.config['SECRET_KEY'])
        if not token:
            return {'error': 'NO ESTAS AUTORIZADO', 'redirect': url_for('auth.login')}, 401
        try:
            data = jwt.decode(token, current_app.config['SECRET_KEY'], algorithms=["HS256"])
            g.usuario = {'usuario_id':data['usuario_id'], 'usuario_role':data['usuario_role']}
        except jwt.InvalidTokenError:
            return {'error':'TOKEN INVALIDO'}, 403
        return func(**kwargs)
    return wrapped_view
