from flask import (
    Blueprint
)
from source.controllers.auth import register, login

bp = Blueprint('auth', __name__, url_prefix='/auth')

bp.post('/register')(register)

bp.post('/login')(login)

