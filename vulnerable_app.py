from flask import Flask, request, jsonify, render_template_string

app = Flask(__name__)

HOME_HTML = """
<!doctype html>
<html lang="es">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Login vulnerable</title>
    <style>
        body { font-family: Arial, sans-serif; background: #f4f4f4; margin: 0; padding: 32px; }
        .card { max-width: 420px; margin: 0 auto; background: #fff; padding: 24px; border-radius: 10px; box-shadow: 0 4px 20px rgba(0,0,0,.08); }
        label { display: block; margin-top: 12px; }
        input, button { width: 100%; padding: 10px; margin-top: 6px; box-sizing: border-box; }
        button { margin-top: 16px; cursor: pointer; }
        .msg { margin-top: 16px; padding: 10px; background: #f7f7f7; border-left: 4px solid #999; }
    </style>
</head>
<body>
    <div class="card">
        <h1>Login vulnerable</h1>
        <p>Este ejemplo no bloquea intentos ni aplica MFA.</p>
        <form method="post" action="/login">
            <label>Usuario</label>
            <input name="username" value="admin" autocomplete="username">
            <label>Contraseña</label>
            <input name="password" type="password" autocomplete="current-password">
            <button type="submit">Entrar</button>
        </form>
        {% if message %}<div class="msg">{{ message }}</div>{% endif %}
    </div>
</body>
</html>
"""


def get_payload():
        if request.is_json:
                return request.get_json(silent=True) or {}
        return request.form or {}


def render_home(message=None):
        return render_template_string(HOME_HTML, message=message)


@app.route('/', methods=['GET'])
def index():
        return render_home()

# Usuarios en memoria (ejemplo simple)
usuarios = {
    "admin": "1234"
}

@app.route('/login', methods=['POST'])
def login():
    # Esta versión es vulnerable: no hay límite de intentos, ni bloqueo, ni MFA,
    # y además filtra información (diferencia si el usuario existe).
    data = get_payload()
    username = data.get('username', '')
    password = data.get('password', '')

    # Información sensible devuelta en mensajes (vulnerabilidad)
    if username not in usuarios:
        if request.is_json:
            return jsonify({"status": "error", "msg": "Usuario no encontrado"}), 401
        return render_home("Usuario no encontrado")

    if usuarios.get(username) == password:
        if request.is_json:
            return jsonify({"status": "ok", "msg": "Login exitoso"}), 200
        return render_home("Login exitoso")
    else:
        if request.is_json:
            return jsonify({"status": "error", "msg": "Contraseña incorrecta"}), 401
        return render_home("Contraseña incorrecta")

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
