from flask import Flask, request, jsonify, render_template_string
from time import time
import secrets

app = Flask(__name__)

HOME_HTML = """
<!doctype html>
<html lang="es">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Login seguro</title>
    <style>
        body { font-family: Arial, sans-serif; background: #eef2f7; margin: 0; padding: 32px; }
        .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 16px; max-width: 920px; margin: 0 auto; }
        .card { background: #fff; padding: 24px; border-radius: 10px; box-shadow: 0 4px 20px rgba(0,0,0,.08); }
        label { display: block; margin-top: 12px; }
        input, button { width: 100%; padding: 10px; margin-top: 6px; box-sizing: border-box; }
        button { margin-top: 16px; cursor: pointer; }
        .msg { margin-top: 16px; padding: 10px; background: #f7f7f7; border-left: 4px solid #2f6feb; }
        .hint { color: #555; font-size: 14px; }
    </style>
</head>
<body>
    <div class="grid">
        <div class="card">
            <h1>Login seguro</h1>
            <p class="hint">Si la contraseña es correcta, se genera un MFA temporal.</p>
            <form method="post" action="/login">
                <label>Usuario</label>
                <input name="username" value="admin" autocomplete="username">
                <label>Contraseña</label>
                <input name="password" type="password" autocomplete="current-password">
                <button type="submit">Enviar login</button>
            </form>
        </div>
        <div class="card">
            <h2>Validar MFA</h2>
            <form method="post" action="/mfa">
                <label>Usuario</label>
                <input name="username" value="admin" autocomplete="username">
                <label>Código MFA</label>
                <input name="code" inputmode="numeric">
                <button type="submit">Validar MFA</button>
            </form>
            <p class="hint">En este ejemplo el código se imprime en la consola del servidor.</p>
        </div>
    </div>
    <div style="max-width:920px;margin:16px auto 0;">
        {% if message %}<div class="msg">{{ message }}</div>{% endif %}
    </div>
</body>
</html>
"""

# Usuarios en memoria (ejemplo simple)
usuarios = {
    "admin": "1234"
}

# Estado simple en memoria
failed_attempts_user = {}      # username -> (count, lock_until)
failed_attempts_ip = {}        # ip -> [timestamps]
mfa_codes = {}                 # username -> (code, expiry)

MAX_ATTEMPTS_USER = 5
LOCK_SECONDS = 300
IP_WINDOW_SECONDS = 60
IP_MAX_PER_WINDOW = 10

def client_ip():
    return request.remote_addr or 'unknown'


def get_payload():
    if request.is_json:
        return request.get_json(silent=True) or {}
    return request.form or {}


def render_home(message=None):
    return render_template_string(HOME_HTML, message=message)


@app.route('/', methods=['GET'])
def index():
    return render_home()

def check_rate_limit(ip):
    now = time()
    arr = failed_attempts_ip.get(ip, [])
    # keep only recent
    arr = [t for t in arr if now - t <= IP_WINDOW_SECONDS]
    if len(arr) >= IP_MAX_PER_WINDOW:
        failed_attempts_ip[ip] = arr
        return False
    arr.append(now)
    failed_attempts_ip[ip] = arr
    return True

@app.route('/login', methods=['POST'])
def login():
    data = get_payload()
    username = data.get('username', '')
    password = data.get('password', '')
    ip = client_ip()

    # Rate limit by IP
    if not check_rate_limit(ip):
        if request.is_json:
            return jsonify({"status": "error", "msg": "Demasiadas solicitudes, intente más tarde"}), 429
        return render_home("Demasiadas solicitudes, intente más tarde")

    # Check account lock
    c, lock_until = failed_attempts_user.get(username, (0, 0))
    now = time()
    if lock_until and now < lock_until:
        if request.is_json:
            return jsonify({"status": "error", "msg": "Cuenta bloqueada temporalmente"}), 423
        return render_home("Cuenta bloqueada temporalmente")

    # Validate
    if usuarios.get(username) == password:
        # Reset failed counters
        failed_attempts_user[username] = (0, 0)
        # Generate MFA code (simple, printed to server logs for demo)
        code = secrets.randbelow(900000) + 100000
        expiry = now + 300
        mfa_codes[username] = (str(code), expiry)
        print(f"[MFA] Código para {username}: {code}")
        if request.is_json:
            return jsonify({"status": "ok", "msg": "Password correcto. Envíe MFA usando /mfa"}), 200
        return render_home("Password correcto. Revisa la consola y luego valida el MFA.")
    else:
        # Increment user failed attempts
        c = c + 1
        lock = 0
        if c >= MAX_ATTEMPTS_USER:
            lock = now + LOCK_SECONDS
            c = 0
        failed_attempts_user[username] = (c, lock)
        if request.is_json:
            return jsonify({"status": "error", "msg": "Credenciales inválidas"}), 401
        return render_home("Credenciales inválidas")

@app.route('/mfa', methods=['POST'])
def mfa():
    data = get_payload()
    username = data.get('username', '')
    code = data.get('code', '')
    now = time()
    stored = mfa_codes.get(username)
    if not stored:
        if request.is_json:
            return jsonify({"status": "error", "msg": "No hay código MFA pendiente"}), 400
        return render_home("No hay código MFA pendiente")
    stored_code, expiry = stored
    if now > expiry:
        del mfa_codes[username]
        if request.is_json:
            return jsonify({"status": "error", "msg": "Código MFA expirado"}), 400
        return render_home("Código MFA expirado")
    if code == stored_code:
        del mfa_codes[username]
        if request.is_json:
            return jsonify({"status": "ok", "msg": "Autenticación completa"}), 200
        return render_home("Autenticación completa")
    else:
        if request.is_json:
            return jsonify({"status": "error", "msg": "Código MFA incorrecto"}), 401
        return render_home("Código MFA incorrecto")

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, debug=True)
