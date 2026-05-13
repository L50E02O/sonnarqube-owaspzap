from flask import Flask, request, jsonify
from time import time
import secrets

app = Flask(__name__)

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
    data = request.get_json() or {}
    username = data.get('username', '')
    password = data.get('password', '')
    ip = client_ip()

    # Rate limit by IP
    if not check_rate_limit(ip):
        return jsonify({"status": "error", "msg": "Demasiadas solicitudes, intente más tarde"}), 429

    # Check account lock
    c, lock_until = failed_attempts_user.get(username, (0, 0))
    now = time()
    if lock_until and now < lock_until:
        return jsonify({"status": "error", "msg": "Cuenta bloqueada temporalmente"}), 423

    # Validate
    if usuarios.get(username) == password:
        # Reset failed counters
        failed_attempts_user[username] = (0, 0)
        # Generate MFA code (simple, printed to server logs for demo)
        code = secrets.randbelow(900000) + 100000
        expiry = now + 300
        mfa_codes[username] = (str(code), expiry)
        print(f"[MFA] Código para {username}: {code}")
        return jsonify({"status": "ok", "msg": "Password correcto. Envíe MFA usando /mfa"}), 200
    else:
        # Increment user failed attempts
        c = c + 1
        lock = 0
        if c >= MAX_ATTEMPTS_USER:
            lock = now + LOCK_SECONDS
            c = 0
        failed_attempts_user[username] = (c, lock)
        return jsonify({"status": "error", "msg": "Credenciales inválidas"}), 401

@app.route('/mfa', methods=['POST'])
def mfa():
    data = request.get_json() or {}
    username = data.get('username', '')
    code = data.get('code', '')
    now = time()
    stored = mfa_codes.get(username)
    if not stored:
        return jsonify({"status": "error", "msg": "No hay código MFA pendiente"}), 400
    stored_code, expiry = stored
    if now > expiry:
        del mfa_codes[username]
        return jsonify({"status": "error", "msg": "Código MFA expirado"}), 400
    if code == stored_code:
        del mfa_codes[username]
        return jsonify({"status": "ok", "msg": "Autenticación completa"}), 200
    else:
        return jsonify({"status": "error", "msg": "Código MFA incorrecto"}), 401

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, debug=True)
