from flask import Flask, request, jsonify

app = Flask(__name__)

# Usuarios en memoria (ejemplo simple)
usuarios = {
    "admin": "1234"
}

@app.route('/login', methods=['POST'])
def login():
    # Esta versión es vulnerable: no hay límite de intentos, ni bloqueo, ni MFA,
    # y además filtra información (diferencia si el usuario existe).
    data = request.get_json() or {}
    username = data.get('username', '')
    password = data.get('password', '')

    # Información sensible devuelta en mensajes (vulnerabilidad)
    if username not in usuarios:
        return jsonify({"status": "error", "msg": "Usuario no encontrado"}), 401

    if usuarios.get(username) == password:
        return jsonify({"status": "ok", "msg": "Login exitoso"}), 200
    else:
        return jsonify({"status": "error", "msg": "Contraseña incorrecta"}), 401

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
