from flask import Flask, request, jsonify, send_from_directory
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import codecs

app = Flask(__name__)

DEBUG = True

''' Chave fixa para permitir exploração do desafio
   A chave é de 32 bytes, adequada para AES-256.
   A chave deve ser mantida em segredo em um ambiente de produção.
   Aqui, é usada para fins de demonstração e exploração do desafio.
   ela é fixa para que o token gerado possa ser explorado. '''
   
KEY = b'0123456789abcdef0123456789abcdef'
FLAG = 'flag{jeremias}'

# Mostra a chave e o token correto para 'gary' no modo debug
if DEBUG:
    cipher_debug = AES.new(KEY, AES.MODE_ECB)
    token_debug = cipher_debug.encrypt(pad(b'gary', AES.block_size)).hex()
    print(f"[DEBUG] Chave AES usada: {KEY.decode()}")
    print(f"[DEBUG] Token válido para 'gary': {token_debug}")

# Função de criptografia

def encrypt(name):
    cipher = AES.new(KEY, AES.MODE_ECB)
    try:
        name_bytes = codecs.escape_decode(name)[0]  
    except Exception:
        name_bytes = name.encode()
    return cipher.encrypt(pad(name_bytes, AES.block_size)).hex()

# Função de descriptografia
def decrypt(ciphertext):
    try:
        cipher = AES.new(KEY, AES.MODE_ECB)
        result = unpad(cipher.decrypt(bytes.fromhex(ciphertext)), AES.block_size)
        return result.decode()
    except Exception:
        return None


@app.route("/")
def index():
    return send_from_directory(".", "index.html")

# Geração de token
@app.route("/generate", methods=["POST"])
def generate():
    data = request.get_json()
    name = data.get("name", "")

    try:
        decoded_name = codecs.escape_decode(name)[0]
    except Exception:
        decoded_name = name.encode()

    if decoded_name == b'gary':
        return jsonify({"error": "nice try!"}), 403

    token = AES.new(KEY, AES.MODE_ECB).encrypt(pad(decoded_name, AES.block_size)).hex()
    return jsonify({"token": token})

# Visualização da flag
@app.route("/view", methods=["POST"])
def view():
    data = request.get_json()
    token = data.get("token", "")
    name = decrypt(token)

    if name is None:
        return jsonify({"error": "invalid token"}), 400

    if name == "gary":
        return jsonify({"flag": FLAG})

    return jsonify({"error": "sorry, only gary can view the flag"}), 403


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
