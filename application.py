from flask import Flask
from flask import render_template
import json
from flask import request
from flask import jsonify
from hybrid import *

app = Flask(__name__)

@app.route('/')

def main():
    return render_template('firstDraft.html')

@app.route("/", methods=['POST'])
def cryptoGen():
    data = request.get_data(as_text=True)
    data = json.loads(data)
    message = data["message"]
    Symmetric = data["Symmetric"]
    Asymmetric = data["Asymmetric"]
    a_key, encrypted_a_key, encrypted_text, private_key, public_key, decrypted_key, decrypted_text = hybrid(Symmetric,Asymmetric,message)
    return jsonify(AsymmetricKey = a_key, EncryptedAsymmetricKey = encrypted_a_key, Encrypted_Text = encrypted_text, PrivateKey = private_key, PublicKey = public_key, DecryptedKey = decrypted_key, DecryptedText = decrypted_text)