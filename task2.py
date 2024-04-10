import json
from flask import Flask, request, jsonify
from flask_cors import CORS
import jwt
from datetime import datetime, timedelta
from functools import wraps



app = Flask(__name__)
CORS(app)
app.config['SECRET_KEY'] = 'abcd'

@app.after_request
def after_request(response):
    response.headers.add('Access-Control-Allow-Origin', '*')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type')
    response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS')
    response.headers.add('Access-Control-Allow-Credentials', 'true')
    return response


users = {
    'rohith': {
        'password': '123',
        'email': 'rohith@mail.com'
    }
}
def authenticate(username, password):
    if username == 'rohu' and password == '123':
        return True 
    else:
        return False


def generate_token(username):
    payload = {
        'username': username,
        'exp': datetime.now() + timedelta(minutes=30)
    } 
    token = jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')
    return token


def verify_token(token):
    try:
        payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        return payload['username']
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None


@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    if authenticate(username, password):
        token = generate_token(username)
        return jsonify({'token': token}) 
    else:
        return jsonify({'message': 'Authentication failed'}), 401


@app.route('/add', methods=['POST'])
def add():
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({'message': 'Missing token'}), 401

    username = verify_token(token)
    print(username)
    if not username:
        return jsonify({'message': 'Invalid token'}), 401

    data = request.get_json()
    num1 = data.get('num1')
    num2 = data.get('num2')
    result = num1 + num2
    return jsonify({'result': result})


@app.route('/subtract', methods=['POST'])
def subtract():
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({'message': 'Missing token'}), 401

    username = verify_token(token)
    if not username:
        return jsonify({'message': 'Invalid token'}), 401

    data = request.get_json()
    num1 = data.get('num1')
    num2 = data.get('num2')
    result = num1 - num2
    return jsonify({'result': result})


@app.route('/multiply', methods=['POST'])
def multiply():
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({'message': 'Missing token'}), 401

    username = verify_token(token)
    if not username:
        return jsonify({'message': 'Invalid token'}), 401

    data = request.get_json()
    num1 = data.get('num1')
    num2 = data.get('num2')
    result = num1 * num2
    return jsonify({'result': result})


@app.route('/divide', methods=['POST'])
def divide():
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({'message': 'Missing token'}), 401

    username = verify_token(token)
    if not username:
        return jsonify({'message': 'Invalid token'}), 401

    data = request.get_json()
    num1 = data.get('num1')
    num2 = data.get('num2')
    if num2 == 0:
        return jsonify({'message': 'Division by zero is not allowed'}), 400
    result = num1 / num2
    return jsonify({'result': result})



if __name__ == '__main__':
    app.run(host="0.0.0.0", port=7000, debug=True)
