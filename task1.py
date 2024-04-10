import json
from bson import ObjectId
from flask import Flask, request, flash, send_file, jsonify, send_from_directory
from flask_cors import CORS
import jwt
from datetime import datetime, timedelta
from functools import wraps
from pymongo import MongoClient
from werkzeug.utils import secure_filename
import os



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


#	User Authentication with JWT

users = {
    'rohith': {
        'password': '123',
        'email': 'rohith@mail.com'
    }
}

def generate_token(username):
    token = jwt.encode({'username': username, 'exp': datetime.now() + timedelta(minutes=30)}, app.config['SECRET_KEY'])
    return token 

def decode_token(token):
    try:
        payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        return payload
    except jwt.ExpiredSignatureError:
        return 'Signature expired. Please log in again.'
    except jwt.InvalidTokenError:
        return 'Invalid token. Please log in again.'

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'message': 'Token is missing!'}), 401

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            current_user = data['username']
        except:
            return jsonify({'message': 'Token is invalid!'}), 401

        return f(current_user, *args, **kwargs)

    return decorated

@app.route('/register', methods=['POST'])
def register():
    response = {}

    try:
        input_payload = json.loads(request.data)
        username = input_payload.get('username', '')
        password = input_payload.get('password', '')
        email = input_payload.get('email', '')

        if username in users:
            status_code = 500
            message = 'User already exists'

        users[username] = {'password': password, 'email': email}

        status_code = 200
        message = 'User registered'
        
    except Exception as e:
        print(e)
        status_code = 500
        message = 'Error occured while registering'
    

    response['statusCode'] = status_code
    response['message'] = message

    return response

@app.route('/login', methods=['POST'])
def login():
    response={}
    token = '' 
    try:
        auth = request.authorization
        if not auth or not auth.username or not auth.password:
            status_code=401
            message= 'could not verify'
        else:
            username = auth.username
            password = auth.password

            if username not in users or users[username]['password'] != password:
                status_code=401
                message= 'wrong username or password'
            else:
                token = generate_token(username)
                status_code=200
                message= 'logged in'
    except Exception as e:
        print(e) 
        status_code=500
        message= 'error occured'


    response['statusCode'] = status_code
    response['message'] = message
    response['token'] = token

    return response

@app.route('/refresh', methods=['POST'])
@token_required
def refresh(current_user):
    token = generate_token(current_user)
    return jsonify({'token': token}), 200

@app.route('/protected', methods=['POST'])
@token_required
def protected(current_user):
    return jsonify({'message': 'You are accessing a protected endpoint!'}), 200


#	Simple CRUD API

client = MongoClient("mongodb://localhost:27017")
db = client.userdata 
collection = db['users']

@app.route('/insert', methods=['POST'])
def create_user():
    data = request.json
    user_id = collection.insert_one(data).inserted_id
    return jsonify({'message': 'User created successfully', 'user_id': str(user_id)}), 201


@app.route('/read', methods=['POST'])
def get_user():
    data = request.json
    user_id=data.get('user_id', '')
    user = collection.find_one({'user_id': user_id})  
    if user:
        return jsonify(str(user)), 200
    else:
        return jsonify({'message': 'User not found'}), 404
 

@app.route('/update', methods=['POST']) 
def update_user():
    data = request.json
    user_id=data.get('user_id', '')
    email=data.get('email', '')
    result = collection.update_one({'user_id': user_id}, {'$set': {'email': email}}) 
    if result.modified_count > 0:
        return jsonify({'message': 'User updated successfully'}), 200
    else:
        return jsonify({'message': 'User not found'}), 404


@app.route('/delete', methods=['POST'])
def delete_user():
    data = request.json
    user_id=data.get('user_id', '')
    result = collection.delete_one({'user_id': user_id}) 
    if result.deleted_count > 0:
        return jsonify({'message': 'User deleted successfully'}), 200
    else:
        return jsonify({'message': 'User not found'}), 404



# 	File Upload and Download API


UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}
MAX_CONTENT_LENGTH = 16 * 1024 * 1024

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS
 

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return {'error': 'No file part'}, 400

    file = request.files['file']

    if file.filename == '':
        return {'error': 'No selected file'}, 400

    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        return {'message': 'File successfully uploaded'}, 200
    else:
        return {'error': 'File type not allowed'}, 400


@app.route('/download', methods=['POST'])
def download_file():
    data = request.json
    filename=data.get('filename', '')
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=True)




if __name__ == '__main__':
    app.run(host="0.0.0.0", port=6000, debug=True)
