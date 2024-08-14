from flask import Flask, jsonify, request, make_response
from flask_mysqldb import MySQL
from passlib.hash import sha256_crypt
from functools import wraps
import jwt
import datetime

app = Flask(__name__)

# Config MySQL
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = ''
app.config['MYSQL_DB'] = 'myflaskapp'
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'
app.config['SECRET_KEY'] = 'your_secret_key'

# Init MySQL
mysql = MySQL(app)

# JWT token required decorator
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.cookies.get('token')
        if not token:
            return jsonify({'message': 'Token is missing!'}), 401
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
        except:
            return jsonify({'message': 'Token is invalid!'}), 401
        return f(*args, **kwargs)
    return decorated

@app.route('/register', methods=['POST'])
def register():
    data = request.json
    name = data['name']
    email = data['email']
    username = data['username']
    password = sha256_crypt.encrypt(str(data['password']))

    cur = mysql.connection.cursor()
    cur.execute('INSERT INTO users(name, email, username, password) VALUES(%s, %s, %s, %s)', (name, email, username, password))
    mysql.connection.commit()
    cur.close()

    return jsonify({'message': 'User registered successfully'}), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data['username']
    password_candidate = data['password']

    cur = mysql.connection.cursor()
    result = cur.execute('SELECT * FROM users WHERE username = %s', [username])

    if result > 0:
        data = cur.fetchone()
        password = data['password']
        if sha256_crypt.verify(password_candidate, password):
            token = jwt.encode({
                'user': username,
                'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)
            }, app.config['SECRET_KEY'])
            
            response = make_response(jsonify({'message': 'Login successful'}))
            response.set_cookie('token', token, httponly=True, secure=True, samesite='Strict')
            return response, 200
        else:
            return jsonify({'message': 'Invalid login'}), 401
    else:
        return jsonify({'message': 'Username not found'}), 404

@app.route('/logout', methods=['POST'])
@token_required
def logout():
    response = make_response(jsonify({'message': 'Logout successful'}))
    response.delete_cookie('token')
    return response, 200

# Rest of your routes remain the same
@app.route('/articles', methods=['GET'])
@token_required
def get_articles():
    cur = mysql.connection.cursor()
    result = cur.execute("SELECT * FROM articles")
    articles = cur.fetchall()
    cur.close()
    return jsonify(articles)

@app.route('/article/<int:id>', methods=['GET'])
@token_required
def get_article(id):
    cur = mysql.connection.cursor()
    result = cur.execute("SELECT * FROM articles WHERE id = %s", [id])
    article = cur.fetchone()
    cur.close()
    if article:
        return jsonify(article)
    return jsonify({'message': 'Article not found'}), 404

@app.route('/article', methods=['POST'])
@token_required
def add_article():
    data = request.json
    title = data['title']
    body = data['body']
    author = data['author']

    cur = mysql.connection.cursor()
    cur.execute("INSERT INTO articles(title, body, author) VALUES(%s, %s, %s)", (title, body, author))
    mysql.connection.commit()
    cur.close()

    return jsonify({'message': 'Article added successfully'}), 201

@app.route('/article/<int:id>', methods=['PUT'])
@token_required
def update_article(id):
    data = request.json
    title = data['title']
    body = data['body']

    cur = mysql.connection.cursor()
    cur.execute("UPDATE articles SET title=%s, body=%s WHERE id=%s", (title, body, id))
    mysql.connection.commit()
    cur.close()

    return jsonify({'message': 'Article updated successfully'})

@app.route('/article/<int:id>', methods=['DELETE'])
@token_required
def delete_article(id):
    cur = mysql.connection.cursor()
    cur.execute("DELETE FROM articles WHERE id=%s", [id])
    mysql.connection.commit()
    cur.close()

    return jsonify({'message': 'Article deleted successfully'})

if __name__ == '__main__':
    app.run(debug=True)