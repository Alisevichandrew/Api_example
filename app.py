from flask import Flask, jsonify, make_response, request
from werkzeug.security import generate_password_hash,check_password_hash
from flask_sqlalchemy import SQLAlchemy
from functools import wraps
import uuid
import jwt
import datetime


app = Flask(__name__)

app.config['SECRET_KEY']='e6cfe2e758d2ed9195aa450426d12b01'
# app.config['SQLALCHEMY_DATABASE_URI']='sqlite://///home/manthantrivedi/Documents/Bacancy/bacancy_blogs/flask_auth/myflaskproject/bookstore.db'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///c:/Users/HP/api_example/bookstore.db'
# app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///c:\\Users\\HP\\api_example\\bookstore.db'
# app.config ['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///bookstore.db'

# sqlite:///c:/absolute/path/to/mysql.db
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True

db = SQLAlchemy(app)

class Users(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.Integer)
    name = db.Column(db.String(50))
    password = db.Column(db.String(50))
    admin = db.Column(db.Boolean)

class Books(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    name = db.Column(db.String(50), unique=True, nullable=False)
    Author = db.Column(db.String(50), unique=True, nullable=False)
    Publisher = db.Column(db.String(50), nullable=False)
    book_prize = db.Column(db.Integer)

"""
begin the function def token_required(f):
"""
def token_required(f):
   @wraps(f)
   def decorator(*args, **kwargs):
       token = None
       if 'x-access-token' in request.headers:
           token = request.headers['x-access-token']
 
       if not token:
           return jsonify({'message': 'a valid token is missing'})
       try:
           data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
           current_user = Users.query.filter_by(public_id=data['public_id']).first()
       except:
           return jsonify({'message': 'token is invalid'})
 
       return f(current_user, *args, **kwargs)
   return decorator
"""
end of function def token_required(f):
"""
"""
none
"""

"""
creating the route for registered in API of user
""" 

@app.route('/register', methods=['POST'])
def signup_user():  
    data = request.get_json()  

    hashed_password = generate_password_hash(data['password'], method='sha256')
 
    new_user = Users(public_id=str(uuid.uuid4()), name=data['name'], password=hashed_password, admin=False) 
    db.session.add(new_user)  
    db.session.commit()    

    return jsonify({'message': 'registeration successfully'})

"""
generating the route for all registered users
"""
# https://www.bacancytechnology.com/blog/flask-jwt-authentication
"""
Now, generate another route that will allow all the registered users 
to log in. With the login route, we will create a view to handle the 
user login feature. When a user logs in, the entered password is 
matched with the user’s stored password. If the password matches 
successfully, a random token is generated to access the Bookstore API. 
For instance, we will keep the expiration time for this random token to 
be 45 minutes.
"""
@app.route('/login', methods=['POST']) 
def login_user():
   auth = request.authorization  
   if not auth or not auth.username or not auth.password: 
       return make_response('could not verify', 401, {'Authentication': 'login required"'})   
 
   user = Users.query.filter_by(name=auth.username).first()  
   if check_password_hash(user.password, auth.password):
       token = jwt.encode({'public_id' : user.public_id, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=45)}, app.config['SECRET_KEY'], "HS256")
 
       return jsonify({'token' : token})
 
   return make_response('could not verify',  401, {'Authentication': '"login required"'})

"""
Create another route in the app.py file to get all the registered users.
 This route verifies the registered users in the Users table and 
 provides the output in JSON format. Use the below code after the 
 login route.

"""

@app.route('/users', methods=['GET'])
def get_all_users():  
   
    users = Users.query.all() 
    result = []   
    for user in users:   
        user_data = {}   
        user_data['public_id'] = user.public_id  
        user_data['name'] = user.name 
        user_data['password'] = user.password
        user_data['admin'] = user.admin 
       
        result.append(user_data)   

    return jsonify({'users': result})
"""
Creating routes for Books tables
Let’s create routes for the Books table. These routes will allow users 
to retrieve all the Books in the database and delete them. 
We will also implement a mandatory check to verify the users having 
valid tokens can only perform any API requests.

Define a route for all the registered users to create a new book. 
The following code creates a route to meet this requirement:
"""
@app.route('/book', methods=['POST'])
@token_required

def create_book(current_user):
   
    data = request.get_json() 

    new_books = Books(name=data['name'], Author=data['Author'], Publisher=data['Publisher'], book_prize=data['book_prize'], user_id=current_user.id)  
    db.session.add(new_books)   
    db.session.commit()   

    return jsonify({'message' : 'new books created'})

"""
Now, create a route to allow a logged in user with valid token to get 
all the books in the Books table as shown below:
"""
@app.route('/books', methods=['GET'])
@token_required
def get_books(current_user):

    books = Books.query.filter_by(user_id=current_user.id).all()

    output = []
    for book in books:
        book_data = {}
        book_data['id'] = book.id
        book_data['name'] = book.name
        book_data['Author'] = book.Author
        book_data['Publisher'] = book.Publisher
        book_data['book_prize'] = book.book_prize
        output.append(book_data)

    return jsonify({'list_of_books' : output})

"""
Finally, we will create the last route to delete a specific book. 
We will create a view responsible for handling requests made to delete 
an existing record in the Books table. It will verify and delete the 
given record from the DB, if exists. The below-mentioned code can be 
implemented after the route allows the user to retrieve a list 
of books.
"""
@app.route('/books/<book_id>', methods=['DELETE'])
@token_required
def delete_book(current_user, book_id):  
    book = Books.query.filter_by(id=book_id, user_id=current_user.id).first()   
    if not book:   
        return jsonify({'message': 'book does not exist'})   

    db.session.delete(book)  
    db.session.commit()   

    return jsonify({'message': 'Book deleted'})
"""
Now run the app.py file by using the following command inside the 
virtual environment in the appropriate directory.
python app.py
"""

if  __name__ == '__main__':  
     app.run(debug=True)