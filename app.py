from flask import Flask, jsonify, request  # Import necessary modules from Flask
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity  # Import JWT-related functions from flask_jwt_extended
import bcrypt  # Import bcrypt for password hashing

# Define a User class to represent user objects
class User(object):
    def __init__(self, id, username, password):
        self.id = id
        self.username = username
        # Hash the password using bcrypt and store it
        self.password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    def __repr__(self):
        return "User(id='%s')" % self.id  # Define a string representation for the User object

# Create a list of users with hashed passwords
users = [
    User(1, 'user1', 'abc123'),
    User(2, 'user2', 'abc123')
]

# Create dictionaries to map usernames and user IDs to user objects
username_table = {u.username: u for u in users}
userid_table = {u.id: u for u in users}

# Define an authentication function to verify username and password
def authenticate(username, password):
    user = username_table.get(username, None)  # Get the user object by username
    # Check if the user exists and the password matches
    if user and bcrypt.checkpw(password.encode('utf-8'), user.password.encode('utf-8')):
        return user  # Return the user object if authentication is successful

# Create a Flask application instance
app = Flask(__name__)
app.debug = True  # Enable debug mode
app.config['SECRET_KEY'] = 'super-secret'  # Set a secret key for the application

# Initialize JWTManager with the Flask app
jwt = JWTManager(app)

# Define a login route to handle user login and token creation
@app.route('/login', methods=['POST'])
def login():
    username = request.json.get('username', None)  # Get the username from the request JSON
    password = request.json.get('password', None)  # Get the password from the request JSON
    user = authenticate(username, password)  # Authenticate the user
    if user:
        access_token = create_access_token(identity=user.id)  # Create an access token for the user
        return jsonify(access_token=access_token), 200  # Return the access token in the response
    return jsonify({"msg": "Bad username or password"}), 401  # Return an error message if authentication fails

# Define a protected route that requires a valid JWT token to access
@app.route('/protected')
@jwt_required()
def protected():
    current_user_id = get_jwt_identity()  # Get the identity of the current user from the JWT token
    return jsonify(logged_in_as=current_user_id), 200  # Return the current user's ID in the response

# Run the Flask application
if __name__ == '__main__':
    app.run()