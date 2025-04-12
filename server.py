from flask import Flask, redirect, url_for, request, render_template
from markupsafe import escape
import re
import bcrypt

def hash_password(password: str) -> str:
    """
    Hashes a password securely using bcrypt.

    Args:
        password (str): The plaintext password to hash.

    Returns:
        str: The hashed password.
    """
    # Generate a salt
    salt = bcrypt.gensalt()
    # Hash the password with the salt
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed_password.decode('utf-8')

def check_password(password: str) -> bool:
    """
    Checks if a given password matches the hashed password.

    Args:
        password (str): The plaintext password to check.

    Returns:
        bool: True if the password matches, False otherwise.
    """
    # Hash the input password with the same salt
    salt = '$2b$12$E0qLJs95eXuC3OtOYim/ye'.encode('utf-8')
    hashed_password = '$2b$12$E0qLJs95eXuC3OtOYim/yeYxaYLLTjrQcPYCR3UfwhBM1hNCg9ezu'.encode('utf-8')
    hashed_input_password = bcrypt.hashpw(password.encode('utf-8'), salt)

    # Compare the rehashed password with the stored hashed password
    return hashed_input_password == hashed_password


# Flask constructor takes the name of 
# current module (__name__) as argument.
app = Flask(__name__)

@app.route('/')
def howdy_world():
    return 'Howdy World'

@app.route('/howdy/<name>')
def login_success(name):
    return render_template('howdy.html', name=name)

@app.route('/secureLogin', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = request.form['email'].strip()
        password = request.form['password'].strip()

        # Validate email format
        email_regex = r'^[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}$'
        if not re.match(email_regex, user):
            return "Invalid email format", 400

        # Sanitize input to prevent injection attacks
        sanitized_user = escape(user)
        sanitized_password = escape(password)

        if not sanitized_user or not sanitized_password:
            return "Invalid input", 400
        
        if not check_password(sanitized_password):
            return "Invalid password", 401
        
        # Redirect to the login_success route
        return redirect(url_for('login_success', name=sanitized_user))
    return render_template('secureLogin.html')

# main driver function
if __name__ == '__main__':

    # run() method of Flask class runs the application 
    # on the local development server.
    app.run()
