from flask import Flask, redirect, url_for, request, render_template, escape
import re

# Flask constructor takes the name of 
# current module (__name__) as argument.
app = Flask(__name__)

@app.route('/')
def howdy_world():
    return 'Howdy World'

@app.route('/howdy/<name>')
def howdy_name(name):
    return 'Howdy %s!' % name

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

        # Redirect to the howdy_name route
        return redirect(url_for('howdy_name', name=sanitized_user))
    return render_template('secureLogin.html')

# main driver function
if __name__ == '__main__':

    # run() method of Flask class runs the application 
    # on the local development server.
    app.run()
