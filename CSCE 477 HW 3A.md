Daniel Fuhrmann | UIN: 432004037
# Part 1
## Vulnerabilities Identified
1. SQL injection vulnerability on the login form.
2. Forgot password exploit.
## Steps Taken
### SQL Injection
I experimented with different SQL statements before entering `' OR true--` in the username field and some random characters in the password field. This granted me access to the admin's account.
### Password Reset
![[Pasted image 20250411225126.png|250]]
I was able to reset the user Jim's account password, and login to his account by first finding his email address in a review he left on a product. Then I used the password reset form to change his password by supplying his email, and using public information to answer his security question.
## Impact
An attacker can use either of these vulnerabilities to gain unauthorized access to a someone else's account, enabling them to view sensitive information, make changes to the app or account, and more.
# Part 2
[Web Application Source Code on GitHub](https://github.com/FuhrmannDaniel/csce-477-web-app)
## Login Form
```HTML
<form action="http://localhost:5000/secureLogin" method="post">
	<h1>Welcome Back!</h1>
    <label for="email">Enter your Email:</label>
    <input type="email" id="email" name="email" placeholder="john.doe@example.com" title="Please enter a valid email address."/>
    <label for="password">Enter your Password:</label>
    <input type="password" id="password" name="password" placeholder="Password"/>
    <input type="submit" value="Login"/>
    <input type="reset" value="Reset"/>
</form>
<script>
	document.querySelector('form').addEventListener('submit', function(event) {
		const email = document.getElementById('email').value.trim();
        const password = document.getElementById('password').value.trim();
        if (!email || !password) {
	        alert('Both email and password are required.');
            event.preventDefault();
            return;
		}
        const emailRegex = /^[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}$/;
        if (!emailRegex.test(email)) {
	        alert('Please enter a valid email address.');
            event.preventDefault();
		}
	});
</script>
```
## Basic Security Measures
```python
from flask import Flask, redirect, url_for, request, render_template
from markupsafe import escape
import re
import bcrypt

def check_password(password: str) -> bool:
    # Hash the input password with the same salt
    salt = '$2b$12$E0qLJs95eXuC3OtOYim/ye'.encode('utf-8')
    hashed_password = '$2b$12$E0qLJs95eXuC3OtOYim/yeYxaYLLTjrQcPYCR3UfwhBM1hNCg9ezu'.encode('utf-8')
    hashed_input_password = bcrypt.hashpw(password.encode('utf-8'), salt)

    return hashed_input_password == hashed_password

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
```
## Security Approach
On the client side of the application, I added input validation for the email field so that a user must enter a valid email address. The validation also requires that the password field be filled out.
![[Pasted image 20250411225442.png|300]]
On the server side, It again verifies the email address, then checks that both the username and password are present. Lastly it escapes the user input to prevent SQL injection attacks. Lastly, the supplied password is hashed with a salt and compared to the already hashed, correct password. This approach verifies the password and the correct password is never stored in plain text.
# Part 3
## Steps Taken
The login form can be easily bypassed. I entered `http://localhost:5000/howdy/john` in the address bar and was able to access the `howdy` page without logging in.
Also the login form does not encourage strong passwords, making it easy to guess the password (`password123`).
## Outcome
I was able to successfully get around the security measures implemented in the login form through password brute forcing and URL guessing.
## Security Fix
The weak password can be fixed by enforcing rigorous password standards during account creation.
The URL vulnerability can be addressed by requiring a cookie indicating a successful login to view the page.