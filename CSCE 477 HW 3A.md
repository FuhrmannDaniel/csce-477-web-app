# Part 1
## Vulnerabilities Identified
I discovered two security flaws in the login form for the OWASP Juice Shop app. The first vulnerability is that the login form is vulnerable to SQL injection. The second vulnerability is that the forgot password form can be used to easily change another user's password.
## Steps Taken
### SQL Injection
I experimented with different SQL statements before entering `' OR true--` in the username field and some random characters in the password field. This granted me access to the admin's account.
### Password Reset
I was able to reset the user Jim's account password, and login to his account by first finding his email address in a review he left on a product. Once I found this, I used the password reset form to change his password by supplying his email, and using public information to answer his security question. I was able to then update his password, and sign into his account.
## Impact
An attacker can use either of these vulnerabilities to gain unauthorized access to a someone else's account, enabling them to view sensitive information, make changes to the app or account, and more.