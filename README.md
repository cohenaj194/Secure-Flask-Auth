# Secure-Flask-Auth

Secure-Flask-Auth is a Python Flask project that provides a secure authentication system. This project uses industry-standard security practices to ensure the safety of user data.

# Features
* Password hashing using bcrypt to store user passwords securely
* Protection against common web application vulnerabilities, such as Cross-Site Scripting (XSS), Cross-Site Request Forgery (CSRF), and SQL Injection
* User session management with secure cookie storage and token-based authentication
* Secure password reset functionality with time-limited reset links
* Thorough logging of security events for auditing and troubleshooting

# Installation
1. Clone this repository
2. Create a virtual environment
3. Install the required packages by running pip install -r requirements.txt
4. Set environment variables for FLASK_APP and FLASK_ENV
5. Run the application using flask run

# Usage
Once the application is running, users can create accounts, log in, and reset their passwords as needed. All data is stored securely and protected against common web application vulnerabilities.

# How it works
Secure-Flask-Auth is a secure authentication system for Flask web applications. It uses the industry-standard hashing algorithm bcrypt to securely store user passwords in the database. When a user creates an account or logs in, the system uses Flask's built-in session management to create a secure session for the user, ensuring that sensitive user data is not stored in cookies.

Here is a brief overview of how the system works:

1. When a user creates an account, their password is immediately hashed using bcrypt and stored in the database. The original            plaintext password is never stored.

2. When a user logs in, the system checks the database for a matching username and password. If the password is correct, a secure        session is created for the user.

3. Throughout the user's session, the system checks their authentication status on every page load. If the user is not authenticated,    they are redirected to the login page.

4. When the user logs out, their session is destroyed and they are redirected to the login page.

5. The system includes various security features such as password strength requirements and rate limiting to prevent brute force          attacks.

By using Secure-Flask-Auth in your Flask web application, you can ensure that your users' data is secure and protected against unauthorized access.

# Contributing
Contributions to this project are welcome! If you find a security issue, please create an issue and report it. If you would like to contribute code, please fork the repository and submit a pull request.

# License
This project is licensed under the MIT License. See the LICENSE file for details.
