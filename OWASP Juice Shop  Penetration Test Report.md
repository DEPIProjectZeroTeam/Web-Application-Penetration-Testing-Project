Security Vulnerability Report
Introduction
This report includes a series of high-severity security vulnerabilities discovered in the application at http://localhost:3000. These vulnerabilities range from SQL Injection, Cross-Site Scripting (XSS) to CSRF attacks, all of which can lead to unauthorized access to data or exploitation of the application in various malicious ways. A detailed explanation of each vulnerability is provided with proof of concept (PoC) steps and remediation recommendations.


1- High:

1. SQL Injection in Login Form
Severity: High

URL: http://localhost:3000/#/login

Description: This vulnerability allows an attacker to log in as an "admin" without knowing the username or password using an SQL injection attack.

Proof of Concept:

Visit the login page here.

Enter ' OR 1=1 -- in the username field.

Enter anything in the password field.

Click "Login".

You will be logged in as admin@juice-sh.op, which is the first record in the users table.

Remediation: Implement input validation and use parameterized queries to prevent SQL injection.

2. Stored XSS in Comment Field on Contact Page
Severity: High

URL: http://localhost:3000/#/contact

Description: An attacker can inject JavaScript code into the comment field, leading to a stored XSS vulnerability.

Proof of Concept:

Go to the Contact page.

Paste the payload <script>alert('XSS')</script> into the comment field.

Choose a rating, complete the CAPTCHA, and click Submit.

Visit About and Administration to observe the XSS alert.

Remediation: Implement input validation and sanitize the comment field to block malicious JavaScript code.

3. Business Logic Vulnerability in Adding Item to Basket
Severity: High

URL: http://localhost:3000/#/

Description: An attacker can add negative quantities of items to their shopping basket, proceed to checkout, and gain money instead of paying.

Proof of Concept:

Add an item to the basket.

Intercept the request and change the quantity to a negative number.

Proceed to checkout.

You will receive a negative amount in your account.

Remediation: Implement input validation to reject negative quantities.

4. SQL Injection to Retrieve All Users’ Data
Severity: High

URL: http://localhost:3000/rest/products/search

Description: This SQL injection vulnerability allows an attacker to retrieve all users' records from the database.

Proof of Concept:

Visit the product search URL.

Change the value of the q parameter to test')) UNION SELECT id, email, password, ... FROM Users--.

All user data is displayed.

Remediation: Validate and sanitize the q parameter to prevent SQL injection.

5. Stored XSS in Email Field During Registration
Severity: High

URL: http://localhost:3000/#/register

Description: This XSS vulnerability allows an attacker to inject JavaScript into the admin panel by manipulating the email field.

Proof of Concept:

Go to the registration page here.

Intercept the packet and change the email parameter to user@domain.com<script>alert('XSS')</script>.

The code is injected successfully. When logged in as admin and visiting the administration page, the alert will be triggered.

Remediation: Validate and sanitize the email field to prevent script injection.

6. File Upload Vulnerability (Incorrect File Type)
Severity: High

URL: http://localhost:3000/#/complain

Description: This vulnerability allows an attacker to upload a file with a different extension (other than .zip or .pdf).

Proof of Concept:

Go to the complain page and enter a message.

Choose a .pdf or .zip file.

Intercept the request and change the file extension to something else.

The file is uploaded successfully.

Remediation: Implement server-side validation to ensure only allowed file types are uploaded.

7. CSRF Attack to Change User’s Password
Severity: High

URL: http://localhost:3000/#/privacy-security/change-password

Description: This vulnerability allows an attacker to change the password of any logged-in user via a CSRF attack.

Proof of Concept:

Log in to the application.

Visit the password change page and change the password.

Using Burp Suite, capture the HTTP request and send it to the repeater.

Modify the request to remove the current=password and observe a successful response.

Find an injection point (e.g., XSS) to execute the password change automatically.

Remediation: Use a CSRF token to prevent unauthorized password changes.

8. CSRF Attack to Change User’s Username
Severity: High

URL: http://localhost:3000/#/privacy-security/change-password

Description: This vulnerability allows an attacker to change the username of any logged-in user via a CSRF attack.

Proof of Concept:

Log in to the application.

Navigate to the profile page and change the username.

Capture the HTTP request using Burp Suite and send it to the repeater.

Modify the request to execute a change of username.

Remediation: Use CSRF tokens to prevent unauthorized username changes.

9. Stored XSS in Adding Products to Website
Severity: High

URL: http://localhost:3000/#/

Description: This XSS vulnerability allows an attacker to inject a script into the product description field.

Proof of Concept:

Sign in as an admin.

Send a POST request to http://localhost:3000/api/Products with the body containing a malicious script.

Search for the product "xss" and observe the XSS alert being triggered.

Remediation: Implement input validation and sanitization for product descriptions.

10. Stored XSS in Last Login IP Page
Severity: High

URL: http://localhost:3000/#/privacy-security/last-login-ip

Description: This XSS vulnerability allows an attacker to inject scripts in the Last Login IP page.

Proof of Concept:

Log in and log out.

Send a request to save the login IP, adding a malicious payload in the header.

Visit the Last Login IP page to trigger the XSS alert.

Remediation: Sanitize and validate input related to login data.

11. Registering User with Admin Role
Severity: High

URL: http://localhost:3000/#/register

Description: A user can register with an "admin" role by modifying the registration request.

Proof of Concept:

Go to the registration page.

Intercept the request and add "rule": "admin" in the JSON body.

A user with the admin role is successfully registered.

Remediation: Ensure that only requests from trusted sources (e.g., localhost) can assign the "admin" role.

12. Blind SSRF via Image URL Parameter
Severity: High

URL: http://localhost:3000/#/profile

Description: An attacker can use this SSRF vulnerability to download any content using the server.

Proof of Concept:

Go to the profile page.

Enter a non-image URL in the Image URL field.

The content is successfully downloaded to the server.

Remediation: Validate input in the Image URL parameter to prevent SSRF attacks.






