Security Vulnerability Report
Introduction
This report includes a series of high-severity security vulnerabilities discovered in the application at http://localhost:3000. These vulnerabilities range from SQL Injection, Cross-Site Scripting (XSS) to CSRF attacks, all of which can lead to unauthorized access to data or exploitation of the application in various malicious ways. A detailed explanation of each vulnerability is provided with proof of concept (PoC) steps and remediation recommendations.
----------------------------------------------------------------------------------------------------------
----------------------------------------------------------------------------------------------------------
----------------------------------------------------------------------------------------------------------


-----High Severity Findings:

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
---------------------------------
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
---------------------------------
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
---------------------------------
4. SQL Injection to Retrieve All Users’ Data
Severity: High

URL: http://localhost:3000/rest/products/search

Description: This SQL injection vulnerability allows an attacker to retrieve all users' records from the database.

Proof of Concept:

Visit the product search URL.

Change the value of the q parameter to test')) UNION SELECT id, email, password, ... FROM Users--.

All user data is displayed.

Remediation: Validate and sanitize the q parameter to prevent SQL injection.
---------------------------------
5. Stored XSS in Email Field During Registration
Severity: High

URL: http://localhost:3000/#/register

Description: This XSS vulnerability allows an attacker to inject JavaScript into the admin panel by manipulating the email field.

Proof of Concept:

Go to the registration page here.

Intercept the packet and change the email parameter to user@domain.com<script>alert('XSS')</script>.

The code is injected successfully. When logged in as admin and visiting the administration page, the alert will be triggered.

Remediation: Validate and sanitize the email field to prevent script injection.
---------------------------------
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
---------------------------------
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
---------------------------------
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
---------------------------------
9. Stored XSS in Adding Products to Website
Severity: High

URL: http://localhost:3000/#/

Description: This XSS vulnerability allows an attacker to inject a script into the product description field.

Proof of Concept:

Sign in as an admin.

Send a POST request to http://localhost:3000/api/Products with the body containing a malicious script.

Search for the product "xss" and observe the XSS alert being triggered.

Remediation: Implement input validation and sanitization for product descriptions.
---------------------------------
10. Stored XSS in Last Login IP Page
Severity: High

URL: http://localhost:3000/#/privacy-security/last-login-ip

Description: This XSS vulnerability allows an attacker to inject scripts in the Last Login IP page.

Proof of Concept:

Log in and log out.

Send a request to save the login IP, adding a malicious payload in the header.

Visit the Last Login IP page to trigger the XSS alert.

Remediation: Sanitize and validate input related to login data.
---------------------------------
11. Registering User with Admin Role
Severity: High

URL: http://localhost:3000/#/register

Description: A user can register with an "admin" role by modifying the registration request.

Proof of Concept:

Go to the registration page.

Intercept the request and add "rule": "admin" in the JSON body.

A user with the admin role is successfully registered.

Remediation: Ensure that only requests from trusted sources (e.g., localhost) can assign the "admin" role.
---------------------------------
12. Blind SSRF via Image URL Parameter
Severity: High

URL: http://localhost:3000/#/profile

Description: An attacker can use this SSRF vulnerability to download any content using the server.

Proof of Concept:

Go to the profile page.

Enter a non-image URL in the Image URL field.

The content is successfully downloaded to the server.

Remediation: Validate input in the Image URL parameter to prevent SSRF attacks.

----------------------------------------------------------------------------------------------------------
----------------------------------------------------------------------------------------------------------
----------------------------------------------------------------------------------------------------------


-----Medium Severity Findings:

1. Insecure Direct Object Reference (IDOR) in Basket
Rating: Medium

URL: http://localhost:3000/#/basket

Description: The application is vulnerable to IDOR, allowing an attacker to access another user's basket by modifying the bid parameter in session storage.

Proof of Concept:

Visit http://localhost:3000/#/basket.

Right-click and click on "Inspect Element".

Navigate to the "Application" tab.

In the "Session Storage" section, click on http://localhost:3000.

Change the bid value to another user’s basket ID.

Refresh the page.

Now, you can access another user's basket.

Remediation: Avoid storing sensitive data in session storage. Instead, rely on tokens to verify and secure the basket access.

2. IDOR in Adding Items to Basket
Rating: Medium

URL: http://localhost:3000#/

Description: An attacker can add items to another user’s basket by manipulating the BasketId in the POST request.

Proof of Concept:

Visit http://localhost:3000#/.

Add any item to the basket.

Intercept the request using Burp Suite.

Observe the POST request:

bash
Copy
Edit
POST /api/BasketItems/ HTTP/1.1
{"ProductId":6,"BasketId":"2","quantity":1}
Modify the request body to add an item to another user's basket, e.g., change BasketId to 1:

json
Copy
Edit
{"ProductId":6,"BasketId":"1","quantity":1}
Send the request.

The item will be added to another user’s basket successfully.

Remediation: Ensure that users can only add items to their own basket, validated by their token, not by the BasketId parameter.

3. File Upload Larger than 100KB
Rating: Medium

URL: http://localhost:3000/#/profile

Description: An attacker can bypass client-side file size validation and upload files larger than 100KB, potentially triggering security issues like Denial of Service (DoS) or storing malicious content.

Proof of Concept:

Go to the profile page.

Upload an image of less than 100KB in size.

Intercept the packet.

Choose a file with a size greater than 100KB.

Upload the file, and it is successfully uploaded, bypassing client-side validation.

Remediation: Implement server-side validation for file size, ensuring only files within the allowed size limit are uploaded.

4. Brute Force of Security Question
Rating: Medium

URL: http://localhost:3000/#/forgot-password

Description: An attacker can brute force the answer to a security question during the password reset process, potentially gaining access to a user’s account.

Proof of Concept:

Go to the Login page and click on "Forgot Password".

Enter the victim's email address.

Enter a new password and repeat it in the confirmation field.

For the security question, input any answer.

Intercept the request and brute force the security question answer by sending multiple requests or by obtaining a list of possible answers.

The attacker successfully guesses the correct answer.

Remediation: Implement brute-force prevention techniques, such as blocking IP addresses after multiple failed attempts or adding a CAPTCHA to limit automated attempts.

----------------------------------------------------------------------------------------------------------
----------------------------------------------------------------------------------------------------------
----------------------------------------------------------------------------------------------------------


-----Low Severity Findings:

1. DOM XSS in Search Field
Rating: Low

URL: http://localhost:3000#/

Description: A DOM-based XSS vulnerability exists in the search field, allowing an attacker to execute arbitrary JavaScript.

Proof of Concept:

Visit http://localhost:3000#/.

Enter the following payload in the search field: <iframe src="javascript:alert(xss)">.

Press Enter.

An alert box will pop up with the message "xss".

Remediation: Implement input validation to sanitize user input in the search field to prevent script injection.

2. Business Logic Vulnerability in Chatbot
Rating: Low

URL: http://localhost:3000#/chatbot

Description: An attacker can exploit a business logic flaw in the chatbot to receive multiple discount coupons.

Proof of Concept:

Click on the sidebar and select "Support Chat".

Inform the bot of your name.

Keep asking the chatbot, "Can I have a coupon code?".

The bot will repeatedly provide a 10% coupon.

Remediation: Prevent the chatbot from issuing coupons and apply validation to limit the number of discounts that can be requested.

3. IDOR in Customer Feedback
Rating: Low

URL: http://localhost:3000#/contact

Description: An IDOR vulnerability allows an attacker to post feedback using another user's username.

Proof of Concept:

Click on the sidebar and select "Customer Feedback".

Inspect the page.

Remove the hidden attribute in the <input> tag:

html
Copy
Edit
<input _ngcontent-c23 hidden id="userId" type="text" class="ng-untouched ng-pristine ng-valid">
Change the id to another user's ID.

Write the feedback and solve the mathematical question.

Submit the feedback.

The feedback is submitted as if you were another user.

Remediation: Authenticate feedback submissions based on the user’s token, not hidden form inputs.

4. Reflected XSS in Track Result ID Parameter
Rating: Low

URL: http://localhost:3000#/

Description: A reflected XSS vulnerability is present in the id parameter of the order tracking feature.

Proof of Concept:

Sign up and log in.

Add products to the basket and place an order.

Navigate to http://localhost:3000#/order-history.

Click the truck icon to track the order.

In the URL, modify the id parameter to:

bash
Copy
Edit
http://localhost:3000#/track-result?id=a0c9-c9272915cd5e11f5
Inject the payload <iframe src="javascript:alert(xss)"> into the id parameter.

Reload the page, and the XSS payload will trigger an alert box.

Remediation: Sanitize the id parameter and all URL parameters to prevent script injection.

5. Business Logic in Customer Feedback
Rating: Low

URL: http://localhost:3000#/contact

Description: Users can submit a zero-star rating due to a business logic flaw, even though the minimum rating is 1 star.

Proof of Concept:

Visit http://localhost:3000#/contact.

Write a comment and select a rating using the slider.

Solve the mathematical question.

Submit the form.

Intercept the request and modify the rating parameter to 0.

Submit the feedback with a zero rating.

Remediation: Implement validation to ensure ratings are within the allowed range (1–5 stars).

6. IDOR in Writing Reviews on Products
Rating: Low

URL: http://localhost:3000#/

Description: An attacker can submit a review for any product using another user’s username by manipulating the request.

Proof of Concept:

Visit http://localhost:3000#/.

Click on any product and write a review.

Submit the review.

Intercept the request and modify the author field to another user’s email.

Remediation: Authenticate reviews based on the user's token, not on passed parameters.

7. Lack of Input Validation in Registration Form
Rating: Low

URL: http://localhost:3000#/register

Description: The registration form lacks validation for password fields, allowing users to bypass the "password mismatch" validation.

Proof of Concept:

Visit http://localhost:3000#/register.

Fill in the email and security question fields.

Enter the same password in both the "password" and "repeat password" fields.

Change the "password" field to another password (at least 5 characters long).

Notice that the "passwords do not match" error does not appear.

Submit the form and log in with the new password.

Remediation: Implement input validation to ensure the "password" and "repeat password" fields match.

8. Exposure of Backup package.json File
Rating: Low

URL: http://localhost:3000/ftp

Description: A backup package.json file is exposed, which could potentially leak sensitive information about the application.

Proof of Concept:

Visit http://localhost:3000/ftp.

Click on package.json.back.

An error page appears.

Modify the URL to http://localhost:3000/ftp/package.json.bak%2500.md to bypass the blacklist validation.

The file is downloaded.

Remediation: Hide all files and restrict access to the file directory to prevent exposure.

9. Exposure of Coupons File
Rating: Low

URL: http://localhost:3000/ftp

Description: The coupons_2013.md.bak file is exposed, which could leak sensitive business information.

Proof of Concept:

Visit http://localhost:3000/ftp.

Click on coupons_2013.md.bak.

An error page appears.

Modify the URL to http://localhost:3000/ftp/coupons_2013.md.bak%2500 to bypass the blacklist validation.

The file is downloaded.

Remediation: Hide all sensitive files and restrict access to the directory.

10. Exposure of Suspicious Errors File
Rating: Low

URL: http://localhost:3000/ftp

Description: The suspicious_errors.yml file is exposed, potentially disclosing error logs and sensitive application data.

Proof of Concept:

Visit http://localhost:3000/ftp.

Click on suspicious_errors.yml.

An error page appears.

Modify the URL to http://localhost:3000/ftp/suspicious_errors.yml%2500.md to bypass the blacklist validation.

The file is downloaded.

Remediation: Hide all files and make them inaccessible to unauthorized users.

11. Exposure of Access Logs Files
Rating: Low

URL: http://localhost:3000/support/logs

Description: The access log files are exposed, which could contain sensitive server or application information.

Proof of Concept:

Visit http://localhost:3000/support/logs.

Click on access.logs.date.

The log file is downloaded.

Remediation: Hide log files and restrict access to them.

12. Bypassing Captcha in Feedback Form
Rating: Low

URL: http://localhost:3000#/contact

Description: An attacker can bypass the CAPTCHA in the feedback form and submit multiple feedbacks using the same CAPTCHA ID.

Proof of Concept:

Visit http://localhost:3000#/contact.

Write a message, select a rating, and solve the CAPTCHA.

Submit the feedback.

Capture the request and send it multiple times with the same CAPTCHA ID.

Remediation: Ensure that CAPTCHA IDs are hidden or validated on the server-side to prevent reuse.

13. Open Redirect Vulnerability
Rating: Low

URL: http://localhost:3000/redirect

Description: An attacker can craft a malicious link to redirect users to an external website.

Proof of Concept:

Visit:

bash
Copy
Edit
http://localhost:3000/redirect?to=https://evil.com/?https://github.com/bkimminich/juice-shop
You will be redirected to evil.com.

Remediation: Validate URLs and prevent redirection to untrusted external sites.








