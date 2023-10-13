# Secure Code Review Guideline

**Disclaimer**: This document serves as a set of guidelines and the examples shown are non-exhaustive. Please apply these recommendations considering your own codebase context. For more information, please visit: https://owasp.org/www-pdf-archive/OWASP_Code_Review_Guide_v2.pdf

## What is Secure Code Review
Secure code review identifies flaws in application features and design to help ensure that software is developed with security in mind. This is applied during merging of pull requests and checks that written code follows security and logical controls.

Some factors to consider when reviewing code include:
- Application features & business rules
- Context, such as data sensitivity level
- User roles and access rights
- Application type
- Programming language & frameworks used
- Design patterns used

It is recommended that these security guidelines are considered during regular code review sessions.

## Secure Code Review Checklist Summary

## Focus Areas

### Authentication
Mistakes in authentication code allow unintended access to protected data and functions.

#### Types of Vulnerabilities
- **Brute-force password guessing**: Allowing weak passwords (e.g. `Password123`) and not adopting login attempt lockouts make a system susceptible to brute-force attacks to get past authentication pages.
- **Flawed two-factor verification logic**: improper implementation allows attackers to bypass 2FA checks after completing only the first step of authentication. 

    For instance, a user logs in to a vulnerable website with his/her credentials. 
    ```
    POST /login/first_part
    Host: example.com

    username=adam&password=StronkP@ssw0rd!
    ```

    He/She is then assigned an `account` cookie (which is simply the username, e.g. `account=adam`), before being asked for a verification code. 
    ```
    HTTP/1.1 200 OK
    Set-Cookie: account=adam

    GET /login/second_part 
    Cookie: account=adam
    ```
    
    When submitting the verification code, the request uses this cookie to determine which account the user is trying to access. Using tools like `burpsuite`, attackers can log in with his/her own credentials, intercept the response, and change the value of the  `account` cookie to any arbitrary username when submitting the verification code to gain access to that user's account.
    ``` bash
    POST /login/first_part
    Host: example.com

    username=attacker&password=AttackerPassword!

    POST /login/second_part
    Host: example.com
    Cookie: account=adam # attacker can now login as adam

    verification_code=123456
    ```

#### Review Checklist
- [ ] Ensure secure password policy is enforced. 
- [ ] Ensure temporary account lockouts and rate-limiting are adopted to prevent brute-force attacks.

### Authorization
Improper authorization allows users to perform unwanted actions on otherwise protected resources.

#### Types of Vulnerabilities
- **Insecure direct object reference**: missing authorization checks result in direct access to objects (e.g. database records, internal URLs, files) by unauthorized users.
    ```python
    @app.get("/profile/{user_id}")
    def get_user_by_id(user_id: int):
        user = db.query(User).filter(User.id == user_id).first()
        if user is None:
            raise HTTPException(status_code=404, detail="User not found")
        return user
    ```

  If `user_id` is known or guessable, simply navigating to `http://www.example.com/profile/{user_id}` would render their profile information, which may be an unintentional leakage of data.

- **Missing function level access control**: if access to protected functions is not properly verified on the backend, users can still send requests to these protected functions and they will still be processed, even though the resultant view is denied to the user.
    ```python
    # assuming authorization check is done only on in the UI
    @app.get("/update_exam_score")
    def update_exam_score():
        # authorization check should have been done here before proceeding
        # e.g. this function should only be accessible after logging in with admin credentials
        request_args = request.args.to_dict()
        student_id = request_args.get("student_id")
        score = request_args.get("score")

        student = db.query(student).filter(student.id == student_id).first()
        if student is None:
            raise HTTPException(status_code=404, detail="student not found")
        student.score = score
        return student
    ```
  When a malicious user sends a request via `curl http://www.example.com/update_exam_score?student_id=123456&score=100`, student with `student_id = 123456` will have his exam score updated to `100`.

#### Review Checklist 
- [ ] Ensure all locations where user input is used to reference objects directly are equipped with authorisation checks. 
- [ ] Ensure least privilege principle is adopted.
- [ ] For functions with higher risk, multiple levels of authorization checks can be considered.

### Business Logic & Design
Flaws in the design and implementation of Business logic can lead to unintended behaviour.

#### Types of Vulnerabilities
- **Lack of bounds checking**: allows users to modify application behaviour with unexpected input. 
    ```python
    user = form.get('user')
    bidding_price = form.get('bidding_price') # business validation should have been done here to ensure input conforms to expected range
    bidding_price_dict.update({user:bidding_price})
    sorted_bidding_price_dict = {k: v for k, v in sorted(bidding_price_dict.items(), key=lambda item: -item[1])}
    highest_bidder = list(sorted_bidding_price_dict.item())[0]
    ```
  The vulnerability arises due to assumptions that users will only input valid amounts. However, malicious users can collude and only input zero/negative values. The resulting `sorted_bidding_price_dict` will look like this:
    ```python
    sorted_bidding_price_dict = {
      "user_a": 0,
      "user_b": -2,
      "user_3": -10
    }
    ```
  The attacker can bid for the object without paying for it.
- **Business logic errors**: failure to align to business context, allowing unintended processing to take place
  ```python
  # Company is running a promotion on an item, which is not supposed to apply if customers use vouchers
  voucher_discount = {
    "code_1": 10,
    "code_2": 30,
    "code_3": 50
  }
  voucher_code = form.get('voucher_code') # voucher discount
  voucher_discount_amount = voucher_discount.get(voucher_code)  
  promo_amount = form.get('discount_amount') # recently added promotion
  # price calculation
  price = original_price - voucher_discount_amount
  price -= promo_amount # recently added promotion calculation
  ```
  The above code calculates item price when a user adds it to their cart. In this case, both the voucher and promotional discount stack, even though the promotion was only meant for users not using vouchers.

  This can result from a poor translation of business requirements into code, or haphazard additions to the codebase that were not checked.

#### Review Checklist
- [ ] Ensure all business logic and data flows are clear and aligned with business requirements. 
- [ ] Make use of validation functions to limit value ranges and input options to values that make sense for the business context.

### Data Management
Sensitive data such as IC numbers deserve extra protection, including encryption at rest and in transit.

#### Types of Vulnerabilities
- **Weak cryptography**: use of outdated encryption algorithms (e.g. `DES`) leads to encrypted data being easily "cracked" and exposed
- **Hardcoding secrets**: hard coding of secrets such as database credentials, API and encryption keys, can lead to them being published in code repositories, allowing unintended access to APIs and data to anyone who has access to the codebase

#### Review Checklist
- [ ] Ensure updated encryption algorithms are used.
- [ ] Ensure `SSL/TLS` is used for protecting data in transit.
- [ ] Ensure the use of secret management tools, with controlled access, to store sensitive data such as credentials and keys.

### Exception Handling
Improper exception handling can lead to leaking of valuable system information.

#### Types of Vulnerabilities
- **Revealing internal error messages**: this can provide malicious users important clues regarding the application. Examples include:
    ```
    - stack traces
    - database dumps
    - error codes
    - software and hardware types and versions
    ```
- **Insecure state due to exception**: initial failure may cause the application to enter an insecure state. Examples include:
    ```
    - resources not locked down and released
    - sessions not terminated properly
    - continuous processing of business logic despite exception
    ```

#### Review Checklist
- [ ] Ensure code artefacts from the debugging process have been removed and that logging levels are set appropriately.
- [ ] Ensure all exits from a function, including exceptions, are covered.
- [ ] Ensure that the program fails gracefully, preferably displaying a generic error page for all exceptions.

### Injection Attack
Injection attack allows a malicious user to add/inject content into an application to modify its behaviours. 

#### Types of Vulnerabilities
- **SQL Injection**: modifies queries that an application makes to the database
    ```python
    username = form.get("username")
    password = form.get("password")
    query = "select * from users where username="+username+" and password="+password+";"
    db_cursor.execute(query)
    ```
  The vulnerability arises due to assumptions that users will only input valid credentials. However, malicious users can input the following to gain access to admin account:
    ```
    username = "admin OR 1=1 #"
    password= ""
    query = select * from users where username=admin OR 1=1 # and password='';
    ```
  The `OR 1=1` condition will always return `TRUE`, and the `#` comments out the rest of the query. In essence, the query becomes `select * from users where username=admin`, and malicious user can login as admin.

#### Review Checklist
- [ ] Ensure all input is validated for expected length and data type and encoded/sanitized of special characters. 
- [ ] Ensure input validation is done on the server side.

### Logging
Application logs are important for debugging errors, but developers should be aware of how to mitigate some of the common unintended behaviours which can arise.

#### Types of Vulnerabilities
- **Sensitive data exposure**: logging sensitive data such as IC numbers and credentials can lead to unintentional exposure.
- **Denial of Service**: malicious users can take advantage of excessive logging to deplete system resources such as processing and disk space leading to outages.
- **Log injection**: without proper sanitization, user input may be injected into logs, leading to log forging and even code execution if log files are consumed programmatically.
    ```python
    val = request.getParameter("val");
    try:
        value = int(val)
    except NumberFormatException:
        log.info("Failed to parse val = " + val)
    ```
  A malicious user can submit this string `twenty-one%0a%0aINFO:+User+logged+out%3dbadguy` and the log will look like the following, hence creating forged entries:
    ```
    INFO: Failed to parse val=twenty-one

    INFO: User logged out=badguy
    ```

#### Review Checklist
- [ ] Ensure that logs are stored in restricted locations.
- [ ] Ensure that log masking is used for sensitive data.
- [ ] Ensure that no user invoked functions that generate excessive logs.

### Session Management
Improper session management can lead to malicious users impersonating others and gaining access to privileged data or application functions.

#### Types of Vulnerabilities
- **Session hijacking**: malicious user can steal someone else's session ID and use it to impersonate that user
    ```python
    @app.get("/sessions/{session_id}")
    def get_session(session_id: str):
        session_obj = sessions.get(session_id)
        return session_obj
    ```
  The code above is vulnerable as `session_id` is exposed in URL and there are no authentication and authorization checks.

- **Session elevation**: An attacker could have captured a session ID prior to user login. If the same session ID is reused when the user logs in, then the attacker can gain access to the elevated session using the captured session ID.

#### Review Checklist
- [ ] Ensure that session IDs are placed in cookies, and these cookies are HTTP-Only.
- [ ] Ensure that session IDs generated by a cryptographically secure funtion and cannot be guessed.
- [ ] Ensure that a new session ID is generated whenever a session is elevated and that session data is flushed when it is de-elevated.
