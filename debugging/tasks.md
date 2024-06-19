# ChatGPT - Introduction

## 0. Debugging

### Task
The following tasks build upon each other, it is recommended that you follow them in order for the best experience.

It has been reported that students in the ‘Creating Pop Music Lyrics With ChatGPT’ subject with a final mark of 85 are receiving an incorrect final grade when their report cards are being generated.

The following python function is responsible for returning the appropriate grade for a student when given their final mark.

```python
def graduate:
    grade = ‘Unknown’
    if mark < 50: 
        grade = ‘Not yet successful’ 
    elif mark >=50 and mark <= 60: 
        grade = ‘Pass’ 
    elif mark > 60 and mark <= 75: 
        grade = ‘Credit’ 
    elif mark > 75 and mark < 85: 
        grade = ‘Distinction’ 
    elif mark > 85: 
        grade = ‘High Distinction’ 
    else: 
        grade = ‘Unknown’
    return grade
```

Having a look at the code yourself, suggest where the issue could potentially be.

Write the correct prompt to explain to ChatGPT the problem that is being experienced with this function and ask it to identify and resolve the issue.

### Solution
The python code below is responsible for returning the appropriate grade for a student when given their final mark.

It has been reported that students with a final mark of 85 are receiving an incorrect final grade when their report cards are being generated.

Please identify and fix the problem with the python code.

```python
def graduate:
    grade = ‘Unknown’
if mark < 50:
    grade = ‘Not yet successful’
elif mark >=50 and mark <= 60:
    grade = ‘Pass’
elif mark > 60 and mark <= 75:
    grade = ‘Credit’
elif mark > 75 and mark < 85:
    grade = ‘Distinction’
elif mark > 85:
    grade = ‘High Distinction’
else:
    grade = ‘Unknown’
return grade
```

### ChatGPT response
The issue with the provided Python code lies in the range conditions for the grades, specifically for the mark of 85. The condition for "High Distinction" is `mark > 85`, which means a mark of exactly 85 does not fit into any of the defined grade categories. To fix this, we need to adjust the condition to include a mark of 85 in the "High Distinction" category.

Additionally, there are some other issues in the code:
1. The function definition syntax is incorrect. It should be `def graduate(mark):`.
2. The string quotation marks are inconsistent (using single quotes but with the wrong characters).
3. The final `else` block is redundant because all cases are covered.

Here is the corrected version of the code:

```python
def graduate(mark):
    grade = 'Unknown'
    if mark < 50: 
        grade = 'Not yet successful' 
    elif mark >= 50 and mark <= 60: 
        grade = 'Pass' 
    elif mark > 60 and mark <= 75: 
        grade = 'Credit' 
    elif mark > 75 and mark < 85: 
        grade = 'Distinction' 
    elif mark >= 85:  # Adjusted this condition to include 85
        grade = 'High Distinction'
    return grade
```

This adjustment ensures that a final mark of 85 receives the appropriate "High Distinction" grade.

## 1. Refactoring

### Task
Once we have corrected the code snippet in ‘Debugging’, lets go ahead and refactor the responsible python code so that it is easier to work with in the future.

Write a prompt to ChatGPT asking it to refactor the code so that the following is achieved:

- Code follows the python PEP 8 style guide.
- The code snippet is wrapped in a function.
- The code snipped raises a ValueError if the mark is outside of the range 0-100.

### Solution
Please refactor the above code such that

- Code follows the python PEP 8 style guide.
- The code snippet is wrapped in a function.
- The code snipped raises a ValueError if the mark is outside of the range 0-100.

### ChatGPT response
Sure, here is the refactored code following the PEP 8 style guide and including a check for the mark range, raising a `ValueError` if the mark is outside the range 0-100:

```python
def get_grade(mark):
    """Return the grade for a given mark.

    Parameters:
    mark (int or float): The final mark of the student.

    Returns:
    str: The grade corresponding to the final mark.

    Raises:
    ValueError: If the mark is not in the range 0-100.
    """
    if not (0 <= mark <= 100):
        raise ValueError("Mark must be between 0 and 100.")

    if mark < 50:
        return 'Not yet successful'
    elif 50 <= mark <= 60:
        return 'Pass'
    elif 61 <= mark <= 75:
        return 'Credit'
    elif 76 <= mark < 85:
        return 'Distinction'
    elif mark >= 85:
        return 'High Distinction'
```

#### Changes made:
1. Renamed the function to `get_grade` for clarity.
2. Added a docstring for the function to describe its purpose, parameters, return value, and exceptions.
3. Added a condition to check if the mark is between 0 and 100, raising a `ValueError` if not.
4. Adjusted the grade ranges to be clear and inclusive where appropriate.
5. Removed redundant variable assignments for simplicity.

## 2. Generate Test Cases

### Task
Now that we have used ChatGPT to refactor our grading function, let’s use to write test cases to ensure our new function is working correctly.

Using the following functional requirements, write a prompt to ChatGPT to generate python test cases for our grading function:

- When given an input of 0-49, the function should return ‘Not yet successful’.
- 50-60 ‘Pass’
- 61-75 ‘Credit’
- 76 – 85 ‘Distinction’
- 86-100 ‘High Distinction’

Given in ‘Refactoring’, you asked ChatGPT to include raising an error when a mark is ouside of the range 0-100, prompt ChatGPT to include test cases to validate this behaviour.

### Solution
Write test cases for the refactored grading function with the following criteria:

- When given an input of 0-49, the function should return ‘Not yet successful’.
- 50-60 ‘Pass’
- 61-75 ‘Credit’
- 76 – 85 ‘Distinction’
- 86-100 ‘High Distinction’
- Throw ValueError when mark is outside the range of 0-100

### ChatGPT response
Here are the test cases for the refactored grading function:

```python
def test_get_grade():
    # Test cases for 'Not yet successful'
    assert get_grade(0) == 'Not yet successful'
    assert get_grade(25) == 'Not yet successful'
    assert get_grade(49) == 'Not yet successful'

    # Test cases for 'Pass'
    assert get_grade(50) == 'Pass'
    assert get_grade(55) == 'Pass'
    assert get_grade(60) == 'Pass'

    # Test cases for 'Credit'
    assert get_grade(61) == 'Credit'
    assert get_grade(70) == 'Credit'
    assert get_grade(75) == 'Credit'

    # Test cases for 'Distinction'
    assert get_grade(76) == 'Distinction'
    assert get_grade(80) == 'Distinction'
    assert get_grade(85) == 'Distinction'

    # Test cases for 'High Distinction'
    assert get_grade(86) == 'High Distinction'
    assert get_grade(90) == 'High Distinction'
    assert get_grade(100) == 'High Distinction'

    # Test cases for ValueError
    try:
        get_grade(-1)
    except ValueError as e:
        assert str(e) == "Mark must be between 0 and 100."
    else:
        assert False, "Expected ValueError for mark -1"

    try:
        get_grade(101)
    except ValueError as e:
        assert str(e) == "Mark must be between 0 and 100."
    else:
        assert False, "Expected ValueError for mark 101"

# Run the test cases
test_get_grade()
```

#### Explanation:
1. **Not yet successful:** Tests for marks in the range 0-49.
2. **Pass:** Tests for marks in the range 50-60.
3. **Credit:** Tests for marks in the range 61-75.
4. **Distinction:** Tests for marks in the range 76-85.
5. **High Distinction:** Tests for marks in the range 86-100.
6. **ValueError:** Tests for marks outside the range 0-100, ensuring the function raises the appropriate error with the correct message.

To run these tests, simply include them in your script or test framework. The function `test_get_grade` will automatically run all test cases and raise an assertion error if any test fails.

## 3. Documentation

### Task
ChatGPT can be a powerful tool in allowing developers to do simpler tasks more quickly and effectively. Using our most recent grading function from ‘Refactoring’, prompt ChatGPT to write documentation for our code.

Reflect on the documentation produced by ChatGPT. Has it covered everything you would expect to see in the documentation of a function? If it has not, go ahead and prompt it to include anything you feel may be missing.

### Solution
Can you write the documentation for refactored grading function get_grade?

### ChatGPT response
Certainly! Here's the documentation for the `get_grade` function:

```python
def get_grade(mark):
    """
    Return the grade for a given mark based on the following criteria:

    - 0-49: 'Not yet successful'
    - 50-60: 'Pass'
    - 61-75: 'Credit'
    - 76-85: 'Distinction'
    - 86-100: 'High Distinction'
    
    Parameters:
    mark (int or float): The final mark of the student. It should be a value between 0 and 100 inclusive.

    Returns:
    str: The grade corresponding to the final mark.

    Raises:
    ValueError: If the mark is not in the range 0-100.

    Examples:
    >>> get_grade(45)
    'Not yet successful'
    
    >>> get_grade(55)
    'Pass'
    
    >>> get_grade(70)
    'Credit'
    
    >>> get_grade(80)
    'Distinction'
    
    >>> get_grade(90)
    'High Distinction'
    
    >>> get_grade(-5)
    Traceback (most recent call last):
        ...
    ValueError: Mark must be between 0 and 100.
    
    >>> get_grade(105)
    Traceback (most recent call last):
        ...
    ValueError: Mark must be between 0 and 100.
    """
    if not (0 <= mark <= 100):
        raise ValueError("Mark must be between 0 and 100.")

    if mark < 50:
        return 'Not yet successful'
    elif 50 <= mark <= 60:
        return 'Pass'
    elif 61 <= mark <= 75:
        return 'Credit'
    elif 76 <= mark < 85:
        return 'Distinction'
    elif mark >= 85:
        return 'High Distinction'
```

#### Explanation of the Documentation:
1. **Function Description:**
   - Explains what the function does and lists the criteria for each grade range.
   
2. **Parameters:**
   - Describes the `mark` parameter, indicating it can be an integer or a float and must be between 0 and 100 inclusive.
   
3. **Returns:**
   - Specifies the type and description of the return value (a string representing the grade).
   
4. **Raises:**
   - Details the conditions under which a `ValueError` will be raised (when the mark is outside the range 0-100).

5. **Examples:**
   - Provides example usages of the function, including examples that will raise a `ValueError`.

## 4. Security checks (OWASP)

### Task
You are conducting a code review with one of your team members who has been working on a python function which returns the total daily spend for a particular customer. After reviewing the code, you have some concerns that it might have some security vulnerabilities.

The python function definition is as below:
```python
def get_customer_daily_sales(customer_code):
    # Get sql db connection
    sql_con = get_sql_connection()

    # Create a cursor
    cur = sql_con.cursor()

     # Produce query to get customer average sales
     query = f"""
         SELECT
                o.CustomerName,
                CAST(o.OrderDt AS DATE) AS OrderDate,
                SUM(o.OrderTotal) AS DailyTotal
            FROM dbo.Orders AS o
            INNER JOIN dbo.Customers AS c
                on o.CustomerKey = c.CustomerKey
            AND c.CustomerCode = '{customer_code}'
            GROUP BY o.CustomerName, CAST(o.OrderDt as DATE);
     """

    # Execute the query
    cur.execute(query)

    # Collect query result
    result = cur.fetchall()

    # Close the connection
    sql_con.close()

    # Return the result
    return result
```
Prompt ChatGPT to review the code to see if it is vulnerable to any of the OWASP 10 top, and if applicable, give an example how it could be exploited. If it has not already done so, prompt ChatGPT to provide a new version of the stored procedure which is not vulnerable.

Ask ChatGPT again what the remaining OWASP top 10 are with an examples for each.

### Solution
The following python code returns the total daily spend for a particular customer.

Can you review the code and check if it's vulnerable to OWASP top 10 vulnerabilities? If yes, can you provide an example of how it can be exploited?

```python
def get_customer_daily_sales(customer_code):
    # Get sql db connection
    sql_con = get_sql_connection()

    # Create a cursor
    cur = sql_con.cursor()

     # Produce query to get customer average sales
     query = f"""
         SELECT
                o.CustomerName,
                CAST(o.OrderDt AS DATE) AS OrderDate,
                SUM(o.OrderTotal) AS DailyTotal
            FROM dbo.Orders AS o
            INNER JOIN dbo.Customers AS c
                on o.CustomerKey = c.CustomerKey
            AND c.CustomerCode = '{customer_code}'
            GROUP BY o.CustomerName, CAST(o.OrderDt as DATE);
     """

    # Execute the query
    cur.execute(query)

    # Collect query result
    result = cur.fetchall()

    # Close the connection
    sql_con.close()

    # Return the result
    return result
```

### ChatGPT response
The provided Python code is vulnerable to several OWASP Top 10 vulnerabilities, primarily **SQL Injection**. This vulnerability occurs because the SQL query is constructed using string formatting with user-provided input (`customer_code`). An attacker can exploit this by injecting malicious SQL code, potentially accessing, modifying, or deleting data in the database.

#### Exploitation Example
An attacker can exploit this vulnerability by providing a specially crafted `customer_code`. For example, if `customer_code` is set to:
```python
customer_code = "abc' OR '1'='1"
```
The resulting SQL query would be:
```sql
SELECT
    o.CustomerName,
    CAST(o.OrderDt AS DATE) AS OrderDate,
    SUM(o.OrderTotal) AS DailyTotal
FROM dbo.Orders AS o
INNER JOIN dbo.Customers AS c
    on o.CustomerKey = c.CustomerKey
AND c.CustomerCode = 'abc' OR '1'='1'
GROUP BY o.CustomerName, CAST(o.OrderDt as DATE);
```
The condition `OR '1'='1'` always evaluates to true, potentially returning all records in the `Orders` and `Customers` tables.

#### Other Potential Vulnerabilities
While SQL Injection is the primary concern, there are other vulnerabilities that could be present depending on the overall context and usage of the code:
1. **Insufficient Logging & Monitoring**: If there is no logging mechanism to monitor for unusual activities, SQL injection attempts might go unnoticed.
2. **Sensitive Data Exposure**: If the database connection details or sensitive data are not properly secured, they could be exposed.

#### Securing the Code
To mitigate the SQL Injection vulnerability, you should use parameterized queries. Here's the revised code using parameterized queries:

```python
import pyodbc  # Make sure you have the appropriate library for your SQL database

def get_customer_daily_sales(customer_code):
    # Get sql db connection
    sql_con = get_sql_connection()

    # Create a cursor
    cur = sql_con.cursor()

    # Produce parameterized query to get customer average sales
    query = """
        SELECT
            o.CustomerName,
            CAST(o.OrderDt AS DATE) AS OrderDate,
            SUM(o.OrderTotal) AS DailyTotal
        FROM dbo.Orders AS o
        INNER JOIN dbo.Customers AS c
            ON o.CustomerKey = c.CustomerKey
        WHERE c.CustomerCode = ?
        GROUP BY o.CustomerName, CAST(o.OrderDt as DATE);
    """

    # Execute the query with parameter
    cur.execute(query, (customer_code,))

    # Collect query result
    result = cur.fetchall()

    # Close the connection
    sql_con.close()

    # Return the result
    return result
```

#### Explanation:
1. **Parameterized Queries**: The query uses a `?` placeholder for the `customer_code` parameter, and the value is passed as a separate argument to `cur.execute()`. This ensures that the input is properly escaped and prevents SQL injection.
2. **Consistency**: Ensures the connection is properly closed after use, preventing potential resource leaks.

By implementing parameterized queries, you significantly reduce the risk of SQL injection and improve the overall security of your code.

### Solution
What are the remaining OWASP top 10 vulnerabilities? Can you provide examples for each of them?

### ChatGPT response
Certainly! The OWASP Top 10 is a list of the most critical security risks to web applications. As of the latest update (2021), here are the OWASP Top 10 vulnerabilities with examples for each:

1. **Broken Access Control**
    - **Example:** A web application allows users to view other users' private data by simply changing the user ID in the URL.
    - **Exploitation:** If `https://example.com/user/1234/profile` displays user 1234's profile, an attacker can access another user's profile by changing the URL to `https://example.com/user/5678/profile`.

2. **Cryptographic Failures**
    - **Example:** Storing passwords in plaintext or using weak encryption algorithms like MD5.
    - **Exploitation:** An attacker who gains access to the database can easily retrieve and crack user passwords.

3. **Injection**
    - **Example:** SQL Injection, as previously discussed.
    - **Exploitation:** Providing malicious SQL code as input to manipulate or retrieve unauthorized data from the database.

4. **Insecure Design**
    - **Example:** An application design that does not properly separate user roles, allowing regular users to perform administrative actions.
    - **Exploitation:** A regular user can elevate their privileges to an administrator by exploiting flaws in the role management system.

5. **Security Misconfiguration**
    - **Example:** Default configurations of web servers, frameworks, and databases are left unchanged.
    - **Exploitation:** An attacker exploits default credentials or unnecessary features to gain unauthorized access.

6. **Vulnerable and Outdated Components**
    - **Example:** Using outdated libraries or frameworks with known vulnerabilities.
    - **Exploitation:** An attacker exploits known vulnerabilities in outdated components to compromise the application.

7. **Identification and Authentication Failures**
    - **Example:** Poor implementation of authentication mechanisms, such as weak password policies or failure to implement multi-factor authentication (MFA).
    - **Exploitation:** An attacker uses brute force or credential stuffing attacks to gain unauthorized access.

8. **Software and Data Integrity Failures**
    - **Example:** Unverified or unsigned code and updates, allowing an attacker to inject malicious code into the application.
    - **Exploitation:** An attacker manipulates the software update process to install malware on user systems.

9. **Security Logging and Monitoring Failures**
    - **Example:** Lack of proper logging mechanisms or monitoring of critical activities.
    - **Exploitation:** An attacker can perform malicious actions without being detected, and the application lacks the necessary logs to investigate the breach.

10. **Server-Side Request Forgery (SSRF)**
    - **Example:** An application fetches remote resources based on user input without proper validation.
    - **Exploitation:** An attacker provides a URL that points to internal services or sensitive endpoints, leading to unauthorized access or information disclosure.

#### Examples of Exploitation for Each Vulnerability:

1. **Broken Access Control**
    ```python
    # Broken Access Control Example in Python
    def view_profile(user_id):
        if user_authenticated():
            # User can change the user_id parameter to access other users' profiles
            profile = db.query(f"SELECT * FROM profiles WHERE user_id = {user_id}")
            return profile
    ```

2. **Cryptographic Failures**
    ```python
    # Weak encryption example
    import hashlib

    def store_password(password):
        # Using MD5, which is a weak hash function
        hashed_password = hashlib.md5(password.encode()).hexdigest()
        db.store(hashed_password)
    ```

3. **Injection**
    ```python
    # SQL Injection Example
    def get_user_data(user_id):
        query = f"SELECT * FROM users WHERE user_id = {user_id}"
        return db.execute(query)
    ```

4. **Insecure Design**
    ```python
    # Insecure design example
    def delete_user(user_id):
        # No role verification
        db.execute(f"DELETE FROM users WHERE user_id = {user_id}")
    ```

5. **Security Misconfiguration**
    ```plaintext
    # Apache default configuration example
    ServerTokens Full
    ServerSignature On
    ```

6. **Vulnerable and Outdated Components**
    ```python
    # Outdated library example
    # Using a vulnerable version of a library
    import flask  # Version 0.12 with known security issues
    ```

7. **Identification and Authentication Failures**
    ```python
    # Weak authentication example
    def login(username, password):
        user = db.query(f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'")
        if user:
            return "Login successful"
        return "Login failed"
    ```

8. **Software and Data Integrity Failures**
    ```python
    # Unverified software updates example
    def update_software(update_url):
        # Download update without verifying its source
        update_package = download_file(update_url)
        install_package(update_package)
    ```

9. **Security Logging and Monitoring Failures**
    ```python
    # Lack of logging example
    def login(username, password):
        user = db.query(f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'")
        if user:
            return "Login successful"
        return "Login failed"
    ```

10. **Server-Side Request Forgery (SSRF)**
    ```python
    # SSRF example
    def fetch_data(url):
        response = requests.get(url)
        return response.text
    ```

By addressing these vulnerabilities and following secure coding practices, you can significantly improve the security posture of your applications.