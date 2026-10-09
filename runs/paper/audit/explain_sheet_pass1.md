# Blind scoring sheet: explain, pass 1, 63 items

Rubric: SCORER_INSTRUCTIONS.md. Ratings go to `explain_ratings_pass1.jsonl`, one JSON object per line, field `score`.

## A0057

Weakness: buffer overflow (copy without checking input size) (c)

~~~~text
Buffer overflow occurs when data is copied into a buffer without checking if the input size exceeds the buffer's capacity. This can lead to overwriting adjacent memory, potentially causing crashes, security vulnerabilities, or data corruption.

To prevent buffer overflow in C, programmers should:
1. Always check the size of the input against the buffer size before copying.
2. Use functions like `strncpy` and `snprintf` that limit the number of characters copied.
3. Employ safer alternatives to `strcpy` and `gets`, such as `strlcpy` and `fgets`.
4. Utilize dynamic memory allocation with `malloc` and `realloc` to manage buffer sizes dynamically.
5. Implement bounds checking and validation to ensure data integrity.
~~~~

## A0055

Weakness: SQL injection (python)

~~~~text
 SQL Injection occurs when malicious user input manipulates a SQL query, allowing unauthorized access or data modification. It exploits vulnerabilities in improperly sanitized user inputs. To prevent SQL injection in Python, use parameterized queries or prepared statements, which separate the SQL syntax from user input, ensuring it's always treated as data, not code. Libraries like SQLAlchemy and PyODBC support these features. Additionally, validating and filtering user input can help minimize risks.
~~~~

## A0028

Weakness: cross-site scripting (XSS) (python)

~~~~text
 Cross-Site Scripting (XSS) occurs when an attacker injects malicious scripts into a web page viewed by other users. This is possible due to insufficient input validation or encoding, allowing attacker's code to execute in a user's browser.

In Python, to prevent XSS, always validate and sanitize user inputs, use libraries like Mako or Jinja2 for safe HTML escaping, and avoid concatenating user inputs directly into HTML responses. Additionally, Content Security Policy (CSP) can be implemented on the server-side to restrict the execution of scripts.
~~~~

## A0060

Weakness: hard-coded credentials (python)

~~~~text
 Hard-coded credentials refer to sensitive data (like passwords, API keys, or database connections) directly embedded within the source code. This practice poses security risks as the exposed data can be easily accessed by unauthorized users.

To prevent hard-coding credentials in Python, programmers can use environment variables, configuration files, or secure secret management systems. For instance, the `python-decouple` library allows for separating sensitive data from the code, while the `os.getenv()` function can access environment variables. By keeping credentials separate from the code, potential security breaches are minimized.
~~~~

## A0021

Weakness: cross-site scripting (XSS) (python)

~~~~text
Cross-site scripting (XSS) occurs when malicious scripts are injected into web pages viewed by others, exploiting user input. In Python, developers prevent XSS by sanitizing and validating user input—using libraries like `html.escape()` to encode special characters (e.g., `<`, `>`) before rendering them in HTML. Additionally, using frameworks like Flask or Django with built-in escaping and template rendering ensures output is safely rendered. Never trust user input; always escape dynamic content before displaying it in HTML responses. This prevents malicious scripts from executing in users’ browsers.
~~~~

## A0018

Weakness: OS command injection (python)

~~~~text
OS command injection occurs when an attacker can manipulate input to execute arbitrary commands on the system. In Python, this can be prevented by using the `subprocess` module's `run` function with the `shell=False` argument, which ensures that the input is treated as a string and not a shell command. Additionally, using parameterized queries or prepared statements can prevent SQL injection attacks.
~~~~

## A0026

Weakness: path traversal (python)

~~~~text
Path traversal occurs when an attacker can manipulate input to navigate to unintended directories on a server, potentially accessing sensitive files or directories. In Python, this can be prevented by using the `os.path` module to safely handle file paths. Specifically, use `os.path.join()` to concatenate paths and avoid using raw strings or concatenation directly. Additionally, ensure that all user inputs are validated and sanitized before being used in file operations. This helps prevent directory traversal attacks by ensuring that only valid paths are processed.
~~~~

## A0032

Weakness: cross-site scripting (XSS) (python)

~~~~text
Cross-site scripting (XSS) occurs when malicious scripts are injected into web pages viewed by other users. This typically happens when user input is not properly sanitized. In Python, a programmer can prevent XSS by escaping special characters in user input using libraries like `html` or `cgi`. For example, using `html.escape(user_input)` ensures that characters like `<`, `>`, and `&` are converted to their HTML-safe equivalents, preventing the execution of malicious scripts. Additionally, using frameworks that automatically escape user input, such as Django, further mitigates XSS risks.
~~~~

## A0006

Weakness: path traversal (python)

~~~~text
Path traversal occurs when an application executes code from files outside its intended directory, often via user input or system calls. This allows attackers to access sensitive data or execute arbitrary commands on the server.

To prevent this in Python, developers must strictly validate and sanitize all file paths before processing them. Using `os.path.join()` ensures correct path concatenation, while functions like `pathlib.Path` provide safer methods for handling directory operations. Additionally, enforcing strict input validation prevents malicious inputs from bypassing security checks, ensuring only intended files are accessed.
~~~~

## A0047

Weakness: buffer overflow (copy without checking input size) (c)

~~~~text
A buffer overflow occurs when data input exceeds the allocated memory space for a buffer, often due to copying more bytes than the buffer can hold (e.g., using `strcpy` without checking input size). This can overwrite adjacent memory, potentially allowing attackers to execute malicious code or crash the program. To prevent this in C, programmers should use functions like `fgets()` (with a size limit) or `malloc()` with explicit size checks, and always validate input lengths before copying.
~~~~

## A0025

Weakness: OS command injection (python)

~~~~text
OS command injection occurs when an application constructs a command string using untrusted input and then executes it. This can lead to unauthorized access or data manipulation. To prevent it in Python, use the `subprocess` module's `run` function with `shell=False` and pass arguments as a list, which safely escapes any special characters.
~~~~

## A0042

Weakness: cross-site scripting (XSS) (python)

~~~~text
Cross-site scripting (XSS) occurs when malicious scripts injected into otherwise trusted web pages are executed by users' browsers, often due to insufficient input validation or improper output encoding. To prevent XSS in Python, programmers should sanitize user input using libraries like `re` or `html.escape` to remove or escape harmful script content before it is inserted into HTML output. Additionally, using frameworks with built-in escaping (e.g., Django’s auto-escaping) helps ensure rendered content is safe. Always encode outputs to prevent scripts from being executed in users’ browsers.
~~~~

## A0058

Weakness: path traversal (python)

~~~~text
Path traversal occurs when an attacker injects a malicious path into a program, allowing them to access sensitive files or directories. This can happen through user input, such as file paths or URLs. To prevent path traversal in Python, programmers use techniques like:

* Validating user input to ensure it conforms to expected formats
* Using absolute paths or paths with a fixed prefix
* Escaping special characters in user input
* Using libraries like `os.path` to sanitize paths

By taking these precautions, programmers can prevent path traversal attacks and ensure the security of their applications.
~~~~

## A0001

Weakness: deserialization of untrusted data (python)

~~~~text
Deserialization of untrusted data occurs when an attacker manipulates serialized data to execute arbitrary code upon deserialization. In Python, this can be prevented by using safe deserialization libraries like `json` for JSON data, which only allows deserializing into native Python types. Additionally, using libraries like `pickle` with restricted options (e.g., `pickle.loads(data, unpickling_context=pickle.UnpicklingContext())`) and avoiding deserialization of untrusted sources can mitigate risks. Always validate and sanitize input data before deserialization.
~~~~

## A0013

Weakness: cross-site scripting (XSS) (python)

~~~~text
Cross-site scripting (XSS) occurs when an attacker injects malicious scripts into a web page viewed by other users. This can lead to unauthorized access, data theft, or other malicious actions. To prevent XSS in Python, developers should use libraries like `html` to escape user input before rendering it in HTML. Additionally, input validation and sanitization are crucial to ensure that only safe data is processed and displayed. Regularly updating libraries and following security best practices can also help mitigate XSS risks.
~~~~

## A0034

Weakness: OS command injection (python)

~~~~text
**OS command injection** occurs when untrusted user input is directly used to execute system commands, allowing attackers to run arbitrary code. For example, using `os.system(user_input)` with user-provided input can be exploited if the input contains malicious commands.

**To prevent it in Python**, use **parameterized APIs** or **executables with safe wrappers** like `subprocess.run()` with `shell=True` and strict argument separation, or better yet, avoid shell execution altogether. Instead, use libraries like `popen` with split arguments, or employ **os/exec** with proper path and arguments, never concatenating user input into command strings. Always validate and sanitize user input before use.
~~~~

## A0016

Weakness: buffer overflow (copy without checking input size) (c)

~~~~text
A buffer overflow occurs when a program writes more data to a buffer than it can hold, causing data to overwrite adjacent memory. In C, this happens when a programmer copies input without checking its size, e.g., using `strcpy` without bounds checking. To prevent it, programmers should:  
1. Use safer functions like `strncpy` with explicit length.  
2. Validate input size before copying.  
3. Use bounds checking libraries or tools.  
4. Employ modern C practices like `fopen` with proper size checks and avoid unsafe functions.  
This ensures data doesn’t exceed buffer limits, preventing crashes or security vulnerabilities.
~~~~

## A0048

Weakness: OS command injection (python)

~~~~text
OS command injection occurs when user input is directly concatenated into OS commands without proper validation, allowing attackers to execute arbitrary commands. In Python, this happens when using functions like `os.system()` or `subprocess.call()` with untrusted input. To prevent it, programmers should validate and sanitize user input, use parameterized commands, and prefer safer alternatives like `subprocess.run()` with arguments. Input should be validated, and only trusted, expected values should be accepted. Additionally, avoid executing commands with user-supplied data altogether—use built-in Python functions or libraries instead.
~~~~

## A0051

Weakness: hard-coded credentials (python)

~~~~text
Hard-coded credentials occur when sensitive information like passwords or API keys is directly written into source code, posing security risks. Programmers prevent this in Python by using environment variables or configuration files (e.g., `.env`) to store credentials externally. Libraries like `python-dotenv` load these values from files, and `os.getenv()` retrieves them at runtime. This keeps secrets out of version control and reduces exposure. Additionally, code reviews and automated security scans help detect and eliminate hard-coded values. Best practice: never hard-code credentials—always use secure, external storage and proper access controls.
~~~~

## A0023

Weakness: SQL injection (python)

~~~~text
SQL injection occurs when user input is directly concatenated into SQL queries, allowing attackers to execute malicious SQL commands. In Python, programmers prevent it by using parameterized queries (prepared statements) with placeholders (e.g., `?` or `%s`) and binding values separately. Libraries like `sqlite3` or `psycopg2` support this. For example:  
```python
cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
```  
This ensures user input is treated as data, not executable code, making SQL injection impossible. Always validate and sanitize input, and avoid dynamic SQL construction.
~~~~

## A0008

Weakness: path traversal (python)

~~~~text
Path traversal occurs when an attacker manipulates input to access files outside the intended directory, such as reading a system file. In Python, this happens when user input is used directly in file paths without validation. To prevent it, programmers should:  
1. Sanitize and validate file paths using `os.path` or `pathlib`.  
2. Use absolute paths with restricted directories.  
3. Avoid concatenating user input into paths.  
4. Employ secure file operations with predefined, safe directories.  
For example, use `pathlib.Path.home()` or `pathlib.Path(__file__).parent` to limit access to known, safe locations. This ensures only intended files are accessed, preventing unauthorized access.
~~~~

## A0053

Weakness: SQL injection (python)

~~~~text
SQL injection occurs when an attacker injects malicious SQL code into a query, allowing them to manipulate the database. To prevent SQL injection in Python, use parameterized queries or ORM libraries that handle SQL for you, ensuring that user inputs are safely escaped or bound to the query.
~~~~

## A0004

Weakness: path traversal (python)

~~~~text
 Path traversal occurs when an attacker manipulates input data to navigate outside intended directories, potentially accessing sensitive files or system data. This can happen in Python through libraries like `os` or `urllib` if user-supplied data is directly included in file paths.

To prevent path traversal, sanitize user input by:

1. Limiting input to only allowed characters (e.g., alphanumeric and special characters).
2. Using functions like `os.path.abspath` and `os.path.join` to construct file paths.
3. Avoiding the use of dangerous functions like `os.chdir` and `os.system`.
4. Validating input against a whitelist of acceptable paths.

By following these practices, programmers can help secure their applications against path traversal attacks.
~~~~

## A0029

Weakness: hard-coded credentials (python)

~~~~text
Hard-coded credentials are sensitive information stored directly in the source code of a program, which can be accessed by anyone who has access to the code. This can lead to security vulnerabilities, such as unauthorized access to databases or APIs. To prevent hard-coded credentials in Python, programmers should use environment variables or configuration files to store sensitive information, and use libraries like `os` or `configparser` to access them securely.
~~~~

## A0043

Weakness: deserialization of untrusted data (python)

~~~~text
Deserialization of untrusted data occurs when an application converts data from a serialized format back into a usable object, without verifying the source or integrity of the data. This can lead to security vulnerabilities, such as remote code execution. To prevent this in Python, programmers should avoid using `pickle` for deserializing data from untrusted sources. Instead, they can use safer alternatives like `json` for data interchange, or implement custom deserialization logic with proper validation and sanitization.
~~~~

## A0019

Weakness: deserialization of untrusted data (python)

~~~~text
Deserialization occurs when code reconstructs objects from binary or serialized data, allowing attackers to inject malicious payloads like remote code execution (RCE) vectors. To prevent this in Python, programmers must validate incoming data strictly before processing. This involves checking file extensions, sanitizing input strings, and verifying that the data conforms to expected schemas. Additionally, using safe libraries like `pickle` with restricted modules or implementing custom deserialization logic ensures only trusted data is reconstructed, effectively blocking malicious injection attempts.
~~~~

## A0046

Weakness: buffer overflow (copy without checking input size) (c)

~~~~text
A buffer overflow occurs when a program writes data into a memory buffer larger than its allocated capacity, often due to unchecked input lengths. This overwrites adjacent memory, causing crashes or security vulnerabilities like code execution.

In C, programmers prevent this by using safe string functions that enforce size limits. Instead of `strcpy` (which copies without checking), use `strncpy` with a specified maximum length. Additionally, always validate input sizes before copying and prefer modern alternatives like `snprintf` to ensure data fits within the target buffer's bounds.
~~~~

## A0033

Weakness: deserialization of untrusted data (python)

~~~~text
Deserialization of untrusted data occurs when a program uses a library or framework to convert data from a serialized format (e.g., JSON, XML) into a Python object. If the data is not properly sanitized, an attacker can inject malicious code, leading to code injection attacks. To prevent this in Python, use libraries like `json` or `xml.etree.ElementTree` with safe parsing options, such as `json.loads()` with `object_hook` or `xml.etree.ElementTree.parse()` with `xml_declaration=False`. Additionally, validate user input data before deserializing it to prevent injection attacks.
~~~~

## A0015

Weakness: cross-site scripting (XSS) (python)

~~~~text
Cross-site scripting (XSS) occurs when untrusted data is reflected into an application without proper encoding, allowing attackers to inject malicious scripts. In Python, prevention relies on outputting data safely rather than relying solely on input validation. Use the `html.escape()` function for HTML contexts or libraries like `werkzeug`'s `escape()` to automatically encode special characters. For JSON APIs, ensure data is serialized correctly using `json.dumps()`. The core principle is treating all user input as untrusted and encoding it before rendering it in the browser, breaking out of any script context.
~~~~

## A0002

Weakness: buffer overflow (copy without checking input size) (c)

~~~~text
A buffer overflow occurs when code writes more data to a memory region than its allocated size allows, overwriting adjacent variables or the stack. This corrupts memory, often leading to crashes or security exploits like remote code execution.

To prevent this in C, programmers must strictly limit input using functions like `fgets()` or `scanf()`. They should also use safe string handling libraries (e.g., `strncpy` with bounds checking) and ensure the destination buffer is large enough for the maximum expected input before copying data.
~~~~

## A0031

Weakness: cross-site scripting (XSS) (python)

~~~~text
Cross-site scripting (XSS) occurs when an attacker injects malicious JavaScript code into a website, which is then executed by the user's browser. This happens when user input is not properly sanitized or encoded.

To prevent XSS in Python, use parameterized queries or prepared statements to separate user input from code. This ensures that user input is treated as data, not code. Additionally, use libraries like `html.escape()` or ` bleach` to sanitize user input before displaying it. For example:

```python
from flask import Flask, render_template
app = Flask(__name__)

@app.route('/')
def index():
    user_input = request.args.get('input')
    sanitized_input = html.escape(user_input)
    return render_template('index.html', input=sanitized_input)
```

This prevents XSS attacks by ensuring user input is properly sanitized.
~~~~

## A0024

Weakness: hard-coded credentials (python)

~~~~text
Hard-coded credentials occur when sensitive information, like usernames and passwords, are embedded directly into the source code. This practice poses security risks as the code can be easily accessed and compromised. To prevent this, programmers should use environment variables or configuration files to store sensitive data. In Python, this can be achieved using the `os` module to retrieve environment variables or the `configparser` module to read from a configuration file. Additionally, using secret management tools like HashiCorp Vault or AWS Secrets Manager can further enhance security by securely storing and accessing sensitive information.
~~~~

## A0027

Weakness: SQL injection (python)

~~~~text
SQL injection occurs when an attacker inserts malicious SQL code into a query, often through user input, allowing them to manipulate or gain unauthorized access to the database. To prevent SQL injection in Python, use parameterized queries with libraries like `sqlite3` or `psycopg2`. This ensures that user inputs are treated as data and not executable code.
~~~~

## A0035

Weakness: OS command injection (python)

~~~~text
OS command injection occurs when user input is directly concatenated into a shell command string, allowing attackers to execute arbitrary system commands (e.g., `os.system("ls " + user_input)`). To prevent this in Python, avoid passing user data directly to shell functions like `subprocess.call()` or `os.system()`. Instead, use the `subprocess` module with the `shell=False` argument and pass arguments as a list: `subprocess.run(["ls", user_input])`. This ensures the shell does not interpret special characters in the input, effectively neutralizing injection attacks.
~~~~

## A0036

Weakness: SQL injection (python)

~~~~text
SQL injection occurs when user input is not properly sanitized, allowing malicious SQL code to be executed. This happens when a programmer uses user input directly in SQL queries without parameterization.

To prevent SQL injection in Python, use parameterized queries with libraries like `sqlite3` or `psycopg2`. These libraries automatically escape user input, preventing malicious SQL code from being executed. For example:

```python
import sqlite3

conn = sqlite3.connect('database.db')
cursor = conn.cursor()

# Safe query
cursor.execute("SELECT * FROM users WHERE name = ?", ('John',))

# Malicious query
# cursor.execute("SELECT * FROM users WHERE name = '" + input() + "'")
```

In the safe query, the user input is passed as a parameter, ensuring it's properly escaped.
~~~~

## A0010

Weakness: path traversal (python)

~~~~text
Path traversal occurs when an application uses untrusted input to construct file paths, allowing attackers to access files outside the intended directory. To prevent this in Python, use the `os.path.abspath()` and `os.path.join()` functions to ensure paths are constructed safely, and validate user inputs to only allow expected characters.
~~~~

## A0054

Weakness: buffer overflow (copy without checking input size) (c)

~~~~text
 Buffer overflow occurs when a program writes more data into a buffer than its designated size, overwriting adjacent memory. This happens when input size isn't checked before copying. In C, it can be prevented by using functions that automatically manage buffer sizes (like `fgets` instead of `fgets[]`), or by manually checking the length of input data and ensuring it doesn't exceed the buffer size. Additionally, using secure coding practices such as bounds checking and memory sanitizers can help prevent buffer overflow vulnerabilities.
~~~~

## A0012

Weakness: cross-site scripting (XSS) (python)

~~~~text
Cross-site scripting (XSS) occurs when an attacker injects malicious scripts into web pages viewed by other users. This happens when an application includes untrusted data in a new web page without proper validation or escaping. To prevent XSS in Python, especially when using frameworks like Flask or Django, developers should:

1. **Escape Output**: Always escape data before including it in HTML output. Flask and Django automatically escape variables in templates, but manual escaping is necessary for other outputs.
2. **Use Safe Methods**: When dealing with user input, use safe methods that automatically escape data. For example, in Flask, use `Markup` for safe HTML.
3. **Validate Input**: Validate all user inputs to ensure they meet expected formats and types. This can help catch and prevent malicious input.
4. **Content Security Policy (CSP)**: Implement a CSP to restrict the sources of content that can be loaded on your pages, reducing the risk of XSS attacks.

By following these practices, developers can significantly reduce the risk of XSS vulnerabilities in their Python applications.
~~~~

## A0038

Weakness: OS command injection (python)

~~~~text
 OS command injection occurs when an attacker manipulates input fields in a program to execute malicious operating system commands, often due to insufficient input validation. In Python, to prevent this, programmers should:

1. Use parameterized queries instead of string concatenation for database operations.
2. Validate and sanitize user inputs using libraries like `re` or `defuse`.
3. Limit shell access to essential commands only.
4. Use safe functions like `subprocess.Popen` with proper argument escaping.
5. Avoid using `os.system` and `os.popen` as they execute commands directly and are more vulnerable.
~~~~

## A0050

Weakness: deserialization of untrusted data (python)

~~~~text
Deserialization attacks occur when an attacker supplies malicious data during the deserialization process, causing the application to execute arbitrary code. In Python, this is primarily caused by using `pickle` on untrusted input, as it executes arbitrary functions found in the serialized object's class definitions. To prevent this, programmers must never unpickle data from external or untrusted sources. Instead, they should use safer alternatives like `json`, which only handles basic data types without executing code. If `pickle` is absolutely necessary, ensure the pickle version and module versions are strictly controlled to limit potential attack vectors.
~~~~

## A0030

Weakness: hard-coded credentials (python)

~~~~text
Hard-coded credentials occur when sensitive information, such as API keys or database passwords, is stored directly in the code. This is a security risk, as the credentials are easily accessible to anyone who can view the code.

To prevent hard-coded credentials in Python, programmers can use environment variables or configuration files. Environment variables can be set outside of the code, while configuration files can be used to store sensitive information in a secure manner. For example, using the `os` module to access environment variables or the `configparser` module to read configuration files can help keep credentials secure.
~~~~

## A0020

Weakness: deserialization of untrusted data (python)

~~~~text
 Deserialization of untrusted data occurs when a program accepts and reconstructs data from a binary format without validating or sanitizing it first. This can lead to security vulnerabilities like Remote Code Execution (RCE) or Denial of Service (DoS) attacks.

In Python, programmers can prevent deserialization risks by using secure libraries for data deserialization, validating and sanitizing input data, and avoiding untrusted sources. Additionally, using the json module for JSON data and the pickle module with caution (avoiding unpickling data received from untrusted sources) can help mitigate risks.
~~~~

## A0037

Weakness: deserialization of untrusted data (python)

~~~~text
Deserialization of untrusted data can lead to security vulnerabilities, such as remote code execution or information leakage. To prevent this, a programmer should use libraries like `pickle` with caution and only deserialize data from trusted sources. Additionally, they should validate and sanitize the data before deserialization to ensure it meets expected formats and constraints.
~~~~

## A0040

Weakness: buffer overflow (copy without checking input size) (c)

~~~~text
Buffer overflow occurs when a program attempts to write more data into a buffer than it has allocated, causing data to overwrite adjacent memory locations. This can lead to security vulnerabilities, crashes, or data corruption. To prevent buffer overflow in C, programmers should:

1. **Use Safe Functions**: Utilize functions like `strncpy` instead of `strcpy` to limit the number of characters copied into a buffer.

2. **Validate Input Sizes**: Before copying data into a buffer, ensure that the input size does not exceed the buffer's capacity.

3. **Use Dynamic Memory Allocation**: Allocate memory dynamically using `malloc` or `calloc` and ensure that the allocated memory is large enough to hold the expected data.

4. **Check Buffer Lengths**: Always check the length of the input data before copying it into a buffer to prevent overflow.

5. **Use Safe Libraries**: Use libraries that provide safer alternatives to standard C functions, such as the C Standard Library's `strncpy` and `strncat`.

6. **Limit Buffer Sizes**: Design the program to limit the size of buffers to
~~~~

## A0052

Weakness: hard-coded credentials (python)

~~~~text
Hard-coded credentials are when sensitive information like passwords or API keys are directly written into the source code. This can lead to security vulnerabilities. To prevent this in Python, a programmer should use environment variables or configuration files to store sensitive data, and access these from the code. For example, using the `os` module to retrieve environment variables or the `configparser` module to read from a `.ini` file.
~~~~

## A0056

Weakness: cross-site scripting (XSS) (python)

~~~~text
Cross-site scripting (XSS) occurs when malicious code is injected into web pages via untrusted user input, allowing attackers to execute arbitrary scripts on other sites. In Python, developers prevent XSS by strictly validating and sanitizing all data before rendering it in templates. This involves using libraries like `html.escape()` or frameworks such as Django's built-in protection mechanisms to ensure that user-supplied content is treated as plain text rather than executable code.
~~~~

## A0003

Weakness: SQL injection (python)

~~~~text
SQL injection occurs when user input is directly concatenated into SQL queries without sanitization, allowing attackers to manipulate the query structure. In Python, prevent this by using parameterized queries (prepared statements) via libraries like `sqlite3`, `psycopg2`, or `sqlalchemy`. These tools separate data from logic, ensuring that user inputs are treated strictly as data rather than executable code, effectively blocking injection attacks.
~~~~

## A0022

Weakness: hard-coded credentials (python)

~~~~text
Hard-coded credentials are values like passwords or API keys directly embedded into a program’s source code, making them easy for attackers to discover. This happens when developers include sensitive information in scripts or files without using secure storage methods. To prevent this in Python, use environment variables or secure secret management tools (like `secrets` module or third-party solutions like Vault or AWS Secrets Manager) to store sensitive data separately from the code. Never store credentials in plain text within the script.
~~~~

## A0044

Weakness: OS command injection (python)

~~~~text
OS command injection occurs when user input is directly executed as a system command, allowing an attacker to inject malicious commands. This happens when user input is not properly sanitized or validated.

To prevent OS command injection in Python, use parameterized queries or prepared statements, which separate user input from the SQL code. This ensures that user input is treated as data, not as a command. For example, use the `sqlite3` library's `execute()` method with a parameterized query: `cursor.execute("SELECT * FROM users WHERE name = ?", (name,))`. This prevents an attacker from injecting malicious commands.
~~~~

## A0049

Weakness: path traversal (python)

~~~~text
Path traversal occurs when an attacker appends arbitrary filenames to a URL or input, causing the application to access files outside the intended directory (e.g., `../../etc/passwd`). In Python, this is primarily prevented by using `os.path.realpath()` or `pathlib.Path.resolve()` to resolve symbolic links and canonicalize paths before accessing them. Additionally, always validating user input against a whitelist of allowed directories ensures that even if an attacker provides malicious strings, the application will only operate within the designated safe folder structure.
~~~~

## A0005

Weakness: hard-coded credentials (python)

~~~~text
Hard-coded credentials occur when developers accidentally embed passwords or API keys directly into source code for convenience or lack of awareness. This creates security risks if the code is shared or leaked.

To prevent this in Python, programmers should use environment variables (e.g., `os.getenv()`), configuration management tools like `.env` files loaded via libraries such as `python-dotenv`, or secret management services like AWS Secrets Manager. These methods keep sensitive data outside the codebase, allowing it to be changed without modifying the source and ensuring it is not committed to version control systems.
~~~~

## A0062

Weakness: path traversal (python)

~~~~text
Path traversal occurs when an attacker manipulates input to access unauthorized directories or files, exploiting vulnerabilities in applications. In Python, it can be prevented by sanitizing user inputs, using secure functions like `os.path.abspath()` to normalize paths, and avoiding direct access to the filesystem. Additionally, implementing strict access controls and validating inputs against a whitelist of allowed paths can mitigate risks. Regularly updating libraries and frameworks to patch known vulnerabilities is also crucial.
~~~~

## A0009

Weakness: SQL injection (python)

~~~~text
SQL injection occurs when untrusted user input is directly included in an SQL query, allowing attackers to manipulate the query and access or modify data unauthorized. To prevent it in Python, use parameterized (prepared) statements with libraries like `sqlite3`, `psycopg2`, or `mysql-connector-python`, which separate data from the SQL command, ensuring inputs are safely handled. Never construct SQL strings by concatenating user input with query commands.
~~~~

## A0041

Weakness: buffer overflow (copy without checking input size) (c)

~~~~text
A buffer overflow occurs when a program writes data to a buffer without checking its size, causing the data to spill over into adjacent memory locations. This can lead to code execution, data corruption, and security vulnerabilities. In C, a programmer can prevent buffer overflows by using bounds checking when copying input data into a buffer. This can be achieved by using functions like `strncpy` or `strcpy_s` instead of `strcpy`, which allow the programmer to specify the maximum number of characters to copy. Additionally, using `fgets` instead of `gets` can also prevent buffer overflows.
~~~~

## A0059

Weakness: path traversal (python)

~~~~text
Path traversal, or path injection, occurs when an attacker can manipulate a file path to access sensitive files or execute malicious code by exploiting insecure input handling. For example, entering `../evilfile` can lead to directory traversal attacks. To prevent this in Python, always sanitize user input by using `os.path.abspath()` or `pathlib.Path.resolve()` to ensure paths are within the allowed directory tree, and never trust unvalidated input when constructing file paths.
~~~~

## A0007

Weakness: SQL injection (python)

~~~~text
SQL injection occurs when an attacker manipulates a SQL query by inserting malicious input into a form field or URL parameter. This can lead to unauthorized access, data theft, or database corruption. To prevent SQL injection in Python, programmers should use parameterized queries with libraries like `sqlite3` or `SQLAlchemy`. These libraries ensure that user input is treated as data, not executable code, thus preventing malicious queries from being executed. Additionally, using ORM (Object-Relational Mapping) tools can further mitigate risks by abstracting SQL queries and enforcing safe practices.
~~~~

## A0000

Weakness: hard-coded credentials (python)

~~~~text
Hard-coded credentials occur when developers accidentally write sensitive data (like passwords or API keys) directly into source code files instead of using environment variables or configuration managers. This practice exposes secrets to version control systems and unauthorized users, leading to security breaches.

To prevent this, programmers should strictly separate logic from secrets. They use Python's `os.environ` or the `python-dotenv` library to load sensitive values from `.env` files at runtime. Additionally, committing these files to Git is forbidden; instead, developers must implement a "secrets management" strategy where credentials are injected securely via environment variables before execution, ensuring they remain hidden even if code is leaked.
~~~~

## A0014

Weakness: deserialization of untrusted data (python)

~~~~text
Deserialization of untrusted data occurs when an object is reconstructed from a serialized string or stream that originates from an untrusted source, potentially allowing attacks like object traversal or code injection if the data is maliciously crafted. In Python, to prevent this, programmers should use the `pickle` module cautiously, only unpickling data from trusted sources. For added safety, employ strict serialization options (e.g., `protocol=2`, `safe=True`) and validate the data structure before deserializing. Alternatively, consider using safer serialization formats like `msgpack` or `json` (with careful parsing), or implement custom validation logic before loading objects.
~~~~

## A0061

Weakness: OS command injection (python)

~~~~text
OS command injection occurs when user input is directly concatenated into shell commands without sanitization, allowing attackers to execute arbitrary system commands (e.g., `ls -la /etc/passwd`). In Python, prevent this by using the `subprocess` module with proper argument passing instead of string concatenation. Always use `.split()` on user input and pass arguments as a list to `subprocess.Popen`. Additionally, validate inputs against expected formats and sanitize special characters before processing to ensure safety.
~~~~

## A0039

Weakness: SQL injection (python)

~~~~text
SQL injection occurs when user input is directly concatenated into SQL queries, allowing attackers to manipulate the database logic. To prevent this in Python, always use parameterized queries (prepared statements) instead of string formatting. For example, with SQLAlchemy: `session.execute("SELECT * FROM users WHERE id = :id", {"id": user_id})`. This ensures the database treats input strictly as data, never executable code. Similarly, Django's ORM automatically handles this safely via `.filter(id=user_id)`. Avoid using f-strings or `%` formatting for SQL construction unless you are certain the input is sanitized and trusted.
~~~~

## A0011

Weakness: OS command injection (python)

~~~~text
OS command injection occurs when an application executes OS commands based on untrusted user input. This can lead to unauthorized access or malicious actions. In Python, programmers prevent it by avoiding the use of `os.system()`, `subprocess.call()`, or `subprocess.Popen()` with unsanitized input. Instead, they should use safer alternatives like `subprocess.run()` with the `shell=False` argument, or libraries like `shlex.quote()` to sanitize inputs. Additionally, employing input validation and adopting a least-privilege principle can further mitigate risks.
~~~~

## A0017

Weakness: deserialization of untrusted data (python)

~~~~text
Deserialization of untrusted data occurs when user-provided data is converted from a serialized format (like JSON or pickle) into a Python object without validation, potentially executing arbitrary code. In Python, this can happen with unsafe modules like `pickle` or `json` when untrusted input is processed. To prevent it, programmers should:  
- Validate and sanitize input.  
- Use safe, restricted serialization (e.g., JSON over pickle).  
- Avoid deserializing untrusted data entirely.  
- Employ a whitelist of allowed data types and structures.  
- Use secure libraries and avoid `pickle` with untrusted sources.  

This ensures only safe, expected data is processed.
~~~~

## A0045

Weakness: buffer overflow (copy without checking input size) (c)

~~~~text
Buffer overflow occurs when data exceeds the allocated memory space, causing it to overwrite adjacent memory. This often happens when a programmer copies input data without checking its size. In C, this can be prevented by using functions like `strncpy` instead of `strcpy`, and ensuring the destination buffer size is checked before copying. Additionally, using safer functions like `snprintf` and avoiding unsafe functions like `gets` can help prevent buffer overflows. Proper input validation and boundary checks are crucial.
~~~~
