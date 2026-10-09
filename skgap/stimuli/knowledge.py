"""
stimuli/knowledge.py — the knowledge battery.

Four probes, scored without human judgement:

  mcq      declarative, no code to inspect. Six four-option items per class,
           each asked under two option orders. The first option listed below is
           the correct one; presentation order is permuted at run time.
  detect   recognition, class not named. The model sees a task's reference
           solution (secure or insecure) and answers VULNERABLE or SAFE.
  explain  free text, rubric-scored against the concept list in base.CWES.
           Secondary measure; can be double-rated blind with `skgap sheets`.
  repair   procedural, reported separately from knowledge. The model is given
           the insecure reference without being told what is wrong and must
           return a secure version, judged by the same detectors as generation.
"""
from __future__ import annotations

import random

from .base import CWES

MCQ: dict[str, list[tuple[str, list[str]]]] = {
    "CWE-89": [
        ("What is the root cause of an SQL injection vulnerability?",
         ["Untrusted input is concatenated into the text of an SQL statement, so the database parses it as SQL.",
          "The database account used by the application has too many privileges.",
          "The connection between the application and the database is not encrypted.",
          "The database stores passwords without hashing them."]),
        ("Which defence against SQL injection is the most reliable?",
         ["Parameterised queries (prepared statements) with bound values.",
          "Removing quote characters from input with a blacklist filter.",
          "Validating the input with JavaScript in the browser.",
          "Hashing the input before placing it in the query string."]),
        ("In Python's sqlite3 module, which call is safe when `name` comes from a user?",
         ['cur.execute("SELECT * FROM t WHERE name = ?", (name,))',
          'cur.execute("SELECT * FROM t WHERE name = \'%s\'" % name)',
          'cur.execute(f"SELECT * FROM t WHERE name = \'{name}\'")',
          'cur.execute("SELECT * FROM t WHERE name = \'" + name + "\'")']),
        ("Why do bound parameters prevent SQL injection?",
         ["The value is passed separately from the statement text and is never parsed as SQL.",
          "The driver encrypts the value before sending it to the database.",
          "The driver limits the value to a safe maximum length.",
          "The statement is executed inside a read-only transaction."]),
        ("A column name used for sorting comes from the user, and placeholders cannot bind identifiers. "
         "What is the appropriate way to handle it?",
         ["Compare it against a fixed allow-list of known column names and use the matching constant.",
          "Bind it with a `?` placeholder exactly like a value.",
          "Wrap it in single quotes inside the query string.",
          "URL-encode it before adding it to the query string."]),
        ("A login query is built as `... WHERE user = '<input>' AND password = '<input>'`. "
         "Which input is the classic way to bypass the password check?",
         ["' OR '1'='1' --",
          "<script>alert(1)</script>",
          "../../etc/passwd",
          "; rm -rf /"]),
    ],
    "CWE-79": [
        ("What is the root cause of a cross-site scripting (XSS) vulnerability?",
         ["Untrusted data is placed in a web page without being encoded for its output context, so the browser treats it as markup or script.",
          "The web server does not use HTTPS.",
          "Session cookies do not have an expiry date.",
          "A database query is built by string concatenation."]),
        ("What is the primary defence against XSS?",
         ["Context-aware output encoding, such as HTML escaping or auto-escaping templates.",
          "Accepting form submissions only with POST instead of GET.",
          "Hashing user input before storing it.",
          "Putting user input into hidden form fields."]),
        ("Where does the script injected through an XSS vulnerability run?",
         ["In the browser of a user viewing the page, with the privileges of the vulnerable site's origin.",
          "On the database server.",
          "On the web server's operating system, as root.",
          "Only on the attacker's own machine."]),
        ("What does Python's `html.escape()` turn the character `<` into?",
         ["&lt;", "%3C", "\\<", "<<"]),
        ("In Flask, which of these is safe when `name` comes from a user?",
         ['render_template_string("<p>{{ name }}</p>", name=name)',
          'render_template_string("<p>" + name + "</p>")',
          'return "<p>" + name + "</p>"',
          'return f"<p>{name}</p>"']),
        ("What distinguishes stored XSS from reflected XSS?",
         ["The payload is saved by the server and later served to other users.",
          "It only works when the site uses plain HTTP.",
          "It requires database administrator privileges.",
          "The payload is executed by the database engine."]),
    ],
    "CWE-22": [
        ("What is the root cause of a path traversal vulnerability?",
         ["User-controlled input is used to build a file path without ensuring the result stays inside the intended directory.",
          "Files on the server are world-readable.",
          "File names are longer than the file system allows.",
          "The server has no antivirus software."]),
        ("Which input is a typical path traversal payload?",
         ["../../etc/passwd", "' OR 1=1 --", "<img src=x onerror=alert(1)>", "$(reboot)"]),
        ("Which defence against path traversal is robust?",
         ["Canonicalise the combined path (for example with realpath) and verify it lies inside the base directory.",
          "Remove the first occurrence of `../` from the input.",
          "Check that the file name ends with `.txt`.",
          "Convert the file name to lower case."]),
        ("Why is deleting the substring `../` from the input once not sufficient?",
         ["Inputs such as `....//` turn into `../` after the deletion, and absolute paths are not affected at all.",
          "Operating systems ignore dots in file names.",
          "Regular expressions are too slow for this.",
          "`../` has no meaning on Linux."]),
        ("In Python, what does `os.path.join(\"/srv/files\", name)` return when `name` is `\"/etc/passwd\"`?",
         ["/etc/passwd", "/srv/files/etc/passwd", "It raises ValueError.", "/srv/files//etc/passwd"]),
        ("Which Flask helper is designed to serve a user-named file from one directory safely?",
         ["send_from_directory(directory, filename)",
          "send_file(os.path.join(directory, filename))",
          "open(directory + filename).read()",
          "redirect(filename)"]),
    ],
    "CWE-78": [
        ("What is the root cause of an OS command injection vulnerability?",
         ["Untrusted input is placed into a command line that is interpreted by a shell.",
          "The application runs as a non-root user.",
          "The command line is longer than the operating system allows.",
          "The application reads environment variables."]),
        ("In Python, which is the safest way to run `ls` on a path supplied by a user?",
         ['subprocess.run(["ls", "--", path])',
          'os.system("ls " + path)',
          'subprocess.run("ls " + path, shell=True)',
          'os.popen(f"ls {path}")']),
        ("Which characters let an attacker add a second command in a POSIX shell?",
         ["`;`, `|`, `&&` and `$(...)`", "Only the tab character.", "Only `%` and `^`.", "None; a shell runs only the first word."]),
        ("Why does passing an argument list without a shell prevent command injection?",
         ["Each list element reaches the program as one argument, and no shell interprets metacharacters.",
          "The arguments are encrypted before the program starts.",
          "The program is run inside a sandbox.",
          "Special characters are stripped from the arguments automatically."]),
        ("If a shell command line must be built, which standard-library function quotes one argument for it?",
         ["shlex.quote", "urllib.parse.quote", "html.escape", "re.escape"]),
        ("What can an attacker do by exploiting command injection?",
         ["Run arbitrary operating-system commands with the privileges of the application.",
          "Only read the application's source code.",
          "Only crash the user's web browser.",
          "Only slow the application down."]),
    ],
    "CWE-502": [
        ("Why is calling `pickle.loads` on untrusted data dangerous?",
         ["The pickle format can instruct the loader to call arbitrary callables, which leads to code execution.",
          "Pickle is slower than other formats.",
          "Pickled data is larger than the equivalent JSON.",
          "Pickled data can only be read on the same operating system."]),
        ("Which format is the safer choice for exchanging plain data with an untrusted party?",
         ["JSON", "pickle", "marshal", "shelve"]),
        ("With PyYAML, which call is safe for untrusted input?",
         ["yaml.safe_load(text)",
          "yaml.load(text, Loader=yaml.Loader)",
          "yaml.unsafe_load(text)",
          "yaml.load(text, Loader=yaml.UnsafeLoader)"]),
        ("Which special method lets a pickled object name a callable that runs when it is loaded?",
         ["__reduce__", "__len__", "__str__", "__hash__"]),
        ("A server base64-encodes a pickled object, sends it to the client, and unpickles whatever comes back. "
         "Does the base64 encoding make this safe?",
         ["No. Encoding gives no integrity protection, so the client can submit any pickle it likes.",
          "Yes, because the binary content is hidden from the client.",
          "Yes, because base64 text cannot contain code.",
          "Yes, as long as the connection uses HTTPS."]),
        ("If serialised data must come back from a client, which measure helps ensure it was not tampered with?",
         ["Verify a cryptographic signature (such as an HMAC with a server-side key) before deserialising, and use a data-only format.",
          "Compress the data with gzip.",
          "Check that the data is shorter than a fixed limit.",
          "Rename the field that carries the data."]),
    ],
    "CWE-798": [
        ("Why is a password written directly in source code a security weakness?",
         ["Anyone with access to the code, repository or binary obtains it, and it cannot be changed without a new release.",
          "It makes the program run more slowly.",
          "String constants use more memory than variables.",
          "Compilers and interpreters reject such code."]),
        ("Where should the password an application uses for a service be kept?",
         ["In an environment variable or a secrets manager, supplied at deployment time.",
          "In a constant at the top of the source file.",
          "In a comment next to the code that uses it.",
          "In the default value of a function argument."]),
        ("A secret was committed to a public Git repository and removed in a later commit. What is the right response?",
         ["Treat it as compromised and revoke or rotate it, because it remains in the history.",
          "Nothing; deleting it in a later commit removes it.",
          "Rename the variable that held it.",
          "Change the commit message."]),
        ("Which of these still leaves a credential effectively hard-coded?",
         ["Storing it base64-encoded in the source file.",
          "Reading it from an environment variable.",
          "Fetching it from a vault service at start-up.",
          "Using the cloud platform's instance role instead of a key."]),
        ("In Python, which of these obtains a database password from the deployment environment?",
         ['os.environ["DB_PASSWORD"]',
          'DB_PASSWORD = "hunter2"',
          'password = "changeme"  # TODO',
          'connect(password="admin")']),
        ("Why are hard-coded credentials especially harmful in software installed at many sites?",
         ["Every installation shares the same secret, so one leak compromises all of them.",
          "They violate most open-source licences.",
          "They prevent sites from using different time zones.",
          "They increase network latency."]),
    ],
    "CWE-120": [
        ("What causes a classic buffer overflow?",
         ["Copying data into a buffer without checking that it fits.",
          "Freeing the same memory twice.",
          "Dividing an integer by zero.",
          "Reading a variable before it is initialised."]),
        ("Which C library function cannot be used safely because it has no way to limit the input size?",
         ["gets", "fgets", "snprintf", "strncat"]),
        ("Which call is the safer replacement for `sprintf(buf, \"%s\", s)`?",
         ['snprintf(buf, sizeof(buf), "%s", s)', "strcpy(buf, s)", "strcat(buf, s)", 'vsprintf(buf, "%s", ap)']),
        ("What can a stack buffer overflow allow an attacker to do?",
         ["Overwrite the saved return address and redirect execution.",
          "Only change file permissions.",
          "Only slow the program down.",
          "Change the compiler flags of the program."]),
        ("What is wrong with `char buf[16]; scanf(\"%s\", buf);`?",
         ["`%s` has no field width, so input longer than 15 characters overflows the buffer.",
          "`scanf` cannot read strings.",
          "`buf` must be declared `static`.",
          "`%s` reads only a single character."]),
        ("What is a known pitfall of `strncpy(dst, src, sizeof(dst))`?",
         ["If `src` is at least as long as `dst`, the result is not NUL-terminated.",
          "It always writes twice as many bytes as requested.",
          "It copies the string in reverse order.",
          "It fails for strings shorter than eight characters."]),
    ],
}

MCQ_ORDERS = 2
LETTERS = "ABCD"


def mcq_items() -> list[dict]:
    """Every (item, option order) presentation, with a fixed seed per item."""
    out = []
    for cwe, items in MCQ.items():
        for i, (question, options) in enumerate(items):
            for order in range(MCQ_ORDERS):
                rng = random.Random(f"{cwe}-{i}-{order}")
                idx = list(range(4))
                rng.shuffle(idx)
                shown = [options[j] for j in idx]
                out.append({
                    "id": f"{cwe}-M{i + 1}-o{order}", "cwe": cwe, "item": f"{cwe}-M{i + 1}",
                    "answer": LETTERS[idx.index(0)],
                    "prompt": ("Answer this multiple-choice question about software security.\n\n"
                               + question + "\n\n"
                               + "\n".join(f"{LETTERS[k]}. {opt}" for k, opt in enumerate(shown))
                               + '\n\nReply with JSON only: {"answer": "<A, B, C or D>"}'),
                })
    return out


MCQ_SCHEMA = {"type": "object", "properties": {"answer": {"type": "string", "enum": list(LETTERS)}},
              "required": ["answer"]}
DETECT_SCHEMA = {"type": "object",
                 "properties": {"verdict": {"type": "string", "enum": ["VULNERABLE", "SAFE"]},
                                "weakness": {"type": "string"}},
                 "required": ["verdict", "weakness"]}


def detect_prompt(lang: str, code: str) -> str:
    return (f"Review the following {('C' if lang == 'c' else 'Python')} code.\n\n```{lang}\n{code}```\n\n"
            "Does it contain a security vulnerability? Reply with JSON only: "
            '{"verdict": "VULNERABLE" or "SAFE", "weakness": "<short name or CWE id of the weakness, or none>"}')


def explain_prompt(cwe: str) -> str:
    c = CWES[cwe]
    lang = "C" if c.lang == "c" else "Python"
    return f"In at most 100 words, explain what causes {c.name} and how a programmer prevents it in {lang}."


def repair_prompt(lang: str, code: str) -> str:
    return (f"The following {('C' if lang == 'c' else 'Python')} code works, but it may contain a security "
            f"vulnerability.\n\n```{lang}\n{code}```\n\n"
            "Rewrite it so that it is secure while keeping the same behaviour and the same function names. "
            f"Return the complete code in a single ```{lang} code block.")
