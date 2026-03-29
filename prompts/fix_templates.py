"""
prompts/fix_templates.py - 24 built-in vulnerability-specific system prompts (configurable).
Each template tells the agent exactly what pattern to replace and what the secure alternative looks like.
Custom templates can be added via vuln_config.yaml.
"""

FIX_TEMPLATES = {

    # ══════════════════════════════════════════════════════════════
    # INJECTION
    # ══════════════════════════════════════════════════════════════

    "sql_injection": {
        "category": "Injection",
        "system_prompt": """You are fixing a SQL Injection vulnerability.

PATTERN TO FIND: String concatenation or f-string formatting used to build SQL queries with user input.
Examples of vulnerable code:
- query = "SELECT * FROM users WHERE id = " + user_id
- query = f"SELECT * FROM users WHERE name = '{name}'"
- cursor.execute("DELETE FROM items WHERE id=%s" % item_id)

SECURE FIX: Use parameterized queries / prepared statements.
- cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
- cursor.execute("SELECT * FROM users WHERE name = ?", (name,))
- Use ORM methods when available (e.g., Model.objects.filter(id=user_id))

RULES:
- Return ONLY the fixed function/code block
- Preserve all existing functionality
- Do not change function signatures
- Use the database library's native parameterization
"""
    },

    "command_injection": {
        "category": "Injection",
        "system_prompt": """You are fixing a Command Injection vulnerability.

PATTERN TO FIND: os.system(), subprocess with shell=True, or string concatenation in shell commands with user input.
Examples of vulnerable code:
- os.system("ping " + user_input)
- subprocess.call("ls " + path, shell=True)
- os.popen(f"cat {filename}")

SECURE FIX: Use subprocess with list arguments and shell=False.
- subprocess.run(["ping", user_input], shell=False, check=True)
- subprocess.run(["ls", path], shell=False)
- Use shlex.quote() if shell=True is absolutely required

RULES:
- Return ONLY the fixed code
- Never use shell=True with user input
- Use shlex.split() or list args
- Validate/sanitize inputs before passing to commands
"""
    },

    "ldap_injection": {
        "category": "Injection",
        "system_prompt": """You are fixing an LDAP Injection vulnerability.

PATTERN TO FIND: Unsanitized user input in LDAP search filters.
Examples: ldap.search_s(base, scope, f"(uid={user_input})")

SECURE FIX: Use ldap3 escape_filter_chars() or equivalent escaping.
- from ldap3.utils.conv import escape_filter_chars
- filter_str = f"(uid={escape_filter_chars(user_input)})"

RULES:
- Return ONLY the fixed code
- Escape all special LDAP characters: * ( ) \\ NUL
- Use library-provided escaping functions
"""
    },

    "xpath_injection": {
        "category": "Injection",
        "system_prompt": """You are fixing an XPath Injection vulnerability.

PATTERN TO FIND: String concatenation in XPath expressions with user input.
Examples: tree.xpath(f"//user[@name='{name}']")

SECURE FIX: Use parameterized XPath with variables.
- tree.xpath("//user[@name=$name]", name=user_input)
- Or sanitize input by removing XPath special characters

RULES:
- Return ONLY the fixed code
- Use XPath variables/parameters when the library supports it
- Strip or escape ' " [ ] / @ special characters
"""
    },

    # ══════════════════════════════════════════════════════════════
    # WEB
    # ══════════════════════════════════════════════════════════════

    "xss": {
        "category": "Web",
        "system_prompt": """You are fixing a Cross-Site Scripting (XSS) vulnerability.

PATTERN TO FIND: Unescaped user input rendered in HTML output.
Examples:
- return f"<h1>Hello {user_name}</h1>"
- response.write("<div>" + comment + "</div>")
- Markup(user_input)  # marking raw input as safe

SECURE FIX: HTML-escape all user input before rendering.
- from markupsafe import escape; return f"<h1>Hello {escape(user_name)}</h1>"
- Use template engine auto-escaping (Jinja2 autoescape=True)
- Use bleach.clean() for rich text that needs some HTML

RULES:
- Return ONLY the fixed code
- Escape output, not input (output encoding)
- Use the framework's built-in escaping
"""
    },

    "csrf": {
        "category": "Web",
        "system_prompt": """You are fixing a Cross-Site Request Forgery (CSRF) vulnerability.

PATTERN TO FIND: State-changing endpoints (POST/PUT/DELETE) without CSRF token validation.
Examples:
- @app.route('/transfer', methods=['POST']) with no CSRF check
- Forms without csrf_token hidden field

SECURE FIX: Add CSRF protection middleware/decorators.
- Flask: from flask_wtf.csrf import CSRFProtect; csrf = CSRFProtect(app)
- Django: ensure {% csrf_token %} in forms, CsrfViewMiddleware enabled
- Add @csrf_protect decorator to views

RULES:
- Return ONLY the fixed code
- Add CSRF token to forms and validate on server
"""
    },

    "open_redirect": {
        "category": "Web",
        "system_prompt": """You are fixing an Open Redirect vulnerability.

PATTERN TO FIND: Unvalidated URL from user input used in redirect.
Examples:
- return redirect(request.args.get('next'))
- response.headers['Location'] = user_url

SECURE FIX: Validate redirect URL against a whitelist of allowed domains/paths.
- from urllib.parse import urlparse
- parsed = urlparse(redirect_url)
- if parsed.netloc and parsed.netloc != request.host: abort(400)
- Only allow relative paths or known trusted domains

RULES:
- Return ONLY the fixed code
- Validate both scheme and netloc
- Default to a safe fallback URL
"""
    },

    "xxe": {
        "category": "Web",
        "system_prompt": """You are fixing an XML External Entity (XXE) vulnerability.

PATTERN TO FIND: XML parsing with external entity processing enabled.
Examples:
- etree.parse(xml_input)  # default allows XXE
- xml.sax.parseString(data)  # default allows XXE
- DocumentBuilderFactory without disabling external entities

SECURE FIX: Disable external entity processing in the XML parser.
- from defusedxml import ElementTree; ElementTree.parse(xml_input)
- Or: parser = etree.XMLParser(resolve_entities=False, no_network=True)
- Or: parser.setFeature(xml.sax.handler.feature_external_ges, False)

RULES:
- Return ONLY the fixed code
- Use defusedxml when available
- Disable DTD processing, external entities, and network access
"""
    },

    # ══════════════════════════════════════════════════════════════
    # FILE & DATA
    # ══════════════════════════════════════════════════════════════

    "path_traversal": {
        "category": "File & Data",
        "system_prompt": """You are fixing a Path Traversal vulnerability.

PATTERN TO FIND: User input used directly in file paths without validation.
Examples:
- open(f"/data/{user_filename}")
- os.path.join(base_dir, request.args['file'])  # join doesn't prevent ../

SECURE FIX: Validate that the resolved path stays within the base directory.
- real_path = os.path.realpath(os.path.join(base_dir, filename))
- if not real_path.startswith(os.path.realpath(base_dir)): raise ValueError
- Use os.path.basename() to strip directory components

RULES:
- Return ONLY the fixed code
- Always resolve to absolute path before checking
- Reject paths containing .. or starting with /
"""
    },

    "insecure_deserialization": {
        "category": "File & Data",
        "system_prompt": """You are fixing an Insecure Deserialization vulnerability.

PATTERN TO FIND: pickle.loads(), yaml.load(), or marshal.loads() on untrusted data.
Examples:
- data = pickle.loads(request.data)
- config = yaml.load(user_yaml)

SECURE FIX: Use safe alternatives.
- Use json.loads() instead of pickle for data interchange
- Use yaml.safe_load() instead of yaml.load()
- If pickle is required, use hmac signing to verify integrity

RULES:
- Return ONLY the fixed code
- Never unpickle untrusted data
- Use JSON or safe_load for configuration
"""
    },

    "arbitrary_file_upload": {
        "category": "File & Data",
        "system_prompt": """You are fixing an Arbitrary File Upload vulnerability.

PATTERN TO FIND: File upload without MIME type or extension validation.
Examples:
- file.save(os.path.join(upload_dir, file.filename))
- No check on file extension or content type

SECURE FIX: Validate file extension against a whitelist, rename with secure random name.
- ALLOWED = {'.jpg', '.png', '.pdf', '.txt'}
- ext = os.path.splitext(filename)[1].lower()
- if ext not in ALLOWED: abort(400)
- secure_name = f"{uuid.uuid4().hex}{ext}"

RULES:
- Return ONLY the fixed code
- Whitelist allowed extensions
- Rename files to prevent path traversal via filename
"""
    },

    "log_injection": {
        "category": "File & Data",
        "system_prompt": """You are fixing a Log Injection vulnerability.

PATTERN TO FIND: Raw user input written directly to log output.
Examples:
- logger.info(f"User logged in: {username}")
- logging.warning("Failed login for: " + user_input)

SECURE FIX: Sanitize log input by stripping newlines and control characters.
- sanitized = username.replace('\\n', '').replace('\\r', '').replace('\\t', '')
- logger.info("User logged in: %s", sanitized)
- Use structured logging (logger.info("login", extra={"user": sanitized}))

RULES:
- Return ONLY the fixed code
- Strip \\n, \\r, \\t, and other control characters
- Use parameterized logging (logger.info("%s", var) not f-strings)
"""
    },

    # ══════════════════════════════════════════════════════════════
    # AUTH & CRYPTO
    # ══════════════════════════════════════════════════════════════

    "hardcoded_secrets": {
        "category": "Auth & Crypto",
        "system_prompt": """You are fixing a Hardcoded Secrets vulnerability.

PATTERN TO FIND: API keys, passwords, or tokens hardcoded as string literals.
Examples:
- API_KEY = "sk-abc123def456"
- password = "admin123"
- DB_CONNECTION = "postgresql://user:pass@host/db"

SECURE FIX: Use environment variables loaded at runtime.
- import os; API_KEY = os.getenv("API_KEY")
- Or use python-dotenv: from dotenv import load_dotenv; load_dotenv()
- Add the key name to .env.example (without the actual value)

RULES:
- Return ONLY the fixed code
- Replace literal values with os.getenv() calls
- Add a sensible default or raise error if env var missing
"""
    },

    "weak_hashing": {
        "category": "Auth & Crypto",
        "system_prompt": """You are fixing a Weak Hashing vulnerability.

PATTERN TO FIND: MD5 or SHA1 used for password hashing.
Examples:
- hashlib.md5(password.encode()).hexdigest()
- hashlib.sha1(password.encode()).hexdigest()

SECURE FIX: Use bcrypt, argon2, or PBKDF2 for password hashing.
- import bcrypt; hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
- Or: from hashlib import pbkdf2_hmac
- Or: from argon2 import PasswordHasher

RULES:
- Return ONLY the fixed code
- Use a proper password hashing algorithm with salt
- Update both hash creation and verification code
"""
    },

    "broken_jwt_auth": {
        "category": "Auth & Crypto",
        "system_prompt": """You are fixing a Broken JWT Authentication vulnerability.

PATTERN TO FIND: JWT verification disabled or using weak settings.
Examples:
- jwt.decode(token, options={"verify_signature": False})
- jwt.decode(token, verify=False)
- jwt.decode(token, algorithms=["none"])

SECURE FIX: Enable full JWT verification with strong algorithm.
- jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
- Ensure verify_signature, verify_exp, verify_aud are all True
- Use RS256 with public/private key pair for production

RULES:
- Return ONLY the fixed code
- Enable all verification options
- Use HS256 or RS256, never "none"
"""
    },

    "weak_randomness": {
        "category": "Auth & Crypto",
        "system_prompt": """You are fixing a Weak Randomness vulnerability.

PATTERN TO FIND: random module used for security-sensitive values.
Examples:
- token = str(random.randint(100000, 999999))
- session_id = ''.join(random.choices(string.ascii_letters, k=32))

SECURE FIX: Use the secrets module for cryptographically secure random values.
- import secrets; token = secrets.token_hex(32)
- session_id = secrets.token_urlsafe(32)
- otp = secrets.randbelow(1000000)

RULES:
- Return ONLY the fixed code
- Replace random.* with secrets.* for any security-sensitive value
- Keep random.* for non-security uses (e.g., shuffling UI elements)
"""
    },

    # ══════════════════════════════════════════════════════════════
    # CODE & CONFIG
    # ══════════════════════════════════════════════════════════════

    "insecure_eval": {
        "category": "Code & Config",
        "system_prompt": """You are fixing an Insecure eval/exec vulnerability.

PATTERN TO FIND: eval() or exec() called on user-controlled input.
Examples:
- result = eval(user_expression)
- exec(request.form['code'])

SECURE FIX: Use ast.literal_eval for safe evaluation, or refactor to avoid eval entirely.
- import ast; result = ast.literal_eval(user_expression)
- For math: use a safe math parser library
- For config: use JSON/YAML parsing instead

RULES:
- Return ONLY the fixed code
- Never eval/exec untrusted input
- ast.literal_eval only works for literals (strings, numbers, lists, dicts)
"""
    },

    "debug_mode_in_prod": {
        "category": "Code & Config",
        "system_prompt": """You are fixing a Debug Mode in Production vulnerability.

PATTERN TO FIND: debug=True hardcoded in application configuration.
Examples:
- app.run(debug=True)
- DEBUG = True
- FLASK_DEBUG = 1

SECURE FIX: Control debug mode via environment variable.
- import os; debug = os.getenv("FLASK_DEBUG", "false").lower() == "true"
- app.run(debug=debug)
- DEBUG = os.getenv("DEBUG", "false").lower() == "true"

RULES:
- Return ONLY the fixed code
- Default to debug=False (safe default)
- Use environment variable for control
"""
    },

    "overly_permissive_cors": {
        "category": "Code & Config",
        "system_prompt": """You are fixing an Overly Permissive CORS vulnerability.

PATTERN TO FIND: Access-Control-Allow-Origin set to * (wildcard).
Examples:
- response.headers['Access-Control-Allow-Origin'] = '*'
- CORS(app, origins='*')
- @cross_origin(origin='*')

SECURE FIX: Restrict to known trusted origins.
- ALLOWED_ORIGINS = os.getenv("CORS_ORIGINS", "https://app.example.com").split(",")
- CORS(app, origins=ALLOWED_ORIGINS)
- Validate Origin header against whitelist

RULES:
- Return ONLY the fixed code
- Use environment variable for allowed origins list
- Never use wildcard with credentials
"""
    },

    "missing_security_headers": {
        "category": "Code & Config",
        "system_prompt": """You are fixing Missing Security Headers.

PATTERN TO FIND: HTTP responses without security headers (CSP, HSTS, X-Frame-Options, etc.).

SECURE FIX: Add security headers via middleware or response decorator.
- Content-Security-Policy: default-src 'self'
- Strict-Transport-Security: max-age=31536000; includeSubDomains
- X-Content-Type-Options: nosniff
- X-Frame-Options: DENY
- X-XSS-Protection: 1; mode=block

For Flask: use flask-talisman
For Django: use SecurityMiddleware (built-in)

RULES:
- Return ONLY the fixed code
- Add all recommended security headers
- Use framework-specific middleware when available
"""
    },

    # ══════════════════════════════════════════════════════════════
    # RESOURCE & MEMORY
    # ══════════════════════════════════════════════════════════════

    "buffer_overflow": {
        "category": "Resource & Memory",
        "system_prompt": """You are fixing a Buffer Overflow vulnerability (C/C++).

PATTERN TO FIND: Unbounded string copy or buffer operations.
Examples:
- strcpy(dest, src);  // no bounds checking
- sprintf(buf, "%s", user_input);
- gets(buffer);

SECURE FIX: Use bounded alternatives.
- strncpy(dest, src, sizeof(dest) - 1); dest[sizeof(dest) - 1] = '\\0';
- snprintf(buf, sizeof(buf), "%s", user_input);
- fgets(buffer, sizeof(buffer), stdin);

RULES:
- Return ONLY the fixed code
- Always null-terminate after strncpy
- Use sizeof for buffer sizes
"""
    },

    "use_after_free": {
        "category": "Resource & Memory",
        "system_prompt": """You are fixing a Use After Free vulnerability (C/C++).

PATTERN TO FIND: Pointer used after memory has been freed.
Examples:
- free(ptr); ... use(ptr);
- delete obj; obj->method();

SECURE FIX: Set pointer to NULL after free, use smart pointers in C++.
- free(ptr); ptr = NULL;
- Use std::unique_ptr or std::shared_ptr in C++
- Check for NULL before use

RULES:
- Return ONLY the fixed code
- NULL pointer after every free/delete
- Use smart pointers when possible (C++)
"""
    },

    "integer_overflow": {
        "category": "Resource & Memory",
        "system_prompt": """You are fixing an Integer Overflow vulnerability (C/C++).

PATTERN TO FIND: Arithmetic operations without overflow checking.
Examples:
- size_t total = count * element_size;  // can overflow
- int result = a + b;  // can overflow if a,b are large

SECURE FIX: Add bounds checking before arithmetic.
- if (count > SIZE_MAX / element_size) { error(); }
- Use __builtin_mul_overflow() on GCC/Clang
- Check result range before assignment

RULES:
- Return ONLY the fixed code
- Check before the operation, not after
- Use compiler built-ins when available
"""
    },

    "redos": {
        "category": "Resource & Memory",
        "system_prompt": """You are fixing a ReDoS (Regular Expression Denial of Service) vulnerability.

PATTERN TO FIND: Regex patterns with catastrophic backtracking.
Examples:
- re.match(r"(a+)+$", user_input)  # nested quantifiers
- re.search(r"(.*a){10}", data)     # exponential backtracking
- Pattern with overlapping alternations and quantifiers

SECURE FIX: Rewrite the regex to avoid backtracking.
- Use atomic groups or possessive quantifiers where supported
- Simplify nested quantifiers: (a+)+ -> a+
- Set a timeout: re.match(pattern, text, timeout=1.0) (Python 3.11+)
- Consider using re2 library for guaranteed linear-time matching

RULES:
- Return ONLY the fixed code
- Eliminate nested quantifiers
- Add input length validation as defense in depth
"""
    },
}


def get_fix_template(vuln_type: str) -> dict:
    """Get the fix template for a given vulnerability type. Returns empty dict if not found."""
    return FIX_TEMPLATES.get(vuln_type, {})


def get_system_prompt(vuln_type: str) -> str:
    """Get the system prompt for a given vulnerability type."""
    template = get_fix_template(vuln_type)
    if template:
        return template['system_prompt']
    # Generic fallback prompt for unknown vulnerability types
    return f"""You are fixing a {vuln_type} vulnerability.

Analyze the vulnerable code, understand the security issue, and generate a minimal targeted fix.
Follow secure coding best practices for this type of vulnerability.

RULES:
- Return ONLY the fixed function/code block
- Preserve all existing functionality
- Do not change function signatures
- Use the most secure approach available in the language
"""


def list_supported_types() -> list:
    """Return list of all supported vulnerability types."""
    return list(FIX_TEMPLATES.keys())
