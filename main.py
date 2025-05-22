import os
import sqlite3
import yaml # PyYAML
import requests # Vulnerable version
from fastapi import FastAPI, Request, HTTPException, Query
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

app = FastAPI()

# --- Setup for Demonstrations ---

# For XSS Demo with Jinja2 (vulnerable version)
templates = Jinja2Templates(directory="templates")

# For SQL Injection Demo
DB_NAME = "vulnerable_app.db"

def init_db():
    if os.path.exists(DB_NAME):
        os.remove(DB_NAME) # Fresh start for demo
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("""
    CREATE TABLE items (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        description TEXT
    )
    """)
    cursor.execute("INSERT INTO items (name, description) VALUES (?, ?)", ("Pen", "A blue pen"))
    cursor.execute("INSERT INTO items (name, description) VALUES (?, ?)", ("Book", "A history book"))
    cursor.execute("INSERT INTO items (name, description) VALUES (?, ?)", ("SecretKey", "admin_only_data"))
    conn.commit()
    conn.close()

init_db() # Initialize the database on startup

# --- Vulnerable Endpoints ---

@app.get("/", response_class=HTMLResponse)
async def read_root():
    return """
    <html>
        <head><title>Vulnerable FastAPI App</title></head>
        <body>
            <h1>Welcome to the Intentionally Vulnerable FastAPI App</h1>
            <p>This app demonstrates common coding mistakes and vulnerable dependencies for educational purposes.</p>
            <p><strong>DO NOT USE THIS IN PRODUCTION.</strong></p>
            <ul>
                <li><a href="/docs">Swagger UI / OpenAPI Docs</a></li>
                <li><a href="/debug_info_hardcoded_secret">Hardcoded Secret Example</a></li>
                <li><a href="/greet_xss?name=<script>alert('XSS')</script>">XSS Example (Reflected)</a></li>
                <li><a href="/items_sqli?name=' OR '1'='1">SQL Injection Example</a></li>
                <li><a href="/user_profile/1">Excessive Data Exposure Example</a></li>
                <li><a href="/load_config_yaml?data=!!python/object/apply:os.system%0A- ls">Unsafe YAML Deserialization</a></li>
                <li><a href="/get_file?filename=../main.py">Path Traversal Example</a></li>
                <li><a href="/check_external_service">Using Outdated 'requests' Library</a></li>
            </ul>
        </body>
    </html>
    """

@app.get("/debug_info_hardcoded_secret")
async def hardcoded_secret():
    # MISTAKE: Hardcoding sensitive information
    # This 'secret_key' might be an API key, password, or encryption key.
    # It should be loaded from environment variables or a secure vault.
    secret_key = "THIS_IS_A_VERY_SECRET_KEY_12345"
    return {"message": "Debug information", "internal_key_hint": f"The key starts with: {secret_key[:10]}..."}

@app.get("/greet_xss", response_class=HTMLResponse)
async def greet_xss(request: Request, name: str = "Guest"):
    # MISTAKE: Reflected Cross-Site Scripting (XSS)
    # User input 'name' is directly embedded into the HTML template without sanitization.
    # Jinja2 (especially older versions) might not auto-escape by default in all contexts
    # or custom configurations might disable it.
    # Try: /greet_xss?name=<script>alert('XSS Vulnerability!')</script>
    return templates.TemplateResponse("vulnerable_page.html", {"request": request, "name": name})

@app.get("/items_sqli")
async def search_items_sqli(name: str = Query(None, description="Item name to search for")):
    # MISTAKE: SQL Injection
    # User input 'name' is directly concatenated into an SQL query.
    # This allows an attacker to manipulate the query.
    # Try: /items_sqli?name=' OR '1'='1
    # Try: /items_sqli?name='; SELECT sql FROM sqlite_master; --
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    # VULNERABLE CODE:
    query = f"SELECT id, name, description FROM items WHERE name LIKE '%{name}%'"
    # A safer way would be to use parameterized queries:
    # query = "SELECT id, name, description FROM items WHERE name LIKE ?"
    # cursor.execute(query, ('%' + name + '%',))
    
    try:
        cursor.execute(query)
        items = cursor.fetchall()
    except sqlite3.Error as e:
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")
    finally:
        conn.close()
    
    if not items and name:
        return {"message": f"No items found matching '{name}'."}
    return {"found_items": items}

class UserInternal(BaseModel):
    user_id: int
    username: str
    email: str
    hashed_password: str # Sensitive
    role: str
    last_login_ip: str # Sensitive

@app.get("/user_profile/{user_id}")
async def get_user_profile(user_id: int):
    # MISTAKE: Returning Excessive Data / Lack of Data Filtering
    # This endpoint returns all user data, including sensitive fields like
    # 'hashed_password' and 'last_login_ip', which should not be exposed.
    
    # Simulating fetching a user from a database
    if user_id == 1:
        user_data = UserInternal(
            user_id=1,
            username="alice",
            email="alice@example.com",
            hashed_password="supersecretbcryptedorwhateverhashvalue",
            role="admin",
            last_login_ip="192.168.1.100"
        )
        return user_data # Returns the whole UserInternal model
    raise HTTPException(status_code=404, detail="User not found")

@app.post("/load_config_yaml")
async def load_config_yaml(data: str = Query(..., description="YAML data to load")):
    # MISTAKE: Unsafe Deserialization with PyYAML
    # PyYAML's yaml.load() is unsafe if used with untrusted input, as it can
    # execute arbitrary code. Always use yaml.safe_load().
    # The PyYAML version in requirements.txt (5.1) is known for this.
    # Try sending a POST request with `data` payload like:
    # !!python/object/apply:os.system ['touch /tmp/yaml_exploited']
    # (URL encoded: !!python/object/apply:os.system%0A-%20ls)
    try:
        # VULNERABLE CODE:
        config = yaml.load(data, Loader=yaml.FullLoader) # FullLoader is also unsafe, like default Loader
        # SAFER: config = yaml.safe_load(data)
        return {"message": "Config loaded (unsafely!)", "config_data": config}
    except Exception as e:
        return {"error": f"Failed to load YAML: {str(e)}"}

@app.get("/get_file")
async def get_file_path_traversal(filename: str):
    # MISTAKE: Path Traversal / Directory Traversal
    # User input 'filename' is used to construct a file path without proper sanitization.
    # An attacker can use '..' to navigate to other directories.
    # Try: /get_file?filename=../main.py
    # Try: /get_file?filename=../../../../etc/passwd (on Linux/macOS if permissions allow)
    
    base_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "safe_files"))
    requested_path = os.path.abspath(os.path.join(base_path, filename))

    # VULNERABLE CHECK (insufficient):
    # A more robust check would ensure requested_path still starts with base_path AFTER normalization.
    if not requested_path.startswith(base_path):
         raise HTTPException(status_code=400, detail="Invalid filename (attempted traversal outside safe_files).")

    if os.path.isfile(requested_path):
        return FileResponse(requested_path)
    else:
        raise HTTPException(status_code=404, detail="File not found or invalid path.")

@app.get("/check_external_service")
async def check_external_service():
    # VULNERABILITY: Using an outdated dependency (requests==2.18.0)
    # Older versions of libraries can have known security vulnerabilities (CVEs).
    # While this specific call might not directly exploit a CVE in `requests 2.18.0`
    # in a simple GET, using outdated dependencies is a major risk.
    # Always keep dependencies updated and monitor for CVEs.
    try:
        response = requests.get("https://httpbin.org/get", timeout=5)
        response.raise_for_status() # Raise an exception for bad status codes
        return {"message": "Successfully connected to external service.", "response_data": response.json()}
    except requests.exceptions.RequestException as e:
        return {"error": f"Could not connect to external service using outdated requests: {str(e)}"}

if __name__ == "__main__":
    import uvicorn
    print("Starting vulnerable FastAPI app. REMEMBER: THIS IS FOR EDUCATIONAL PURPOSES ONLY.")
    uvicorn.run(app, host="0.0.0.0", port=8000)