import html
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse

test_app = FastAPI(title="Harness Testbed Server")

@test_app.get("/secure", response_class=HTMLResponse)
async def secure_page(q: str = "", test: str = ""):
    safe_q = html.escape(q)
    return f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Secure Testbed</title>
</head>
<body>
    <h1>Secure Web Application</h1>
    <p>Search query: <span id="output">{safe_q}</span></p>
    <a href="https://example.com/safe">Safe Link</a>
</body>
</html>
"""

@test_app.get("/vulnerable", response_class=HTMLResponse)
async def vulnerable_page(q: str = "", redirect: str = ""):
    # Deliberate vulnerability: raw unescaped reflection in HTML body
    raw_reflection = q
    # Deliberate vulnerability: unvalidated javascript: link
    dangerous_link = redirect if redirect else "javascript:alert('xss')"

    return f"""<!DOCTYPE html>
<html>
<head>
    <title>Vulnerable Testbed</title>
</head>
<body>
    <h1>Vulnerable Application</h1>
    <div id="results">User query: {raw_reflection}</div>
    <a id="bad-link" href="{dangerous_link}">Click Here</a>
    <script>
        // Deliberate eval usage for V1.3.2 detection
        var x = "123";
        eval("var dynamic = " + x);
    </script>
</body>
</html>
"""

@test_app.get("/ssti_vulnerable", response_class=HTMLResponse)
async def ssti_vulnerable_page(template: str = "", q: str = "", search: str = ""):
    val = template or q or search
    rendered = "49" if ("7*7" in val) else html.escape(val)
    return f"""<!DOCTYPE html>
<html>
<head><title>SSTI Vulnerable</title></head>
<body>
    <h1>SSTI Testbed</h1>
    <div id="template-output">{rendered}</div>
</body>
</html>
"""

@test_app.get("/ssti_secure", response_class=HTMLResponse)
async def ssti_secure_page(template: str = "", q: str = "", search: str = ""):
    val = template or q or search
    return f"""<!DOCTYPE html>
<html>
<head><title>SSTI Secure</title></head>
<body>
    <h1>SSTI Secure Testbed</h1>
    <div id="template-output">{html.escape(val)}</div>
</body>
</html>
"""

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(test_app, host="127.0.0.1", port=8001)
