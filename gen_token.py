#!/usr/bin/env python3
"""Generate a PentAGI API token and create a flow via GraphQL."""
import hashlib
import hmac
import json
import base64
import os
import time
import subprocess
import urllib.request
import ssl

# ========== Configuration ==========
COOKIE_SALT = "7ab5decba2d052d54dee0ac0acd8d6ed3d379f0f3ba49c4cb3f6f5636e016997"
USER_ID = 1
ROLE_ID = 1
USER_HASH = "dbf11376fbe80f16d1b75ca7a76ff8e2"
TTL = 86400 * 30  # 30 days
BASE62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

# ========== Step 1: Generate Token ID ==========
token_id = "".join(BASE62[ord(os.urandom(1)) % 62] for _ in range(10))
print(f"Token ID: {token_id}")

# ========== Step 2: Derive JWT signing key ==========
# password = "4c1e9cb77df7f9a58fcc5f52d40af685|{globalSalt}|09784e190148d13d48885aa47cf8a297"
password = "|".join([
    "4c1e9cb77df7f9a58fcc5f52d40af685",
    COOKIE_SALT,
    "09784e190148d13d48885aa47cf8a297",
]).encode("utf-8")
# salt = "pentagi.jwt.signing|{globalSalt}"
salt = ("pentagi.jwt.signing|" + COOKIE_SALT).encode("utf-8")
# PBKDF2 with SHA-512, 210000 iterations, 32 bytes
signing_key = hashlib.pbkdf2_hmac("sha512", password, salt, 210000, 32)
print(f"Signing key derived: {signing_key.hex()[:16]}...")

# ========== Step 3: Create JWT (HS256) ==========
def b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

header = {"alg": "HS256", "typ": "JWT"}
now = int(time.time())
claims = {
    "tid": token_id,
    "rid": ROLE_ID,
    "uid": USER_ID,
    "uhash": USER_HASH,
    "exp": now + TTL,
    "iat": now,
    "sub": "api_token",
}

header_b64 = b64url(json.dumps(header, separators=(",", ":")).encode())
payload_b64 = b64url(json.dumps(claims, separators=(",", ":")).encode())
signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
signature = hmac.new(signing_key, signing_input, hashlib.sha256).digest()
jwt_token = f"{header_b64}.{payload_b64}.{b64url(signature)}"
print(f"JWT Token: {jwt_token[:50]}...")

# ========== Step 4: Insert token into database ==========
sql = (
    f"INSERT INTO api_tokens (token_id, user_id, role_id, name, ttl, status) "
    f"VALUES ('{token_id}', {USER_ID}, {ROLE_ID}, 'mixed-deploy-{int(time.time())}', {TTL}, 'active');"
)
result = subprocess.run(
    ["docker", "exec", "pgvector", "psql", "-U", "postgres", "-d", "pentagidb", "-c", sql],
    capture_output=True, text=True
)
print(f"DB insert: {result.stdout.strip()}")
if result.returncode != 0:
    print(f"DB error: {result.stderr.strip()}")
    exit(1)

# Verify
result = subprocess.run(
    ["docker", "exec", "pgvector", "psql", "-U", "postgres", "-d", "pentagidb", "-c",
     f"SELECT id, token_id, name, status FROM api_tokens WHERE token_id='{token_id}';"],
    capture_output=True, text=True
)
print(f"DB verify:\n{result.stdout}")

# ========== Step 5: Create flow via GraphQL ==========
graphql_query = """
mutation CreateFlow($provider: String!, $input: String!) {
  createFlow(modelProvider: $provider, input: $input) {
    id
    title
    status
    createdAt
  }
}
"""

variables = {
    "provider": "custom",
    "input": "对 http://172.17.0.1:8080 进行 DVWA 渗透测试，默认账号 admin/password，评估 SQL 注入与 XSS。范围只读不破坏。交付中文报告。"
}

body = json.dumps({"query": graphql_query, "variables": variables}).encode("utf-8")

req = urllib.request.Request(
    "https://localhost:8443/api/v1/graphql",
    data=body,
    headers={
        "Authorization": f"Bearer {jwt_token}",
        "Content-Type": "application/json",
    },
)

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

try:
    with urllib.request.urlopen(req, context=ctx, timeout=120) as resp:
        result = json.loads(resp.read().decode("utf-8"))
        print(f"\n=== Flow Creation Result ===")
        print(json.dumps(result, indent=2, ensure_ascii=False))
except urllib.error.HTTPError as e:
    body = e.read().decode("utf-8", errors="replace")
    print(f"\nHTTP Error {e.code}: {body}")
except Exception as e:
    print(f"\nError: {e}")
