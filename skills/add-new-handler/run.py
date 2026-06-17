#!/usr/bin/env python3
import argparse, sys
from pathlib import Path

HANDLER_TMPL = """package {m}

import (
    "context"
    "net/http"
    "github.com/thought-machine/sso/core"
)

func Handle{name}(deps Deps, ctx context.Context, w http.ResponseWriter, r *http.Request) {{
    // 1. Bind params, 2. Validate, 3. Execute, 4. Response
    // Credential/bearer: tokenNoStoreHeaders(ctx, w) at entry
    // 401: setBearerChallenge(ctx, w, ...)
}}
"""

STORE_TMPL = """package {m}

import (
    "context"
    "time"
    "github.com/thought-machine/sso/core"
)

type {name}Store struct {{}}

func New{name}Store() *{name}Store {{ return &{name}Store{{}} }}
"""

def gen(args):
    md = {"oauth": "oauth", "oidc": "oidc", "admin": "admin", "security": "security"}[args.module]
    content = (HANDLER_TMPL if args.type == "handler" else STORE_TMPL).format(m=md, name=args.name)
    fname = f"handle_{args.name.lower()}.go"
    fp = Path(md) / fname
    if fp.exists():
        print(f"ERROR: {fp} exists", file=sys.stderr); return 1
    fp.parent.mkdir(parents=True, exist_ok=True)
    fp.write_text(content)
    print(f"Created {fp}")
    print("Next: wire in sso.go, advertise in discovery, make acceptance")
    return 0

if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--name", "-n", required=True)
    p.add_argument("--type", "-t", choices=["handler", "store"], default="handler")
    p.add_argument("--module", "-m", choices=["oauth", "oidc", "admin", "security"], default="oauth")
    p.add_argument("--description", "-d", default="")
    sys.exit(gen(p.parse_args()))
