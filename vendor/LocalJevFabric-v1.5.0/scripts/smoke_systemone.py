#!/usr/bin/env python3
from __future__ import annotations
import argparse, json, urllib.request

p = argparse.ArgumentParser()
p.add_argument('--url', default='http://127.0.0.1:8090/v1/systemone')
p.add_argument('--model', default='local-jev-fabric')
p.add_argument('--api-key')
a = p.parse_args()
body = {"model": a.model, "state": {"request": "read the project README"}, "questions": {
    "needs_tool": {"type": "noul", "instructions": "Does this request require a tool?"},
    "tool": {"type": "choice", "instructions": "Which tool is best?", "criteria": {
        "read_file": "Read a local file", "search": "Search external information", "none": "No tool"}}
}}
headers={"content-type":"application/json"}
if a.api_key: headers["authorization"] = "Bearer " + a.api_key
req=urllib.request.Request(a.url, data=json.dumps(body).encode(), headers=headers, method='POST')
with urllib.request.urlopen(req, timeout=15) as r:
    print(json.dumps(json.load(r), indent=2))
