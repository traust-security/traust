import os
import subprocess
from pathlib import Path

import anthropic
import torch
from huggingface_hub import hf_hub_download, snapshot_download
from mcp.server.fastmcp import FastMCP
from mcp.server.sse import SseServerTransport
from openai import OpenAI
from transformers import AutoModel, AutoTokenizer, pipeline

client = OpenAI()
claude = anthropic.Anthropic()
mcp = FastMCP("orders")


def load_models(name):
    # ruleid: traust-python-llm-application-trust-remote-code
    AutoModel.from_pretrained(name, revision="3f1c2a7", trust_remote_code=True)

    # ruleid: traust-python-llm-application-trust-remote-code
    pipeline("text-classification", model=name, trust_remote_code=True)

    # ok: traust-python-llm-application-trust-remote-code
    AutoModel.from_pretrained(name, revision="3f1c2a7", trust_remote_code=False)

    # ruleid: traust-python-llm-application-unpinned-model-download
    AutoTokenizer.from_pretrained(name)

    # ok: traust-python-llm-application-unpinned-model-download
    AutoTokenizer.from_pretrained(name, revision="3f1c2a7")

    # ok: traust-python-llm-application-unpinned-model-download
    AutoTokenizer.from_pretrained("./models/tokenizer")

    # ruleid: traust-python-llm-application-unpinned-model-download
    hf_hub_download(repo_id=name, filename="adapter.bin")

    # ok: traust-python-llm-application-unpinned-model-download
    snapshot_download(repo_id=name, revision="3f1c2a7")


def load_checkpoint(path):
    # ruleid: traust-python-llm-application-unsafe-model-deserialization
    state = torch.load(path, weights_only=False)

    # ruleid: traust-python-llm-application-model-load-default-pickle
    legacy = torch.load(path)

    # ok: traust-python-llm-application-model-load-default-pickle
    # ok: traust-python-llm-application-unsafe-model-deserialization
    safe = torch.load(path, weights_only=True)
    return state, legacy, safe


def run_suggested_command(question):
    reply = client.chat.completions.create(model="m", messages=[{"role": "user", "content": question}])
    command = reply.choices[0].message.content
    # ruleid: traust-python-llm-application-output-to-shell-taint
    subprocess.run(command, shell=True)

    # ok: traust-python-llm-application-output-to-shell-taint
    subprocess.run(["uptime"])


def evaluate_formula(question):
    msg = claude.messages.create(model="m", max_tokens=100, messages=[{"role": "user", "content": question}])
    expression = msg.content[0].text
    # ruleid: traust-python-llm-application-output-to-code-exec-taint
    return eval(expression)


def ask_database(conn, question):
    reply = client.chat.completions.create(model="m", messages=[{"role": "user", "content": question}])
    sql = reply.choices[0].message.content
    # ruleid: traust-python-llm-application-output-to-sql-taint
    rows = conn.execute(sql).fetchall()

    # ok: traust-python-llm-application-output-to-sql-taint
    conn.execute("SELECT name FROM products WHERE label = ?", (sql,))
    return rows


def save_summary(question):
    reply = client.chat.completions.create(model="m", messages=[{"role": "user", "content": question}])
    filename = reply.choices[0].message.content
    # ruleid: traust-python-llm-application-output-to-path-taint
    with open(filename, "w") as fh:
        fh.write("summary")

    # ok: traust-python-llm-application-output-to-path-taint
    with open("summary.txt", "w") as fh:
        fh.write(filename)


def research(question):
    messages = [{"role": "user", "content": question}]
    # ruleid: traust-python-llm-application-unbounded-agent-loop
    while True:
        msg = client.chat.completions.create(model="m", messages=messages).choices[0].message
        if msg.content.startswith("DONE"):
            return msg.content
        messages.append({"role": "assistant", "content": msg.content})


def bounded_research(question, max_steps=8):
    messages = [{"role": "user", "content": question}]
    steps = 0
    # ok: traust-python-llm-application-unbounded-agent-loop
    while True:
        steps += 1
        if steps > max_steps:
            return None
        msg = client.chat.completions.create(model="m", messages=messages).choices[0].message
        if msg.content.startswith("DONE"):
            return msg.content


def poll_queue(queue):
    # ok: traust-python-llm-application-unbounded-agent-loop
    while True:
        item = queue.get()
        if item is None:
            return
        os.write(1, item)


def ask_via_wrapper(conn, question, complete):
    reply = complete([{"role": "user", "content": question}])
    sql = reply.choices[0].message.content.strip()
    # ruleid: traust-python-llm-application-output-to-sql-taint
    return conn.execute(sql).fetchall()


def load_with_options(path, **kwargs):
    # ok: traust-python-llm-application-model-load-default-pickle
    return torch.load(path, **kwargs)


def serve_http():
    # ruleid: traust-python-llm-application-mcp-http-without-auth
    mcp.run(transport="streamable-http")


def serve_local(transport):
    # ok: traust-python-llm-application-mcp-http-without-auth
    mcp.run()
    # ok: traust-python-llm-application-mcp-http-without-auth
    mcp.run(transport="stdio")
    # ok: traust-python-llm-application-mcp-http-without-auth
    mcp.run(transport=transport)


# ruleid: traust-python-llm-application-mcp-http-without-auth
asgi_app = mcp.sse_app()

# ruleid: traust-python-llm-application-mcp-http-without-auth
low_level_sse = SseServerTransport("/messages/")
