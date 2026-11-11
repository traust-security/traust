from mcp.server.auth.settings import AuthSettings
from mcp.server.fastmcp import FastMCP

# Auth configured on the server: the kwarg exclusion, not the file-scope one.
mcp = FastMCP(
    "orders",
    auth=AuthSettings(issuer_url="https://idp.example", resource_server_url="https://mcp.example"),
)

# ok: traust-python-llm-application-mcp-http-without-auth
mcp.run(transport="streamable-http")
