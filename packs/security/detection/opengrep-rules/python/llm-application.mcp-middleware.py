from mcp.server.fastmcp import FastMCP
from starlette.middleware.authentication import AuthenticationMiddleware

mcp = FastMCP("orders")

# ok: traust-python-llm-application-mcp-http-without-auth
app = mcp.streamable_http_app()
app.add_middleware(AuthenticationMiddleware, backend=BearerTokenBackend())
