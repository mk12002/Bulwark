"""A clean, benign MCP server used as the negative control for Airlock tests.

Plain tool descriptions, no dangerous capabilities, no secrets, no hidden unicode,
unique non-shadowing names. Airlock should report zero findings against it.

Run:  python fixtures/mcp/clean_server.py
"""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("clean-demo")


@mcp.tool()
def add_numbers(a: int, b: int) -> int:
    """Add two integers and return their sum."""
    return a + b


@mcp.tool()
def reverse_text(text: str) -> str:
    """Return the input text reversed, character by character."""
    return text[::-1]


@mcp.tool()
def word_count(text: str) -> int:
    """Count the number of whitespace-separated words in the given text."""
    return len(text.split())


if __name__ == "__main__":
    mcp.run()
