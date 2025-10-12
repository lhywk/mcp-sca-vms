from mcpserver import git_clone
from mcpserver import syft
from mcpserver import grype
from mcpserver import vuln
from mcpserver import dashboard
from mcpserver.core import mcp

def main():
    mcp.run()

if __name__ == "__main__":
    main()
