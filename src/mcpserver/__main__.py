# from mcpserver.git_clone_mcp_server import mcp
from mcpserver.syft_mcp_server import mcp
from mcpserver.grype_mcp_server import mcp
from mcpserver.vuln_manage_mcp_server import mcp
from mcpserver.dashboard_mcp_server import mcp

def main():
    mcp.run()
    
if __name__ == "__main__":
    main()