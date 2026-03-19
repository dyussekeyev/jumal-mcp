import json
import os
import requests
from fastmcp import FastMCP

# Initialize MCP server
mcp = FastMCP("MCP-Jumal", description="Junior Malware Analyst Bridge")

# Address of our isolated Docker worker (configurable via env)
WORKER_URL = os.environ.get("WORKER_URL", "http://localhost:8000/api/v1")

# Get API key from environment variables
VT_API_KEY = os.environ.get("VT_API_KEY")

@mcp.tool()
def analyze_file_triage(file_path: str) -> str:
    """
    Performs initial triage of a malware file.
    Computes hashes (MD5, SHA1, SHA256), file size, and runs Detect It Easy (DIE) scan.
    Use this tool first to understand the nature of the file, identify packers or protectors.

    Args:
        file_path: File name or relative path inside the samples directory.
    """
    try:
        response = requests.post(
            f"{WORKER_URL}/triage",
            json={"file_path": file_path},
            timeout=60  # Timeout slightly larger than inside the worker
        )
        response.raise_for_status()
        # Return nicely formatted JSON string to the AI
        return json.dumps(response.json(), indent=2)
    except requests.exceptions.RequestException as e:
        return f"Error communicating with isolated Worker: {str(e)}"


@mcp.tool()
def extract_pe_info(file_path: str) -> str:
    """
    Performs deep analysis of PE file structure (Windows Executable, DLL).
    Extracts imphash, section count, and identifies anomalies (e.g. sections with high entropy).
    Use this if triage analysis showed it is a PE file.

    Args:
        file_path: File name or relative path inside the samples directory.
    """
    try:
        response = requests.post(
            f"{WORKER_URL}/pe-info",
            json={"file_path": file_path},
            timeout=60
        )
        response.raise_for_status()
        return json.dumps(response.json(), indent=2)
    except requests.exceptions.RequestException as e:
        return f"Error communicating with isolated Worker: {str(e)}"


@mcp.tool()
def check_virustotal(file_hash: str) -> str:
    """
    Checks file reputation by its hash (MD5, SHA-1, or SHA-256) in the VirusTotal database.
    Use this tool AFTER obtaining a hash from the analyze_file_triage tool.
    Returns antivirus detection statistics and associated tags.

    Args:
        file_hash: String containing the file hash.
    """
    if not VT_API_KEY:
        return "Error: VT_API_KEY is not configured on the server."

    headers = {
        "accept": "application/json",
        "x-apikey": VT_API_KEY
    }
    
    # Using API v3
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    
    try:
        response = requests.get(url, headers=headers, timeout=10)
        
        # If file not found on VT — this is also an important indicator (possibly APT or unique sample)
        if response.status_code == 404:
            return json.dumps({"status": "not_found", "message": "Sample not found in VirusTotal database. Possibly a zero-day threat."})
            
        response.raise_for_status()
        data = response.json().get("data", {})
        attributes = data.get("attributes", {})
        
        # Extract only the most important data to avoid overflowing the LLM context
        stats = attributes.get("last_analysis_stats", {})
        result = {
            "status": "found",
            "meaningful_name": attributes.get("meaningful_name", "Unknown"),
            "type_description": attributes.get("type_description", "Unknown"),
            "reputation_score": attributes.get("reputation", 0),
            "detections": {
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "undetected": stats.get("undetected", 0)
            },
            "popular_threat_category": [
                cat.get("value") 
                for cat in attributes.get("popular_threat_classification", {}).get("popular_threat_category", [])
            ]
        }
        
        return json.dumps(result, indent=2)

    except requests.exceptions.RequestException as e:
        return f"Error querying VirusTotal API: {str(e)}"


@mcp.tool()
def scan_yara(file_path: str) -> str:
    """
    Scans a file with a local set of YARA rules to identify known malware families,
    specific code patterns, or cryptographic constants.
    Use this tool to check a file against your organization's known signatures.

    Args:
        file_path: File name or relative path inside the samples directory.
    """
    try:
        response = requests.post(
            f"{WORKER_URL}/yara",
            json={"file_path": file_path},
            timeout=30  # YARA can take longer than standard triage when there are thousands of rules
        )
        response.raise_for_status()
        
        data = response.json()
        if data.get("error"):
            return json.dumps({"status": "error", "message": data["error"]}, indent=2)
            
        if not data.get("matches"):
            return json.dumps({"status": "clean", "message": "No YARA rules matched."}, indent=2)
            
        return json.dumps({
            "status": "matched",
            "triggered_rules": data["matches"]
        }, indent=2)

    except requests.exceptions.RequestException as e:
        return f"Error communicating with isolated Worker: {str(e)}"


@mcp.tool()
def get_strings(file_path: str, min_length: int = 4) -> str:
    """
    Extracts strings from a file using FLARE FLOSS (Mandiant) and identifies potential IOCs
    (URLs, IPs, emails, file paths) using regex filters.
    FLOSS extracts static strings, decoded strings, stack strings, and tight strings —
    far superior to basic regex-based extraction.
    Use this tool to find embedded indicators of compromise, including obfuscated strings.

    Args:
        file_path: File name or relative path inside the samples directory.
        min_length: Minimum string length to extract (default: 4).
    """
    try:
        response = requests.post(
            f"{WORKER_URL}/strings",
            json={"file_path": file_path, "min_length": min_length},
            timeout=180
        )
        response.raise_for_status()
        return json.dumps(response.json(), indent=2)
    except requests.exceptions.RequestException as e:
        return f"Error communicating with Worker: {str(e)}"


if __name__ == "__main__":
    # The .run() method by default starts the server in stdio mode (standard input/output),
    # which is the standard for interaction with desktop clients (e.g., Claude Desktop).
    mcp.run()
