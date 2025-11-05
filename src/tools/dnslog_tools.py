import requests
from langchain.tools import tool
from typing import Dict, Any, List
from requestrepo import Requestrepo
import os

# We use a global variable to maintain session state between tool calls
# In more complex applications, consider using a class for encapsulation
SESSION_STORAGE: Dict[str, Any] = {}


def get_dnslog_subdomain():
    """
    When you need to verify an out-of-band vulnerability (such as SSRF or Log4j RCE), call this tool to get a new, temporary DNSLog subdomain.
    This tool returns a dictionary containing 'subdomain' and 'token'. You must use this subdomain to build your attack payload in subsequent steps.
    """
    global SESSION_STORAGE
    session = requests.Session()
    try:
        response = session.post("https://requestrepo.com/api/get_token", json={}, timeout=10)
        response.raise_for_status()
        data = response.json()
        subdomain = data.get("subdomain")
        token = data.get("token")
        
        if subdomain and token:
            # Store session information for check_dnslog_records to use
            SESSION_STORAGE['subdomain'] = subdomain
            SESSION_STORAGE['token'] = token
            print(f"--- [DNSLog Tool] Successfully obtained subdomain: {subdomain} and {token}---")
            
            
            return Requestrepo(token=token, host="requestrepo.com", port="443", protocol="https")
        return {"error": "API response missing subdomain or token."}
    except requests.RequestException as e:
        print(f"--- [DNSLog Tool] Error: Unable to get DNSLog subdomain: {e} ---")
        return {"error": str(e)}


def check_dnslog_records(client: Requestrepo) -> List[Dict[str, Any]]:
    """
    After executing a DNSLog-based PoC, call this tool to check if there are any DNS or HTTP records.
    You must provide the 'token' previously obtained from get_dnslog_subdomain.
    The presence of any records proves successful vulnerability exploitation.
    """
    
    try:
        records = client.get_request()
        if records:
            print(f"--- [DNSLog Tool] Successfully found {records} ---")
        else:
            print(f"--- [DNSLog Tool] No records found ---")
        return records
    except Exception as e:
        print(f"--- [DNSLog Tool] Error: Unable to check DNSLog records: {e} ---")
        return None





if __name__ == "__main__" :
    client = get_dnslog_subdomain()
    check_dnslog_records(client)