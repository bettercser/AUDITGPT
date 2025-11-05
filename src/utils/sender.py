import requests

class Sender:
    """
    A tool class for sending HTTP requests, used for PoC validation.
    Can handle different processing based on vulnerability type, such as regular requests and file uploads.
    """

    def __init__(self, base_url="http://localhost:8080"):
        """
        Initialize Sender.
        :param base_url: Base URL of the target application.
        """
        self.base_url = base_url
        self.session = requests.Session()

    def send_poc_request(self, api, method, params, vuln_type, files=None):
        """
        Send request based on PoC information.

        :param api: API path to request, e.g., "/api/v1/getUser"
        :param method: HTTP method, e.g., "POST", "GET"
        :param params: Request parameters (dict)
        :param vuln_type: Vulnerability type, e.g., "sql_injection", "file_upload"
        :param files: File dictionary for file upload, e.g., {'file': ('test.txt', b'content')}
        :return: response object or error information
        """
        url = self.base_url + api
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }

        try:
            print(f"[*] Preparing to send PoC request to: {url}")
            print(f"[*] Method: {method}, Parameters: {params}, Vulnerability type: {vuln_type}")

            if vuln_type == "file_upload":
                if not files:
                    return {"error": "File upload vulnerability requires providing files."}
                print(f"[*] Executing file upload...")
                response = self.session.post(url, files=files, data=params, headers=headers)
            else:
                if method.upper() == 'GET':
                    response = self.session.get(url, params=params, headers=headers)
                elif method.upper() == 'POST':
                    # Send POST request based on common Content-Type
                    if any(p in vuln_type for p in ["json", "xml"]):
                         response = self.session.post(url, json=params, headers=headers)
                    else:
                         response = self.session.post(url, data=params, headers=headers)
                else:
                    return {"error": f"Unsupported HTTP method: {method}"}
            
            response.raise_for_status()  # If request fails (status code 4xx or 5xx), raise exception
            
            print(f"[+] Request successful, status code: {response.status_code}")
            # For demonstration, we only return status code and partial text
            return {
                "status_code": response.status_code,
                "text": response.text[:200] # Avoid returning overly long response
            }

        except requests.exceptions.RequestException as e:
            print(f"[!] Request failed: {e}")
            return {"error": str(e)}

# Example usage
if __name__ == '__main__':
    sender = Sender(base_url="http://httpbin.org") # Use httpbin for testing
    
    # Test regular GET request
    print("\n--- Testing GET request ---")
    get_params = {'userId': '123', 'userAge': '25'}
    sender.send_poc_request('/get', 'GET', get_params, 'sql_injection')

    # Test regular POST request
    print("\n--- Testing POST request ---")
    post_params = {'userName': "' OR 1=1 --"}
    sender.send_poc_request('/post', 'POST', post_params, 'sql_injection')

    # Test file upload request
    print("\n--- Testing file upload request ---")
    upload_files = {'file': ('poc.txt', b'this is the exploit content')}
    upload_data = {'description': 'a test file'}
    sender.send_poc_request('/post', 'POST', upload_data, 'file_upload', files=upload_files)
