import requests

api_token = None

def set_api_token(token):
    global api_token
    api_token = token

def get_api_token():
    return api_token

def get_rate_limit_status():
    if not api_token:
        raise ValueError("API token is not set")
    
    url = "https://api.blockcypher.com/v1/btc/main"
    headers = {
        "Authorization": f"Bearer {api_token}"
    }
    response = requests.get(url, headers=headers)
    
    if response.status_code == 200:
        return response.headers.get("X-RateLimit-Remaining")
    else:
        response.raise_for_status()
