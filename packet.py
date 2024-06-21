import requests

# Send an HTTP GET request to a specific IP
response = requests.get("http://1.2.3.4")

print(f"Status Code: {response.status_code}")
print(f"Response: {response.text}")
