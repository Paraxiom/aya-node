import json
import time
import requests

NODE_URL = "http://127.0.0.1:9944"
QUEUE_URL = "http://127.0.0.1:5555"

def send_jsonrpc_request(url, method, params):
    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": params
    }
    response = requests.post(url, json=payload)
    return response.json()

def submit_event():
    event = {
        "id": int(time.time()),
        "data": json.dumps({
            "type": "RegistrationEvent",
            "data": {
                "user_id": "user123",
                "username": "johndoe",
                "email": "johndoe@example.com"
            }
        }),
        "timestamp": int(time.time()),
        "block_height": 1000000
    }
    priority = 10
    response = send_jsonrpc_request(QUEUE_URL, "submit_event", [event, priority])
    print("Event submission response:", response)
    return event['id']

def check_all_storage():
    # This assumes your pallet's name is 'Registration'
    prefix = "0x" + "Registration".encode().hex()
    response = send_jsonrpc_request(NODE_URL, "state_getPairs", [prefix])
    print("All storage:", json.dumps(response, indent=2))
    return response.get('result')

def main():
    event_id = submit_event()
    print(f"Submitted event with ID: {event_id}")

    max_attempts = 30
    attempt = 0
    while attempt < max_attempts:
        print(f"\nAttempt {attempt + 1}")
        try:
            all_storage = check_all_storage()
            if all_storage:
                print("Event found in storage!")
                break
        except requests.exceptions.RequestException as e:
            print(f"Error connecting to node: {e}")
        time.sleep(2)
        attempt += 1

    if attempt == max_attempts:
        print("Event processing timed out")

if __name__ == "__main__":
    main()