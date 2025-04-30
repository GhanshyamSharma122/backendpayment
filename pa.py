import requests
import uuid
import hashlib
import json

BASE_URL = "http://localhost:3000"

def prompt_user_info(who):
    print(f"\n=== Enter {who} info ===")
    username    = input("Username: ").strip()
    email       = input("Email: ").strip()
    phone       = input("Phone number: ").strip()
    password    = input("Password: ").strip()
    first_name  = input("First name: ").strip()
    last_name   = input("Last name: ").strip()
    dob         = input("Date of birth (YYYY-MM-DD): ").strip()
    return {
        "username": username,
        "email": email,
        "phone_number": phone,
        "password": password,
        "first_name": first_name,
        "last_name": last_name,
        "date_of_birth": dob
    }

def register(user):
    r = requests.post(f"{BASE_URL}/api/auth/register", json=user)
    r.raise_for_status()
    return r.json()["user"]

def login(identifier, password):
    r = requests.post(f"{BASE_URL}/api/auth/login", json={
        "identifier": identifier,
        "password":  password
    })
    r.raise_for_status()
    data = r.json()
    return data["token"]

def online_payment(token, sender_id, recipient_id, amount):
    payload = {
        "sender_id": sender_id,
        "recipient_id": recipient_id,
        "amount": amount,
        "currency": "INR",
        "description": "Test online payment",
        "transaction_type": "TEST",
        "timestamp":    __import__("datetime").datetime.utcnow().isoformat() + "Z"
    }
    r = requests.post(
        f"{BASE_URL}/api/payment/initiate",
        headers={"Authorization": f"Bearer {token}"},
        json=payload
    )
    r.raise_for_status()
    return r.json()

def offline_sync(token, sender_id, recipient_identifier, amount):
    # fake local_transaction_id + encrypted_data (hash of fields)
    local_tx_id = str(uuid.uuid4())
    record = {
        "local_transaction_id": local_tx_id,
        "recipient_identifier": recipient_identifier,
        "amount": amount,
        "currency": "INR",
        "timestamp": __import__("datetime").datetime.utcnow().isoformat() + "Z",
    }
    # compute a simple HMAC-like signature for dedupe
    sig_str = f"{sender_id}|{recipient_identifier}|{amount}|INR|{record['timestamp']}"
    record["encrypted_data"] = hashlib.sha256(sig_str.encode()).hexdigest()

    payload = {
        "user_id": sender_id,
        "device_id": str(uuid.uuid4()),
        "transactions": [record]
    }
    r = requests.post(
        f"{BASE_URL}/api/offline/sync",
        headers={"Authorization": f"Bearer {token}"},
        json=payload
    )
    r.raise_for_status()
    return r.json()

def fetch_transactions(token):
    r = requests.get(
        f"{BASE_URL}/api/transactions",
        headers={"Authorization": f"Bearer {token}"}
    )
    r.raise_for_status()
    return r.json()

def main():
    # 1) Register two users
    sender_info   = prompt_user_info("SENDER")
    receiver_info = prompt_user_info("RECEIVER")

    print("\nRegistering users…")
    sender   = register(sender_info)
    receiver = register(receiver_info)
    print(f" → Sender ID:   {sender['id']}")
    print(f" → Receiver ID: {receiver['id']}")

    # 2) Login as sender
    print("\nLogging in as sender…")
    token = login(sender_info["username"], sender_info["password"])
    print(" → JWT token acquired.")

    # 3) Online payment
    amt_online = float(input("\nEnter amount to pay ONLINE: "))
    print("Performing online payment…")
    online_resp = online_payment(token, sender["id"], receiver["id"], amt_online)
    print("Online payment response:")
    print(json.dumps(online_resp, indent=2))

    # 4) Offline transaction
    amt_offline = float(input("\nEnter amount to pay OFFLINE: "))
    print("Syncing offline payment…")
    offline_resp = offline_sync(token, sender["id"], receiver_info["username"], amt_offline)
    print("Offline sync response:")
    print(json.dumps(offline_resp, indent=2))

    # 5) Fetch all transactions
    print("\nFetching full transaction history…")
    history = fetch_transactions(token)
    print(json.dumps(history, indent=2))

if __name__ == "__main__":
    main()
