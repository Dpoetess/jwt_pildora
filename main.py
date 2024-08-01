import jwt
import datetime
import time

SECRET_KEY = "admin"
REFRESH_SECRET_KEY = "refresh_secret"

db = {"Lynn": "1234"}

def create_access_token(username):
    payload = {
        "user_id": 1,
        "username": username,
        "exp": datetime.datetime.now(datetime.UTC) + datetime.timedelta(seconds=10)
    }
    token = jwt.encode(payload, SECRET_KEY, algorithm="HS256")
    return token

def create_refresh_token(username):
    payload = {
        "user_id": 1,
        "username": username,
        "exp": datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=7)
    }
    token = jwt.encode(payload, REFRESH_SECRET_KEY, algorithm="HS256")
    return token


def authenticate(username, password):
    if db.get(username) == password:
        access_token = create_access_token(username)
        refresh_token = create_refresh_token(username)
        return access_token, refresh_token
    else:
        return None, None

def validate_token(token):
    try:
        payload = jwt.decode(token, SECRET_KEY,algorithms=["HS256"])
        return payload
    except jwt.ExpiredSignatureError:
        return "Error: The token has expired."
    except jwt.InvalidTokenError:
        return "Error: The token is invalid."

def refresh_access_token(refresh_token):
    try:
        payload = jwt.decode(refresh_token, REFRESH_SECRET_KEY,algorithms=["HS256"])
        username = payload["username"]
        new_access_token = create_access_token(username)
        return new_access_token
    except jwt.ExpiredSignatureError:
        return "Error: The token has expired."
    except jwt.InvalidTokenError:
        return "Error: The token is invalid."


def main():
    username = input("Enter username: ")
    password = input("Enter password:")

    print("Authenticating...")
    access_token, refresh_token = authenticate(username, password)

    if access_token and refresh_token:
        print(f"Access Token: {access_token}\n")
        print(f"Access Token: {refresh_token}\n")

        print("Validating the Access Token...")
        result = validate_token(access_token)
        print(f"Result: {result}")

        print("Waiting for 10s for access token to expire...")
        time.sleep(10)

        print("Validating the expired Access Token...")
        result = validate_token(access_token)
        print(f"Result: {result}")
        time.sleep(2)

        print("Refreshing the Access Token...")
        new_access_token = refresh_access_token(refresh_token)
        print(f"New Access Token: {new_access_token}")

    else:
        print("Authentication failed. Invalid username or password.")


if __name__ == "__main__":
    main()