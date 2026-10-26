# Clean fixture: secrets come from the environment at runtime,
# never as literals in this file.
import os
from getpass import getpass

token = None
secret = os.environ.get("APP_SECRET")
password = getpass("Password: ")


def connect():
    return os.environ.get("DATABASE_URL")
