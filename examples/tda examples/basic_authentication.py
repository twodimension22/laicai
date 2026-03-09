''' An example on how to set up logging in.
Copy .env.example to .env and keep the real file untracked. You can store your
encryption password there with the following value:

tda_encryption_passcode=keep_this_key_somewhere_safe
'''

import os
from getpass import getpass

import robin_stocks.tda as t
##!!! Optionally load environment variables from .env
from dotenv import load_dotenv
load_dotenv()
keep_this_key_somewhere_safe = os.environ.get("tda_encryption_passcode")
if not keep_this_key_somewhere_safe:
    keep_this_key_somewhere_safe = getpass("TDA encryption passcode: ")
##!!!

# Generate a new passcode once with:
# keep_this_key_somewhere_safe = t.generate_encryption_passcode()
# Save it somewhere safe before using login_first_time().

#!!! Only call login_first_time once! Delete this code after running the first time!
t.login_first_time(
    keep_this_key_somewhere_safe,
    "client_id_goes_here",
    "authorization_token_goes_here",
    "refresh_token_goes_here")
#!!!

# Call login as much as you want.
t.login(os.environ["tda_encryption_passcode"])
