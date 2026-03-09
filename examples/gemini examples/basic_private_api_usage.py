''' The most basic way to use the Private API. Start from .env.example,
copy it to .env, and keep the real file untracked.
'''
import os

import robin_stocks.gemini as g
from dotenv import load_dotenv
##
ticker = "btcusd"
##
load_dotenv()
g.login(os.environ['gemini_account_key'], os.environ['gemini_account_secret'])
my_trades, error = g.get_trades_for_crypto(ticker, jsonify=True)
if error:
    print("oh my an error")
else:
    print("no errors here")
    print("trade count:", len(my_trades))
