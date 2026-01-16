import os
from utils.util import is_valid_url

url = input("Enter URL: ")

if is_valid_url(url):
    print("Valid URL")
else:
    print("Invalid URL")