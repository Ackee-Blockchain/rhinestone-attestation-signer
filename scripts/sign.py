from wake.deployment import *
from .util import sign_file


def main():
    directory = "attestations/"
    files = [
        "FirstExample.json",
        "SecondExample.json",
    ]
    acc = Account.from_alias("signer")
    for file in files:
        path = directory + file
        sign_file(path, acc)
