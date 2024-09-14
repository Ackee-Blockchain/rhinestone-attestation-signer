# Rhinestone Attestation Signer

![horizontal splitter](https://github.com/Ackee-Blockchain/wake-detect-action/assets/56036748/ec488c85-2f7f-4433-ae58-3d50698a47de)

This repository serves the signature of Rhinestone Attestation Module Registry for attester written in Wake.

## Setup

Specify private key in the `test/test_default.py` (Replace `chain.accounts[0].private_key`).


```
data = Account.from_key(chain.accounts[0].private_key).sign(actual_hash)  
```


And run `wake test`
