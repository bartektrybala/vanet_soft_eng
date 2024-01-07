## Client

To spawn a node client with PEM public key

```sh
python3 client.py --pk public_key1.pem
```

Or the following command which will autmoatically read the necessary keys from pre-made folders:

```shell
python3 client.py --pki 1
```

The folders to look for key files and the key files' formats
are defined by constants in `settings.py`.
