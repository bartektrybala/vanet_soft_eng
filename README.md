## Client

To spawn a node client with PEM public key

```sh
python3 client.py --pk public_key1.pem
```

Or the following command which will read the public
key file from the folder `keys` called `public_key1.pem`.

```shell
python3 client.py --pki 1
```
The folder to look for the public key file and the filename's format
are defined by constants `KEYS_FOLDER` and `KEYFILE_FORMAT` in `settings.py`.
