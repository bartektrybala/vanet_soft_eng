## Dependencies

Other than python packages and utilities needed to run `make format_all`, an installation of Python bindings to the `mcl` library is needed.

This repo uses this particular bindings implementation: [github repo](https://github.com/umberto10/mcl-python).

While there is a small chance other bindings will work, they most probably won't. There are multiple subtle differences (naming conventions, curves used, binding installation etc.) between this and other similar bindings.


## Client

To spawn a node client with PEM public key

```sh
python3 client.py --pk public_key1.pem
```

Or the following command which will autmoatically read the necessary keys from pre-made folders:

```shell
python3 client.py --pki 1
```

The folders to look for key files and the key files' formats are defined by constants in `settings.py`.
