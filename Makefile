format_all:
	black .
	isort .
	flake8 .

# [TODO] probably should be moved to a separate script
generate_keys:
	@echo "Generating keys..."
	@public_keys_dir="public_keys"; \
	private_keys_dir="private_keys"; \
	mkdir -p $$public_keys_dir; \
	mkdir -p $$private_keys_dir; \
    echo "The script will generate $(num_keys) key(s)."; \
	for i in $$(seq 1 $(num_keys)); do \
		openssl genpkey -algorithm RSA -out $$private_keys_dir/private_key_$$i.pem -pkeyopt rsa_keygen_bits:2048; \
		openssl rsa -pubout -in $$private_keys_dir/private_key_$$i.pem -out $$public_keys_dir/public_key_$$i.pem; \
	done
