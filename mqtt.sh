#!/bin/bash
# Simulation of AES session key exchange using RSA over MQTT

# 1. Generate RSA key pair for Bob (2048-bit for example)
openssl genpkey -algorithm RSA -out bob_private.pem -pkeyopt rsa_keygen_bits:2048
openssl rsa -in bob_private.pem -pubout -out bob_public.pem
echo "Bob's RSA key pair generated (bob_private.pem & bob_public.pem)."

# 2. Alice obtains Bob's public key (assume bob_public.pem is shared with Alice)

# 3. Alice generates a random 128-bit AES session key (16 bytes)
AES_KEY_HEX=$(openssl rand -hex 16)  # 32 hex characters
echo "Alice generated AES session key (hex): $AES_KEY_HEX"
# Save the raw binary key to a file for encryption
echo "$AES_KEY_HEX" | xxd -r -p > aes_key.bin

# 4. Alice encrypts the AES key using Bob's RSA public key
openssl rsautl -encrypt -pubin -inkey bob_public.pem -in aes_key.bin -out aes_key_encrypted.bin
# (Note: rsautl is used for simplicity; in practice RSA encryption should use padding like OAEP.)
ENC_KEY_BASE64=$(base64 < aes_key_encrypted.bin)  # encode encrypted key for transport
echo "Alice encrypts AES key with Bob's RSA public key."
echo "Encrypted AES key (Base64): $ENC_KEY_BASE64"

# 5. Alice publishes the encrypted AES key to Bob via MQTT
# (Assumes an MQTT broker is running at broker.example.com and 'mosquitto_pub' is installed)
mosquitto_pub -h broker.example.com -t "key_exchange/Bob" -m "$ENC_KEY_BASE64"
echo "Alice published encrypted AES key to MQTT topic 'key_exchange/Bob'."

# --- (At Bob's side, concurrently) ---
# Bob subscribes to the "key_exchange/Bob" topic to receive the encrypted AES key:
# mosquitto_sub -h broker.example.com -t "key_exchange/Bob" -C 1 > received_key.b64 &
# (The -C 1 option makes it exit after receiving one message)

# Simulate Bob receiving the message (in practice, the above subscriber writes to file)
RECEIVED_KEY_BASE64="$ENC_KEY_BASE64"  # (for simulation, we use the same variable)
echo "Bob received encrypted AES key: $RECEIVED_KEY_BASE64"

# Bob decodes the Base64 message and decrypts it with his RSA private key
echo "$RECEIVED_KEY_BASE64" | base64 -d > aes_key_encrypted.bin
openssl rsautl -decrypt -inkey bob_private.pem -in aes_key_encrypted.bin -out decrypted_aes_key.bin
DECRYPTED_AES_HEX=$(xxd -p decrypted_aes_key.bin)
echo "Bob decrypted AES session key (hex): $DECRYPTED_AES_HEX"
# Bob now has the same AES key that Alice generated.

# 6. Bob uses the AES key to encrypt an acknowledgment message for Alice
echo "Session OK" > ack_message.txt
openssl enc -aes-128-cbc -K "$DECRYPTED_AES_HEX" -iv 00000000000000000000000000000000 -in ack_message.txt -out ack_message.enc
# (Using a zero IV for demonstration; in practice, use a random IV and send it as well.)
ACK_MSG_BASE64=$(base64 < ack_message.enc)
echo "Bob encrypted acknowledgment with AES key. Encrypted ACK (Base64): $ACK_MSG_BASE64"

# 7. Bob publishes the encrypted ACK back to Alice via MQTT
mosquitto_pub -h broker.example.com -t "key_exchange/Alice" -m "$ACK_MSG_BASE64"
echo "Bob published encrypted ACK to MQTT topic 'key_exchange/Alice'."

# --- (Alice's side listening for ACK) ---
# Alice subscribes to "key_exchange/Alice" and receives the ACK message:
# mosquitto_sub -h broker.example.com -t "key_exchange/Alice" -C 1 > received_ack.b64

# Simulate Alice receiving the ACK (here we directly use the variable for demo)
RECEIVED_ACK_BASE64="$ACK_MSG_BASE64"
echo "Alice received encrypted ACK: $RECEIVED_ACK_BASE64"

# Alice decodes and decrypts the ACK using the shared AES key
echo "$RECEIVED_ACK_BASE64" | base64 -d > ack_message.enc
openssl enc -d -aes-128-cbc -K "$AES_KEY_HEX" -iv 00000000000000000000000000000000 -in ack_message.enc -out decrypted_ack.txt
DECRYPTED_ACK=$(cat decrypted_ack.txt)
echo "Alice decrypted the ACK message: '$DECRYPTED_ACK'"

# If the decrypted message is "Session OK", Alice knows the key exchange succeeded.
