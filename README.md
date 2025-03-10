## PASSWORD MANAGER
- Create a vault
    - [hash of master] | [salt] | [nonce] | [cipher_text]
    - Create a vault in '.local'
    - Get the master password
    - Generate a random salt
    - Hash the (master password + salt --> key) 
    - Generate a random nonce
    - JSON the cipher text (empty passwords JSON)
    - Use the generated key to create a new AES instance with the generated nonce AES.MODE_GCM
    - HASH the master password
    - Write to vault
