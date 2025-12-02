#!/usr/bin/env python3
import torch
import hashlib

def get_device():
    if torch.backends.mps.is_available():
        return torch.device("mps")
    elif torch.cuda.is_available():
        return torch.device("cuda")
    else:
        return torch.device("cpu")

def key_stream_xor(text_bytes, key_bytes, device, iterations):
    sha_digest = hashlib.sha256(key_bytes).digest()
    seed = int.from_bytes(sha_digest[:8], 'big') 

    prng = torch.Generator(device=device).manual_seed(seed)

    data_tensor = torch.tensor(list(text_bytes), dtype=torch.uint8, device=device)
    for _ in range(iterations):
        rand_bytes = torch.randint(0, 256, (len(data_tensor),), dtype=torch.uint8, generator=prng, device=device)
        data_tensor = data_tensor ^ rand_bytes
    return data_tensor

def main():
    device = get_device()
    key = input("Set your encryption key: ").encode('utf-8')
    text = input("Enter text to encrypt: ").encode('utf-8')

    encrypted_data = key_stream_xor(text, key, device, 10**6)

    encrypted_hex = encrypted_data.cpu().numpy().tobytes().hex()
    print("\n--- Encrypted Output ---")
    print(encrypted_hex)

if __name__ == "__main__":
    main()
