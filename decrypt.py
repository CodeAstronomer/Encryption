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
    key = input("Enter your encryption key: ").encode('utf-8')
    encrypted_hex = input("Enter encrypted text (hex): ")
    encrypted_bytes = bytes.fromhex(encrypted_hex)

    decrypted_data = key_stream_xor(encrypted_bytes, key, device, 10**6)

    decrypted_text = decrypted_data.cpu().numpy().tobytes().decode('utf-8', errors='replace')
    print("\n--- Decrypted Output ---")
    print(decrypted_text)

if __name__ == "__main__":
    main()
