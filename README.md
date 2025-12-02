# GPU-Accelerated XOR Encryption/Decryption

This project demonstrates a simple symmetric XOR encryption and decryption scheme that leverages PyTorch for potential GPU acceleration. It allows users to encrypt and decrypt text messages using a shared secret key, with the computationally intensive key stream generation benefiting from GPU capabilities (Apple Silicon's MPS or NVIDIA's CUDA) or falling back to CPU.

## Features

- **Symmetric Encryption/Decryption:** Uses a single shared key for both encryption and decryption.
- **Key Derivation:** The encryption key is securely hashed using SHA256 to seed a pseudo-random number generator (PRNG).
- **Pseudo-random Key Stream:** A unique key stream is generated for each encryption/decryption operation based on the seed and number of iterations.
- **GPU Acceleration:** Utilizes `torch.backends.mps` (for Apple Silicon) or `torch.cuda` (for NVIDIA GPUs) for accelerated computations, if available. Falls back to CPU if no compatible GPU is found.
- **High Iteration Count:** The key stream generation involves a large number of iterations (10^6) to enhance randomness and computational complexity.

## Setup

### Prerequisites

- Python 3.8 or newer.
- `pip` (Python package installer).
- **For GPU Acceleration:**
  - **Apple Silicon (MPS):** macOS 12.3+ (Monterey) with a supported Apple M-series chip. No additional drivers are usually needed beyond system updates.
  - **NVIDIA CUDA:** Compatible NVIDIA GPU and NVIDIA drivers, along with CUDA Toolkit. Refer to the [PyTorch Get Started](https://pytorch.org/get-started/locally/) page for detailed instructions on installing CUDA for PyTorch.

### Installation

1.  **Clone the repository (if applicable) or download the files:**

    ```bash
    git clone <repository_url>
    cd py-gpu-test
    ```

2.  **Create a Python Virtual Environment:**
    It's recommended to use a virtual environment to manage project dependencies.

    ```bash
    python3 -m venv venv
    ```

3.  **Activate the Virtual Environment:**

    - **On macOS/Linux:**
      ```bash
      source venv/bin/activate
      ```

4.  **Install Dependencies:**
    This project primarily depends on PyTorch. The installation command varies based on your desired backend (CPU, CUDA, or MPS).

    - **For CPU-only:**
      ```bash
      pip install torch torchvision torchaudio --index-url https://download.pytorch.org/whl/cpu
      ```
    - **For Apple Silicon (MPS):**
      ```bash
      pip install torch torchvision torchaudio
      # PyTorch will automatically detect and use MPS on supported hardware
      ```
    - **For NVIDIA CUDA (example with CUDA 12.1):**
      ```bash
      pip install torch torchvision torchaudio --index-url https://download.pytorch.org/whl/cu121
      # Adjust 'cu121' to your CUDA version as per PyTorch documentation.
      ```

## Usage

### Encryption

Run the `encrypt.py` script, provide your secret key, and the text you wish to encrypt. The script will output the encrypted text in hexadecimal format.

```bash
python3 encrypt.py
```

**Example:**

```
Set your encryption key: mysecretkey123
Enter text to encrypt: Hello, this is a secret message!

--- Encrypted Output ---
1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b
```

_(Note: The actual output will be a much longer hexadecimal string)_

### Decryption

To decrypt, run the `decrypt.py` script. You must provide the _exact same secret key_ used for encryption and the hexadecimal encrypted text.

```bash
python3 decrypt.py
```

**Example:**

```
Enter your encryption key: mysecretkey123
Enter encrypted text (hex): 1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b

--- Decrypted Output ---
Hello, this is a secret message!
```

## How it works (Briefly)

1.  **Device Detection:** The `get_device()` function checks for MPS, then CUDA, and finally defaults to CPU.
2.  **Key to Seed:** Your provided encryption key is hashed using SHA256. The first 8 bytes of this hash are converted into an integer to serve as the seed for PyTorch's random number generator.
3.  **Key Stream Generation:** A `torch.Generator` is initialized with the seed. This generator is then used to produce a sequence of pseudo-random bytes (the key stream) with the same length as the input text, iterated `10^6` times to mix the state.
4.  **XOR Operation:** The input text (converted to a `torch.tensor` of bytes) is XORed with the generated key stream. Due to the properties of XOR, applying the same key stream twice (once for encryption, once for decryption) with the same seed and iterations will revert the text to its original form.
5.  **Output:** Encrypted text is converted to a hexadecimal string for easy handling. Decrypted text is converted back from hexadecimal and then decoded into a UTF-8 string.

## Important Note

This project is for **demonstration purposes only** and should **NOT** be used for securing sensitive or critical data in a production environment. Custom encryption schemes are often prone to vulnerabilities unless thoroughly vetted by cryptography experts. Always use well-established and peer-reviewed cryptographic libraries for real-world security needs.
