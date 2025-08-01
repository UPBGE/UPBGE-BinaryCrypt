# UPBGE BinaryCrypt

UPBGE BinaryCrypt is a dual-tool system for encrypting and decrypting `.blend` files used in UPBGE games.

- `upbge_binarycrypt_tool/`: Raylib-based GUI to encrypt game data
- `upbge_binarycrypt_launcher/`: headless binary to decrypt and launch the game

## 🔧 Build Instructions

### Linux
```bash
sudo apt install build-essential cmake pkg-config libraylib-dev libgl1-mesa-dev openssl
cmake -B build
cmake --build build
