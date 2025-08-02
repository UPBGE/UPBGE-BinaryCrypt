# UPBGE BinaryCrypt

UPBGE BinaryCrypt is a dual-tool system for encrypting and decrypting `.blend` files allowing a secure deployment of UPBGE games.
This system complies with the GPL license of UPBGE/Blender and, at the same time, avoids exposing the encryption password, 
thus providing a way to protect .blend files in games, should the game developer choose to do so.

It includes the option to generate a password at compile time, which is very useful for offline games, or alternatively, 
the ability to retrieve the password from an online source.

- `upbge_binarycrypt_tool/`: Raylib-based GUI to encrypt game data
- `upbge_binarycrypt_launcher/`: headless binary to decrypt and launch the game

**⚠️ WARNING: These are the expected features but are not yet implemented. Once the project reaches a sufficient level of maturity
for its intended purpose, I will remove this warning and publish the first release.**

# 🔧 Build Instructions

### Linux
```bash
sudo apt install build-essential cmake pkg-config libraylib-dev libgl1-mesa-dev openssl
cmake -B build
cmake --build build
```

### Windows
#### 📁 Recommended project structure for Windows
```bash
Root/
    ├── Source/
    │         ├── aes/
    │         |      ├── aes.c
    │         |      └── aes.h
    |         ├── cmake/
    |         ├── upbge_binarycrypt_tool/
    │         |                         └── main.c
    |         ├── upbge_binarycrypt_launcher/
    │         |                             └── main.c
    |         ├── CMakeLists.txt
    |         ├── README.md
    |         └── .github/
    |                    └── workflows/
    |                                 └── build.yml
    ├── Libs/
    │       └── raylib-5.5_win64_msvc16/
    │                                  ├── include/
    │                                  └── lib/
    └── Build/
```
