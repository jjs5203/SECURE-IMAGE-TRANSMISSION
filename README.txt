=========================================================
SECURE IMAGE ENCRYPTION & INTEGRITY VERIFICATION SYSTEM
=========================================================

Author      : Jiya Jay Singh

---------------------------------------------------------
1. PROJECT OVERVIEW
---------------------------------------------------------

This project implements a complete image security system using:

1. Custom C++ encryption engine
2. AES-CTR (OpenSSL) + XOR lightweight cipher
3. Base64 encoding
4. SHA-256 hashing for integrity
5. JSON packet packaging
6. Full Python-based GUI
7. PSNR + SSIM-based image similarity analysis

The system supports:

✔ Image Encryption  
✔ Image Decryption  
✔ Packet generation (JSON)  
✔ Identity & tamper detection  
✔ Visual comparison  
✔ Quality measurement (PSNR, SSIM)  
✔ Cross-platform encryption engine  
✔ A standalone .EXE GUI application  

---------------------------------------------------------
2. FILE STRUCTURE
---------------------------------------------------------

secureimage/
│
├── secure_image.cpp            (C++ Encryption/Decryption Engine)
├── secure_image.exe            (Compiled executable from C++)
│
├── GUI.py                      (Main Python GUI Code)
├── SecureImageTool.exe         (Final GUI application - PyInstaller build)
│
├── images.jpg                  (Sample input image)
├── output.png / output.jpg     (Decrypted output image)
├── packet.json                 (Generated encrypted packet)
├── integrity_report.txt        (PSNR/SSIM verification output)
│
├── psnr_ssim_test.py           (PSNR/SSIM script - optional)
└── README.txt                  (Project documentation)

---------------------------------------------------------
3. ENCRYPTION PIPELINE
---------------------------------------------------------

The image is encrypted using the following steps:

1. Read image as binary
2. Compute SHA-256 hash of original image
3. Base64 encode the image
4. Apply XOR cipher using a fixed string key
5. Generate AES key (derived from XOR key)
6. AES Encryption (AES-CTR):
    - Random IV generated using RAND_bytes()
    - Data encrypted using EVP_Encrypt*
7. Convert ciphertext → hex string
8. Store:
    - method used
    - payload_hex
    - cipher_hash (SHA-256 of ciphertext)
    - iv_hex
    - original_sha256
  Into a JSON-like text packet

This output JSON is the “encrypted packet”.

---------------------------------------------------------
4. DECRYPTION PIPELINE
---------------------------------------------------------

1. Read JSON packet
2. Extract:
   - ciphertext (hex)
   - IV
   - method
   - original hash
3. Verify ciphertext hash (detects tampering)
4. AES-CTR decrypt OR fallback to XOR-only
5. XOR reverse step
6. Base64 decode to retrieve raw image bytes
7. Save output image (.png/.jpg)
8. Compute SHA-256 of decrypted image
9. Compare with original SHA-256 stored in packet

If both hashes match → PERFECT decryption.

---------------------------------------------------------
5. INTEGRITY VERIFICATION (PSNR & SSIM)
---------------------------------------------------------

The GUI includes image similarity verification using:

1. **PSNR (Peak Signal-to-Noise Ratio)**
   - Measures pixel-level similarity
   - PSNR > 40 dB = high similarity
   - PSNR = Infinity means identical images

2. **SSIM (Structural Similarity Index)**
   - Measures structural features
   - SSIM = 1.0 means identical images

Expected results after correct decryption:

PSNR  : ~∞ or very high  
SSIM  : 1.000000  
Integrity: PASS

---------------------------------------------------------
6. GRAPHICAL USER INTERFACE (GUI)
---------------------------------------------------------

Written in Python (Tkinter), features:

- Load input image
- Encrypt to packet.json
- Decrypt packet to output image
- Auto integrity check on decryption
- Manual integrity testing tool
- Image previews (original & decrypted)
- Real-time log and status display
- Fully packaged into SecureImageTool.exe

User-friendly steps:

1. Select an input image
2. Select packet output path
3. Click "Encrypt"
4. Select packet for decryption
5. Select output image path
6. Click "Decrypt"
7. View integrity results instantly

---------------------------------------------------------
7. BUILDING & COMPILATION DETAILS
---------------------------------------------------------

C++ Compilation (MinGW-w64 with OpenSSL):

g++ secure_image.cpp -o secure_image.exe -lssl -lcrypto

Python GUI Packaging:

pyinstaller --noconsole --onefile --add-data "secure_image.exe;." GUI.py

---------------------------------------------------------
8. SAMPLE RESULTS
---------------------------------------------------------

------ INTEGRITY REPORT ------
PSNR : 361.2020 dB
SSIM : 1.000000
Integrity: PASS (Images are identical)

---------------------------------------------------------
9. IMPORTANT NOTES
---------------------------------------------------------

• AES-CTR does not require padding  
• SHA-256 ensures tamper detection  
• JSON is written in a simple text format to avoid parser issues  
• Project verified on Windows 10/11  
• Requires OpenSSL (linked statically/dynamically through MinGW)

---------------------------------------------------------
10. CONCLUSION
---------------------------------------------------------

This project successfully demonstrates:

✓ Hybrid Cryptography (AES + XOR)  
✓ Image hashing & integrity verification  
✓ Packet-based secure transport  
✓ Practical decryption with zero loss  
✓ GUI packaging into a standalone application  
✓ Academic + real-world security relevance  

This system can be extended for:

- Secure messaging  
- Secure file transport  
- Multi-layer encryption  
- Cloud-safe storage  

---------------------------------------------------------
END OF DOCUMENT
---------------------------------------------------------
