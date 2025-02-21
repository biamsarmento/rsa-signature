# 🔒 RSA Signature Generator/Verifier

## 📖 About the Project

This project focuses on implementing an **RSA signature generator and verifier** for files. The project is divided into three main parts:  
1. **Key Generation and RSA Encryption/Decryption**  
2. **Hybrid Encryption**  
3. **Signature Generation and Verification**  

🔗 **Reference:** [RSA - Wikipedia](https://pt.wikipedia.org/wiki/RSA_(criptografia))

## 🔑 Part I: Key Generation and RSA Encryption/Decryption

The first part implements the following functionalities:  
- **Key Generation:** Generates two large prime numbers (`p` and `q`) with at least 1024 bits.  
- **RSA Encryption/Decryption using OAEP:** Implements the RSA encryption and decryption process using the **Optimal Asymmetric Encryption Padding (OAEP)** for better security.

## 🔄 Part II: Hybrid Encryption

In this part, a hybrid encryption scheme is used:
- **AES Symmetric Encryption:** A message `M` is encrypted with an AES key `k`.  
- **Encryption Process:** The AES key `k` is then encrypted using the RSA public key, and the encrypted message is combined with the AES-encrypted message.  
  - `Enc_h(M, k) = (Enc_PK(k), AES(k, M))`

## 🧪 Part III: Signature Generation and Verification

The final part involves the implementation of the RSA signature and verification process:
### a) Signature Generation
- **Message Hashing:** The plain message is hashed using the **SHA-3** hash function.  
- **Signing the Hash:** The hash of the message is then signed using the private RSA key.  
- **Formatting:** The signature is formatted in **BASE64** encoding to include special characters and verification information.

### b) Signature Verification
- **Parsing the Signed Document:** The signed document is parsed, and the signature is decrypted using the public RSA key.  
- **Hash Verification:** The decrypted signature is compared with the hash of the file to ensure integrity.

## 📂 Project Structure

- **`rsa.py`** → RSA implementation (key generation, encryption, decryption) with OAEP.  
- **`aes.py`** → AES encryption and decryption for hybrid encryption.  
- **`signature.py`** → RSA signature generation and verification implementation.  
- **`test.py`** → Test scripts for encrypting and signing files and generating results.  
- **`results/`** → Contains encrypted files, signatures, and hash comparisons.  
- **`report.pdf`** → Detailed explanation of the cryptographic processes, results, and analysis.  

## 🛠️ Technologies Used

- **Python**  
- **NumPy (for matrix operations)**  
- **SHA-3 (for hashing)**  
- **Custom-built RSA and AES encryption (no external cryptographic libraries used for encryption)**  
- **BASE64 (for signature formatting)**  

## 🎯 Objective

The goal of this project was to **implement RSA encryption, signature generation, and verification** from scratch, ensuring the proper handling of encryption, decryption, and digital signatures. Additionally, the project uses **hybrid encryption** with RSA and AES to enhance security and analyze the effects of both encryption techniques.

## 🔧 How to Run the Project

### 📦 Cloning the Repository
```bash
git clone https://github.com/biamsarmento/rsa-signature.git
cd rsa-signature
