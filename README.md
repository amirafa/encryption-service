<p align="center">
  <a href='https://postimages.org/' target='_blank'>
    <img 
      src='https://i.postimg.cc/mrBJJjMJ/Encryption-Service-logo.png'       
      width="250" 
      height="250"  
      border='0' 
      alt='vuexp-logo'
    />
  </a>
</p>

# Encryption Service

A lightweight library to use E2EE

## 🚀 Installation

### From npm
```bash
npm install @amirafa/encryption-service
```

### From yarn
```bash
yarn add @amirafa/encryption-service
```

### From pnpm
```bash
pnpm add @amirafa/encryption-service
```

---

## 🧩 Import and Usage

```ts
import { EncryptionService } from "@amirafa/encryption-service";

const enc = EncryptionService();

// generate user keys
await enc.generateAndStoreIdentityKeyPair("alice");
await enc.generateAndStoreECDHKeyPair("alice");

// example: encrypt and decrypt a message
const alicePriv = await enc.importPrivateKey(localStorage.getItem("alice-privateKey")!);
const bobPub = await enc.importPublicKey(localStorage.getItem("bob-publicKey")!);

const sharedKey = await enc.deriveSharedKey(alicePriv, bobPub);

const { encryptedMessage, iv } = await enc.encryptMessageAES("Hello Bob!", sharedKey);
const plain = await enc.decryptMessageAES(encryptedMessage, sharedKey, iv);

console.log(plain); // "Hello Bob!"
```

---

# Full Flow & Backend Schema

This document describes how the `EncryptionServiceClass` implements **end-to-end encryption (E2EE)** for a secure chat system and how the **backend** should store and handle related data.

---

## 🧩 Architecture Overview

The system uses three cryptographic layers:

1. **ECDSA (Identity)** — for signing and verifying identity keys.  
2. **ECDH (Shared Key)** — for deriving a mutual secret key between two users.  
3. **AES-GCM (Message Encryption)** — for encrypting and decrypting messages.

All encryption/decryption logic happens **in the browser (client-side)**.  
The backend only stores **public keys**, **signatures**, and **encrypted data** — never plaintext or private keys.

---

## 🧱 Function Reference (Client-Side)

### `generateAndStoreIdentityKeyPair(username)`
Generates an **ECDSA key pair** (identity keys) and stores both in `localStorage`.

```ts
await enc.generateAndStoreIdentityKeyPair("alice");
```

Stored keys:
```
alice-id-publicKey
alice-id-privateKey
```

---

### `generateAndStoreECDHKeyPair(username)`
Generates an **ECDH key pair** for secure message key exchange.

```ts
await enc.generateAndStoreECDHKeyPair("alice");
```

Stored keys:
```
alice-publicKey
alice-privateKey
```

---

### `signEcdhPublicKey(identityPriv, ecdhPub)`
Signs the ECDH public key using the identity private key (ECDSA).

```ts
const sig = await enc.signEcdhPublicKey(aliceIdPriv, aliceEcdhPub);
```

---

### `verifyEcdhPublicKeySignature(identityPub, ecdhPub, signature)`
Verifies that an ECDH public key truly belongs to a given identity.

```ts
const ok = await enc.verifyEcdhPublicKeySignature(bobIdPub, bobEcdhPub, sig);
```

---

### `deriveSharedKey(privateKey, publicKey)`
Derives a shared AES key using your **private ECDH key** and the other user’s **public ECDH key**.

```ts
const aesKey = await enc.deriveSharedKey(alicePrivEcdh, bobPubEcdh);
```

Both sides independently derive **the same AES key**.

---

### `encryptMessageAES(message, aesKey)`
Encrypts a plaintext message using AES-GCM.

```ts
const { encryptedMessage, iv } = await enc.encryptMessageAES("Hello Bob", aesKey);
```

`iv` (Initialization Vector) must be sent along with the ciphertext.

---

### `decryptMessageAES(encryptedMessage, aesKey, iv)`
Decrypts a message using the same AES key and IV.

```ts
const plain = await enc.decryptMessageAES(encryptedMessage, aesKey, iv);
```

---

### `getIdentityFingerprint(identityPub)`
Generates a SHA-256 fingerprint of an identity key for display and manual verification (TOFU).

```ts
const fpr = await enc.getIdentityFingerprint(aliceIdentityPub);
console.log("Alice fingerprint:", fpr);
```

---

## 🧭 Full Message Exchange Flow

### 1️⃣ Key Generation (first time only)
```ts
await enc.generateAndStoreIdentityKeyPair("alice");
await enc.generateAndStoreECDHKeyPair("alice");

await enc.generateAndStoreIdentityKeyPair("bob");
await enc.generateAndStoreECDHKeyPair("bob");
```

---

### 2️⃣ Alice signs her ECDH key
```ts
const idPriv = await enc.importIdentityPrivateKey(localStorage.getItem("alice-id-privateKey")!);
const ecdhPub = await enc.importPublicKey(localStorage.getItem("alice-publicKey")!);
const signature = await enc.signEcdhPublicKey(idPriv, ecdhPub);

const alicePackage = {
  identityPublicKey: localStorage.getItem("alice-id-publicKey")!,
  ecdhPublicKey: localStorage.getItem("alice-publicKey")!,
  signature
};
```
Alice sends this JSON package to Bob via the server.

---

### 3️⃣ Bob verifies Alice’s identity
```ts
const aliceIdPub = await enc.importIdentityPublicKey(alicePackage.identityPublicKey);
const aliceEcdhPub = await enc.importPublicKey(alicePackage.ecdhPublicKey);
const valid = await enc.verifyEcdhPublicKeySignature(aliceIdPub, aliceEcdhPub, alicePackage.signature);
if (!valid) throw new Error("Fake Alice detected!");
```

---

### 4️⃣ Both derive the shared AES key
```ts
const bobPriv = await enc.importPrivateKey(localStorage.getItem("bob-privateKey")!);
const sharedKey = await enc.deriveSharedKey(bobPriv, aliceEcdhPub);
```

Both parties now hold the same symmetric AES key.

---

### 5️⃣ Alice encrypts and sends the message
```ts
const { encryptedMessage, iv } = await enc.encryptMessageAES("Hi Bob!", sharedKey);
const chatEntry = {
  sender: "alice",
  recipient: "bob",
  message: Array.from(new Uint8Array(encryptedMessage)),
  iv: Array.from(iv)
};
// send chatEntry to server
```

---

### 6️⃣ Bob receives and decrypts
```ts
const msgBuf = new Uint8Array(chatEntry.message).buffer;
const ivBuf = new Uint8Array(chatEntry.iv);
const plain = await enc.decryptMessageAES(msgBuf, sharedKey, ivBuf);
console.log("Decrypted:", plain); // "Hi Bob!"
```

---

## 🗄 Recommended Database Schema (Backend)

### Users Table
```ts
{
  username: string,
  identityPublicKey: string,
  ecdhPublicKey: string,
  signature: string
}
```

### Messages Table
```ts
{
  sender: string,
  recipient: string,
  message: number[],
  iv: number[]
}
```

---

## 💾 SQL Implementation Example

### `users`
```sql
CREATE TABLE users (
  id SERIAL PRIMARY KEY,
  username VARCHAR(50) UNIQUE NOT NULL,
  identity_public_key TEXT NOT NULL,
  ecdh_public_key TEXT NOT NULL,
  signature TEXT NOT NULL,
  created_at TIMESTAMP DEFAULT NOW()
);
```

### `messages`
```sql
CREATE TABLE messages (
  id SERIAL PRIMARY KEY,
  sender VARCHAR(50) NOT NULL,
  recipient VARCHAR(50) NOT NULL,
  message BYTEA NOT NULL,
  iv BYTEA NOT NULL,
  created_at TIMESTAMP DEFAULT NOW(),
  FOREIGN KEY (sender) REFERENCES users(username),
  FOREIGN KEY (recipient) REFERENCES users(username)
);
```

---

## 🔄 Example API Flow

### Client → Server (Send Message)
```json
{
  "sender": "alice",
  "recipient": "bob",
  "message": "BASE64_ENCRYPTED_DATA",
  "iv": "BASE64_IV"
}
```

### Server → Client (Retrieve Message)
```json
{
  "sender": "alice",
  "message": "BASE64_ENCRYPTED_DATA",
  "iv": "BASE64_IV"
}
```

### Client Decrypts
```ts
const msg = await enc.decryptMessageAES(
  base64ToArrayBuffer(message),
  aesKey,
  base64ToUint8Array(iv)
);
console.log(msg); // "Hello Bob!"
```

---

## 🔒 Security Notes

- The server stores **only public keys** and **encrypted data**.  
- **Private keys and plaintext** never leave the user’s device.  
- Messages must be delivered **only to their intended recipient**.  
- The backend is **zero-knowledge** — even a data leak reveals nothing readable.

---

## ✅ Summary

| Component             | Responsibility              | Location |
| --------------------- | --------------------------- | -------- |
| ECDSA                 | Identity and signature      | Client   |
| ECDH                  | Shared key derivation       | Client   |
| AES-GCM               | Message encryption/decryption | Client |
| Key & message storage | Persistence only            | Backend  |
| Plaintext visibility  | Sender & recipient devices only | — |

---

## 🧾 License

MIT © 2025 — Encryption Service by Amirafa  
Feel free to use, modify, and distribute under the terms of the MIT license.

---

## Changelog

### [Version 1.0.4] - 2025-10-26

-   Add `logo`

### [Version 1.0.3] - 2025-10-26

-   Add `type declaration`
-   Update `README.md`

### [Version 1.0.2] - 2025-10-26

-   Add `README.md`

### [Version 1.0.1] - 2025-10-26

-   Minor `fixes`

### [Version 1.0.0] - 2025-10-26

-   published `@amirafa/encryption-service`