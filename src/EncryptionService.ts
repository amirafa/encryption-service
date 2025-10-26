export interface ChatLogEntry {
    sender: string;
    recipient: string;
    message: number[];
    iv: number[];
}

export interface SignedPublicKeyPackage {
    identityPublicKey: string; // Base64 raw
    ecdhPublicKey: string; // Base64 raw
    signature: string; // Base64 ECDSA signature
}

export class EncryptionServiceClass {
    private static _instance: EncryptionServiceClass | null = null;

    public static getInstance(): EncryptionServiceClass {
        if (!this._instance) this._instance = new EncryptionServiceClass();
        return this._instance;
    }

    public static resetInstance(): void {
        this._instance = null;
    }

    public chatLog: ChatLogEntry[] = [];

    // === Base64 helpers =====================================================
    
    private normalizeBase64(input: string): string {
        if (typeof input !== "string")
            throw new Error("Expected Base64 string");
        let s = input.trim();
        const m = s.match(/^data:([^;]+);base64,(.*)$/i);
        if (m) s = m[2];
        s = s.replace(/\s+/g, "").replace(/-/g, "+").replace(/_/g, "/");
        const padLen = s.length % 4;
        if (padLen) s += "=".repeat(4 - padLen);
        return s;
    }

    public arrayBufferToBase64(buffer: ArrayBuffer): string {
        const bytes = new Uint8Array(buffer);
        let binary = "";
        for (let i = 0; i < bytes.byteLength; i++)
            binary += String.fromCharCode(bytes[i]);
        return window.btoa(binary);
    }

    public base64ToArrayBuffer(base64: string): ArrayBuffer {
        const norm = this.normalizeBase64(base64);
        const binary = window.atob(norm);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
        return bytes.buffer;
    }

    // === Identity (ECDSA) keys =============================================

    /** Generate ECDSA P-256 identity key pair and store locally */
    public async generateAndStoreIdentityKeyPair(
        username: string
    ): Promise<void> {
        const keyPair = await crypto.subtle.generateKey(
            { name: "ECDSA", namedCurve: "P-256" },
            true,
            ["sign", "verify"]
        );

        const pub = await crypto.subtle.exportKey("raw", keyPair.publicKey);
        const priv = await crypto.subtle.exportKey("pkcs8", keyPair.privateKey);

        localStorage.setItem(
            `${username}-id-publicKey`,
            this.arrayBufferToBase64(pub)
        );
        localStorage.setItem(
            `${username}-id-privateKey`,
            this.arrayBufferToBase64(priv)
        );
    }

    /** Import identity public key (Base64 raw) */
    public async importIdentityPublicKey(base64: string): Promise<CryptoKey> {
        const keyData = this.base64ToArrayBuffer(base64);
        return await crypto.subtle.importKey(
            "raw",
            keyData,
            { name: "ECDSA", namedCurve: "P-256" },
            true,
            ["verify"]
        );
    }

    /** Import identity private key (Base64 pkcs8) */
    public async importIdentityPrivateKey(base64: string): Promise<CryptoKey> {
        const keyData = this.base64ToArrayBuffer(base64);
        return await crypto.subtle.importKey(
            "pkcs8",
            keyData,
            { name: "ECDSA", namedCurve: "P-256" },
            true,
            ["sign"]
        );
    }

    /** Sign an ECDH public key using identity private key */
    public async signEcdhPublicKey(
        identityPriv: CryptoKey,
        ecdhPub: CryptoKey
    ): Promise<string> {
        const ecdhRaw = await crypto.subtle.exportKey("raw", ecdhPub);
        const sig = await crypto.subtle.sign(
            { name: "ECDSA", hash: "SHA-256" },
            identityPriv,
            ecdhRaw
        );
        return this.arrayBufferToBase64(sig);
    }

    /** Verify that signature binds ECDH key to given identity public key */
    public async verifyEcdhPublicKeySignature(
        identityPub: CryptoKey,
        ecdhPub: CryptoKey,
        signatureB64: string
    ): Promise<boolean> {
        const sig = new Uint8Array(this.base64ToArrayBuffer(signatureB64));
        const ecdhRaw = await crypto.subtle.exportKey("raw", ecdhPub);
        return await crypto.subtle.verify(
            { name: "ECDSA", hash: "SHA-256" },
            identityPub,
            sig,
            ecdhRaw
        );
    }

    /** Produce a fingerprint (SHA-256 hex) of identity public key for TOFU display */
    public async getIdentityFingerprint(
        identityPub: CryptoKey
    ): Promise<string> {
        const raw = await crypto.subtle.exportKey("raw", identityPub);
        const hash = await crypto.subtle.digest("SHA-256", raw);
        return [...new Uint8Array(hash)]
            .map((b) => b.toString(16).padStart(2, "0"))
            .join("");
    }

    // === ECDH key management ===============================================

    public async generateAndStoreECDHKeyPair(username: string): Promise<void> {
        const keyPair = await crypto.subtle.generateKey(
            { name: "ECDH", namedCurve: "P-256" },
            true,
            ["deriveKey"]
        );

        const publicKey = await crypto.subtle.exportKey(
            "raw",
            keyPair.publicKey
        );
        const privateKey = await crypto.subtle.exportKey(
            "pkcs8",
            keyPair.privateKey
        );

        localStorage.setItem(
            `${username}-publicKey`,
            this.arrayBufferToBase64(publicKey)
        );
        localStorage.setItem(
            `${username}-privateKey`,
            this.arrayBufferToBase64(privateKey)
        );
    }

    public async importPublicKey(base64Key: string): Promise<CryptoKey> {
        const keyData = this.base64ToArrayBuffer(base64Key);
        return await crypto.subtle.importKey(
            "raw",
            keyData,
            { name: "ECDH", namedCurve: "P-256" },
            true,
            []
        );
    }

    public async importPrivateKey(base64Key: string): Promise<CryptoKey> {
        const keyData = this.base64ToArrayBuffer(base64Key);
        return await crypto.subtle.importKey(
            "pkcs8",
            keyData,
            { name: "ECDH", namedCurve: "P-256" },
            true,
            ["deriveKey"]
        );
    }

    // === ECDH → AES-GCM ====================================================

    public async deriveSharedKey(
        privateKey: CryptoKey,
        publicKey: CryptoKey
    ): Promise<CryptoKey> {
        return await crypto.subtle.deriveKey(
            { name: "ECDH", public: publicKey },
            privateKey,
            { name: "AES-GCM", length: 256 },
            true,
            ["encrypt", "decrypt"]
        );
    }

    public async encryptMessageAES(
        message: string,
        aesKey: CryptoKey,
        ivKey?: Uint8Array
    ): Promise<{ encryptedMessage: ArrayBuffer; iv: Uint8Array }> {
        const iv = ivKey ?? crypto.getRandomValues(new Uint8Array(12));
        const encoded = new TextEncoder().encode(message);
        const encryptedMessage = await crypto.subtle.encrypt(
            { name: "AES-GCM", iv: iv as BufferSource },
            aesKey,
            encoded
        );
        return { encryptedMessage, iv };
    }

    public async decryptMessageAES(
        encryptedMessage: ArrayBuffer,
        aesKey: CryptoKey,
        iv: Uint8Array
    ): Promise<string> {
        const decryptedMessage = await crypto.subtle.decrypt(
            { name: "AES-GCM", iv: iv as BufferSource },
            aesKey,
            encryptedMessage
        );
        return new TextDecoder().decode(decryptedMessage);
    }

    // === Chat log ==========================================================

    public addChatEntry(entry: ChatLogEntry): void {
        this.chatLog.push(entry);
    }

    public clearChatLog(): void {
        this.chatLog = [];
    }
}

// ---- Factory wrapper ----------------------------------------------------

interface EncryptionServiceOptions {
    isolated?: boolean;
}

export function EncryptionService(
    options?: EncryptionServiceOptions
): EncryptionServiceClass {
    return options?.isolated
        ? new EncryptionServiceClass()
        : EncryptionServiceClass.getInstance();
}
