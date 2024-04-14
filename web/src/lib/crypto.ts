import { randomBytes, createCipheriv, createDecipheriv, type Encoding, type Cipher, type Decipher } from "node:crypto";

export type CryptoOptions = {
    inputEncoding: Encoding;
    outputEncoding: Encoding;
    ivLength: number;
    separator: string;
};

const DEFAULT_OPTIONS: CryptoOptions = {
    inputEncoding: "utf8",
    outputEncoding: "base64url",
    ivLength: 16,
    separator: ".",
};

export class CryptoSuite {
    readonly #algorithm: string;
    readonly #key: Buffer;
    readonly #options: CryptoOptions;

    constructor(algorithm: string, key: Buffer, options?: Partial<CryptoOptions>) {
        this.#algorithm = algorithm;
        this.#key = key;
        this.#options = {
            ...DEFAULT_OPTIONS,
            ...options,
        };
    }

    encrypt(data: string): string {
        const iv = randomBytes(this.#options.ivLength);
        const cipher = createCipheriv(this.#algorithm, this.#key, iv);
        let ciphered = cipher.update(data, this.#options.inputEncoding, this.#options.outputEncoding);
        ciphered += cipher.final(this.#options.outputEncoding);

        const authTag = getAuthTag(cipher);
        if (authTag) {
            return this.#combine(iv, ciphered, authTag);
        } else {
            return this.#combine(iv, ciphered);
        }
    }

    decrypt(data: string): string {
        const [iv, ciphered, authTag] = this.#split(data);
        const decipher = createDecipheriv(this.#algorithm, this.#key, iv);
        setAuthTag(decipher, authTag);
        let deciphered = decipher.update(ciphered, this.#options.outputEncoding, this.#options.inputEncoding);
        deciphered += decipher.final(this.#options.inputEncoding);

        return deciphered;
    }

    #combine(iv: Buffer, ciphered: string, authTag?: Buffer): string {
        const parts: string[] = [iv.toString(this.#options.outputEncoding), ciphered];
        if (authTag) {
            parts.push(authTag.toString(this.#options.outputEncoding));
        }
        return parts.join(this.#options.separator);
    }

    #split(combined: string): [Buffer, string, Buffer | undefined] {
        const parts = combined.split(this.#options.separator);
        const iv = Buffer.from(parts[0]!, this.#options.outputEncoding);
        const ciphered = parts[1]!;
        const authTag = parts[2] ? Buffer.from(parts[2], this.#options.outputEncoding) : undefined;

        return [iv, ciphered, authTag];
    }
}

function getAuthTag(cipher: Cipher): Buffer | undefined {
    if (hasGetAuthTag(cipher)) {
        try {
            return cipher.getAuthTag();
        } catch (err) {}
    }
    return undefined;
}

function hasGetAuthTag(cipher: Cipher): cipher is Cipher & { getAuthTag: () => Buffer } {
    return "getAuthTag" in cipher;
}

function setAuthTag(decipher: Decipher, authTag: Buffer | undefined): void {
    if (hasSetAuthTag(decipher) && authTag) {
        decipher.setAuthTag(authTag);
    }
}

function hasSetAuthTag(decipher: Decipher): decipher is Decipher & { setAuthTag: (buffer: Buffer) => void } {
    return "setAuthTag" in decipher;
}
