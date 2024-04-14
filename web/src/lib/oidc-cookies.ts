import type { AstroCookies } from "astro";
import { Cookie } from "./Cookie";
import { jwtDecode } from "jwt-decode";
import type { CookieSerializeOptions } from "cookie";
import { CryptoSuite } from "./crypto";

const ALGORITHM = import.meta.env.OIDC_REFRESH_TOKEN_ALGORITHM;
const KEY = Buffer.from(import.meta.env.OIDC_REFRESH_TOKEN_KEY, "latin1");

class BaseCookie extends Cookie {
    constructor(cookies: AstroCookies, name: string, options?: CookieSerializeOptions) {
        super(cookies, name, {
            sameSite: "lax",
            httpOnly: true,
            secure: true,
            path: "/",
            ...options,
        });
    }
}

export class AuthStateCookie extends BaseCookie {
    constructor(cookies: AstroCookies) {
        super(cookies, "auth-state");
    }
}

export class AccessTokenCookie extends BaseCookie {
    constructor(cookies: AstroCookies) {
        super(cookies, "access-token");
    }

    override set(value: string, overrides?: Pick<CookieSerializeOptions, "expires" | "maxAge">) {
        const jwt = jwtDecode(value);
        super.set(value, {
            expires: getExpiry(jwt),
            ...overrides,
        });
    }
}

export class RefreshTokenCookie extends BaseCookie {
    readonly #crypto: CryptoSuite;

    constructor(cookies: AstroCookies) {
        super(cookies, "refresh-token");
        this.#crypto = new CryptoSuite(ALGORITHM, KEY);
    }

    override value() {
        try {
            const value = super.value();
            return value ? this.#crypto.decrypt(value) : value;
        } catch (err) {
            console.error("invalid cookie:", err);
            return undefined;
        }
    }

    override set(value: string, overrides?: Pick<CookieSerializeOptions, "expires" | "maxAge">) {
        const jwt = jwtDecode(value);
        super.set(this.#crypto.encrypt(value), {
            expires: getExpiry(jwt),
            ...overrides,
        });
    }
}

function getExpiry({ exp }: { exp?: number }): Date | undefined {
    return exp ? new Date(1000 * exp) : undefined;
}
