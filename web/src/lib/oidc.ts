import type { AstroCookies } from "astro";
import { AuthStateCookie, AccessTokenCookie, RefreshTokenCookie } from "./oidc-cookies";
import { jwtDecode } from "jwt-decode";

const { BASE_URL, REALM, CLIENT_ID, CLIENT_SECRET } = import.meta.env;

export type RealmConfig = {
    issuer: string;
    authorization_endpoint: string;
    token_endpoint: string;
    end_session_endpoint: string;
};

export type Tokens = {
    access_token: string;
    expires_in: number;
    refresh_expires_in: number;
    refresh_token: string;
    token_type: string;
    ["not-before-policy"]: 0;
    session_state: string;
    scope: string;
};

export class OIDC {
    readonly #authStateCookie: AuthStateCookie;
    readonly #accessTokenCookie: AccessTokenCookie;
    readonly #refreshTokenCookie: RefreshTokenCookie;
    #cachedConfig: RealmConfig | undefined = undefined;

    constructor(cookies: AstroCookies) {
        this.#authStateCookie = new AuthStateCookie(cookies);
        this.#accessTokenCookie = new AccessTokenCookie(cookies);
        this.#refreshTokenCookie = new RefreshTokenCookie(cookies);
    }

    get #accessToken(): string | undefined {
        return this.#accessTokenCookie.value();
    }

    get #refreshToken(): string | undefined {
        return this.#refreshTokenCookie.value();
    }

    get #authState(): string | undefined {
        return this.#authStateCookie.value();
    }

    /**
     * Returns per token when they will expire.
     *
     * @returns The expirations for the tokens.
     */
    getExpirations(): {
        accessToken: Date | undefined;
        refreshToken: Date | undefined;
    } {
        const at = this.#accessToken;
        const atJwt = at ? jwtDecode(at) : undefined;
        const atExp = atJwt?.exp ? new Date(atJwt.exp * 1000) : undefined;

        const rt = this.#refreshToken;
        const rtJwt = rt ? jwtDecode(rt) : undefined;
        const rtExp = rtJwt?.exp ? new Date(rtJwt.exp * 1000) : undefined;

        return {
            accessToken: atExp,
            refreshToken: rtExp,
        };
    }

    /**
     * Check if there is currently a logged in user.
     *
     * @returns If the user is logged in.
     */
    isLoggedIn(): boolean {
        return Boolean(this.#refreshToken);
    }

    /**
     * Log the user out.
     */
    async logout(): Promise<URL> {
        this.#deleteTokens();
        const config = await this.#getRealmConfig();

        const logoutUrl = new URL(config.end_session_endpoint);
        logoutUrl.searchParams.set("post_logout_redirect_uri", `${BASE_URL}/`);
        logoutUrl.searchParams.set("client_id", CLIENT_ID);

        return logoutUrl;
    }

    #deleteTokens(): void {
        this.#accessTokenCookie.delete();
        this.#refreshTokenCookie.delete();
    }

    /**
     * Returns an access token for the currently logged in user.
     *
     * @returns An access token if the user is logged in or undefined otherwise.
     */
    async getAccessToken(): Promise<string | undefined> {
        const current = this.#accessToken;
        if (current) {
            return current;
        }

        await this.refresh();

        return this.#accessToken;
    }

    /**
     * Refresh the access token.
     */
    async refresh(): Promise<void> {
        if (!this.#refreshToken) {
            return;
        }
        const request = await this.#createRefreshTokenRequest(this.#refreshToken);
        const response = await fetch(request);
        const data = await response.json();

        console.log(response);
        console.log(data);

        if (isExpiredSession(response, data)) {
            this.#deleteTokens();
            return;
        }

        if (!response.ok || !isTokens(data)) {
            throw new Error(`refreshing access token failed (status=${response.status}): ${JSON.stringify(data)}`);
        }

        this.#accessTokenCookie.set(data.access_token);
        this.#refreshTokenCookie.set(data.refresh_token);
    }

    /**
     * Trigger the next step in an OIDC login flow.
     *
     * @param params The URLSearchParams that were provided in the request.
     * @returns The URL to redirect to in order to trigger the next step in the flow.
     */
    async handleLoginFlow(params: URLSearchParams): Promise<URL | string> {
        const state = params.get("state");
        const code = params.get("code");

        return code ? this.completeLoginFlow(state, code) : this.startLoginFlow();
    }

    /**
     * Starts an OIDC login flow.
     *
     * @returns The URL to redirect to in order to start the login flow.
     */
    async startLoginFlow(): Promise<URL | string> {
        const state = generateRandomState();
        this.#authStateCookie.set(state);

        const config = await this.#getRealmConfig();

        const authUrl = new URL(config.authorization_endpoint);
        authUrl.searchParams.set("client_id", CLIENT_ID);
        authUrl.searchParams.set("response_type", "code");
        authUrl.searchParams.set("redirect_uri", `${BASE_URL}/login`);
        authUrl.searchParams.set("state", state);

        return authUrl;
    }

    /**
     * Completes an OIDC login flow.
     *
     * @param state The state that was provided by the identity provider.
     * @param code The code that was returned by the identity provider.
     * @returns The URL to redirect to where the user sees that they are now logged in.
     */
    async completeLoginFlow(state: string | null, code: string): Promise<URL | string> {
        if (state === null || state !== this.#authState) {
            throw new Error("state did not match");
        }

        const request = await this.#createAuthorizationCodeRequest(code);
        const response = await fetch(request);
        const data = await response.json();

        if (!response.ok || !isTokens(data)) {
            throw new Error(`fetching tokens failed (status=${response.status}): ${JSON.stringify(data)}`);
        }

        this.#accessTokenCookie.set(data.access_token);
        this.#refreshTokenCookie.set(data.refresh_token);

        return "/";
    }

    /**
     * Fetch the OpenID configuration for the login realm.
     *
     * @returns The OpenID configuration for the login realm.
     */
    async #getRealmConfig(): Promise<RealmConfig> {
        if (this.#cachedConfig === undefined) {
            const response = await fetch(`${REALM}/.well-known/openid-configuration`);
            const data = await response.json();
            if (!isRealmConfig(data)) {
                throw new Error("unable to retrieve realm configuration");
            }
            this.#cachedConfig = data;
        }
        return this.#cachedConfig;
    }

    /**
     * Creates a request to retrieve tokens based on an authorization code.
     *
     * @param code The code that was returned by the identity provider.
     * @returns A request to the token endpoint.
     */
    async #createAuthorizationCodeRequest(code: string): Promise<Request> {
        const config = await this.#getRealmConfig();

        const tokenUrl = new URL(config.token_endpoint);

        const body = new URLSearchParams();
        body.set("client_id", CLIENT_ID);
        body.set("client_secret", CLIENT_SECRET);
        body.set("grant_type", "authorization_code");
        body.set("code", code);
        body.set("redirect_uri", `${BASE_URL}/login`);

        return new Request(tokenUrl, {
            method: "POST",
            body,
        });
    }

    /**
     * Creates a request to retrieve tokens based on a refresh token.
     *
     * @param code The code that was returned by the identity provider.
     * @returns A request to the token endpoint.
     */
    async #createRefreshTokenRequest(refreshToken: string): Promise<Request> {
        const config = await this.#getRealmConfig();

        const tokenUrl = new URL(config.token_endpoint);

        const body = new URLSearchParams();
        body.set("client_id", CLIENT_ID);
        body.set("client_secret", CLIENT_SECRET);
        body.set("grant_type", "refresh_token");
        body.set("refresh_token", refreshToken);

        return new Request(tokenUrl, {
            method: "POST",
            body,
        });
    }
}

/**
 * Generate a random string that can be used as the state parameter.
 *
 * @returns A random string that can be used as the state parameter.
 */
function generateRandomState(): string {
    return `${Math.floor(Math.random() * 1e8)}`;
}

function isExpiredSession(response: Response, data: unknown): boolean {
    return (
        response.status === 400 &&
        data !== null &&
        typeof data === "object" &&
        "error" in data &&
        data.error === "invalid_grant" &&
        "error_description" in data &&
        data.error_description === "Session not active"
    );
}

/**
 * Check if a provided value is a valid realm configuration.
 *
 * @param value The value to check.
 * @returns Whether the value is a valid realm configuration.
 */
function isRealmConfig(value: unknown): value is RealmConfig {
    return (
        value !== null &&
        typeof value === "object" &&
        "authorization_endpoint" in value &&
        typeof value.authorization_endpoint === "string" &&
        "token_endpoint" in value &&
        typeof value.token_endpoint === "string" &&
        "end_session_endpoint" in value &&
        typeof value.end_session_endpoint === "string"
    );
}

/**
 * Check if a provided value is a valid Tokens object.
 *
 * @param value The value to check.
 * @returns Whether the value is a valid Tokens object.
 */
function isTokens(value: unknown): value is Tokens {
    return (
        value !== null &&
        typeof value === "object" &&
        "access_token" in value &&
        typeof value.access_token === "string" &&
        "refresh_token" in value &&
        typeof value.refresh_token === "string"
    );
}
