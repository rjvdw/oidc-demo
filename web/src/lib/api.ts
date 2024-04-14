import type { OIDC } from "./oidc";

const { API_URL } = import.meta.env;

export class Api {
    readonly #oidc: OIDC;

    constructor(oidc: OIDC) {
        this.#oidc = oidc;
    }

    async getHello() {
        const request = new Request(`${API_URL}/hello`);
        const accessToken = await this.#oidc.getAccessToken();
        if (accessToken) {
            request.headers.append("Authorization", `Bearer ${accessToken}`);
        }
        return fetch(request);
    }
}
