import type { APIRoute } from "astro";
import { OIDC } from "../lib/oidc";

export const GET: APIRoute = async ({ redirect, cookies }) => {
    const oidc = new OIDC(cookies);
    const url = await oidc.logout();

    return redirect(url.toString());
};
