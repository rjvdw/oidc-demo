# OIDC demo

This project showcases a Astro application with a Quarkus backend using OIDC for authentication.
To run this project the following steps are needed:

1. Set up an identity provider such as for example Keycloak
2. Configure a client within this identity provider
3. Create a `.env` file in the api directory, using `.env.example` as a template
4. Create a `.env` file in the web directory, using `.env.example` as a template
5. Start the backend: `cd api; quarkus dev` or `cd api; mvn compile quarkus:dev`
6. Run `npm install`
7. Start the frontend: `cd web; npm run dev`

You can now visit the frontend in your browser using the URL that was printed by `npm run dev`.
If you log in, you should be redirected to the login page of your identity provider.
After logging in, you will be redirected back to `/login` where your login will be completed.
