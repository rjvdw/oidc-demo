package dev.rdcl.api;

import io.quarkus.security.identity.SecurityIdentity;
import jakarta.annotation.security.RolesAllowed;
import jakarta.inject.Inject;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import lombok.extern.slf4j.Slf4j;
import org.eclipse.microprofile.jwt.JsonWebToken;
import org.jboss.resteasy.annotations.cache.NoCache;

import java.security.Principal;

@Slf4j
@Path("/hello")
public class HelloResource {

    @Inject
    SecurityIdentity securityIdentity;

    @GET
    @Produces("text/plain")
    @RolesAllowed("USER")
    @NoCache
    public String hello() {
        Principal principal = securityIdentity.getPrincipal();
        log.info("identity: {}", principal);

        return "Hello, %s!".formatted(getName(principal));
    }

    private String getName(Principal principal) {
        String name = null;
        if (principal != null) {
            if (principal instanceof JsonWebToken jwt) {
                name = jwt.getClaim("nickname");
                if (name == null) {
                    name = jwt.getSubject();
                }
            }
            if (name == null) {
                name = principal.getName();
            }
        }
        if (name == null) {
            name = "World";
        }
        return name;
    }
}
