package eu.andymel.authservicespring.jwt;

import com.fasterxml.jackson.annotation.JsonIgnore;

import io.jsonwebtoken.Claims;

/**
 * 
 * 
 * from http://www.svlada.com/jwt-token-authentication-with-spring-boot/#ajax-authentication
 *
 * Raw representation of JWT Token.
 * 
 * @author vladimir.stankovic
 *
 *         May 31, 2016
 */
public final class AccessJwtToken implements JwtToken {
    private final String rawToken;
    @JsonIgnore private Claims claims;

    protected AccessJwtToken(final String token, Claims claims) {
        this.rawToken = token;
        this.claims = claims;
    }

    @Override
	public String getToken() {
        return this.rawToken;
    }

    public Claims getClaims() {
        return claims;
    }
}
