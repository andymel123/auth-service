package eu.andymel.authservicespring.jwt;

import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Arrays;
import java.util.Date;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import java.util.stream.Collectors;

import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

/**
 *  from http://www.svlada.com/jwt-token-authentication-with-spring-boot/#ajax-authentication
 * Factory class that should be always used to create {@link JwtToken}.
 * 
 * @author vladimir.stankovic
 *
 * May 31, 2016
 */
@Component
public class JwtTokenFactory {
    private final JwtSettings settings;

    @Autowired
    public JwtTokenFactory(JwtSettings settings) {
    	Objects.requireNonNull(settings, "need settings for JWTTokenFactory");
        this.settings = settings;
    }

    public AccessJwtToken createAccessJwtToken(Authentication authenticationData) {
        
    	if (StringUtils.isBlank(authenticationData.getName())) 
            throw new IllegalArgumentException("Cannot create JWT Token without username");

        if (authenticationData.getAuthorities() == null || authenticationData.getAuthorities().isEmpty()) 
            throw new IllegalArgumentException("User doesn't have any privileges");

        Claims claims = Jwts.claims().setSubject(authenticationData.getName());
        claims.put("scopes", authenticationData.getAuthorities().stream().map(s -> s.toString()).collect(Collectors.toList()));

        LocalDateTime currentTime = LocalDateTime.now();
        
        String token = Jwts.builder()
          .setClaims(claims)
          .setIssuer(settings.getTokenIssuer())
          .setIssuedAt(Date.from(currentTime.atZone(ZoneId.systemDefault()).toInstant()))
          .setExpiration(Date.from(currentTime
              .plusMinutes(settings.getTokenExpirationTime())
              .atZone(ZoneId.systemDefault()).toInstant()))
          .signWith(SignatureAlgorithm.HS512, settings.getTokenSigningKey())
        .compact();

        return new AccessJwtToken(token, claims);
    }

	public JwtToken createRefreshToken(Authentication authenticationData) {
        if (StringUtils.isBlank(authenticationData.getName())) {
            throw new IllegalArgumentException("Cannot create JWT Token without username");
        }

        LocalDateTime currentTime = LocalDateTime.now();

        Claims claims = Jwts.claims().setSubject(authenticationData.getName());
        claims.put("scopes", Arrays.asList(Scopes.REFRESH_TOKEN.authority()));
        
        String token = Jwts.builder()
          .setClaims(claims)
          .setIssuer(settings.getTokenIssuer())
          .setId(UUID.randomUUID().toString())
          .setIssuedAt(Date.from(currentTime.atZone(ZoneId.systemDefault()).toInstant()))
          .setExpiration(Date.from(currentTime
              .plusMinutes(settings.getRefreshTokenExpTime())
              .atZone(ZoneId.systemDefault()).toInstant()))
          .signWith(SignatureAlgorithm.HS512, settings.getTokenSigningKey())
        .compact();

        return new AccessJwtToken(token, claims);
    }
	
    private String getUserNameFromAuthenticationData(Authentication authenticationData) {
    	if(authenticationData instanceof OAuth2Authentication) {
			OAuth2Authentication a = (OAuth2Authentication)authenticationData;
			Object det = a.getUserAuthentication().getDetails();
			if(det instanceof Map) {
				Map<?,?> details = (Map<?, ?>) ((OAuth2Authentication) authenticationData).getUserAuthentication().getDetails();

				/*
				 * TODO  add token value extractor per provider!
				 */
				
				String name = asString(details, "name");
				if(name == null || name.equals("null")) {
					name = asString(details, "sub");
				}
				if(name == null || name.equals("null")) {
					assert false: "TODO";
				}
				return name;
			}
		}else {
			assert false:"need oauth as authentication to generate a JWT at the moment!";
		}
    	return "NO_NAME";
	}


    private String asString(Map<?, ?> details, String key) {
		Object o = details.get(key);
		if(o==null)return "null";
		return o.toString();
	}
    

}
