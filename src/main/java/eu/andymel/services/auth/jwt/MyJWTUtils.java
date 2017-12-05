package eu.andymel.services.auth.jwt;

import io.jsonwebtoken.Jwts;

public class MyJWTUtils {
    public static final String SECRET = "SecretKeyToGenJWTs";
    public static final int EXPIRATION_TIME = 5*60*1000; // 5 min
    public static final boolean USE_PREFIX = false;
    public static final String TOKEN_PREFIX = "Bearer ";
    public static final String COOKIE_STRING = "access_token";

    public static final String USER_DATA_URL = "/user";
	
    
    
    public static String getNameFromJWTTokenString(String accessToken) {
		try {
	    	String name = Jwts.parser()
	                .setSigningKey(SECRET.getBytes())
	                .parseClaimsJws(accessToken.replace(TOKEN_PREFIX, ""))
	                .getBody()
	                .getSubject();
			return name;
		}catch(Exception e) {
			throw new RuntimeException("Can't parse jwt token '"+accessToken+"'", e);
		}
	}
}