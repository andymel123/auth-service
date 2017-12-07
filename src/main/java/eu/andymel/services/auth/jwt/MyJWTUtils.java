package eu.andymel.services.auth.jwt;

import java.io.IOException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.ClassPathResource;

import io.jsonwebtoken.Jwts;

public class MyJWTUtils {
    public static final String SECRET = "SecretKeyToGenJWTs";
    public static final int EXPIRATION_TIME = 5*60*1000; // 5 min
    public static final boolean USE_PREFIX = false;
    public static final String TOKEN_PREFIX = "Bearer ";
    public static final String COOKIE_STRING = "access_token";	// or use OAuth2AccessToken.ACCESS_TOKEN

    public static final String USER_DATA_URL = "/user";
	
//    @Value("${jwt.key-store}")
//    private String jwtKeystore;
//
//    @Value("${jwt.keyStoreType}")
//    private String keyStoreType;
//
//    @Value("${jwt.key-store}")
//    private String jwtKeystore;
//
//    @Value("${jwt.key-store}")
//    private String jwtKeystore;

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
    
    public static Key getPrivateJWTKey() throws KeyStoreException, UnrecoverableKeyException, NoSuchAlgorithmException, CertificateException, IOException {
    	// from https://github.com/jwtk/jjwt/issues/131
    	ClassPathResource resource = new ClassPathResource("keystore.jks");
        KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
        keystore.load(resource.getInputStream(), "jkspassword".toCharArray());

        Key key = keystore.getKey("jwtkey", "keypassword".toCharArray());
        Certificate cert = keystore.getCertificate("jwtkey");
        PublicKey publicKey = cert.getPublicKey();
        return key;
    }
    
}