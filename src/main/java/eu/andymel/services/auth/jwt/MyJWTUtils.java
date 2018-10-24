package eu.andymel.services.auth.jwt;

import java.io.IOException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Base64;
import java.util.Date;
import java.util.Map;
import java.util.Set;

import javax.annotation.PostConstruct;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.ClassPathResource;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Component;

import eu.andymel.services.auth.MyAuthenticationToken;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwsHeader;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

 
@Component // to let the class be instantiated as a SpringBean (so the @Value annotations get processed)
public class MyJWTUtils {

	// TODO set in application.yml
	// could also be set dynamically based on the load of the auth service (with min/max I guess?!)
    public static final boolean USE_PREFIX = false;
    public static final String TOKEN_PREFIX = "Bearer ";
    public static final String COOKIE_STRING = "access_token";	// or use OAuth2AccessToken.ACCESS_TOKEN
    public static final String USER_DATA_URL = "/user";

    // already set in application.yml
    private static String jwtKeystore;
    private static String keyStoreType;
    private static String keyAlias;
    private static String keyStorePassword;
	private static int expirationTime = 30*60*1000; // 30 min

    // TODO hide the code that loads from application.yml in a super class
    // setting static @Values from https://www.mkyong.com/spring/spring-inject-a-value-into-static-variables/
	@Value("${jwt.key-store}")
	public void setKeystore(String s) {
		jwtKeystore = s;
	}
	@Value("${jwt.keyStoreType}")
	public void setKeyStoreType(String s) {
		keyStoreType = s;
	}
	@Value("${jwt.keyAlias}")
    public void setKeyAlias(String s) {
		keyAlias = s;
	}
	@Value("${jwt.key-store-password}")
    public void setKeyStorePassword(String s) {
		keyStorePassword = s;
	}
	@Value("${jwt.expirationTime}")
    public void setExpirationTime(int s) {
		expirationTime = s;
	}
	
	
    // cache keys in memory
    private static KeyStore jwtKeyStore = null;
    private static Key privateKey = null;
    private static PublicKey publicKey = null;

    @PostConstruct
	private void init() throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException, UnrecoverableKeyException {
    	privateKey = getPrivateJWTKey();
    	publicKey = getPublicJWTKey();
    	
    	if(privateKey==null) {
    		throw new RuntimeException("Could not load private JWT key!");
    	}
    	if(publicKey==null) {
    		throw new RuntimeException("Could not load public JWT key!");
    	}
	}

    private static Key getPrivateJWTKey() throws KeyStoreException, UnrecoverableKeyException, NoSuchAlgorithmException, CertificateException, IOException {
    
    	if(privateKey!=null) {
    		return privateKey;
    	}
    	
    	if(jwtKeyStore==null) {
    		jwtKeyStore = loadJWTKeystore();
    	}

    	Key privateKey = jwtKeyStore.getKey(keyAlias, keyStorePassword.toCharArray());
        return privateKey;
    }
    
    private static PublicKey getPublicJWTKey() throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
    	
    	if(publicKey!=null) {
    		return publicKey;
    	}
    	
    	if(jwtKeyStore==null) {
    		jwtKeyStore = loadJWTKeystore();
    	}
        
    	Certificate cert = jwtKeyStore.getCertificate(keyAlias);
        PublicKey publicKey = cert.getPublicKey();
        return publicKey;
    	
    }
    
    private static KeyStore loadJWTKeystore() throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
    	
    	// from https://github.com/jwtk/jjwt/issues/131
    	ClassPathResource resource = new ClassPathResource(jwtKeystore);
        KeyStore keystore = KeyStore.getInstance(keyStoreType);
        keystore.load(resource.getInputStream(), keyStorePassword.toCharArray());
        
        return keystore;
    	
    }
    
    /**
     * The token is valid if there is no exception parsing it (not altered) and
     * the expiration date is in the future
     * 
     * @param accessToken
     * @return true if valid, false otherwise
     */
//	public static boolean isValidJWTTokenString(String accessToken) {
//		try {
//			Date expirationDate = Jwts.parser()
//	                .setSigningKey(publicKey)
//	                .parseClaimsJws(accessToken.replace(TOKEN_PREFIX, ""))
//	                .getBody().getExpiration();
//			return expirationDate!=null && expirationDate.after(new Date());
//		}catch(Exception e) {
//			return false;
//		}
//	}
    
    public static String getNameFromJWTTokenString(String accessToken) {
		try {
	    	
			Claims body = Jwts.parser()
	                .setSigningKey(publicKey)
	                .parseClaimsJws(accessToken.replace(TOKEN_PREFIX, ""))
	                .getBody();

			return body.getSubject();
	    	
		}catch(Exception e) {
			throw new RuntimeException("Can't parse jwt token '"+accessToken+"'", e);
		}
	}

	public static MyAuthenticationToken buildMyTokenFromIDProviderToken(Principal providerToken) throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {

		// TODO get name, for now, same as subject
		String name = providerToken.getName();

		Claims claims = Jwts.claims();
		claims.setSubject(name);
		
		JwtBuilder myToken = Jwts.builder()
                //.setHeaderParam("typ" , "JWT")
                .setSubject(name)
                .setClaims(claims)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + MyJWTUtils.expirationTime*1000))
                .signWith(SignatureAlgorithm.RS256, MyJWTUtils.getPrivateJWTKey());
		
		String myTokenString = myToken.compact();
		
		MyAuthenticationToken t = new MyAuthenticationToken(name, myTokenString);
		
		return t;
	}

	public static MyAuthenticationToken buildMyTokenFromFormerTokenStringIfValid(String accessToken) {

		String name = MyJWTUtils.getNameFromJWTTokenString(accessToken);
        
		if(name==null){
			throw new JwtInvalidException("JWT has no name!");
		}
		
		Date expirationDate = Jwts.parser()
                .setSigningKey(publicKey)
                .parseClaimsJws(accessToken.replace(TOKEN_PREFIX, ""))
                .getBody().getExpiration();
		
		if(expirationDate==null || expirationDate.before(new Date())){
			throw new JwtInvalidException("JWT for name '"+name+"' expired on "+expirationDate);
		}
		
		return new MyAuthenticationToken(name, accessToken);
		
	}
	
	public static void main(String[] args) throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
		
		MyJWTUtils m = new MyJWTUtils();
		
		m.setKeystore("authservice.jks");
		m.setKeyStoreType("JKS");
		
		// removed as published to github
		// If I need this again...read from (git ignored) file
		m.setKeyAlias("***");
		m.setKeyStorePassword("***");
		
		m.init();

		MyAuthenticationToken t = m.buildMyTokenFromIDProviderToken(new Principal() {
			
			@Override
			public String getName() {
				return "testName";
			}
			
		});
		
		String jwt = t.getJWTString();
		
		
		d("pubkey format '"+publicKey.getFormat()+"'");
    	d("pubkey encoded '"+Base64.getEncoder().encodeToString(publicKey.getEncoded())+"'");
		
		Jws<Claims> claims = Jwts.parser()
                .setSigningKey(publicKey)
                .parseClaimsJws(jwt.replace(TOKEN_PREFIX, ""));
		
		
        Claims body = claims.getBody();
        JwsHeader header = claims.getHeader();
        String signature = claims.getSignature();

		d(header);
		d(body);
		d(jwt);
	}
	
	public static int getExpirationTime() {
		return expirationTime;
	}
	
	private static void d(Object o) {
		
		if(o instanceof Map) {
			Map m = (Map)o;
			Set keys = m.keySet();
			keys.forEach(k -> {d(k+" => "+m.get(k));});
		} else {
			System.out.println(o);
		}
		
	}
	
}