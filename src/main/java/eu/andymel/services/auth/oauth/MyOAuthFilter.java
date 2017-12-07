package eu.andymel.services.auth.oauth;

import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.boot.autoconfigure.security.oauth2.resource.UserInfoTokenServices;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.filter.OAuth2ClientAuthenticationProcessingFilter;
import org.springframework.security.oauth2.provider.OAuth2Authentication;

import eu.andymel.services.auth.MyAuthenticationToken;
import eu.andymel.services.auth.jwt.MyJWTUtils;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

public class MyOAuthFilter extends OAuth2ClientAuthenticationProcessingFilter {

	private static final Log logger = LogFactory.getLog(MyOAuthFilter.class);
	
	private String defaultFilterProcessesUrl;
	
	public MyOAuthFilter(OAuthProviderConfig oAuthProvider, String defaultFilterProcessesUrl, OAuth2ClientContext oauth2ClientContext) {
		super(defaultFilterProcessesUrl);

		this.defaultFilterProcessesUrl = defaultFilterProcessesUrl;
		
		OAuth2RestTemplate template = new OAuth2RestTemplate(
			oAuthProvider.getClient(), 
			oauth2ClientContext
		);
		setRestTemplate(template);
	
		UserInfoTokenServices tokenServices = new UserInfoTokenServices(
			oAuthProvider.getResource().getUserInfoUri(), 
			oAuthProvider.getClient().getClientId()
		);
		tokenServices.setRestTemplate(template);
		setTokenServices(tokenServices);

	}

	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException, IOException, ServletException {
		
		Authentication origAut = super.attemptAuthentication(request, response);

		logger.debug("attemptAuthentication "+this+" ["+defaultFilterProcessesUrl+"] => "+origAut);

		OAuth2Authentication oa = (OAuth2Authentication)origAut;


		// build my own token (same style no matter which id provider is used)
		Authentication myAut;
		try {
			myAut = buildMyTokenFromIDProviderToken(oa);
		} catch (Exception e) {
			// Any exception in here should prevent authentication
			throw new InternalAuthenticationServiceException(
				"Can't issue JWT for "+origAut+"!", 
				e
			);
		}
		
		return myAut;
	}
	
	@Override
    protected void successfulAuthentication(HttpServletRequest req,
                                            HttpServletResponse res,
                                            FilterChain chain,
                                            Authentication auth) throws IOException, ServletException {
		
		logger.debug("successfull OAUth2 Authentication! => adding jwt token as cookie [name: "+auth.getName()+", "+auth+"]");

		String myToken = ((MyAuthenticationToken)auth).getJWTString(); 
		
    	if(MyJWTUtils.USE_PREFIX) {
    		myToken = MyJWTUtils.TOKEN_PREFIX + myToken;
    	}
    	    
        Cookie jwtAccessCookie = new Cookie("access_token", myToken);
        
        jwtAccessCookie.setPath("/");		// so it is visible set for all paths, not just for the login/provider sub path
        jwtAccessCookie.setSecure(true);	// browser may only add this cockie if https 	
        jwtAccessCookie.setHttpOnly(true);	// javascript may not read the cookie 
        jwtAccessCookie.setMaxAge(MyJWTUtils.EXPIRATION_TIME/1000);	// same as jwt token
        
        res.addCookie(jwtAccessCookie);

        /* added to let the OAuth2ClientAuthenticationProcessingFilter
         * take care about the redirect from /auth/... back to '/' */
        super.successfulAuthentication(req, res, chain, auth);
        
    }
	
	
	private MyAuthenticationToken buildMyTokenFromIDProviderToken(OAuth2Authentication providerToken) throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
		
		// TODO get name, for now, same as subject
		String name = providerToken.getName();

        Map<String, Object> claims = new HashMap<>();
        claims.put("name", name);
		
		String myToken = Jwts.builder()
                .setSubject(name)
                .setClaims(claims)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + MyJWTUtils.EXPIRATION_TIME))
                .signWith(SignatureAlgorithm.RS256, MyJWTUtils.getPrivateJWTKey())
                .compact();
		
		return new MyAuthenticationToken(name, myToken);
	}
}
