package eu.andymel.services.auth.oauth;

import java.io.IOException;
import java.util.Date;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.boot.autoconfigure.security.oauth2.resource.UserInfoTokenServices;
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
		
		Authentication ret = super.attemptAuthentication(request, response);

		logger.debug("attemptAuthentication "+this+" ["+defaultFilterProcessesUrl+"] => "+ret);

		OAuth2Authentication oa = (OAuth2Authentication)ret;
		
		// build my own token (same style no matter which id provider is used)
		ret = buildMyTokenFromIDProviderToken(oa);
		
		return ret;
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
         * take care about the redirect from /login/... back to '/' */
        super.successfulAuthentication(req, res, chain, auth);
        
    }
	
	
	private MyAuthenticationToken buildMyTokenFromIDProviderToken(OAuth2Authentication providerToken) {
		String name = providerToken.getName();
		String myToken = Jwts.builder()
                .setSubject(providerToken.getName())
                .setExpiration(new Date(System.currentTimeMillis() + MyJWTUtils.EXPIRATION_TIME))
                .signWith(SignatureAlgorithm.HS512, MyJWTUtils.SECRET.getBytes())
                .compact();
		
		return new MyAuthenticationToken(name, myToken);
	}
}
