package eu.andymel.services.auth.jwt;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.util.WebUtils;

import eu.andymel.services.auth.MyAuthenticationToken;

public class JWTAuthorizationFilter extends AbstractAuthenticationProcessingFilter {

	private static final Log logger = LogFactory.getLog(JWTAuthorizationFilter.class);
	private static final Log logInOut = LogFactory.getLog("andymel_LogInOut");
	
	public JWTAuthorizationFilter() {
		super(new RequestMatcher() {
				
			@Override
			public boolean matches(HttpServletRequest request) {
				// if the jwt cookie is present, do authorization with this filter
				// otherwise do authorization with my OAuth filters
				Cookie accessTokenCookie = WebUtils.getCookie(request, MyJWTUtils.COOKIE_STRING); 
				logger.debug("request.getRequestURI()->'"+request.getRequestURI()+"', jwt: '"+accessTokenCookie+"'");
		    	//just check if cockie is present not if it's valid (done below in attemptAuthentication)
				return accessTokenCookie != null;
			}
	
		});
	}

/*
 * commened out as I don't understand why I did this from the comments
 * I states the redirect to / as a problem...but I don't get why...maybe this 
 * only was a problem when using the service differently?! I try to invoke the same problem
 * that I had back then by simply commenting this out.
 */
//	@Override
//	protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
//			Authentication authResult) throws IOException, ServletException {
//
//		super.successfulAuthentication(request, response, chain, authResult);
//		
//		/* added this because the default behavior of AbstractAuthenticationProcessingFilter is
//		 * redirecting to / after successful authentication
//		 *  
//		 *  At the moment I get a 403 for the /user request, although this 
//		 *  successfulAuthentication method is called. Seems like the authentication 
//		 *  object is not set as I don't call super now.
//		 *  
//		 *  lets try saving it myself
//		 */
//
//		logger.info("jwt auth success => setting Authentication object..."+authResult);
//
//		SecurityContextHolder.getContext().setAuthentication(authResult);
//		
//		chain.doFilter(request, response);
//	}
	
	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException, IOException, ServletException {
    	
		
		Cookie accessTokenCookie = WebUtils.getCookie(request, MyJWTUtils.COOKIE_STRING); 
        if (accessTokenCookie == null) {
        	throw new AuthenticationCredentialsNotFoundException("No accessTokenCookie!");
        }

        String accessToken = accessTokenCookie.getValue();
        if (accessToken == null || accessToken.length()==0) {
        	throw new JwtInvalidException("AccessToken string is empty/null.");
        }

    	if(!MyJWTUtils.USE_PREFIX || accessToken.startsWith(MyJWTUtils.TOKEN_PREFIX)) {
    		
    		// throws AuthenticationExceptions on invalid jwt
    		MyAuthenticationToken ret = MyJWTUtils.buildMyTokenFromFormerTokenStringIfValid(accessToken);
    		logger.debug("attemptAuthentication "+this+" => "+ret);
//            SecurityContextHolder.getContext().setAuthentication(authentication);
            return ret;
    		
    	} else {
    		throw new JwtInvalidException("Can't process accessToken '"+accessToken+"'");
    	}
	}
	
	
//	private MyAuthenticationToken getAuthentication(String accessToken) {
//        
//    	if (accessToken != null) {
//    		// parse the token for the name
//            String name = MyJWTUtils.getNameFromJWTTokenString(accessToken);
//            return new MyAuthenticationToken(name, accessToken);
//        }
//        return null;
//    }


}