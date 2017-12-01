package eu.andymel.authservicespring;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import com.fasterxml.jackson.databind.ObjectMapper;

import eu.andymel.authservicespring.jwt.JwtToken;
import eu.andymel.authservicespring.jwt.JwtTokenFactory;

/*
 * inspired by http://www.svlada.com/jwt-token-authentication-with-spring-boot/#ajax-authentication
 * 
 * but I extend SavedRequestAwareAuthenticationSuccessHandler as this is the standard success handler used if not overridden.
 * It keeps track of which url to call after successful authentication
 */

@Component
public class AuthenticationSuccessHandlerJWT extends SavedRequestAwareAuthenticationSuccessHandler {  
//    private final ObjectMapper mapper;
    private final JwtTokenFactory tokenFactory;

    @Autowired
    public AuthenticationSuccessHandlerJWT(final ObjectMapper mapper, final JwtTokenFactory tokenFactory) {
//        this.mapper = mapper;
        this.tokenFactory = tokenFactory;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {

        JwtToken accessToken = tokenFactory.createAccessJwtToken(authentication);
        JwtToken refreshToken = tokenFactory.createRefreshToken(authentication);

//        Map<String, String> tokenMap = new HashMap<String, String>();
//        tokenMap.put("token", accessToken.getToken());
//        tokenMap.put("refreshToken", refreshToken.getToken());

        Cookie jwtAccessCookie = new Cookie("access_token", accessToken.getToken());
        Cookie jwtRefreshCookie = new Cookie("refresh_token", refreshToken.getToken());
        
        // so it is visible set for all paths, not just for the login/provider sub path
        jwtAccessCookie.setPath("/");
        jwtRefreshCookie.setPath("/");
        
        // TODO: set max age of cockie to same time as access/refresh token??
        
//        commenting out as I have no https on dev at the moment
//        jwtAccessCookie.setSecure(true);
//        jwtRefreshCookie.setSecure(true);
        
        jwtAccessCookie.setHttpOnly(true);
        jwtRefreshCookie.setHttpOnly(true);
        
        response.addCookie(jwtAccessCookie);
        response.addCookie(jwtRefreshCookie);
        
        /* the cockie is not visible :(
         * https://stackoverflow.com/questions/28788736/is-there-a-solution-to-keep-a-cookie-on-browser-while-redirect-the-response
         * 
         * I set the path as the cockie is only seen in subpaths of the path where it was set regarding to one anser it this SO post
         * Other answers state that the cockie is not set during a redirect by all (any?) browsers, I should make a forward...lets try (buttey say that does not change the url)
         * 
         */
        
        
        // either I use the SavedRequestAwareAuthenticationSuccessHandler that remembers from which site the login started
        super.onAuthenticationSuccess(request, response, authentication);
        
//        or I redirect by myself wherever I want the user to go next
//        getRedirectStrategy().sendRedirect(request, response, "/");
        
    }

}
