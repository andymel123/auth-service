package eu.andymel.services.auth.jwt;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.web.util.WebUtils;

public class JWTCookieRemoverOnLogout implements LogoutSuccessHandler{

	private static final Log logger = LogFactory.getLog(JWTCookieRemoverOnLogout.class);
	
	@Override
	public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {

		/* SO: Delete Cookie from servlet response
		 * https://stackoverflow.com/a/9828731/7869582 */

		Cookie accessTokenCookie = WebUtils.getCookie(request, MyJWTUtils.COOKIE_STRING);
		if(accessTokenCookie==null)return;
		String v = accessTokenCookie.getValue();
		if(v==null || v.isEmpty())return;
		
		
		Cookie cookie = new Cookie(MyJWTUtils.COOKIE_STRING, "");//null); // Not necessary, but saves bandwidth.
		cookie.setPath("/");	// can't take path with 'accessTokenCookie.getPath()' as this returns null
		cookie.setHttpOnly(true);
		cookie.setMaxAge(0); // Don't set to -1 or it will become a session cookie!
		response.addCookie(cookie);
		
		String name = MyJWTUtils.getNameFromJWTTokenString(v);
		logger.info("Logged out: "+name);
	}

}
