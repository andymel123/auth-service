package eu.amcoustics.auth.test.springauthtutorial;

import java.util.LinkedHashMap;
import java.util.Map;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableOAuth2Client;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;


/*
 * The tutorial I have the delegation of authentication to social id providers from is 
 * 1.) https://spring.io/guides/tutorials/spring-boot-oauth2/ 
 * 
 * For the JWT part I will try to get infos from 
 * 2.) https://auth0.com/blog/implementing-jwt-authentication-on-spring-boot/
 * 
 * if thats not enough I will try to get info from 
 * 3.) http://www.svlada.com/jwt-token-authentication-with-spring-boot/#ajax-authentication
 * 
 * Regarding to (2) i need
 * 	a) implement an authentication filter to issue JWTS to users sending credentials
 * 		this should be done by (1) I just need to issue JWT instead of the session
 * 
 * 	b) implement an authorization filter to validate requests containing JWTs
 *  	this I will need on every (resource) microservice. Here in the AuthService I mainly need 
 *  	the refresh logic
 *  
 * 	c) implemnet a custom version of UserDetailsService to help Spring Security loading user-specific data in the framework
 *  	lets see?!
 *  
 * 	d) use the WebSecurityConfigurerAdapter to customize the security framework
 *  	this was also done in (1) I will need to cahnge that I guess
 * 
 * 
 * regarding 2a)
 * In (1) I have all one OAuth2ClientAuthenticationProcessingFilter per id provider
 * In (2) he builds a JWTAuthenticationFilter (extending UsernamePasswordAuthenticationFilter)
 * Both (the OAUth.. as well as the UsernameP... filters) are extending AbstractAuthenticationProcessingFilter so I simply leave the combined filter from (1) intact.
 * But (2) already includes the JWT issuing logic inside of his JWTAuthenticationFilter class so I need to extract this and put it into the OAUth filters.
 * But I will not extend the OAuth filter like (2) does (because of composition over inheritance). 
 * In fact I switch to (3) because there it is already done by composition:
 * In (3) he builds an AjaxLoginProcessingFilter, also extending AbstractAuthenticationProcessingFilter. The consturctor gets custom made
 * AuthenticationSuccessHandler and AuthenticationFailureHandler. 
 * I start by copying the first one and simply try to add it as handler to my 
 *  
 * 
 */


@EnableConfigurationProperties
@SpringBootApplication
@EnableOAuth2Client
@Controller // I need @Controller now, not RestController as otherwise the /unauthenticated "redirect:/" does not work
//@RestController is the same as @Controller but @ResponseBody is automatically added to all @RequestMapping methods

public class AuthServiceSpringApplication{

	
	public static void main(String[] args) {
		SpringApplication.run(AuthServiceSpringApplication.class, args);
	}
	
	/* an own endpoint to get the data of the logged in user
	 * (only allowed when logged in) */
	@RequestMapping("/user")
	@ResponseBody // necessary as my app is a @Controller now not a @RestController anymore
	public Map<String, String> user(MyAuthenticationToken authentication) {
		Map<String, String> map = new LinkedHashMap<>();
		map.put("name", authentication.getUserName());
		return map;
	}
	
	/*
	 * After an authentication error I redirect to the home page with a flag set in 
	 * the query parameters. On the client I show an error msg if this flag is set.
	 * 
	 * see ServletCustomizer.java - this adds an ErrorPage for HttpStatus.UNAUTHORIZED to "/unauthenticated"
	 */
	@RequestMapping("/unauthenticated")
	public String unauthenticated() {
	  return "redirect:/?error=true";
	}
	
	
	

	
}
