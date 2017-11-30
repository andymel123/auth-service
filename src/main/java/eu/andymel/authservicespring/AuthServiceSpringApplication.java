package eu.andymel.authservicespring;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableOAuth2Client;

/*
 * ### Inspirations ### 
 * The tutorial I have the delegation of authentication to social id providers from is 
 * 1.) https://spring.io/guides/tutorials/spring-boot-oauth2/ 
 * 
 * For the JWT part I will try to get infos from 
 * 2.) https://auth0.com/blog/implementing-jwt-authentication-on-spring-boot/
 * 3.) http://www.svlada.com/jwt-token-authentication-with-spring-boot/#ajax-authentication
 *  * 
 * I need
 * 	a) An authentication filter to issue JWTS to users sending credentials
 * 		this should be done by (1) I just need to issue JWT instead of the session
 * 
 * 	b) An authorization filter?! to refresh JWTs
 *  
 * 	c) Configure WebSecurityConfigurerAdapter 

 * 
 * regarding 2a)
 * In (1) I have all one OAuth2ClientAuthenticationProcessingFilter per id provider
 * In (2) he builds a JWTAuthenticationFilter (extending UsernamePasswordAuthenticationFilter)
 * Both (the OAUth.. as well as the UsernameP... filters) are extending AbstractAuthenticationProcessingFilter so I simply leave the combined filter from (1) intact.
 * But (2) already includes the JWT issuing logic inside of his JWTAuthenticationFilter. I will not extend the OAuth filter like (2) does (because of composition over inheritance). 
 * (3) already does composition:
 * he builds an AjaxLoginProcessingFilter, also extending AbstractAuthenticationProcessingFilter. The consturctor gets custom made
 * AuthenticationSuccessHandler and AuthenticationFailureHandler. 
 * I use such an AuthenticationSuccessHandler and simply try to add it as handler to my OAuth filters 
 */

@SpringBootApplication
@EnableOAuth2Client

public class AuthServiceSpringApplication {

	public static void main(String[] args) {
		SpringApplication.run(AuthServiceSpringApplication.class, args);
	}
}
