package eu.andymel.services.auth;

import java.util.LinkedHashMap;
import java.util.Map;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.embedded.EmbeddedServletContainerCustomizer;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.web.servlet.ErrorPage;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableOAuth2Client;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import eu.andymel.services.auth.jwt.JWTCookieRemoverOnLogout;
import eu.andymel.services.auth.oauth.MyOAuthFilter;
import eu.andymel.services.auth.oauth.OAuthProviderConfig;


/**
 * The tutorial I have the delegation of authentication to social id providers from is 
 * 1.) https://spring.io/guides/tutorials/spring-boot-oauth2/ 
 * 
 * For the JWT part I took inspiration from (but simplified a lot)
 * 2.) https://auth0.com/blog/implementing-jwt-authentication-on-spring-boot/
 * 3.) http://www.svlada.com/jwt-token-authentication-with-spring-boot/#ajax-authentication
 *
 * What happens if a user connects to this AuthService:
 * 	> The Service checks if there already is a jwt token set
 * 	> If not it returns the possible ID Providers to login
 *  > Depending on which ID Provider is choosen by the user, the next request comes to a specific path /login/provider
 *  > from there the service redirects to the providers login page (OAuth2)
 *  > After login the provider redirects back to login/provider.
 *  > The AuthService checks the given data from the provider 
 *  > if the data is correct the AuthService issues a JWT token and sets it as (httpOnly and secure) cookie in the users request
 *  > As it's a cookie all future requests will contain this cookie as long as its valid
 *  > if a valid jwt cookie is set in a request the AuthService (and all other services) authorize the user with this cookie
 * 
 * This project contains:
 * As general code:
 *  > This {@link AuthServiceSpringApplication} class
 *  > The {@link AuthServiceConfigurer} class to do the configuration
 *  > The {@link MyAuthenticationToken} as {@link Authentication} object (used by spring security to hold data about the authenticated user)
 *  
 * For the OAuth part:
 *  > {@link MyOAuthFilter} extends OAuth2ClientAuthenticationProcessingFilter and adds 
 *  	> loading the provider data from the application.yml
 * 		> creating my {@link MyAuthenticationToken} when getting a successful answer from tzhe id provider
 * 		> creating a cookie with the JWT token in the users request
 *  > {@link OAuthProviderConfig} holds the id-provider data from the application.yml
 *  
 * For the JWT part:
 *  > {@link JWTCookieRemoverOnLogout} extends LogoutSuccessHandler is called when a user logs out and simply removes the jwt token
 *  > MYJWTUtils prevents code duplication by holding whatever jwt related code I need more than once
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
	
	@Bean
	public EmbeddedServletContainerCustomizer customizer() {
		return container -> {
			container.addErrorPages(new ErrorPage(HttpStatus.UNAUTHORIZED, "/unauthenticated"));
		};
	}
	
}
