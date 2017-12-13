package eu.andymel.services.auth;

import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.StreamSupport;

import javax.annotation.PostConstruct;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.core.env.AbstractEnvironment;
import org.springframework.core.env.EnumerablePropertySource;
import org.springframework.core.env.Environment;
import org.springframework.core.env.MutablePropertySources;
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
 *  > Depending on which ID Provider is choosen by the user, the next request comes to a specific path /auth/provider
 *  > from there the service redirects to the providers login page (OAuth2)
 *  > After login the provider redirects back to /auth/provider.
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

	private static final Log logger = LogFactory.getLog(AuthServiceSpringApplication.class);
	
	public static void main(String[] args) {
		SpringApplication.run(AuthServiceSpringApplication.class, args);
	}
	
	@Autowired
	Environment springEnv;
	
	private List<String> activeProviders;
	
	@PostConstruct
	public void init() {

		// this prints all properties set in the spring environment with DEBUG level
		// inspired by https://stackoverflow.com/a/42521523/7869582 
		if(logger.isDebugEnabled()) {
			StringBuffer sb = new StringBuffer("\n");
			MutablePropertySources propSrcs = ((AbstractEnvironment) springEnv).getPropertySources();
			StreamSupport.stream(propSrcs.spliterator(), false)
		        .filter(ps -> ps instanceof EnumerablePropertySource)
		        .map(ps -> ((EnumerablePropertySource) ps).getPropertyNames())
		        .flatMap(Arrays::<String>stream)
		        .sorted()
		        .forEach(propName -> {
		        	sb.append(propName).append("\t=> ");
		        	sb.append(springEnv.getProperty(propName)).append('\n');
		        });
			
			logger.debug(sb.toString());
		}
		
		String activeProvidersString = springEnv.getProperty("oauth.active");
		
		activeProviders = Arrays.asList(activeProvidersString.split("\\s*,\\s*"));

		logger.debug("List of active providers: "+activeProviders);
		
	}

	/* endpoint to get the data of the logged in user (only allowed when logged in) */
	@RequestMapping("/auth/user")
	@ResponseBody // necessary as my app is a @Controller now not a @RestController anymore
	public Map<String, String> user(MyAuthenticationToken authentication) {
		Map<String, String> map = new LinkedHashMap<>();
		map.put("name", authentication.getName());
		return map;
	}
	
	/* endpoint to get data of the available id providers */
	@RequestMapping("/auth")
	@ResponseBody // necessary as my app is a @Controller now not a @RestController anymore
	public List<String> getIdProviders() {
//		// replace by configured data once reading dynamic data from application.yml works
//		// so https://stackoverflow.com/questions/47676164/bind-complex-config-data-from-application-yml-in-spring-boot
		
		
		return activeProviders;
//		return Arrays.asList("facebook", "google", "twitter", "github_al");
	}
	
	
	
	/*
	 * TODO answer this if github redirect works again 
	 * https://stackoverflow.com/questions/36252758/spring-boot-oauth2-https-redirect-uri-instead-of-http
	 * 
	 * and here
	 * https://stackoverflow.com/questions/33812471/spring-oauth-redirect-uri-not-using-https
	 * 
	 */
	
	
	
	/*
	 * After an authentication error I redirect to the home page with a flag set in 
	 * the query parameters. On the client I show an error msg if this flag is set.
	 * 
	 * see ServletCustomizer.java - this adds an ErrorPage for HttpStatus.UNAUTHORIZED to "/unauthenticated"
	 */
/*
 * commented out as it makes problems and is not really needed at the moment
 * it redirects to http://localhost...even if my request comdes from https://amcoustics.local
 */
//	@RequestMapping("/unauthenticated")
//	public String unauthenticated() {
//	  return "redirect:/?error=true";
//	}
//	
//	@Bean
//	public EmbeddedServletContainerCustomizer customizer() {
//		return container -> {
//			container.addErrorPages(new ErrorPage(HttpStatus.UNAUTHORIZED, "/unauthenticated"));
//		};
//	}
	
}
