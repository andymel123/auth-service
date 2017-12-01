package eu.andymel.authservicespring;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableOAuth2Client;
import org.springframework.web.bind.annotation.RestController;

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
@RestController   //@RestController is the same as @Controller but @ResponseBody is automatically added to all @RequestMapping methods
// if I need Controller instead I may not forget to add @ResponseBody to the @RequestMapping methods where necessary 
public class AuthServiceSpringApplication {

	public static void main(String[] args) {
		SpringApplication.run(AuthServiceSpringApplication.class, args);
	}
	
	
//	/* an own endpoint to get the data of the logged in user
//	 * (only allowed when logged in) */
//	@RequestMapping("/user")
//	public Map<String, String> user(Principal principal) {
//		Map<String, String> map = new LinkedHashMap<>();
//		// put in the map what is needed on the client side
//
//		/* this should always give me a unique id for the provider
//		 * but not a human readable name (eg for facebook its a long number) */
//		
//		
//		// in addition I try to get a human readable name out of the data
//		if(principal instanceof OAuth2Authentication) {
//			OAuth2Authentication a = (OAuth2Authentication)principal;
//			Object det = a.getUserAuthentication().getDetails();
//			if(det instanceof Map) {
//				Map<?,?> details = (Map<?, ?>) ((OAuth2Authentication) principal).getUserAuthentication().getDetails();
//
//				/*
//				 * TODO read spmewhere/somehow depending on provider
//				 */
//				
//				// facebook and github
//				map.put("id", 		asString(details, "id"));
//				map.put("name", 	asString(details, "name"));
//				                                     
//				// only in github data               
//		        map.put("location", asString(details, "location"));
//		        map.put("company",  asString(details, "company"));
//		        map.put("website",  asString(details, "blog"));
//		        map.put("pic",  	asString(details, "avatar_url"));
//                                                     
//		        // google                          
//		        map.put("sub", 		asString(details, "sub"));	// ist die ID! (google hat kein feld "id")
//				map.put("email", 	asString(details, "email"));
//				map.put("gender", 	asString(details, "gender"));
//				map.put("pic", 		asString(details, "picture"));
//				map.put("locale", 	asString(details, "locale"));
//			}
//		}
//
//		return map;
//	}
	
}
