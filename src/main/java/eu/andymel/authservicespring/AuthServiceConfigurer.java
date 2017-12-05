package eu.andymel.authservicespring;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.servlet.Filter;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.oauth2.resource.UserInfoTokenServices;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.filter.OAuth2ClientAuthenticationProcessingFilter;
import org.springframework.security.oauth2.client.filter.OAuth2ClientContextFilter;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.web.filter.CompositeFilter;

import eu.andymel.authservicespring.jwt.TokenExtractor;


@Configuration
@EnableWebSecurity
public class AuthServiceConfigurer extends WebSecurityConfigurerAdapter {

	public static final String JWT_TOKEN_HEADER_PARAM = "X-Authorization";
	public static final String FORM_BASED_LOGIN_ENTRY_POINT = "/api/auth/login";
    public static final String TOKEN_BASED_AUTH_ENTRY_POINT = "/api/**";
    public static final String TOKEN_REFRESH_ENTRY_POINT = "/api/auth/token";
    

	// OAuth2ClientContext to build my OAuth2 authentication filters
	@Autowired private OAuth2ClientContext oauth2ClientContext;
	
    
	// JWT issuer
	@Autowired private AuthenticationSuccessHandler successHandler;

	// JWT checker
	@Autowired private AuthenticationManager authenticationManager;
	@Autowired private TokenExtractor tokenExtractor;
	
	/* a method of WebSecurityConfigurerAdapter */
	@Override
	protected void configure(HttpSecurity http) throws Exception {

		http
			
			// all requests are protected by default!
			.antMatcher("/**").authorizeRequests()
					
			// only allow the following requests without being logged in
			.antMatchers("/", "/login**", "/webjars/**").permitAll()
			
			// all others are only allowed when logged in and will result in a 401 if not
			.anyRequest().authenticated()

			// Unauthenticated users are re-directed to the home page
//			.and().exceptionHandling()
//		      .authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/"))

			// spring logout
			.and().logout().logoutSuccessUrl("/").permitAll()
	
			// fügt csrf token hinzu (3ter Schritt im tutorial..logout)
			/*
			 * The CookieCsrfTokenRepository persists the CSRF token in a cookie named
			 * "XSRF-TOKEN" and reads from the header "X-XSRF-TOKEN" following the
			 * conventions of AngularJS. On the client: We fake this behavior on the client
			 * (we don't use angular) by setting this header for each potentially writing
			 * (state changing) request to the server.
			 * 
			 * 
			 * TODO will not need that for stateless use I think?!
			 */
//			.and().csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
			.and().csrf().disable() // We don't need CSRF for JWT based authentication
			
			// added in step 4 of the tutorial, adding my OAuth2 authentication filter
			.addFilterBefore(
				authenticationFilter(), 	// my combined OAuth2 filter for all providers 
				BasicAuthenticationFilter.class	// add it before this filter class
			)
			.addFilterBefore(
				buildJwtTokenAuthenticationProcessingFilter(), 
				BasicAuthenticationFilter.class	// add it before this filter class
			)
				
			/* I don't need a session, I use JWTs
			 * github issue why jsessionID is still sent to client 
	         * https://github.com/spring-projects/spring-security/issues/4242 
	         * 
	         * "this configuration only controls what Spring Security does – not the entire application"
	         * http://www.baeldung.com/spring-security-session
	         * 
	         */
			.sessionManagement()
	            .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
			
		;
	}
	
	protected JwtTokenAuthenticationProcessingFilter buildJwtTokenAuthenticationProcessingFilter() throws Exception {
        List<String> pathsToSkip = Arrays.asList(TOKEN_REFRESH_ENTRY_POINT, FORM_BASED_LOGIN_ENTRY_POINT);
        SkipPathRequestMatcher matcher = new SkipPathRequestMatcher(pathsToSkip, TOKEN_BASED_AUTH_ENTRY_POINT);
        JwtTokenAuthenticationProcessingFilter filter = new JwtTokenAuthenticationProcessingFilter(
//        	failureHandler, 	// removed that, hoping, that it simply trys the other filters (OAuth login) if no JWT token is set
        	tokenExtractor, 
        	matcher
        );
        filter.setAuthenticationManager(this.authenticationManager);
        return filter;
    }

	
	/*
	 * get my oauth2 settings from the application.yml
	 */
	@Bean
	@ConfigurationProperties("github")
	public OAuthProviderConfig github() {
		return new OAuthProviderConfig();
	}
	@Bean
	@ConfigurationProperties("facebook")
	public OAuthProviderConfig facebook() {
		return new OAuthProviderConfig();
	}
	@Bean
	@ConfigurationProperties("google")
	public OAuthProviderConfig google() {
		return new OAuthProviderConfig();
	}

	/*
	 * Combine my authentication filters to one filter
	 */
	private Filter authenticationFilter() {
		
		CompositeFilter filter = new CompositeFilter();
		
		// TODO read path from application.yml in OAuthProviderConfig
		
		List<Filter> filters = new ArrayList<>();
		
		// TODO is this the right place to add a filter that checks for already existing JWTs before logging in?! 
		
		filters.add(ssoFilter(facebook(), "/login/facebook"));
		filters.add(ssoFilter(google(), "/login/google"));
		filters.add(ssoFilter(github(), "/login/github"));
		
		filter.setFilters(filters);
		return filter;
		
	}
	
	// build an own authentication filter for my OAuth2 id providers
	private Filter ssoFilter(OAuthProviderConfig oAuthProviderConfig, String path) {
		
//		OAuth2ClientAuthenticationProcessingFilter filter = new OAuth2ClientAuthenticationProcessingFilter(path);
		OAuth2ClientAuthenticationProcessingFilter filter = new MyOAuth2AuthenticationProcessingFilter(path);
		
		
		OAuth2RestTemplate template = new OAuth2RestTemplate(
			oAuthProviderConfig.getClient(), 
			oauth2ClientContext
		);
		filter.setRestTemplate(template);
		
		UserInfoTokenServices tokenServices = new UserInfoTokenServices(
			oAuthProviderConfig.getResource().getUserInfoUri(),
			oAuthProviderConfig.getClient().getClientId()
		);
		tokenServices.setRestTemplate(template);
		filter.setTokenServices(tokenServices);
		
		filter.setAuthenticationSuccessHandler(successHandler);
		
		
		return filter;
		
	}
	
	
	
	/*
	 * We need a filter to explicitly support the redirects from our app to Facebook and other id providers.
	 * The filter is already available in the application context because we used @EnableOAuth2Client. 
	 * All that is needed is to wire the filter up so that it gets called in the right order in our 
	 * Spring Boot application. To do that we need a FilterRegistrationBean
	 */
	@Bean
	public FilterRegistrationBean oauth2ClientFilterRegistration(OAuth2ClientContextFilter filter) {
		FilterRegistrationBean registration = new FilterRegistrationBean();
		registration.setFilter(filter);
		/* Has to come before the main Spring Security filter. In this way we can use it to handle 
		 * redirects signaled by exceptions in authentication requests.*/
		registration.setOrder(-100); 
		return registration;
	}

}
