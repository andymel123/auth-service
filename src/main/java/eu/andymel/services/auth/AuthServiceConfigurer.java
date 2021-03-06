package eu.andymel.services.auth;

import java.util.ArrayList;
import java.util.List;

import javax.servlet.Filter;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.client.filter.OAuth2ClientContextFilter;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.web.filter.CompositeFilter;

import eu.andymel.services.auth.jwt.JWTAuthorizationFilter;
import eu.andymel.services.auth.jwt.JWTCookieRemoverOnLogout;
import eu.andymel.services.auth.oauth.MyOAuthFilter;
import eu.andymel.services.auth.oauth.OAuthProviderConfig;

@Configuration
@EnableWebSecurity
public class AuthServiceConfigurer extends WebSecurityConfigurerAdapter {

	private static final Log logger = LogFactory.getLog(AuthServiceConfigurer.class);
	
	// OAuth2ClientContext to build my OAuth2 authentication filters
	@Autowired
	private OAuth2ClientContext oauth2ClientContext;

	/* a method of WebSecurityConfigurerAdapter */
	@Override
	protected void configure(HttpSecurity http) throws Exception {

		http
			
			// all requests are protected by default!
			.antMatcher("/**").authorizeRequests()
					
			// only allow the following requests without being logged in
			.antMatchers("/", "/auth**", "/webjars/**", "/**/favicon.ico", "/auth/assets/**").permitAll()
			
			// all others are only allowed when logged in and will result in a 401 if not
			.anyRequest().authenticated()

			// spring logout
			.and().logout()
				.logoutUrl("/auth/logout")
				.logoutSuccessUrl("/")
				.logoutSuccessHandler(new JWTCookieRemoverOnLogout())
				.permitAll()
	
			// fügt csrf token hinzu (3ter Schritt im tutorial..logout)
			/*
			 * The CookieCsrfTokenRepository persists the CSRF token in a cookie named
			 * "XSRF-TOKEN" and reads from the header "X-XSRF-TOKEN" following the
			 * conventions of AngularJS. On the client: We fake this behavior on the client
			 * (we don't use angular) by setting this header for each potentially writing
			 * (state changing) request to the server.
			 * 
			 * To protect my JWT cookie
			 */
			.and().csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())

			// no sessionid, no session
			.and().sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
			
			.and()
				// set the OAuth filter before, it will only handle login/provider requests
				// all other requests, will go on in the filter chain and reach my jwt filter net
				.addFilterBefore(
					oauthAuthenticationFilter(), 	// my combined OAuth2 filter that filters a given path per id provider 
					BasicAuthenticationFilter.class	// add it before this filter class
				)
				.addFilterBefore(
					new JWTAuthorizationFilter(), 	// authorizes on every path if a valid jwt token is found in the request
					BasicAuthenticationFilter.class	// add it before this filter class
				)
		
		;
		
//		http.
		
		int i=1;
	}

	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		super.configure(auth);
	}
	
	
	
	/*
	 * get my oauth2 settings from the application.yml
	 */
	@Bean
	@ConfigurationProperties("oauth.github")
	public OAuthProviderConfig github() {
		return new OAuthProviderConfig();
	}
	@Bean
	@ConfigurationProperties("oauth.github_al")
	public OAuthProviderConfig github_al() {
		return new OAuthProviderConfig();
	}
	@Bean
	@ConfigurationProperties("oauth.facebook")
	public OAuthProviderConfig facebook() {
		return new OAuthProviderConfig();
	}
	@Bean
	@ConfigurationProperties("oauth.google")
	public OAuthProviderConfig google() {
		return new OAuthProviderConfig();
	}
	@Bean
	@ConfigurationProperties("oauth.twitter")
	public OAuthProviderConfig twitter() {
		return new OAuthProviderConfig();
	}

	
	
	
//	###################
//	so könnte das lesen von anderem prop file gehen für private sachen! 
//	@ConfigurationProperties(prefix="tenantdb", locations={"datasources.yml"})
//	from https://stackoverflow.com/a/33751950/7869582

	
	
	/*
	 * Combine my authentication filters to one filter
	 */
	private Filter oauthAuthenticationFilter() {
		
		CompositeFilter filter = new CompositeFilter();
		
		List<Filter> filters = new ArrayList<>();
		
		// TODO move oauthclientcontext and config key name into myOauthFilter class!?
		filters.add(new MyOAuthFilter(facebook(), 	"/auth/facebook", 	oauth2ClientContext));
		filters.add(new MyOAuthFilter(google(), 	"/auth/google", 	oauth2ClientContext));
		filters.add(new MyOAuthFilter(twitter(), 	"/auth/twitter", 	oauth2ClientContext));
		filters.add(new MyOAuthFilter(github_al(), 	"/auth/github_al",	oauth2ClientContext));
		
		filter.setFilters(filters);
		
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
