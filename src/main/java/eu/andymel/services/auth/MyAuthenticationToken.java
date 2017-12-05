package eu.andymel.services.auth;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.authentication.AbstractAuthenticationToken;

public class MyAuthenticationToken extends AbstractAuthenticationToken{

	private static final Log logger = LogFactory.getLog(MyAuthenticationToken.class);
			
	private String myJsonToken; 
	private String name; 
	
	public MyAuthenticationToken(String name, String jsonToken) {
		super(null);
		this.myJsonToken = jsonToken;
		this.name = name;
	}

	@Override
	public Object getCredentials() {
		return myJsonToken;
	}

	@Override
	public Object getPrincipal() {
		return name;
	}

	
	
	// for better readability
	public String getUserName() {
		return this.name;
	}
	public String getJWTString() {
		return myJsonToken;
	}
	
}
