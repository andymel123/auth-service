package eu.andymel.authservicespring.jwt;

/**
 *  
 *  from http://www.svlada.com/jwt-token-authentication-with-spring-boot/#ajax-authentication
 *  
 * Scopes
 * 
 * @author vladimir.stankovic
 *
 * Aug 18, 2016
 */
public enum Scopes {
    REFRESH_TOKEN;
    
    public String authority() {
        return "ROLE_" + this.name();
    }
}
