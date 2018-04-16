# auth-service
OAuth2 in => JWT out 

**> not production ready yet <**

What I want

- To get authorized to use one of my future microservices a user retrieves a JWT from this service first
- authentication will be delegated to google,facebook,...

# How to run
either simply start in IDE (AuthServiceSpringApplication.java has main entrypoint)
or build a jar with mvn package (is saved in target/ folder)
and run the jar 
	- directly
	- or with the Dockerfile, for example:
		- docker build -t auth-service --build-arg JAR_FILE=target/auth-service-spring-0.0.1-SNAPSHOT.jar .
		- docker run -p 8443:8443 --name auth-service auth-service
		