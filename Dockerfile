# inspired by https://spring.io/guides/gs/spring-boot-docker/

FROM openjdk:8-jdk-alpine
ARG JAR_FILE
ADD ${JAR_FILE} app.jar
EXPOSE 8080
ENTRYPOINT ["java","-Djava.security.egd=file:/dev/./urandom","-jar","/app.jar"]