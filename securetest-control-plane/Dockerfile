# SecureTest AI control plane. Build: mvn -pl securetest-control-plane -am package
FROM eclipse-temurin:17-jre
COPY target/securetest-control-plane-1.0.1-exec.jar /app/control-plane.jar
USER 65532:65532
EXPOSE 8090
ENV SERVER_PORT=8090
ENTRYPOINT ["java", "-XX:MaxRAMPercentage=75", "-jar", "/app/control-plane.jar"]
