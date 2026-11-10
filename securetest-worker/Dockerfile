# SecureTest AI remote worker AND per-job sandbox image (the worker starts this image with the "sandbox" argument).
# Build: mvn -pl securetest-worker -am package && docker build -t securetest/worker:1.0.2 securetest-worker
FROM eclipse-temurin:17-jre
COPY target/securetest-worker-1.0.2-exec.jar /app/worker.jar
USER 65532:65532
ENTRYPOINT ["java", "-jar", "/app/worker.jar"]
