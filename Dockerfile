FROM openjdk:11
WORKDIR /app
COPY ./target/vet-pet-0.0.1-SNAPSHOT.jar .
EXPOSE 8001
ENTRYPOINT ["java","-jar","vet-pet-0.0.1-SNAPSHOT.jar"]