# Stage 1: Build the application
FROM gradle:8.10-jdk17 AS builder

# Set working directory inside the container
WORKDIR /app

# Copy the project files
COPY . .

# Build the application using Gradle
RUN ./gradlew clean build

# Stage 2: Run the application using a minimal Java runtime image
FROM bellsoft/liberica-openjdk-alpine AS runtime

# Set working directory inside the container
WORKDIR /app

# Copy the compiled JAR from the build stage
COPY --from=builder /app/build/libs/*-all.jar modbus-security-cli.jar

# Define the entry point to run the Kotlin application
ENTRYPOINT ["java", "-jar", "modbus-security-cli.jar"]
