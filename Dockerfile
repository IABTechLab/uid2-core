# sha from https://hub.docker.com/layers/library/eclipse-temurin/8u472-b08-jre-alpine-3.23/images/sha256-c10101f6b597cfeb8265cb7969f32ba9704afb52d28a2967f72c4dfca69633b5
FROM eclipse-temurin@sha256:d5a08fce8cc0bd81591a0793ede78cbc2167c3fbdd0b45743022cbe126b94916

WORKDIR /app
EXPOSE 8088

ARG JAR_NAME=uid2-core
ARG JAR_VERSION=1.0.0-SNAPSHOT
ARG IMAGE_VERSION=1.0.0.unknownhash
ENV JAR_NAME=${JAR_NAME}
ENV JAR_VERSION=${JAR_VERSION}
ENV IMAGE_VERSION=${IMAGE_VERSION}

COPY ./target/${JAR_NAME}-${JAR_VERSION}-jar-with-dependencies.jar /app/${JAR_NAME}-${JAR_VERSION}.jar
COPY ./target/${JAR_NAME}-${JAR_VERSION}-sources.jar /app
COPY ./conf/default-config.json /app/conf/
COPY ./conf/*.xml /app/conf/

RUN adduser -D uid2-core && mkdir -p /app && chmod 705 -R /app && mkdir -p /app/file-uploads && chmod 777 -R /app/file-uploads && mkdir -p /app/pod_terminating && chmod 777 -R /app/pod_terminating
USER uid2-core

CMD java \
    -Djava.security.egd=file:/dev/./urandom \
    -Dvertx.logger-delegate-factory-class-name=io.vertx.core.logging.SLF4JLogDelegateFactory \
    -Dlogback.configurationFile=/app/conf/logback.xml \
    -jar ${JAR_NAME}-${JAR_VERSION}.jar
