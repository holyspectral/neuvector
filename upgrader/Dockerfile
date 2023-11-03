FROM alpine:3.18 as builder
RUN apk add curl wget
RUN curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl" && chmod +x kubectl
RUN wget https://github.com/fullstorydev/grpcurl/releases/download/v1.8.9/grpcurl_1.8.9_linux_x86_64.tar.gz && tar zxvf grpcurl_1.8.9_linux_x86_64.tar.gz

FROM alpine:3.18
COPY --from=builder /kubectl /grpcurl /
ADD common.proto controller_service.proto scan.proto /
ADD entrypoint.sh /
ADD test.json /
ENTRYPOINT ["/entrypoint.sh"]
