# go install github.com/golang/protobuf/protoc-gen-go@v1.3.4 
all:
	@protoc *.proto --go_out=plugins=grpc:.
	@sed -i 's:"golang.org/x/net/context":"context":' *.go
