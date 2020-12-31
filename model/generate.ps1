protoc -I . --go_opt=paths=source_relative --go_out=.  *.proto
protoc -I . --go-grpc_opt=paths=source_relative --go-grpc_out=.  *.proto
protoc-go-tags --dir=./