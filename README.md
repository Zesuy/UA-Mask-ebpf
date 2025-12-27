apk add kmod-sched-bpf
apk add kmod-sched-core

go generate

CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags "-s -w" -o mvp_tool