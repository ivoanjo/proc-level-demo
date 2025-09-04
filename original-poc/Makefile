all: run
build:
	echo "Building binaries..."
	g++ -g -o writer anon_mapping.cc
	go build reader.go
	echo "Giving reader PTRACE capabilities"
	sudo setcap cap_sys_ptrace+ep reader
run-writer:
	echo "Running Writer in background..."
	./writer &
run: build  run-writer
	echo "Running reader..."
	./reader -pid $(shell pgrep writer)
clean:
	$(RM) reader writer
	pkill writer
