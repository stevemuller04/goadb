all:
	go build -o build/ ./...

clean:
	rm -r build/
