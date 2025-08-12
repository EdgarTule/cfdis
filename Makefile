BINARY_NAME=satxml-go

.PHONY: build install clean

build:
	@echo "Building $(BINARY_NAME)..."
	@cd satxml-go && go build -o ../$(BINARY_NAME)

install: build
	@echo "Installing $(BINARY_NAME) to /usr/local/bin..."
	@sudo install $(BINARY_NAME) /usr/local/bin/

clean:
	@echo "Cleaning up..."
	@rm -f $(BINARY_NAME)
	@cd satxml-go && go clean
