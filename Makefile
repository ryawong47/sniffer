.PHONY: build run stop logs clean

# Build the Docker image
build:
	docker build -t network-sniffer .

# Run with docker-compose
run:
	docker-compose up -d
	@echo "Network sniffer is running. Use 'make logs' to view output."

# Stop the container
stop:
	docker-compose down

# View logs
logs:
	docker-compose logs -f

# Run interactively (not detached)
run-interactive:
	docker-compose up

# Clean up
clean:
	docker-compose down -v
	docker rmi network-sniffer || true

# Run with docker directly (without compose)
run-docker:
	docker run --rm \
		--network host \
		--cap-add NET_RAW \
		--cap-add NET_ADMIN \
		--privileged \
		-v /proc:/host/proc:ro \
		-e HOST_PROC=/host/proc \
		network-sniffer

# Build and run
all: build run-interactive