# Network Sniffer Docker Test

This Docker setup allows you to test the network sniffer library with the improvements for reducing unknown processes on Linux.

## Prerequisites

- Docker
- Docker Compose (optional, for easier running)

## Building the Docker Image

```bash
docker build -t network-sniffer .
```

## Running the Sniffer

### Option 1: Using Docker Compose (Recommended)

```bash
docker-compose up
```

To run in the background:
```bash
docker-compose up -d
docker-compose logs -f  # to view logs
```

To stop:
```bash
docker-compose down
```

### Option 2: Using Docker Run

```bash
docker run --rm \
  --network host \
  --cap-add NET_RAW \
  --cap-add NET_ADMIN \
  --privileged \
  -v /proc:/host/proc:ro \
  -e HOST_PROC=/host/proc \
  network-sniffer
```

## Test Programs

Two test programs are included:

1. **test_sniffer.go** - A more detailed test that prints formatted statistics
2. **test_simple.go** - A simple test that follows your exact loop

To use the simple test, modify the Dockerfile:
```dockerfile
# Change this line:
RUN go build -o sniffer-test test_sniffer.go
# To:
RUN go build -o sniffer-test test_simple.go
```

## Important Notes

1. **Privileges**: The sniffer requires elevated privileges to capture network packets:
   - `CAP_NET_RAW` capability for packet capture
   - Access to `/proc` for process information
   - Host network mode to see all network traffic

2. **Security**: Running with `--privileged` and host network mode has security implications. Only use in trusted environments.

3. **Performance**: The improvements implemented should reduce unknown processes by:
   - Caching process information for 5 seconds
   - Using port-based fallback matching
   - Handling permission errors gracefully
   - Parallel processing of `/proc` entries

## Troubleshooting

If you see many `<UNKNOWN>` processes:

1. Ensure the container has proper permissions
2. Check if SELinux or AppArmor is blocking access
3. Verify that `/proc` is properly mounted
4. Try running with `--privileged` flag

## Output Example

The test program will continuously print network statistics including:
- Total connections and bandwidth
- Top processes by network usage
- Top remote addresses
- Top individual connections

Each entry will show the process name instead of `<UNKNOWN>` when the process can be identified.