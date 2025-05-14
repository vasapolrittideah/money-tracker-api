export default {
  "(services|shared)/**/*.go": [
    () => "go fmt ./...",
    () => "go vet ./...",
    () => "golangci-lint run",
  ],
};
