export default {
  "(services|shared)/**/*.go": (files) =>
    files.flatMap((file) => [
      `golangci-lint fmt ${file}`,
      `golangci-lint run --fix ${file}`,
    ]),
};
