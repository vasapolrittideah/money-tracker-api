#!/usr/bin/env bash

set -e

OS="$(uname)"
ARCH="$(uname -m)"

echo "Detected OS: $OS"
echo "Detected Architecture: $ARCH"

install_protobuf() {
  if command -v protoc >/dev/null; then
    echo "✅ protoc is already installed"
    return
  fi

  echo "Installing protoc..."

  if [[ "$OS" == "Darwin" ]]; then
    if ! command -v brew >/dev/null; then
      echo "❌ Homebrew not found. Please install Homebrew first."
      exit 1
    fi
    brew install protobuf
  elif [[ "$OS" == "Linux" ]]; then
    VERSION="24.4"
    PLATFORM="linux-x86_64"
    ARCHIVE_NAME="protoc-${VERSION}-${PLATFORM}.zip"

    TMP_DIR="/tmp/protoc_install"
    mkdir -p "$TMP_DIR"
    cd "$TMP_DIR"

    curl -LO "https://github.com/protocolbuffers/protobuf/releases/download/v${VERSION}/${ARCHIVE_NAME}"
    unzip -o "$ARCHIVE_NAME" -d "$TMP_DIR"

    sudo cp -r bin/* /usr/local/bin/
    sudo cp -r include/* /usr/local/include/

    cd -
    rm -rf "$TMP_DIR"
  elif [[ "$OS" =~ MINGW.* || "$OS" =~ MSYS.* ]]; then
    echo "⚠️ Please install protoc manually on Windows: https://github.com/protocolbuffers/protobuf/releases"
    return
  else
    echo "❌ Unsupported OS for protoc installation"
    exit 1
  fi

  echo "✅ protoc installed"
}

install_bazel() {
  if command -v bazel >/dev/null; then
    echo "✅ Bazel is already installed"
    return
  fi

  echo "Installing Bazel..."
  if [[ "$OS" == "Darwin" ]]; then
    if ! command -v brew >/dev/null; then
      echo "❌ Homebrew not found. Please install Homebrew first."
      exit 1
    fi
    brew install bazelisk
  elif [[ "$OS" == "Linux" || "$OS" == MINGW* || "$OS" == MSYS* ]]; then
    curl -LO https://github.com/bazelbuild/bazelisk/releases/latest/download/bazelisk-linux-amd64
    chmod +x bazelisk-linux-amd64
    sudo mv bazelisk-linux-amd64 /usr/local/bin/bazel
  else
    echo "❌ Unsupported OS for Bazel installation."
    exit 1
  fi
  echo "✅ Bazel installed"
}

install_docker() {
  if command -v docker >/dev/null; then
    echo "✅ Docker is already installed"
    return
  fi

  echo "Installing Docker..."
  if [[ "$OS" == "Darwin" ]]; then
    brew install --cask docker
    echo "⚠️ Please open Docker Desktop manually to complete setup"
  elif [[ "$OS" == "Linux" || "$OS" == MINGW* || "$OS" == MSYS* ]]; then
    curl -fsSL https://get.docker.com -o get-docker.sh
    sudo sh get-docker.sh
    sudo usermod -aG docker "$USER"
    echo "✅ Docker installed. You may need to log out and log in again."
  else
    echo "❌ Unsupported OS for Docker installation."
    exit 1
  fi
}

install_golangci_lint() {
  if command -v golangci-lint >/dev/null; then
    echo "✅ golangci-lint is already installed"
    return
  fi

  echo "Installing golangci-lint..."
  curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(go env GOPATH)/bin v1.59.0
  echo "✅ golangci-lint installed"
}

install_bun() {
  if command -v bun >/dev/null; then
    echo "✅ Bun is already installed"
    return
  fi

  echo "Installing Bun..."
  curl -fsSL https://bun.sh/install | bash
  export PATH="$HOME/.bun/bin:$PATH"
  echo "✅ Bun installed"
}

run_bun_install() {
  if [ -f "bun.lockb" ] || [ -f "package.json" ]; then
    echo "Running bun install to install dependencies..."
    bun install
    echo "✅ bun install completed"
  else
    echo "ℹ️ No Bun project detected (missing package.json or bun.lockb)"
  fi
}

# Main Execution
install_protobuf
install_bazel
install_docker
install_bun
install_golangci_lint

run_bun_install

echo "🎉 All tools installed successfully!"
