# === General Config ===
DOCKER_COMPOSE = docker compose
COMPOSE_FILE = docker-compose.yml

# === Docker Compose Targets ===
.PHONY: up down restart logs build

up:
	$(DOCKER_COMPOSE) -f $(COMPOSE_FILE) up -d

down:
	$(DOCKER_COMPOSE) -f $(COMPOSE_FILE) down

restart: down up

logs:
	$(DOCKER_COMPOSE) -f $(COMPOSE_FILE) logs -f

build:
	$(DOCKER_COMPOSE) -f $(COMPOSE_FILE) build

# === Bazel Targets ===
.PHONY: bazel-gazelle bazel-build bazel-tidy bazel-test

bazel-gazelle:
	bazel run //:gazelle

bazel-build:
	bazel build //...

bazel-tidy:
	bazel run @rules_go//go -- mod tidy -v

bazel-test:
	bazel test //...

bazel-clean:
	bazel clean

# === Combined Commands ===
.PHONY: init all

init: bazel-gazelle bazel-tidy

all: bazel-gazelle bazel-tidy bazel-build bazel-test