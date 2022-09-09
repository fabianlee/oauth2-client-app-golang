THISDIR := $(notdir $(CURDIR))
PROJECT := $(THISDIR)
OWNER := fabianlee
DOCKER_VER := 1.0.0
#SHELL := /bin/bash
GO := go

run: init get build
	bin/$(PROJECT)

init: 
	echo "initializing project $(PROJECT)..."
	@echo "making sure 'go' executable is in PATH"
	$(GO) version

get:
	$(GO) get

build:
	mkdir -p bin
	CGO_ENABLED=0 $(GO) build -o bin/$(PROJECT)

clean:
	$(GO) clean
	rm -fr bin

format:
	gofmt -w main.go

build-cross: build
	env CGO_ENABLED=0 GOOS=linux   GOARCH=amd64 $(GO) build -o bin/$(PROJECT).amd64
	env CGO_ENABLED=0 GOOS=linux   GOARCH=386   $(GO) build -o bin/$(PROJECT).386
	env CGO_ENABLED=0 GOOS=windows GOARCH=amd64 $(GO) build -o bin/$(PROJECT).amd64.exe
	env CGO_ENABLED=0 GOOS=windows GOARCH=386   $(GO) build -o bin/$(PROJECT).386.exe

# build local image
docker-build:
	docker build -t $(OWNER)/$(PROJECT):$(DOCKER_VER) .

# push to docker hub
docker-push:
	docker push $(OWNER)/$(PROJECT):$(DOCKER_VER)

# run image locally on port 8080
docker-run:
	docker run -it --rm \
	--network host \
	-p 8080:8080 \
	-e AUTH_PROVIDER=$(AUTH_PROVIDER) \
	-e AUTH_SERVER=$(AUTH_SERVER) \
	-e CLIENT_ID=$(CLIENT_ID) \
	-e CLIENT_SECRET=$(CLIENT_SECRET) \
	-e SCOPE="$(SCOPE)" \
	-e REALM="$(REALM)" \
	$(OWNER)/$(PROJECT):$(DOCKER_VER) $(PROJECT)

