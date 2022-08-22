THISDIR := $(notdir $(CURDIR))
PROJECT := $(THISDIR)
OWNER := fabianlee
DOCKER_VER := 1.0.0
#SHELL := /bin/bash
GO := go

run: init get build
	bin/$(PROJECT)

run-adfs: init get build
	ADFS=$(ADFS) ADFS_CLIENT_ID=$(ADFS_CLIENT_ID) ADFS_CLIENT_SECRET=$(ADFS_CLIENT_SECRET) ADFS_SCOPE="$(ADFS_SCOPE)" ./$(PROJECT)

init: 
	echo "initializing project $(PROJECT)..."
	@echo "making sure 'go' executable is in PATH"
	$(GO) version

get:
	$(GO) get

build:
	mkdir -p bin
	$(GO) build -o bin/$(PROJECT)

clean:
	$(GO) clean
	rm -fr bin

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
docker-run-adfs:
	docker run -it --rm \
	--network host \
	-p 8080:8080 \
	-e ADFS=$(ADFS) \
	-e ADFS_CLIENT_ID=$(ADFS_CLIENT_ID) \
	-e ADFS_CLIENT_SECRET=$(ADFS_CLIENT_SECRET) \
	-e ADFS_SCOPE="$(ADFS_SCOPE)" \
	$(OWNER)/$(PROJECT):$(DOCKER_VER) $(PROJECT)

