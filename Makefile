# TODO: tag & version
RUNNER := docker
IMAGE_BUILDER := $(RUNNER) buildx
MACHINE := neuvector
BUILDX_ARGS ?= --sbom=true --attest type=provenance,mode=max
DEFAULT_PLATFORMS := linux/amd64,linux/arm64,linux/x390s,linux/riscv64
TARGET_PLATFORMS ?= linux/amd64,linux/arm64

REPO ?= holyspectral


buildx-machine:
	@docker buildx ls | grep $(MACHINE) || \
	docker buildx create --name=$(MACHINE) --platform=$(DEFAULT_PLATFORMS)


push-controller-image: buildx-machine
	$(IMAGE_BUILDER) build -f build/Dockerfile.controller \
		--builder $(MACHINE) $(IMAGE_ARGS) $(IID_FILE_FLAG) $(BUILDX_ARGS) \
		--build-arg VERSION=$(VERSION) --platform=$(TARGET_PLATFORMS) -t "$(REPO)/controller:$(TAG)" --push .
	@echo "Pushed $(IMAGE)"
	
push-enforcer-image: buildx-machine
	$(IMAGE_BUILDER) build -f build/Dockerfile.enforcer \
		--builder $(MACHINE) $(IMAGE_ARGS) $(IID_FILE_FLAG) $(BUILDX_ARGS) \
		--build-arg VERSION=$(VERSION) --platform=$(TARGET_PLATFORMS) -t "$(REPO)/enforcer:$(TAG)" --push .
	@echo "Pushed $(IMAGE)"
