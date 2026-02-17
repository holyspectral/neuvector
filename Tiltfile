tilt_settings_file = "./tilt-settings.yaml"
settings = read_yaml(tilt_settings_file)

allow_k8s_contexts(settings.get("clusters"))

update_settings(
    k8s_upsert_timeout_secs=180,
)

# Create the namespace
# This is required since the helm() function doesn't support the create_namespace flag
load("ext://namespace", "namespace_create")
namespace_create("neuvector")

controller_image = settings.get("controller").get("image")

helm_options = [
	"controller.replicas=1",
	"controller.image.repository=" + controller_image,
	"controller.apisvc.type=NodePort",
	"cve.scanner.replicas=0",
	"manager.svc.type=NodePort",
]

yaml = helm(
    "../neuvector-helm/charts/core",
    name="neuvector",
    namespace="neuvector",
    set=helm_options
)

k8s_yaml(yaml)

# Hot reloading containers
local_resource(
    "controller_tilt",
    "make -C controller/",
    deps=[
        "go.mod",
        "go.sum",
        "controller/",
        "share/",
    ],
    ignore=[
        "controller/controller",
    ],
)

entrypoint = ["/controller"]
dockerfile = "./hack/Dockerfile.controller.tilt"

load("ext://restart_process", "docker_build_with_restart")
docker_build_with_restart(
    controller_image,
    ".",
    dockerfile=dockerfile,
    entrypoint=entrypoint,
    # `only` here is important, otherwise, the container will get updated
    # on _any_ file change.
    only=[
        "./controller/controller",
    ],
    live_update=[
        sync("./controller/controller", "/controller"),
    ],
)
