package main

import (
	"fmt"
	"os"
	"time"

	"github.com/jrhouston/k8slock"
	log "github.com/sirupsen/logrus"

	"github.com/urfave/cli/v2"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

const (
	TARGET_SECRET_SOURCE_NAME_CACERT = "target-cacert"
	TARGET_SECRET_SOURCE_NAME_CERT   = "target-cert"
	TARGET_SECRET_SOURCE_NAME_KEY    = "target-key"

	// TODO: change file name to align with cert-manger default?
	CACERT_FILENAME = "ca.crt"
	CERT_FILENAME   = "tls.crt"
	KEY_FILENAME    = "tls.key"

	NEW_SECRET_PREFIX    = "new-"
	DEST_SECRET_PREFIX   = "dest-"
	ACTIVE_SECRET_PREFIX = ""
)

// Go 1.14 + client-go  We had below options at design stage:
// 1. Use client-go + Go 1.16 => Need to patch build environment.
// 2. Use client-go + Go 1.14 => Works since we also include kubectl in this executable.
// 3. Use global.ORCH.StartWatchResource + Go 1.14 => should work too, but if we want cache support it will be getting complex.

var (
	ControllerPodLabelSelector = fields.OneTermEqualSelector("app", "neuvector-controller-pod").String()
	ScannerPodLabelSelector    = fields.OneTermEqualSelector("app", "neuvector-scanner-pod").String()
	EnforcerPodLabelSelector   = fields.OneTermEqualSelector("app", "neuvector-enforcer-pod").String()
	RunningPodFieldSelector    = fields.OneTermEqualSelector("status.phase", "Running").String()
)

var (
	ControllerConsulPort = "18300"
	ControllerGRPCPort   = "18400"
	EnforcerGRPCPort     = "18401"
	ScannerGRPCPort      = "18402"
)

func NewK8sClient(kubeconfig string) (dynamic.Interface, error) {
	var err error
	var config *rest.Config
	if len(kubeconfig) > 0 {
		config, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
		if err != nil {
			return nil, fmt.Errorf("failed to build config from kubeconfig: %w", err)
		}
	} else {
		config, err = rest.InClusterConfig()
		if err != nil {
			return nil, fmt.Errorf("failed to read in-cluster config: %w", err)
		}
	}

	return dynamic.NewForConfig(config)
}

func CreateLocker(namespace string, holdername string) (*k8slock.Locker, error) {
	return k8slock.NewLocker(
		"internal-cert-migration-lock",
		k8slock.RetryWaitDuration(time.Second*30),
		k8slock.Namespace(namespace),
		k8slock.TTL(time.Minute*5),
		k8slock.ClientID(holdername),
	)
}

func main() {
	app := cli.NewApp()

	app.Flags = []cli.Flag{
		&cli.StringFlag{
			Name:  "kube-config",
			Value: "",
			Usage: "the active secret used by containers",
		},
		&cli.StringFlag{
			Name:  "namespace",
			Value: "neuvector",
			Usage: "The k8s namespace where NeuVector is running in",
		},
		&cli.StringFlag{
			Name:  "internal-secret-name",
			Value: "neuvector-internal-certs",
			Usage: "the new secret to be applied",
		},
		&cli.BoolFlag{
			Name:  "skip-cert-creation",
			Value: false,
			Usage: "skip cert creation",
		},
	}
	app.Commands = cli.Commands{
		&cli.Command{
			Name:  "pre-sync-hook",
			Usage: "Run neuvector pre sync hook",
			Flags: []cli.Flag{
				&cli.BoolFlag{
					Name:  "force-update-cert",
					Value: false,
					Usage: "Force to create new internal certificates",
				},
				&cli.BoolFlag{
					Name:  "user-managed-cert",
					Value: false,
					Usage: "Whether user manages on their own",
				},
				&cli.StringFlag{
					Name:  "image",
					Value: "",
					Usage: "The image path used by upgrader job",
				},
			},
			Action: PreSyncHook,
		},
		&cli.Command{
			Name:  "post-sync-hook",
			Usage: "Run neuvector post sync hook",
			Flags: []cli.Flag{
				&cli.StringFlag{
					Name:  "certificate-cn",
					Value: "NeuVector",
					Usage: "The common field in internal certificate",
				},
				&cli.DurationFlag{
					Name:  "rollout-timeout",
					Value: 0,
					Usage: "The timeout for waiting deployment to complete",
				},
				&cli.IntFlag{
					Name:  "rsa-key-length",
					Value: 4096,
					Usage: "RSA key length when creating new internal key and certificate",
				},
				&cli.DurationFlag{
					Name:  "expiry-cert-threshold",
					Value: 30 * 24 * time.Hour,
					Usage: "The threshold to automatically upgrade an internal cert",
				},
				&cli.IntFlag{
					Name:  "ca-cert-validity-days",
					Value: 365 * 5, // 5 years
					Usage: "The ca cert's validity period in days",
				},
				&cli.IntFlag{
					Name:  "cert-validity-days",
					Value: 365 * 2, // 2 years
					Usage: "The cert's validity period in days",
				},
				&cli.BoolFlag{
					Name:  "fresh-install",
					Value: false,
					Usage: "Whether it's a fresh install.  When in fresh install mode, upgrader will create certs and bypass the rolling update flow.",
				},
			},
			Action: PostSyncHook,
		},
	}

	if err := app.Run(os.Args); err != nil {
		log.WithError(err).Fatal("failed to run the command")
		os.Exit(1)
	}

}
