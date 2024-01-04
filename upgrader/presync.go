package main

import (
	"fmt"
	"os"

	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli/v2"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	k8sError "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
)

const (
	UPGRADER_JOB_NAME = "neuvector-upgrader-job"
)

// Get deployment ID from environment variable.
// The ID is generated from sha256(.Values), so it changes when an overrides changes or a new version of charts is available.
func GetHelmDeploymentUID(ctx *cli.Context, client dynamic.Interface, namespace string) (string, error) {
	return os.Getenv("OVERRIDE_CHECKSUM"), nil
}

// Create post-sync job and leave.
func CreatePostSyncJob(ctx *cli.Context, client dynamic.Interface, namespace string, helmDeploymentUID string, withLock bool) error {
	// TODO: Find a better lock mechanism
	if withLock {
		lock, err := CreateLocker(namespace, "neuvector-controller-init-container")
		if err != nil {
			return fmt.Errorf("failed to acquire cluster-wide lock: %w", err)
		}
		lock.Lock()
		defer lock.Unlock()
	}

	var job *batchv1.Job
	item, err := client.Resource(
		schema.GroupVersionResource{
			Resource: "jobs",
			Version:  "v1",
			Group:    "batch",
		},
	).Namespace(namespace).Get(ctx.Context, UPGRADER_JOB_NAME, metav1.GetOptions{})

	if err != nil {
		if !k8sError.IsNotFound(err) {
			return fmt.Errorf("failed to find upgrader job: %w", err)
		}
	} else {
		var resc batchv1.Job
		err = runtime.DefaultUnstructuredConverter.
			FromUnstructured(item.UnstructuredContent(), &resc)
		if err != nil {
			return fmt.Errorf("failed to convert to job: %w", err)
		}
		job = &resc
	}

	if job != nil {
		if job.Annotations["overrides"] == helmDeploymentUID {
			// This is created by the same deployment.
			log.Info("Upgrader job is already created.  Exit.")
			return nil
		}

		log.Info("Old job is detected...Will delete it.")
		background := metav1.DeletePropagationBackground
		err := client.Resource(
			schema.GroupVersionResource{
				Resource: "jobs",
				Version:  "v1",
				Group:    "batch",
			},
		).Namespace(namespace).Delete(ctx.Context, UPGRADER_JOB_NAME, metav1.DeleteOptions{
			PropagationPolicy: &background,
		})
		if err != nil {
			return fmt.Errorf("failed to delete old upgrade job: %w", err)
		}
	}

	// Create a new job now.
	newjob := batchv1.Job{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Job",
			APIVersion: "batch/v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: UPGRADER_JOB_NAME,
			//Labels:      map[string]string{}, // TODO: fill these
			Annotations: map[string]string{
				"overrides": helmDeploymentUID,
			},
		},
		Spec: batchv1.JobSpec{
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Name:      UPGRADER_JOB_NAME,
					Namespace: namespace,
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						corev1.Container{
							Name:            "upgrader",
							Image:           "holyspectral/kubectl",
							Command:         []string{"/bin/bash", "-c", "/upgrader post-sync-hook"},
							ImagePullPolicy: corev1.PullAlways,
							Env: []corev1.EnvVar{
								corev1.EnvVar{
									Name:  "PODNAME",
									Value: os.Getenv("PODNAME"),
								},
								corev1.EnvVar{
									Name:  "OVERRIDE_CHECKSUM",
									Value: os.Getenv("OVERRIDE_CHECKSUM"),
								},
							},
						},
					},
					RestartPolicy: corev1.RestartPolicyNever,
				},
			},
		},
	}

	unstructedJob, err := runtime.DefaultUnstructuredConverter.ToUnstructured(&newjob)
	if err != nil {
		return fmt.Errorf("failed to convert target job: %w", err)
	}

	_, err = client.Resource(
		schema.GroupVersionResource{
			Resource: "jobs",
			Version:  "v1",
			Group:    "batch",
		},
	).Namespace(namespace).Create(ctx.Context, &unstructured.Unstructured{Object: unstructedJob}, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("failed to create upgrade job: %w", err)
	}
	log.Info("post upgrade job is created")
	return nil
}

func PreSyncHook(ctx *cli.Context) error {
	skip := ctx.Bool("skip-cert-creation")

	if skip {
		log.Info("skipping certificate creation")
		return nil
	}

	namespace := ctx.String("namespace")
	kubeconfig := ctx.String("kube-config")

	log.Info("Creating k8s client")

	client, err := NewK8sClient(kubeconfig)
	if err != nil {
		return fmt.Errorf("failed to create k8s client: %w", err)
	}

	log.Info("Getting this pod's owner UID")

	deploymentUID, err := GetHelmDeploymentUID(ctx, client, namespace)
	if err != nil {
		return fmt.Errorf("failed to get this pod's owner UID: %w", err)
	}

	log.WithField("uid", deploymentUID).Info("retrieved helm deployment UID successfully")

	log.Info("Creating cert upgrade job")
	if err := CreatePostSyncJob(ctx, client, namespace, deploymentUID, true); err != nil {
		return fmt.Errorf("failed to create post sync job: %w", err)
	}

	// Check if we've had internal certs created.  If not, retry later.
	_, err = os.Stat("/etc/neuvector/certs/internal/ca.cert")
	if err != nil {
		return fmt.Errorf("failed to find internal cert. Upgrader should create it and trigger rolling update.  Retry later: %w", err)
	}

	log.Info("Completed")
	return nil
}
