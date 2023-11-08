package main

import (
	"os"

	"github.com/pkg/errors"
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

// Create post-sync job and leave.
func CreatePostSyncJob(ctx *cli.Context, client dynamic.Interface, namespace string, ownerUID string) error {
	// TODO: Find a better lock mechanism
	lock, err := CreateLocker(namespace, "init-container")
	if err != nil {
		return errors.Wrap(err, "failed to acquire cluster-wide lock")
	}
	lock.Lock()
	defer lock.Unlock()

	var job *batchv1.Job
	item, err := client.Resource(
		schema.GroupVersionResource{
			Resource: "jobs",
			Version:  "v1",
			Group:    "batch",
		},
	).Namespace(namespace).Get(ctx.Context, "neuvector-upgrader-job", metav1.GetOptions{})

	if err != nil {
		if !k8sError.IsNotFound(err) {
			return errors.Wrap(err, "failed to find upgrader job")
		}
	} else {
		var resc batchv1.Job
		err = runtime.DefaultUnstructuredConverter.
			FromUnstructured(item.UnstructuredContent(), &resc)
		if err != nil {
			return errors.Wrap(err, "failed to convert to job")
		}
		job = &resc
	}

	if job != nil {
		if job.Labels["owner"] == ownerUID {
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
			return errors.Wrap(err, "failed to delete old upgrade job")
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
			//Annotations: map[string]string{}, // TODO: fill these
		},
		Spec: batchv1.JobSpec{
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Name:      UPGRADER_JOB_NAME,
					Namespace: namespace,
					Labels: map[string]string{
						"owner": ownerUID,
					},
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
		return errors.Wrap(err, "failed to convert target job")
	}

	_, err = client.Resource(
		schema.GroupVersionResource{
			Resource: "jobs",
			Version:  "v1",
			Group:    "batch",
		},
	).Namespace(namespace).Create(ctx.Context, &unstructured.Unstructured{Object: unstructedJob}, metav1.CreateOptions{})
	if err != nil {
		return errors.Wrap(err, "failed to create upgrade job")
	}
	log.Info("post upgrade job is created")
	return nil
}
