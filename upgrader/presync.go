package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

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
	UPGRADER_JOB_NAME       = "neuvector-upgrader-job"
	UPGRADER_CRONJOB_NAME   = "neuvector-upgrader-pod"
	UPGRADER_UID_ANNOTATION = "upgrader-uid"

	CONTROLLER_LEASE_NAME = "neuvector-controller"
)

// Check controller pods to see if they are all coming from the same owner (ReplicaSet)
// It's more complicated to check if we're doing an upgrade instead of creating a new pod.
// Luckily, we only need this information to speed up cert rotation during fresh install.
func IsFreshInstall(ctx context.Context, client dynamic.Interface, namespace string) (bool, error) {

	// Get all controller pods including those being initialized.
	item, err := client.Resource(
		schema.GroupVersionResource{
			Resource: "pods",
			Version:  "v1",
		},
	).Namespace(namespace).List(ctx, metav1.ListOptions{
		LabelSelector: ControllerPodLabelSelector,
	})
	if err != nil {
		return false, fmt.Errorf("failed to find controller pods: %w", err)
	}

	var pods corev1.PodList
	err = runtime.DefaultUnstructuredConverter.
		FromUnstructured(item.UnstructuredContent(), &pods)
	if err != nil {
		return false, fmt.Errorf("failed to read pod list: %w", err)
	}

	ownerID := ""
	// Examine all controller pods to see if their certificate expires or they're still using legacy certs.
	for _, pod := range pods.Items {
		uid := ""
		if len(pod.OwnerReferences) > 0 {
			uid = string(pod.OwnerReferences[0].UID)
		}

		log.WithFields(log.Fields{
			"pod":      pod.Status.PodIP,
			"ownerUID": uid,
		}).Debug("Getting pod's owner UID")

		if len(pod.OwnerReferences) != 1 {
			// Shouldn't be more than one owner reference...return error in this case.
			return false, errors.New("invalid owner reference are detected")
		}
		if ownerID == "" {
			ownerID = uid
			continue
		}
		if ownerID != uid {
			log.Info("Controller pods belonging to other replicaset is detected.  We're not in a fresh install.")
			return false, nil
		}
	}

	log.Info("All controllers coming from the same replicaset. It's a fresh install.")
	return true, nil
}

// Create post-sync job and leave.
func CreatePostSyncJob(ctx context.Context, client dynamic.Interface, namespace string, upgraderUID string, withLock bool) (*batchv1.Job, error) {
	// Global cluster-level lock with 5 mins TTL
	if withLock {
		lock, err := CreateLocker(namespace, CONTROLLER_LEASE_NAME)
		if err != nil {
			return nil, fmt.Errorf("failed to acquire cluster-wide lock: %w", err)
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
	).Namespace(namespace).Get(ctx, UPGRADER_JOB_NAME, metav1.GetOptions{})

	if err != nil {
		if !k8sError.IsNotFound(err) {
			return nil, fmt.Errorf("failed to find upgrader job: %w", err)
		}
	} else {
		var resc batchv1.Job
		err = runtime.DefaultUnstructuredConverter.
			FromUnstructured(item.UnstructuredContent(), &resc)
		if err != nil {
			return nil, fmt.Errorf("failed to convert to job: %w", err)
		}
		job = &resc
	}

	// Delete existing jobs if it meets certain condition
	if job != nil {

		// Make sure jobs created by other init containers will not be deleted.
		if job.Annotations[UPGRADER_UID_ANNOTATION] == upgraderUID {
			// This is created by the same deployment.
			log.Info("Upgrader job is already created.  Exit.")
			return job, nil
		}

		background := metav1.DeletePropagationBackground
		err := client.Resource(
			schema.GroupVersionResource{
				Resource: "jobs",
				Version:  "v1",
				Group:    "batch",
			},
		).Namespace(namespace).Delete(ctx, UPGRADER_JOB_NAME, metav1.DeleteOptions{
			PropagationPolicy: &background,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to delete old upgrade job: %w", err)
		}
		log.Info("Job from the previous deployment/values is deleted.")
	}

	freshInstall, err := IsFreshInstall(ctx, client, namespace)
	if err != nil {
		return nil, fmt.Errorf("failed to check if it's a fresh install or not: %w", err)
	}

	// Get cron job's template to create job
	item, err = client.Resource(
		schema.GroupVersionResource{
			Resource: "cronjobs",
			Version:  "v1",
			Group:    "batch",
		},
	).Namespace(namespace).Get(ctx, UPGRADER_CRONJOB_NAME, metav1.GetOptions{})

	if err != nil {
		return nil, fmt.Errorf("failed to find upgrader cronjob: %w", err)
	}
	var cronjob batchv1.CronJob
	err = runtime.DefaultUnstructuredConverter.
		FromUnstructured(item.UnstructuredContent(), &cronjob)
	if err != nil {
		return nil, fmt.Errorf("failed to convert to job: %w", err)
	}

	annotations := make(map[string]string)
	annotations["cronjob.kubernetes.io/instantiate"] = "manual"
	annotations[UPGRADER_UID_ANNOTATION] = upgraderUID

	for k, v := range cronjob.Spec.JobTemplate.Annotations {
		annotations[k] = v
	}

	newjob := &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Labels:            cronjob.Spec.JobTemplate.Labels,
			Annotations:       annotations,
			Name:              UPGRADER_JOB_NAME,
			Namespace:         namespace,
			CreationTimestamp: metav1.Time{Time: time.Now()},
			OwnerReferences:   []metav1.OwnerReference{*metav1.NewControllerRef(&cronjob, batchv1.SchemeGroupVersion.WithKind("CronJob"))},
		},
		Spec: cronjob.Spec.JobTemplate.Spec,
	}

	if freshInstall {
		newjob.Spec.Template.Spec.Containers[0].Command = append(newjob.Spec.Template.Spec.Containers[0].Command, "--fresh-install")
	}

	unstructedJob, err := runtime.DefaultUnstructuredConverter.ToUnstructured(&newjob)
	if err != nil {
		return nil, fmt.Errorf("failed to convert target job: %w", err)
	}

	retjob, err := client.Resource(
		schema.GroupVersionResource{
			Resource: "jobs",
			Version:  "v1",
			Group:    "batch",
		},
	).Namespace(namespace).Create(ctx, &unstructured.Unstructured{Object: unstructedJob}, metav1.CreateOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to create upgrade job: %w", err)
	}

	var ret batchv1.Job
	err = runtime.DefaultUnstructuredConverter.
		FromUnstructured(retjob.UnstructuredContent(), &ret)
	if err != nil {
		return nil, fmt.Errorf("failed to convert to job: %w", err)
	}

	log.Info("Post upgrade job is created")
	return &ret, nil
}

func PreSyncHook(ctx *cli.Context) error {
	namespace := ctx.String("pod-namespace")
	kubeconfig := ctx.String("kube-config")
	secretName := ctx.String("internal-secret-name")
	timeout := ctx.Duration("timeout")

	log.WithFields(log.Fields{
		"namespace":  namespace,
		"kubeconfig": kubeconfig,
		"secretName": secretName,
	}).Info("init container starts")

	client, err := NewK8sClient(kubeconfig)
	if err != nil {
		return fmt.Errorf("failed to create k8s client: %w", err)
	}

	log.Info("Getting helm values check sum")

	valuesChecksum := os.Getenv("OVERRIDE_CHECKSUM")

	timeoutCtx, cancel := context.WithTimeout(ctx.Context, timeout)
	defer cancel()

	var secret *corev1.Secret
	if secret, err = GetK8sSecret(timeoutCtx, client, namespace, secretName); err != nil {
		// The secret is supposed to be created by helm.
		// If the secret is not created yet, it can be automatically retried by returning error.
		if err != nil {
			return fmt.Errorf("failed to find source secret: %w", err)
		}
	}
	secretUID := string(secret.UID)

	log.WithField("checksum", valuesChecksum).Info("Retrieved values sha256 sum successfully")

	log.Info("Creating cert upgrade job")

	// Here we create a UID combined with neuvector-internal-certs's resource ID (created/deleted via helm)
	// If secret.UID is changed, that means this is a different deployment, so we have to delete the existing job.
	// If the deploymentUID, which is a sha256 sum of all helm values, changes, we do the same thing.
	// If this UID is the same, skip the job creation.
	if _, err := CreatePostSyncJob(timeoutCtx, client, namespace, secretUID+valuesChecksum, true); err != nil {
		return fmt.Errorf("failed to create post sync job: %w", err)
	}

	// At this point, we should have a job is running.
	// Let's wait until the job exits or this container gets restarted.  If we exit here, it would cause race condition.

	log.Info("Completed")
	return nil
}
