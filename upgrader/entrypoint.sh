#!/bin/sh

# Wait until rollout completes
/kubectl rollout status deployment neuvector-controller-pod
IPs=`/kubectl get pod -n neuvector -l app=neuvector-controller-pod --field-selector=status.phase==Running -o=jsonpath='{.items[*].status.podIPs[*].ip}'`
# TODO: Should only handle new pods.  
echo ${IPs}
for ip in ${IPs}; do
	cat /test.json | /grpcurl -d '@' -vv -import-path / -proto /controller_service.proto -servername NeuVector -cacert /etc/neuvector/certs/internal/grpc/ca.cert -cert /etc/neuvector/certs/internal/grpc/cert.pem -key /etc/neuvector/certs/internal/grpc/key.pem ${ip}:18400 share.ControllerCtrlService.UpdateInternalCerts
done
