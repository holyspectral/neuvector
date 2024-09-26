#!/bin/bash
set -e

STAGE_DIR=stage

machine=$(uname -m)
echo "Machine hardware architecture is \"$machine\""

echo "==> Unitest"
go test github.com/neuvector/neuvector/...

echo "==> Making monitor"
make -C monitor
echo "==> Making nstools"
make -C tools/nstools/
echo "==> Making controller"
make -C controller/
echo "==> Making upgrader"
make -C upgrader/

mkdir -p ${STAGE_DIR}/usr/local/bin/scripts/cis_yamls/
mkdir -p ${STAGE_DIR}/etc/
mkdir -p ${STAGE_DIR}/etc/neuvector/templates
#
cp monitor/monitor ${STAGE_DIR}/usr/local/bin/
cp controller/controller ${STAGE_DIR}/usr/local/bin/
cp upgrader/upgrader ${STAGE_DIR}/usr/local/bin/
cp tools/nstools/nstools ${STAGE_DIR}/usr/local/bin/
#
cp scripts/sysctl.conf ${STAGE_DIR}/etc/
cp scripts/teardown.sh ${STAGE_DIR}/usr/local/bin/scripts/
cp scripts/runtime-gdb.py ${STAGE_DIR}/usr/local/bin/scripts/
#
cp templates/podTemplate.json ${STAGE_DIR}/etc/neuvector/templates/podTemplate.json
cp -r agent/nvbench/kubernetes-cis-benchmark/cis-1.6.0/ ${STAGE_DIR}/usr/local/bin/scripts/cis_yamls/
cp -r agent/nvbench/kubernetes-cis-benchmark/cis-1.23/ ${STAGE_DIR}/usr/local/bin/scripts/cis_yamls/
cp -r agent/nvbench/kubernetes-cis-benchmark/cis-1.24/ ${STAGE_DIR}/usr/local/bin/scripts/cis_yamls/
cp -r agent/nvbench/kubernetes-cis-benchmark/cis-1.8.0/ ${STAGE_DIR}/usr/local/bin/scripts/cis_yamls/
cp -r agent/nvbench/kubernetes-cis-benchmark/cis-k3s-1.8.0/ ${STAGE_DIR}/usr/local/bin/scripts/cis_yamls/
cp -r agent/nvbench/kubernetes-cis-benchmark/gke-1.4.0/ ${STAGE_DIR}/usr/local/bin/scripts/cis_yamls/
cp -r agent/nvbench/kubernetes-cis-benchmark/aks-1.4.0/ ${STAGE_DIR}/usr/local/bin/scripts/cis_yamls/
cp -r agent/nvbench/kubernetes-cis-benchmark/eks-1.4.0/ ${STAGE_DIR}/usr/local/bin/scripts/cis_yamls/
cp -r agent/nvbench/ocp/rh-1.4.0/ ${STAGE_DIR}/usr/local/bin/scripts/cis_yamls/
