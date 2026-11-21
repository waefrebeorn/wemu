#!/bin/sh
# Reproducible local-capability probe for the WEMU EPT / cross-process-isolation
# leg.  Reports kernel, /dev/kvm accessibility, KVM API version, VM creation,
# a few extensions, VT-x/EPT CPU flags, and kernel headers.  Read-only.
set -u
echo "=== kernel ==="; uname -a
echo "=== /dev/kvm node ==="; ls -l /dev/kvm 2>&1 || true
if [ -r /dev/kvm ] && [ -w /dev/kvm ]; then
  echo "dev/kvm: readable+writable"
else
  echo "dev/kvm: NOT usable"; exit 0
fi
echo "=== CPU VT-x / EPT flags ==="
grep -m1 '^flags' /proc/cpuinfo | tr ' ' '\n' | grep -E '^(vmx|svm|ept|npt)$' | sort -u || true
echo "=== kernel headers ==="
ls -d /usr/src/linux-headers-* 2>/dev/null | head -3 || true
ls -l /usr/include/linux/kvm.h 2>&1 || true
echo "=== KVM ioctl probe ==="
TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT HUP INT TERM
cat > "$TMP/probe.c" <<'EOF'
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <linux/kvm.h>
int main(void){
  int fd=open("/dev/kvm",O_RDWR|O_CLOEXEC);
  if(fd<0){perror("open");return 1;}
  printf("KVM_GET_API_VERSION=%d\n",ioctl(fd,KVM_GET_API_VERSION,0));
  printf("KVM_GET_VCPU_MMAP_SIZE=%d\n",ioctl(fd,KVM_GET_VCPU_MMAP_SIZE,0));
  int vm=ioctl(fd,KVM_CREATE_VM,0);
  printf("KVM_CREATE_VM=%d (errno=%d)\n",vm,errno);
  if(vm>=0){
    struct{int c;const char*n;}q[]={
      {KVM_CAP_NR_VCPUS,"NR_VCPUS"},{KVM_CAP_MAX_VCPUS,"MAX_VCPUS"},
      {KVM_CAP_SET_TSS_ADDR,"SET_TSS_ADDR"},{KVM_CAP_NR_MEMSLOTS,"NR_MEMSLOTS"},
      {76,"CAP76"},{77,"CAP77"}};
    for(unsigned i=0;i<sizeof(q)/sizeof(q[0]);i++)
      printf("  cap %-14s (%d)=%d\n",q[i].n,q[i].c,ioctl(fd,KVM_CHECK_EXTENSION,q[i].c));
    close(vm);
  }
  close(fd);return 0;
}
EOF
if command -v gcc >/dev/null 2>&1; then
  gcc -O0 -o "$TMP/probe" "$TMP/probe.c" && "$TMP/probe"
else
  echo "gcc unavailable: skipping ioctl probe"
fi
