#
# Makefile for the RBAC LSM
#
obj-$(CONFIG_SECURITY_RBAC) := rbac.o
rbac-y := rbac_lsm.o
