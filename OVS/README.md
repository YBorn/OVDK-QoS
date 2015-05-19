# Intel(R) DPDK vSwitch

## What is Intel(R) DPDK vSwitch?

The Intel(R) DPDK Accelerated Open vSwitch (Intel(R) DPDK vSwitch) is a fork
of the open source Open vSwitch multilayer virtual switch found at
[http://openvswitch.org/](openvswitch.org).

For more information on the project, check out the Intel(R) DPDK vSwitch
homepage at [01.org](https://01.org/packet-processing/intel%C2%AE-ovdk).

## Getting Started

To get started right away, we recommend that you check out the latest version
of the [Intel(R) DPDK vSwitch Getting Started Guide][ovdk gsg] hosted on
[01.org][ovdk gsg]. This document gives an in-depth overview of the components,
system requirements and basic operation of Intel(R) DPDK vSwitch.

[ovdk gsg]: https://01.org/downloads/222

## Build Instructions

Three different utilities are necessary to build Open vSwitch: Intel(R) DPDK,
QEMU and Open vSwitch. Of these, DPDK must be built first due to dependencies
in DPDK vSwitch.

 * DPDK

    Refer to the [Intel(R) DPDK Getting Started Guide](http://dpdk.org/doc) for
    a relevant make target, eg:

        cd $(DPDK_DIR)
        make install T=x86_64-ivshmem-linuxapp-gcc

 * Openvswitch

        cd $(OVS_DIR)/openvswitch
        ./boot.sh
        ./configure RTE_SDK=$(DPDK_DIR)
        make

 *  Qemu

        cd $(OVS_DIR)/qemu
        ./configure --enable-kvm --dpdkdir=$(DPDK_DIR) --target-list=x86_64-softmmu
        make

## Further Information

For further information, please check out the Getting Started Guide, or use
the mailing list.

## Contribute

Please submit all questions, bugs and patch requests to the official
[mailing list](https://lists.01.org/mailman/listinfo/dpdk-ovs). For further
information on this process, please refer to the ``CONTRIBUTE`` file.

