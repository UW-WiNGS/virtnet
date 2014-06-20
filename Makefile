# 
# Copyright (C) 2014 Joshua Hare, Lance Hartung, and Suman Banerjee.
# 
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
# 

virtNet-deps := virt.c virtIoctl.c virtDevList.c virtEgress.c virtEgressLookup.c virtIngress.c virtStats.c virtProcFs.c virtHeader.c virtFlowTable.c virtParse.c virtNetwork.c virtPolicy.c virtSelectInterface.c virtPassive.c virtRoute.c virtReorder.c virtNAT.c virtPath.c virtHashTable.c virtMemory.c virtCoding.c virtRetransmission.c

# If KERNELRELEASE is defined, we've been invoked from the
# kernel build system and can use its language
ifneq ($(KERNELRELEASE),)
	obj-m := virtNet.o
	virtNet-objs := virt.o virtIoctl.o virtDevList.o virtEgress.o virtEgressLookup.o virtIngress.o virtStats.o virtProcFs.o virtHeader.o virtFlowTable.o virtParse.o virtNetwork.o virtPolicy.o virtSelectInterface.o virtPassive.o virtRoute.o virtReorder.o virtNAT.o virtPath.o virtHashTable.o virtMemory.o virtCoding.o virtRetransmission.o

# otherwise we were called directly from the command
# line; invoke the kernel build system.
else

    # Assume the source tree is where the running kernel was built
    # You should set KERNELDIR in the environment if it's elsewhere
    KERNELDIR ?= /lib/modules/$(shell uname -r)/build
    # The current directory is passed to sub-makes as argument
    PWD := $(shell pwd)

all: virtNet.ko

virtNet.ko: $(virtNet-deps)
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules

clean:
	rm -rf *.o *~ core .depend .*.cmd virtNet.ko *.mod.c *.order .tmp_versions Module.symvers

endif


