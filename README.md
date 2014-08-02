WiRover Virtual Network Driver
==============================

The virtNet module introduces a powerful virtual network framework that runs on
top of the Linux network stack.  virtNet enables network-layer link aggregation
across heterogeneous devices, for example, WiFi and cellular devices, with
highly configurable routing behavior.  virtNet can be used to mask IP address
changes and link failures from applications, making it suitable for
implementing mobility solutions.

For more information, please see our 
[project page] (http://research.cs.wisc.edu/wings/projects/wirover/).

Features
--------

 * Network-layer link aggregation across heterogenous devices (eg. WiFi + Cellular).
 * Fine-grained policy-based routing.
 * Extensively configurable behavior through command-line tools (vpolicy and virtnet).

Authors
-------

 * Joshua Hare <hare@cs.wisc.edu>
 * Lance Hartung <hartung@cs.wisc.edu>
 * Suman Banerjee <suman@cs.wisc.edu>

