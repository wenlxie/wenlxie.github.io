---
layout: post
tags: cpu, performance, linux 
title: cpu sys usage high
categories: Linux
date: 2022-08-29 10:50:32-0700
excerpt: cpu sys usage high
---

## Phenomenon
When I login into a node to check for a network latency issue. I found a wired issue in one of the nodes. 

* When runs top, two cpu cores are always in cpu high

![](/assets/2022-08-29-cpu-sys-high-cpu-top-busy.png)

sys usage kepts high.

## Debug
* Use perf to check for what these two cpus are busy for

![](/assets/2022-08-29-cpu-sys-high-perf-report.png)

We can see that they are busy do something related with USB.

* Check for dmesg 

```
root@xxxxxxx:~# journalctl -k > kernel
root@xxxxxxx:~# cat kernel |grep -i usb
Jul 12 23:00:37 localhost kernel: ACPI: bus type USB registered
Jul 12 23:00:37 localhost kernel: usbcore: registered new interface driver usbfs
Jul 12 23:00:37 localhost kernel: usbcore: registered new interface driver hub
Jul 12 23:00:37 localhost kernel: usbcore: registered new device driver usb
Jul 12 23:00:37 localhost kernel: ehci_hcd: USB 2.0 'Enhanced' Host Controller (EHCI) Driver
Jul 12 23:00:37 localhost kernel: ohci_hcd: USB 1.1 'Open' Host Controller (OHCI) Driver
Jul 12 23:00:37 localhost kernel: uhci_hcd: USB Universal Host Controller Interface driver
Jul 12 23:00:37 localhost kernel: xhci_hcd 0000:00:14.0: new USB bus registered, assigned bus number 1
Jul 12 23:00:37 localhost kernel: xhci_hcd 0000:00:14.0: new USB bus registered, assigned bus number 2
Jul 12 23:00:37 localhost kernel: xhci_hcd 0000:00:14.0: Host supports USB 3.0 SuperSpeed
Jul 12 23:00:37 localhost kernel: usb usb1: New USB device found, idVendor=1d6b, idProduct=0002, bcdDevice= 5.04
Jul 12 23:00:37 localhost kernel: usb usb1: New USB device strings: Mfr=3, Product=2, SerialNumber=1
Jul 12 23:00:37 localhost kernel: usb usb1: Product: xHCI Host Controller
Jul 12 23:00:37 localhost kernel: usb usb1: Manufacturer: Linux 5.4.0-96-generic xhci-hcd
Jul 12 23:00:37 localhost kernel: usb usb1: SerialNumber: 0000:00:14.0
Jul 12 23:00:37 localhost kernel: hub 1-0:1.0: USB hub found
Jul 12 23:00:37 localhost kernel: usb usb2: New USB device found, idVendor=1d6b, idProduct=0003, bcdDevice= 5.04
Jul 12 23:00:37 localhost kernel: usb usb2: New USB device strings: Mfr=3, Product=2, SerialNumber=1
Jul 12 23:00:37 localhost kernel: usb usb2: Product: xHCI Host Controller
Jul 12 23:00:37 localhost kernel: usb usb2: Manufacturer: Linux 5.4.0-96-generic xhci-hcd
Jul 12 23:00:37 localhost kernel: usb usb2: SerialNumber: 0000:00:14.0
Jul 12 23:00:37 localhost kernel: hub 2-0:1.0: USB hub found
Jul 12 23:00:37 localhost kernel: usb: port power management may be unreliable
Jul 12 23:00:37 localhost kernel: usb usb1-port3: over-current condition

```

There are logs related with USB

* Fix the issue

Actually there are no usb device for that node, so try to unbind the use device to make it recover.

```
root@xxxxxxx:/sys/bus/pci/drivers# cd xhci_hcd/
root@xxxxxxx:/sys/bus/pci/drivers/xhci_hcd# ls
0000:00:14.0  bind  new_id  remove_id  uevent  unbind
root@xxxxxxx:/sys/bus/pci/drivers/xhci_hcd# ls -lah
total 0
drwxr-xr-x  2 root root    0 Jul 12 23:00 .
drwxr-xr-x 30 root root    0 Jul 12 23:00 ..
lrwxrwxrwx  1 root root    0 Aug 10 23:16 0000:00:14.0 -> ../../../../devices/pci0000:00/0000:00:14.0
--w-------  1 root root 4.0K Aug 10 23:16 bind
--w-------  1 root root 4.0K Aug 10 23:16 new_id
--w-------  1 root root 4.0K Aug 10 23:16 remove_id
--w-------  1 root root 4.0K Jul 12 23:00 uevent
--w-------  1 root root 4.0K Aug 10 23:15 unbind
root@xxxxxxx:/sys/bus/pci/drivers/xhci_hcd# echo "0000:00:14.0" > unbind

```

* CPU usage after ubind the usb device

![](/assets/2022-08-29-cpu-sys-high-cpu-usage-normal.png)

## issues left
* What's error log really means for usb driver? And what caused this issue? Is it related with the HW of usb bus?
* Why it caused cpu sys usage high? 
