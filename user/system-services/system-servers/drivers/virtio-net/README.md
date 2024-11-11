# How to use virtio-net?

## Start the virtio-net driver
After entering the chcore shell, type the following command to start the virtio-net driver.
```
$ virtio-net.bin &
```
After the initialization process has completed, the virtio-net driver will do `ipc_call` to the lwip network stack to add an network interface. You will see the following output if the DHCP process is successful.
```
[lwip] DHCP got
  IP: 10.0.2.15
  Netmask: 255.255.255.0
  Gateway: 10.0.2.2
```
The DHCP process will take a few minutes if you use QEMU user mode networking. Please wait... :)

**Warning:** QEMU user mode networking does not support a number of networking features like ICMP. Certain applications (like ping) may not function properly and the host can not directly access the guest.

## TCP Echo Demo
To access guest from host, we need to use a QEMU option `hostfwd=tcp::1234-:9000`. 
This command will forward the host port 1234 to the guest port 9000.

Then launch the TCP Echo Server in the guest by running the following command
```
$ tcp_echo_server.bin [procmgr] Launching /tcp_echo_server.bin...
TCP Server is running at 0.0.0.0:9000
```
To test the TCP Echo Server, run the following command in your host shell:
```
$ telnet localhost 1234
```
