
### Transfer times

Encryption

![plot](./sender_window_size_delayed_encryption.png)
![plot](./receiver_window_size_delayed_encryption.png)

No encryption

![plot](./sender_window_size_no_encryption_stack.png)
![plot](./receiver_window_size_no_encryption_stack.png)

### Packets dumps

[Send data](./send_capture_no_encryption_stack.pcap)

[Receive data](./receive_capture_no_encryption_stack.pcap)

[Optional encryption send](./send_capture_delayed_encryption.pcap)

[Optional encryption receive](./receive_capture_delayed_encryption.pcap)

[Full encryption send and receive](./full_encryption_capture.pcap)


### Flamegraphs

Alloc encryption

![plot](./send_flamegraph.svg)
![plot](./receive_flamegraph.svg)
![plot](./server_flamegraph.svg)

Stack no encryption

![plot](./send_flamegraph_no_encryption_stack.svg)
![plot](./receive_flamegraph_no_encryption_stack.svg)
![plot](./server_flamegraph_no_encryption_stack.svg)