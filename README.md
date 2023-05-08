# rosserial_python_revision

This repo is revised from rosserial_python.

I changed the timeout for re-sync to the device. ( Currently is 1 second )    
The program will restart the serial port when the device is disconnected, it should take about 2 seconds to finish.

If you want to check the connection more frequently,  
not only need to change the timeout in this package but also change the timeout in the device,  
where is located in the node_handle.h with ```SYNC_SECONDS```.

## NOTE

You should install rosserial_msgs.  

```=
sudo apt install ros-noetic-rosserial_msgs
```  