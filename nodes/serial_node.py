#!/usr/bin/env python

import rospy
from rosserial_python_revision import SerialClient
from serial import SerialException
from time import sleep

import sys

if __name__=="__main__":
    rospy.init_node("serial_node")
    rospy.loginfo("ROS Serial Python Revision Node")

    port_name = rospy.get_param('~port','/dev/ttyUSB0')
    baud = int(rospy.get_param('~baud','57600'))
    timeout = float(rospy.get_param('~timeout','1.0'))
    
    isMega2560 = bool(rospy.get_param('~isMega2560','False'))
   
    while not rospy.is_shutdown():
        rospy.loginfo("Connecting to %s at %d baud" % (port_name,baud) )
        try:
            client = SerialClient(port_name, baud, timeout, isMega2560)
            client.run()
        except KeyboardInterrupt:
            break
        except SerialException:
            sleep(1.0)
            continue
        except OSError:
            sleep(1.0)
            continue
        except:
            rospy.logwarn("Unexpected Error: %s", sys.exc_info()[0])
            client.port.close()
            sleep(1.0)
            continue
