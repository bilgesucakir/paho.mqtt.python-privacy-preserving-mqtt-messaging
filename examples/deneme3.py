import paho.mqtt.client as mqtt
import time

def on_connect(client, userdata, flags, rc):
 
    if rc == 0:
        print("Connected to broker")
        global Connected                
        Connected = True                
 
    else:
        print("Connection failed")

def on_publish(client, obj, mid):
    print("mid: "+str(mid))

def on_message(client, obj, msg):
    print(msg.topic+" "+str(msg.qos)+" "+str(msg.payload))
 
Connected = False 
broker_address = "172.20.10.2"
client = mqtt.Client("P11")
client.on_connect = on_connect
client.on_publish = on_publish

'''
try:
    client.connect(broker_address) #connect to broker
except:
    print("FAİLED")
    exit(1) #Should quit or raise flag to quit or retry
'''
    
client.connect(broker_address) #connect to broker


client.loop_start() 
while Connected != True:    
    time.sleep(0.1)
if Connected == True:
    client.publish("python/mqtt", "off")
client.disconnect()
client.loop_stop()
