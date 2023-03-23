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

 
Connected = False 
broker_address = "127.0.0.1"
client = mqtt.Client(client_id="Client123",  clean_session=True)
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
