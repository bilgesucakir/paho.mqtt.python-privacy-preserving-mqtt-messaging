# subscriber
import paho.mqtt.client as mqtt

client = mqtt.Client()
client.connect('127.0.0.1', 1883)

def on_connect(client, userdata, flags, rc):
    print("Connected to a broker!")
    client.subscribe("topic/test", qos = 2, retain=False )

def on_message(client, userdata, message):
    print(message.payload.decode())

while True:
    client.on_connect = on_connect
    client.on_message = on_message
    client.loop_forever()