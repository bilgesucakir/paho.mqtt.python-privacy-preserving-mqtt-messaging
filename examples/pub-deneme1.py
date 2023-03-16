# publisher
import paho.mqtt.client as mqtt

client = mqtt.Client()
client.connect('127.0.0.1', 1883)

while True:
    client.publish("topic/test", input('Message : '))
