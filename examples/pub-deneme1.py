# publisher
import paho.mqtt.client as mqtt

client = mqtt.Client()
#client = mqtt.Client(client_id="client1") #should be tried with given client id
client.connect('127.0.0.1', 1883)

dontStop = True

inp2 = "Y"
while inp2 == "Y":
    if dontStop:
        while dontStop:
            inp = input('Message (write stopInput to exit): ')
            if inp != "stopInput":
                client.publish("topic/test", inp)
            else:
                dontStop = False
    else:
        inp2 = input("Do you wish to continue publishing? (Y/n)")

        if inp2 == "Y":
            dontStop = True
        
