'''
Read QR code and verify.

Depedencies:
pyzbar
openCV

Special thanks: Caihao.Cui for openCV reading
'''

from __future__ import print_function

import pyzbar.pyzbar as pyzbar
import numpy as np
import cv2
import time
from bitsign_qr import get_message, verify_message


# get the webcam:  
cap = cv2.VideoCapture(0)

cap.set(3,640)
cap.set(4,480)
time.sleep(2)

def decode(im) : 
    # Find barcodes and QR codes
    decodedObjects = pyzbar.decode(im)
    # Print results
    for obj in decodedObjects:
        print('Type : ', obj.type)
        print('Data : ', obj.data,'\n')     
    return decodedObjects


font = cv2.FONT_HERSHEY_SIMPLEX

while(cap.isOpened()):
    # Capture frame-by-frame
    ret, frame = cap.read()
    # Our operations on the frame come here
    im = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
         
    decodedObjects = decode(im)

    for decodedObject in decodedObjects: 
        points = decodedObject.polygon
     
        # If the points do not form a quad, find convex hull
        if len(points) > 4 : 
          hull = cv2.convexHull(np.array([point for point in points], dtype=np.float32))
          hull = list(map(tuple, np.squeeze(hull)))
        else : 
          hull = points;
         
        # Number of points in the convex hull
        n = len(hull)     
        # Draw the convext hull
        for j in range(0,n):
          cv2.line(frame, hull[j], hull[ (j+1) % n], (255,0,0), 3)

        print('Type : ', decodedObject.type)
        print('Data : ', decodedObject.data,'\n')

        data = decodedObject.data
        type = decodedObject.type

        if len(decodedObject) > 0:
            cap.release()
            cv2.destroyAllWindows()
        else:
            print('Error decodedObject len')
               
    # Display screen
    cv2.imshow('frame',frame)
    key = cv2.waitKey(1)  

data = data.split(' ')

btc_address = data[0]
tx_hash = data[1]

text = raw_input('Enter Name: ')

message = get_message(tx_hash)

print ('Verify: ',verify_message(btc_address, message, text))
print ('Approved by: ', btc_address)