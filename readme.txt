Source code is available in AIS or from this github repo:
https://github.com/vikioza/DP

Installation:

1. Import all dependencies
using pip: requirements.txt
using conda: environment.yaml

2. install TShark (packaged together with the WireShark application)

3. Discover you network interfaces 
Using the jupyter notebook located in src/sniffer/utils/find_interfaces.ipynb
This step may require some trial and error, but you the interface you want to use should probably be labeled either WiFi or Ethernet

4. Add you interface to config
- src/sniffer/config.py class Interfaces
- select the newly added interface in main.py 

Steps 2 through 4 are only required if you intend to run the entire system. 
If you only want to run the data processing or model training modules, step 1 is sufficient

In case of any issues, don't hesitate to contact me at xszabov@stuba.sk

The data and trained models are available from this google drive: 
https://drive.google.com/drive/folders/1Z609_-iVWfKaMMmouIlCn0Oa0XFfTdZd?usp=sharing

Alternatively, you can find them on a USB drive which will be delivered to the thesis supervisor.

Place the models into DP/src/models/saved/
Place data into DP/datasets/ according to the read me in the drive / on the USB

The image data needs to be generated from the .csv files provided on the drive. Follow the details in the attached readme file.
