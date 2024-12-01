## tracker folder

It contains tracker.cpp file and tracker_info.txt file

tracker.cpp
..........
compilation command: g++ -o tracker tracker.cpp
execution command: ./tracker tracker_info.txt tracker_number

The tracker number specifies which tracker in the tracker_info file should be selected for listening

tracker_info.txt
................
It contains IP and Port addresses of the available trackers in text format as <IP> <PORT>
In our program we are using 2 trackers, so the file contains info of two trackers.

## client folder

It contains client.cpp file

compilation command: g++ -o client client.cpp -lssl -lcrypto -Wno-deprecated-declarations
execution command: ./client <IP>:<PORT> ../tracker/tracker_info.txt

The tracker_info.txt is in tracker folder.
The client reads the tracker_info.txt file and finds the active tracker and connects to it for response of commands
The <IP> and <PORT> mentioned in the command line arguments are used for creating client socket that listens at.
