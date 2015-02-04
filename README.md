# Tcp Traffic Analysis


-Analyzed a traffic trace (about 61 MB) containing more than 2,000,000 packets using C++.
-Calculated average bit rate, average bit rate for every five minute window, distribution of packets based on payload sizes and also found the top 3 destination and source ports based on traffic volume on each port.
-Performed load balancing using round-robin and then developed a new scheme using hashing for load balancing while also avoiding out of order packet delivery.
