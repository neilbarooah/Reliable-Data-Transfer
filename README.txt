Name: Neil Barooah, Tai Tran
Email: neilbarooah@gatech.edu, ttran95@gatech.edu

CS 3251: Networking I
03/16/2018
Programming Assignment 2

Files submitted:
1. Ringo.py - file that implements the reliable data transfers for Ring Network.


Instructions to run:

Tested on networklab machines, using Python 2 on Mac OSX.

Ringo implementation:
1. Open a tab in Terminal and SSH into one of the 8 CoC networklab machines. Run the Ringo.py file with the following command:
	
	python2 ringo.py <flag> <local-port> <PoC-name> <PoC-port> <N>
	Eg: python2 ringo.py S 9090 networklab5 9090 5

2. Repeat this command from the other networklab machines in other tabs based on how many Ringos you’d like in the network. 

3. Note that in case no PoC is provided for a Ringo (<PoC-name> = “0” and <PoC-post> = “0”), the server listens until it hears from another Ringo, at which point it adds that Ringo (and its peers) to it’s own peers and then pings them all to share its list of peers with others. We assume that no PoC is provided for the first Ringo in the network. However, you may include a PoC for it if you wish. We have handled both cases.

4. In case the user inputs the IP address as a hostname, then we convert the input IP address into the network hostname and use it to display in the Ringo.
	
	Eg: Networklab3 has an IP address of `130.207.107.14`, so if the user enters the following command:
	$[networklab4 ~]$: python2 ringo.py S 9090 130.207.107.14 9090 5
	We internally convert the IP address `130.207.107.14` to `networklab3`



OUTPUT:

The following are sample outputs when we run the Ringo program:

$[networklab3 ~]$: python2 ringo.py S 9090 0 0 5

$[networklab4 ~]$: python2 ringo.py S 9090 networklab5 9090 5

$[networklab5 ~]$: python2 ringo.py S 9090 networklab3 9090 5

$[networklab6 ~]$: python2 ringo.py S 9090 networklab4 9090 5

$[networklab7 ~]$: python2 ringo.py S 9090 networklab5 9090 5

Once the networks have discovered all the peers, computed the RTT vectors and RTT Matrix (takes a couple seconds), you will see the prompt “Ringo command.” At this point, you may enter the following input commands:

$Ringo command: show-ring
> Optimal Path: ('networklab3:9090', 'networklab6:9090', 'networklab4:9090', 'networklab5:9090','networklab7:9090') Total RTT: 581.528076171


$Ringo command: show-matrix
                
>		networklab3:9090 networklab4:9090 networklab5:9090 networklab6:9090 networklab7:9090
networklab3:9090      0.0            124.89            81.84            104.59            83.39      
networklab4:9090      118.93            0.0            129.73            172.85            143.89      
networklab5:9090      92.62            144.14            0.0            122.22            98.01      
networklab6:9090      105.45            163.02            126.26            0.0            122.47      
networklab7:9090      86.19            141.07            94.94            127.21            0.0      

