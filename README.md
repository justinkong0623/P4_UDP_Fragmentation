# P4_UDP_Fragmetation
**Setup on Window Computer**  

1.Create a new project in Programmer Studio.  

![image](https://github.com/user-attachments/assets/96fd70ee-1a34-47af-8375-daaa845fbdf6)  

2.Add UDP_Fragmentation.p4, configuration.p4cfg, and sleep.c to the project.  

3.Change the debug mode from Simulation to Hardware.  

![image](https://github.com/user-attachments/assets/e6e4a9fa-489b-4166-bad6-a22b67af0ca6)  

4.Set the IP address for the SmartNIC.  

![image](https://github.com/user-attachments/assets/6a2af2e4-a551-43d0-9191-e6bb8fef5419)  

5.Modify the build settings as shown below.  

![image](https://github.com/user-attachments/assets/f0ac3785-f1e7-459a-a7dd-d90d4b667a1a)  

6.Rebuild the project (Alt + F7).

**Setup on Linux Computer 1 (with SmartNIC)**  

sudo systemctl start nfp-sdk6-rte  

sudo systemctl start nfp-hwdbg-srv  

sudo make setup  


**Setup on Linux Computer 2 (without SmartNIC)**  

sudo make2  


**Setup on Window Computer**  

Start Debugging (F12)  

