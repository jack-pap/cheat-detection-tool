import subprocess
import sys
import time
import os
import threading
import logging

# In order to run this script make sure that the volatility3 library is in the same directory.
# Provide the process name as a system argument aswell as optionally the number of DLLs used by the process.

processTarget = sys.argv[1] # Process name to find in memory dump
weight = 0 # Weight calculated through plugin output
weightLock = threading.Lock() # Lock for weight variable
id = -1 # Process ID of the processTarget found later
dllCount = -1 # Dll count assigned depending if one was provided 

logging.basicConfig(level=logging.DEBUG, format='[%(asctime)s] %(message)s', datefmt='%H:%M:%S')

def main(): 
    print("====================================================")
    print("|            Starting Anti-Cheat Script            |")
    print("====================================================\n")
    
    global id # Process ID of game
    global dllCount # Number of DLL files used within process
    id = pslistScan()

    # Creates threads for multitasking
    if len(sys.argv) > 2:
        dllCount = int(sys.argv[2])    
        dllThread = threading.Thread(target=dlllistScan)
        dllThread.start()

    # Start threads
    malfindThread = threading.Thread(target=malfindScan)
    vadyaraThread = threading.Thread(target=vadyaraScan)
    malfindThread.start()
    vadyaraThread.start()
    
    # Wait for all threads to finish
    malfindThread.join()
    vadyaraThread.join()
    if len(sys.argv) > 2:
        dllThread.join()

    # Calculated weight and remove temp files
    weightResult(weight)
    os.remove("processes.txt")

# Generates a list of processes running at the time of the execution and writes the list to a text file
def pslistScan():    
    try:
        logging.info("Running windows.pslist to get the memory dump process list....")
        #print(getTime(), "Running windows.pslist to get the memory dump process list....")
        pslistProcess = subprocess.Popen('python volatility3/vol.py -f physmem.raw windows.pslist > processes.txt', stdout=subprocess.PIPE,
                                          stderr=subprocess.PIPE, shell=True) 
        output, error = pslistProcess.communicate()
        pslistProcess.wait()
        if pslistProcess.returncode != 0:
            raise subprocess.CalledProcessError(pslistProcess.returncode, pslistProcess.args, error.decode())
        logging.info("Pslist finished succesfully \n")
    except Exception as e: 
        logging.error("Pslist was unsuccesful: ", "\n", e, "\n", error.decode())
        sys.exit()
    logging.info("Scanning processes.txt to find PID for " + processTarget + "....") 
    with open('processes.txt') as file:
         for line in file:
             if (processTarget in line and line.split()[4] != "0"):
                pid = line.split()[0]
                return pid

# Checks original count of DLL files in process and compares to sys.argv[2]
def dlllistScan():
    global weight
    try:
        logging.info("Running windows.dlllist to get the DLL list for" + processTarget + "....") 
        dlllistProcess = subprocess.Popen('python volatility3/vol.py -f physmem.raw windows.dlllist --pid ' + id , stdout=subprocess.PIPE,
                                          stderr=subprocess.PIPE, shell=True) 
        output, error = dlllistProcess.communicate()
        outstr = output.decode().count('\n') - 4 # For filler lines 
        if dlllistProcess.returncode != 0:
            raise subprocess.CalledProcessError(dlllistProcess.returncode, dlllistProcess.args, error.decode())
        if outstr > dllCount:
            with weightLock:
                weight = weight + 6
            logging.warning("Dlllist found extra DLL files")
        logging.info("Dlllist finished succesfully\n")
    except Exception as e: 
        logging.error("Dlllist was unsuccesful", exc_info=True)
        print(error.decode())
        os._exit(1)

# Checks memory page permissions (write, execute, read)
def malfindScan():
    global weight
    try:
        logging.info("Running windows.malfind to identify memory permissions....")
        malfindProcess = subprocess.Popen('python volatility3/vol.py -f physmem.raw windows.malfind --pid ' + id , 
                                           stdout=subprocess.PIPE , stderr=subprocess.PIPE , shell=True) 
        output, error = malfindProcess.communicate()
        if malfindProcess.returncode != 0:
            raise subprocess.CalledProcessError(malfindProcess.returncode, malfindProcess.args, error.decode())
        outstr = output.decode().count('\n')
        if outstr > 4:
            with weightLock:
                weight = weight + 3
            logging.warning("Malfind found suspicious VAD tags")
        logging.info("Malfind finished succesfully\n")
    except Exception as e: 
        logging.error("Malfind was unsuccesful", exc_info=True)
        print(error.decode())
        os._exit(1)

# Checks for occurrences of known file signatures found in dump
def vadyaraScan():
    global weight
    try:
        logging.info("Running windows.vadyarascan to scan known file signatures....")
        vadyarascanProcess = subprocess.Popen('python volatility3/vol.py -f physmem.raw windows.vadyarascan.VadYaraScan --yara-file yaraRules.yar --pid ' + id ,
                                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
        output, error = vadyarascanProcess.communicate()
        if vadyarascanProcess.returncode != 0:
            raise subprocess.CalledProcessError(vadyarascanProcess.returncode, vadyarascanProcess.args, error.decode())
        outstr = output.decode().count('\n')
        if outstr > 4: 
            with weightLock:          
                weight = weight + 7
            logging.warning("Vadyarascan found file signatures belonging to cheats")
        logging.info("Vadyarascan finished succesfully\n")
    except Exception as e: 
        logging.error("Vadyarascan was unsuccesful", exc_info=True)
        print(error.decode())
        os._exit(1)

# Outputs message based on weight
def weightResult(weight):
    if weight < 5:
        logging.warning("There are little to no indications that cheats are present in the process")
    elif weight < 10:
        logging.warning("There are some indications that point to cheats being present in the process")
    else:
        logging.warning("There are many indications that point to cheats being present in the process")

if __name__ == '__main__':
    main()


