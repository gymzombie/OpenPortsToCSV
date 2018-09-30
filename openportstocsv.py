#!/usr/bin/python
#
# It's ugly, I admit.  But it gets the job done.
# Chris Wallace - @ImAnEnabler

import csv
import os
import argparse


parser = argparse.ArgumentParser(description='Script to loop through all grepable nmap files (*.gnmap) in a folder '
                                             'and provide CSV output of IP address, and ports.')
parser.add_argument('--folder', '-f', required=True, help='Name of folder where .gnmap files are located')
args = parser.parse_args()

# Setting initial variables
C_IP = 0
C_TCP = 1
C_UDP = 2
host_list = []

folder_name = args.folder()
filelist = os.listdir(folder_name)


def checkaddr(mlist, maddr):
    for a in mlist:
        if a[C_IP] == maddr:
            return mlist.index(a)
    return -1


def openfiles(filelist):
    """ Open the .gnmap files and creates the output CSV for writing. Turns the .gnmap into a tab delimited array"""
    for file_name in filelist:
        if file_name.endswith(".gnmap"):
            # print("opening: " + file_name)
            csvFile = open(folder_name + file_name)
            csvReader = csv.reader(csvFile, delimiter='\t')
            csvdata = list(csvReader)
            return csvdata


def getinterestingdata(csvdata):
    """Return a list of entire data for the hosts that have open ports"""
    interestingrows = []
    for i in range(len(csvdata)):
        if csvdata[i][0].startswith('Host') and csvdata[i][1].startswith('Ports'):
            interestingrows.append(csvdata[i])
    return interestingrows
    

def gethosts(interestingrows):
    """Get the IP addresses of the hosts with open ports"""
    interestinghosts = []
    for eachhost in range(len(interestingrows)):
        interestinghosts.append(interestingrows[eachhost][0].split(' ')[1])
    return interestinghosts
    
    
def getports(interestingrows):
    """A List of lists consisting of [tcp[port1,port2]][udp[port1,port2]]"""
    interestingports = []
    for eachhost in range(len(interestingrows)):
        # Lets get rid of "Ports:" and the spaces
        interestingports.append(interestingrows[eachhost][1].split(' ')[1:])
        for eachrow in range(len(interestingports)):
            interestingports.split('/')[eachrow]
    return interestingports
      
                                
    hostandports.append(eachhost)
    for eachport in eachhost:
                    

    """if open -> append to List of list of list
    upper protocol
    sort by port
    format
        
     
      [ [[host1],[tcp[port1,port2,port3]],[udp[port1]]],[[host2],[tcp[port1,port2,port3]]]] """
      
      
        
''' gymzombie is trying to replace all this. Hopefully this is no longer used:

def populatescandata(csvdata):
    """Doing the initial population of the CSV file with raw data from the grepable nmap scan results"""
    for i in range(len(csvdata)):
        if csvdata[i][0].startswith('Host') and csvdata[i][1].startswith('Ports'):
            # listHost is literally "each host in the list"
            listHost = csvdata[i][0].split()
            # NEEDHELP: I believe this is checking to see if listHost is empty?
            checkval = checkaddr(host_list, listHost[1])
            # NEEDHELP: Does this ever get called? Based on the checkaddr function, I don't know what would trigger this.
            if checkval == -1:
                m_listitem = [listHost[1], [], []]
                listports = csvdata[i][1][7:].split(',')
                for p in range(len(listports)):
                    # -# uncomment the below if you need to debug
                    # print(p)
                    # print(csvData[i][1][7:])
                    mPorts = listports[p].split('/')
                    if mPorts[1] == 'open':
                        if mPorts[2] == 'tcp':
                            m_listitem[C_TCP].append(int(mPorts[0].strip()))
                        if mPorts[2] == 'udp':
                            m_listitem[C_UDP].append(int(mPorts[0].strip()))
                host_list.append(m_listitem)
            else:
                m_listitem = [listHost[1], [], []]
                listports = csvdata[i][1][7:].split(',')
                for p in range(len(listports)):
                    mPorts = listports[p].split('/')
                    if mPorts[1] == 'open':
                        if mPorts[2] == 'tcp':
                            host_list[checkval][C_TCP].append(int(mPorts[0].strip()))
                        if mPorts[2] == 'udp':
                            host_list[checkval][C_UDP].append(int(mPorts[0].strip()))
            return host_list
'''


def dropdupetcp(host_list):
    """Sorts through TCP ports, dropping duplicates"""
    for line in host_list:
        str_tcp = ''
        if len(line[C_TCP]) > 0:
            list_tcp = list(set(line[C_TCP]))
            list_tcp.sort()
            for i_tcp in list_tcp:
                str_tcp += str(i_tcp) + ', '
            if len(str_tcp) > 0:
                str_tcp = str_tcp[:-2]
    return str_tcp


def dropdupeudp(host_list):
    """Sorts through UDP ports, dropping duplicates"""
    for line in host_list:
        str_udp = ''
        if len(line[C_UDP]) > 0:
            list_udp = list(set(line[C_UDP]))
            list_udp.sort()
            for i_udp in list_udp:
                str_udp += str(i_udp) + ', '
            if len(str_udp) > 0:
                str_udp = str_udp[:-2]
    return str_udp


def prettyoutput(host_list):
    """Converts the raw CSV to human friendly format"""
    str_ip = line[C_IP]
    for line in host_list:
        if len(str_tcp) > 0 and len(str_udp) > 0:
            print('\"' + str_ip + '\",\"TCP: ' + str_tcp + '\nUDP: ' + str_udp + '\"')
        if len(str_tcp) == 0 and len(str_udp) > 0:
            print('\"' + str_ip + '\",\"UDP: ' + str_udp + '\"')
        if len(str_tcp) > 0 and len(str_udp) == 0:
            print('\"' + str_ip + '\",\"TCP: ' + str_tcp + '\"')


def main():
    getinterestinghosts(openfiles(filelist))

    prettyoutput(makenmapgreatagain(


if __name__ == "__main__":
    # execute only if run as a script
    main()
