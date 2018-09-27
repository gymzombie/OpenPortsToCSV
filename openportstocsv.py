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
file_list = os.listdir(folder_name)


def checkaddr(mlist, maddr):
    for a in mlist:
        if a[C_IP] == maddr:
            return mlist.index(a)
    return -1


def openfiles(filelist):
    """ Open the .gnmap files and creates the output CSV for writing """
    for file_name in filelist:
        if file_name.endswith(".gnmap"):
            # print("opening: " + file_name)
            csvFile = open(folder_name + file_name)
            csvReader = csv.reader(csvFile, delimiter='\t')
            csvData = list(csvReader)
            return csvData


def populatescandata(csvData):
    """Doing the initial population of the CSV file with raw data from the grepable nmap scan results"""
    for i in range(len(csvData)):
        if csvData[i][0].startswith('Host') and csvData[i][1].startswith('Ports'):
            listHost = csvData[i][0].split()
            checkval = checkaddr(host_list, listHost[1])
            if checkval == -1:
                m_listitem = [listHost[1], [], []]
                listPorts = csvData[i][1][7:].split(',')
                for p in range(len(listPorts)):
                    # -# uncomment the below if you need to debug
                    # print(p)
                    # print(csvData[i][1][7:])
                    mPorts = listPorts[p].split('/')
                    if mPorts[1] == 'open':
                        if mPorts[2] == 'tcp':
                            m_listitem[C_TCP].append(int(mPorts[0].strip()))
                        if mPorts[2] == 'udp':
                            m_listitem[C_UDP].append(int(mPorts[0].strip()))
                host_list.append(m_listitem)
            else:
                m_listitem = [listHost[1], [], []]
                listPorts = csvData[i][1][7:].split(',')
                for p in range(len(listPorts)):
                    mPorts = listPorts[p].split('/')
                    if mPorts[1] == 'open':
                        if mPorts[2] == 'tcp':
                            host_list[checkval][C_TCP].append(int(mPorts[0].strip()))
                        if mPorts[2] == 'udp':
                            host_list[checkval][C_UDP].append(int(mPorts[0].strip()))


def makenmapgreatagain(host_list):
    """Converts the raw CSV to human friendly format"""
    for line in host_list:
        str_ip = line[C_IP]
        str_tcp = ''
        str_udp = ''
        if len(line[C_TCP]) > 0:
            list_tcp = list(set(line[C_TCP]))
            list_tcp.sort()
            for i_tcp in list_tcp:
                str_tcp += str(i_tcp) + ', '
            if len(str_tcp) > 0:
                str_tcp = str_tcp[:-2]

        if len(line[C_UDP]) > 0:
            list_udp = list(set(line[C_UDP]))
            list_udp.sort()
            for i_udp in list_udp:
                str_udp += str(i_udp) + ', '
            if len(str_udp) > 0:
                str_udp = str_udp[:-2]
        if len(str_tcp) > 0 and len(str_udp) > 0:
            print('\"' + str_ip + '\",\"TCP: ' + str_tcp + '\nUDP: ' + str_udp + '\"')
        if len(str_tcp) == 0 and len(str_udp) > 0:
            print('\"' + str_ip + '\",\"UDP: ' + str_udp + '\"')
        if len(str_tcp) > 0 and len(str_udp) == 0:
            print('\"' + str_ip + '\",\"TCP: ' + str_tcp + '\"')


def main():
    makenmapgreatagain(populatescandata(openfiles(file_list)))


if __name__ == "__main__":
    # execute only if run as a script
    main()
