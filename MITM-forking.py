#!/usr/bin/env python

import sudo
import socket
import zlib
import httplib
import os
import time
import random
import math
import signal
import traceback

def tryDecompress(response):
    '''For decompressing a gzipped http server response using zlib'''
    magicNum = "\x1f\x8b\x08"
    magicOffset = response.find(magicNum)
    #magicCount = response.count(magicNum)
    if magicOffset > -1:
        try:
            # Ignore the 10-byte gzip file header and try to decompress the rest
            gunzipped = zlib.decompress(response[magicOffset+10:], -15)
            print os.getpid(), ": Decompress complete."
            return gunzipped
        except zlib.error as e:
            print e
            return response
    else:
        return response

def tamper(data):
    ''' Inject our own content/remove theirs as proof of concept '''
    targets = {
        '</html>':
        '<h1>BenHallBenHallBenHallBenHallBenHallBenHallBenHallBenHall</h1></html>',
        '<script':
        '<!--script',
        '</script>':
        '</script-->'
        
        }
    keys = targets.keys()
    for n in range(len(keys)):
        data = data.replace(keys[n], targets[keys[n]])
    return data

def cleanup(REDIR_APP, PROXY_PORT):
    ''' Called on unhandled exception or keyboard interrupt '''
    print "\n*************** FATAL:\n"
    traceback.print_exc()
    # Stop redirecting traffic to this app
    sudo.sudo('iptables -t nat -D OUTPUT -p tcp --dport 80 -m owner --uid-owner %s -j REDIRECT --to-ports %s'%(REDIR_APP, PROXY_PORT))
    print "\n***Removed iptables proxy settings"
    print "DONE"

def killChildProcs():
    ''' Get a sorted list of all forked child process ID's '''
    thisPid = os.getpid()
    if thisPid == parentPid:
        # We're in the parent. Open a socket to listen
        # for connects from child processes.
        parentSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        parentSock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        parentSock.bind(('127.0.0.1', 14001))
        parentSock.listen(1)
        childPids = []
        while len(childPids) < MAX_PROCS-1:
            commSock = parentSock.accept()[0]
            childPid = commSock.recv(24)
            childPids.append(childPid)
        parentSock.close()
        childPids.sort()
        print ">> Worker PIDs:", childPids
        print "Killing", killNum, "processes"
        for n in range(killNum):
            os.kill(int(childPids[n]), signal.SIGKILL)
            ret = os.wait()
            print "Killed pid:", ret
    if thisPid != parentPid:
        ## We're in a child, get our pid and send it to the parent.
        # Generate a random float <= 0.50 as a wait time
        # before trying to connect to parent socket to reduce resource contention.
        random.seed(thisPid)
        # Yields: 0 <= wait <=0.50
        wait = abs(round(random.random(), 2) - 0.50)
        time.sleep(wait)
        childSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        childSock.connect(('127.0.0.1', 14001))
        childSock.send(str(thisPid))
        childSock.close()

def printError(actionTried, remoteHost, error):
        print '\n', os.getpid(), ': %s: %s'%(actionTried, remoteHost)
        print error, '\n'

def handle(listener):
    try:
        clientPipeline = listener.accept()[0]
        clientPipeline.settimeout(None)
        # TODO: may need to make this a while loop for large receives, i.e. POST data
        request = clientPipeline.recv(32768)
        requestLines = request.split('\r\n')
        #print requestLines[0]
        requestHeaders = {}
        for n in range(1, (len(requestLines)-2)):
            temp = requestLines[n].split(': ')
            #print temp
            if len(temp) == 2:
                requestHeaders[temp[0]] = temp[1]
        if 'Host' in requestHeaders:
            remoteHost = requestHeaders["Host"]
            # Dropping traffic to Google analytics
            if remoteHost.find("google-anal") == -1:
                method = request.split(' ')[0]
                url = request.split(' ')[1].split(' ')[0]
                conn = httplib.HTTPConnection(remoteHost, 80, timeout=30)
                try:
                    conn.connect()
                except Exception as e:
                    printError('Error connecting to', remoteHost, e)
                try:
                    conn.request(method, url, None, requestHeaders)
                except Exception as e:
                    printError('Error making request to', remoteHost, e)
                data = ''
                try:
                    response = conn.getresponse()
                    data = response.read()
                except Exception as e:
                    printError('Error getting response from', remoteHost, e)
                
                conn.close()
                #print repr(data[:768])
                #responseHeaders = response.getheaders()
                #print repr(responseHeaders)
                data = tryDecompress(data)
                #data = tamper(data)
                try:
                    result = clientPipeline.sendall(data)
                    if result == None:
                        clientPipeline.close()
                except Exception as e:
                    print "Error returning data to client:", e
    except Exception:
        print
        traceback.print_exc()
        print
try:
    # TODO: single port may be fragile on some systems, provide several posssibilities
    PROXY_PORT = 13998
    PROXY_ADDR = ''
    REDIR_APP = 'app_152'
    sudo.sudo('iptables -t nat -F OUTPUT')
    sudo.sudo('iptables -t nat -A OUTPUT -p tcp --dport 80 -m owner --uid-owner %s -j REDIRECT --to-ports %s'%(REDIR_APP, PROXY_PORT))
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((PROXY_ADDR, PROXY_PORT))
    listener.settimeout(None)
    listener.listen(1)
    print '\n>> Now listening on port: %s'%PROXY_PORT
    parentPid = os.getpid()
    print ">> Parent PID:", parentPid
    # forks:  1, 2, 3,  4,  5,  6,   7
    # procs:  2, 4, 8, 16, 32, 64, 128
    # User selectable; maximum nuimber of processes to use
    USER_MAX_PROCS = 6
    forks=0
    procs=1
    while procs < USER_MAX_PROCS:
        procs += 2**forks
        forks += 1
    print forks
    print "Forking", forks, "times"
    MAX_PROCS = 2**forks
    killNum = MAX_PROCS - USER_MAX_PROCS    
    print '>> Worker processes:', USER_MAX_PROCS-1
    for n in range(forks):
        os.fork()
    killChildProcs()
    while 1:
        handle(listener)

except KeyboardInterrupt:
    if os.getpid() == parentPid:
        cleanup(REDIR_APP, PROXY_PORT)
