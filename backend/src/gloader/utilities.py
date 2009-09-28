#!/usr/bin/python

# file: utilities.py

def findIndex(list, key):
    for i in range(len(list)):
        if list[i] == key:
            return i
    return -1

