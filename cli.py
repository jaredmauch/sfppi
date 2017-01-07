#!/usr/bin/python

import cmd
import string
import sys
import argparse
import getpass
import os

class wbo_shell(cmd.Cmd):

    def emptyline(self):
        pass

    def help_show(self):
        print "Possible arugments:"
        print " interfaces"
        print " power"
        print " temperature"
        print " transciever"

    def do_show(self, line):
        ''' show some results
            Possible arguments:
                interfaces
                power
                temperature
                transciever'''
        commands = line.split()
        if len(commands) < 2:
            print "Insufficient arguments to show"
            return
        print commands

    def do_exit(self, line):
        return True

    def do_EOF(self, line):
        return True



myUser = getpass.getuser()
myHostName = os.uname()[1]
my_shell = wbo_shell()
my_shell.prompt = myUser + "@" + myHostName + "> "
my_shell.cmdloop()
