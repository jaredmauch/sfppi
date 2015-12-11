#!/usr/bin/python

import cmd
import string
import sys
import argparse


my_shell = wbo_shell()
my_shell.prompt = myUser + "@" + myHostName + "> "
my_shell.cmdloop()
