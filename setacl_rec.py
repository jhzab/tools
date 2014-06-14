#!/usr/bin/python3

import getpass
import imaplib
import argparse
import re

parser = argparse.ArgumentParser(description='Process some integers.')
parser.add_argument('--host', nargs='?',
                    help='Hostname to connect to.')
parser.add_argument('--user', nargs='?',
                    help='Log in username.')
parser.add_argument('--who', nargs='?',
                    help='Which user to give access.')
parser.add_argument('--perm', nargs='?',
                    help='Permissions. Default is: lrwstipekxa')

args = parser.parse_args()

if not args.perm:
    args.perm = "lrwstipekxa"

print("User: " + args.user)
username = args.user

I = imaplib.IMAP4_SSL(host=args.host)
I.login(username, getpass.getpass())
I.select()

if I.list("*")[1] != [None]:
    for m in I.list("*")[1]:
        m = re.search('.*?\s"."\s"*(.+?)"*$', m.decode('utf-8'))
        print(m.group(1))
        I.setacl('"' + m.group(1) + '"', args.who, args.perm)
