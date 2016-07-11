#!/usr/bin/env python3
# Matt's DNS management tool
# Manage DNS using DDNS features
#
# See http://planetfoo.org/blog/archive/2012/01/24/a-better-nsupdate/
#
# Usage: dnsupdate -s server -k key -t ttl add _minecraft._tcp.mc.example.com SRV 0 0 25566 mc.example.com.
# -h HELP!
# -s the server
# -k the key
# -t the ttl
# the action (add, delete, replace) and record specific parameters

import argparse
import re
import dns
import dns.query
import dns.tsigkeyring
import dns.update
import dns.reversename
import dns.resolver
import socket
import os

VERBOSE = False


def get_args():
    args = argparse.ArgumentParser(
        description='Add, delete, update DNS records using DDNS.')
    subparsers = args.add_subparsers(help='sub-command help')

    args.add_argument('-s', '--server', dest='server', required=True,
                      help='DNS server to update (Required)')

    args.add_argument('-k', '--key', dest='key', required=True,
                      help='TSIG key. The TSIG key file should be in DNS KEY record format. (Required)')

    args.add_argument('-o', '--origin', dest='origin', required=False,
                      help='Specify the origin. Optional, if not provided origin will be determined')

    args.add_argument('-p', '--ptr', dest='ptr', action='store_true', default=False,
                      help='Also modify the PTR for a given A or AAAA record. Forward and reverse zones must be on the same server.')

    args.add_argument('-v', '--verbose', dest='verbose', action='store_true',
                      help='Print the rcode returned with for each update')

    args.add_argument('-t', '--ttl', dest='ttl', required=False,
                      default="86400",
                      help='Specify the TTL. Optional, if not provided TTL will be default to 86400 (1 day).')

    add_parser = subparsers.add_parser('add', help='Add new entry')
    add_parser.add_argument('hostname', help='Hostname to update')
    add_parser.add_argument('type', help='Type of the to be changed record: A, PTR, CNAME, ...')
    add_parser.add_argument('target',
                            help='FQDN or IP address of the target')
    add_parser.set_defaults(func=add)

    update_parser = subparsers.add_parser('update',
                                          help='Update an existing entry')
    update_parser.add_argument('hostname', help='Hostname to update')
    update_parser.add_argument('type', help='Type of the to be changed record: A, PTR, CNAME, ...')
    update_parser.add_argument('target',
                               help='FQDN or IP address of the target')
    update_parser.set_defaults(func=update)

    delete_parser = subparsers.add_parser('delete', help='Delete an entry')
    delete_parser.add_argument('hostname', help='Hostname to remove')
    delete_parser.add_argument('type', help='Type to remove')
    delete_parser.add_argument('target', help='Target to remove')
    delete_parser.set_defaults(func=delete)

    my_args = args.parse_args()
    return my_args


def is_valid_type(t):
    if t == 'A' or t == 'AAAA' or t == 'PTR' or t == 'CNAME' or t == 'MX':
        return True
    else:
        return False


def get_ttl(TTL):
    try:
        TTL = dns.ttl.from_text(TTL)
        return TTL
    except Exception as e:
        print('TTL:', TTL, 'is not valid', e)
        raise e


def is_valid_ptr(ptr):
    if re.match(r'\b(?:\d{1,3}\.){3}\d{1,3}.in-addr.arpa\b', ptr):
        return True
    else:
        print('Error:', ptr, 'is not a valid PTR record')
        return False


def is_validv4_addr(Address):
    try:
        dns.ipv4.inet_aton(Address)
    except:
        print('Error:', Address, 'is not a valid IPv4 address')
        return False
    return True


def is_validv6_addr(Address):
    try:
        dns.ipv6.inet_aton(Address)
    except SyntaxError:
        print('Error:', Address, 'is not a valid IPv6 address')
        return False
    return True


def is_resolvable(host):
    try:
        socket.gethostbyname(host)
    except:
        print('Error:', host, 'is not a valid FQDN')
        return False
    return True


def is_valid_name(fqdn):
    is_valid = re.match("^(([a-zA-Z]|[a-zA-Z][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z]|[A-Za-z][A-Za-z0-9\-]*[A-Za-z0-9])[.]?$", fqdn)

    if is_valid is not None:
        return True
    else:
        return False


# mainly interested in A, CNAME and PTR records
def add(key, args):
    origin, hostname = parse_name(args.origin, args.hostname)
    fqdn = hostname + "." + origin
    ttl = get_ttl(args.ttl)

    if args.type == 'PTR':
        if not is_valid_ptr(fqdn):
            raise Exception("Not a valid ptr: %s" % fqdn)

        if not is_valid_name(args.target):
            raise Exception(
                "Not a valid target fqdn for PTR: %s" % args.target)

        __add(origin, hostname, args.target, ttl, args.type, args.server, key)

    if args.type == 'CNAME':
        if not is_valid_name(fqdn):
            raise Exception("FQDN is not valid: %s" % fqdn)
        if not is_resolvable(args.target):
            raise Exception("Target of CNAME is not resolvable: %s" % args.target)

        __add(origin, hostname, args.target, ttl, args.type, args.server, key)

    if args.type == 'A':
        if not is_validv4_addr(args.target):
            raise Exception("Target isn't a valid IPv4 address: %s" % args.target)

        __add(origin, hostname, args.target, ttl, args.type, args.server, key)

        if args.type == 'A' and args.ptr:
            ptr = gen_ptr(args.target).to_text()
            ptr_origin, ptr_name = parse_name(None, ptr)
            __add(ptr_origin, ptr_name, hostname + '.' + origin,
                  ttl, 'PTR', args.server, key)


def __add(origin, hostname, target, ttl, _type, server, key):
    update = dns.update.Update(origin, keyring=key)
    update.add(hostname, ttl, _type, target)
    run_update(update, server)


def update(key, algo, args):
    pass


def delete(key, args):
    origin, hostname = parse_name(args.origin, args.hostname)

    __delete(origin, hostname, args.server, key)
    if args.ptr:
        if args.type == 'A' and is_validv4_addr(args.target):
            ptr = gen_ptr(args.target).to_text()
            ptr_origin, ptr_name = parse_name(None, ptr)
            __delete(ptr_origin, ptr_name, args.server, key)
        else:
            print("Target isn't a correct IPv4 address,",
                  "could not remove PTR record.")
            exit(-1)


def __delete(origin, hostname, server, key):
    print("Removing origin: %s hostname: %s" % (origin, hostname))
    update = dns.update.Update(origin, keyring=key)
    update.delete(hostname)
    run_update(update, server)


def get_key(keypath):
    if os.access(keypath, os.R_OK):
        with open(keypath) as keyfile:
            buf = keyfile.readline()
            data = buf.split(' ')
            b = {data[0]: data[6] + ' ' + data[7]}
            try:
                return dns.tsigkeyring.from_text(b)
            except Exception as e:
                print("File is not a valid key: %s" % keypath)
                raise e
    else:
        raise Exception("Cannot access key file: %s" % keypath)


def gen_ptr(Address):
    try:
        a = dns.reversename.from_address(Address)
    except:
        print('Error:', Address, 'is not a valid IP adresss')
        return None
    return a


def parse_name(origin, hostname):
    try:
        n = dns.name.from_text(hostname)
    except:
        print('Error:',  n, 'is not a valid name')
        exit()
    if origin is None:
        origin = dns.resolver.zone_for_name(n)
        hostname = n.relativize(origin)
        return origin.to_text(), hostname.to_text()
    else:
        try:
            origin = dns.name.from_text(origin)
        except:
            print('Error:',  hostname, 'is not a valid origin')
            exit()
        hostname = n - origin
        return origin.to_text(), hostname


def doUpdate(args):
    # Sanity check the data and get the action and record type
    action, _type = verify_input(my_input)
    ttl = is_valid_TTL(TimeToLive)
    # Get the hostname and the origin
    Origin, name = parse_name(Origin, my_input[1])
    # Validate and setup the Key
    keyring, keyalgo = get_key(KeyFile)
    # Start constructing the DDNS Query
    update = dns.update.Update(Origin, keyring=keyring,
                               keyalgorithm=getattr(dns.tsig, keyalgo))
    # Put the payload together.
    my_payload = ''  # Start with an empty payload.
    do_ptr = doPTR

    if _type == 'A' or _type == 'AAAA':
        my_payload = my_input[3]
        if doPTR == True:
            ptr_target = name.to_text() + '.' + Origin.to_text()
            ptr_origin, ptr_name = parse_name(None, genPTR(my_payload).to_text())
            ptr_update = dns.update.Update(ptr_origin, keyring=keyring)
    if action != 'del' and _type == 'CNAME' or _type == 'NS' or _type == 'TXT' or _type == 'PTR':
        my_payload = my_input[3]
        do_ptr = False
    elif type == 'SRV':
        my_payload = my_input[3] + ' ' + my_input[4] + ' ' + my_input[5] + ' ' + my_input[6]
        do_ptr = False
    elif type == 'MX':
        my_payload = my_input[3]+' '+my_input[4]
        do_ptr = False
    elif type == 'CNAME':
        do_ptr = False
    # Build the update
    if action == 'add':
        update.add(name, ttl, _type, my_payload)
        if do_ptr is True and _type:
            ptr_update.add(ptr_name, ttl, 'PTR', ptr_target)
    elif action == 'delete' or action == 'del':
        if my_payload != '':
            update.delete(name, _type, my_payload)
        else:
            update.delete(name)

        if do_ptr is True and (_type == 'A' or _type == 'AAAA'):
            ptr_update.delete(ptr_name, 'PTR', ptr_target)
        else:
            do_ptr = False
    elif action == 'update':
        update.replace(name, ttl, _type, my_payload)
        if doPTR is True:
            ptr_update.replace(ptr_name, ttl, 'PTR', ptr_target)


def run_update(update, server):
    try:
        response = dns.query.tcp(update, server)
    except dns.tsig.PeerBadKey as error:
        print('ERROR: The server is refusing our key')
        exit(-1)
    except dns.tsig.PeerBadSignature as error:
        print('ERROR: Something is wrong with the signature of the key')
        exit(-1)
    except socket.error as error:
        print(error)
        exit(error.errno)
    if VERBOSE is True:
        # print('Manipulating', t, 'record for', name,
        #     'resulted in:', dns.rcode.to_text(response.rcode()))
        print(response)


def main():
    args = get_args()
    global VERBOSE
    if args.verbose is True:
        VERBOSE = True
        print(args)

    if not is_resolvable(args.server) and not is_validv4_addr(args.server):
        print("The server argument is neither a valid FQDN nor a valid IPv4 address")
        exit(-1)

    try:
        key = get_key(args.key)

        if hasattr(args, 'func'):
            args.func(key, args)
        else:
            print("You need to supply a command to execute: add, update, del")
    except Exception as error:
        print("Error occured:", error)
        raise error
        exit(-1)

main()
