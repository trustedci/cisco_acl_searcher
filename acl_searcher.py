#!/usr/bin/env python

import re
import sys
import argparse
from netaddr import IPAddress, IPNetwork, IPSet, AddrFormatError


class VerboseParser(argparse.ArgumentParser):
    def error(self, message):
        self.print_help()
        sys.stderr.write('\n** Error: %s\n' % message)
        sys.exit(2)


def return_source(match):
    if match.group('sourceany'):
        return ANY
    elif match.group('sourcehost'):
        return IPSet(IPNetwork('%s/32' % m.group('sourcehost')))
    elif match.group('sourcenet'):
        return IPSet(IPNetwork('%s/%s' % tuple(m.group('sourcenet').split())))


def return_dest(match):
    if match.group('destany'):
        return ANY
    elif match.group('desthost'):
        return IPSet(IPNetwork('%s/32' % m.group('desthost')))
    elif match.group('destnet'):
        return IPSet(IPNetwork('%s/%s' % tuple(m.group('destnet').split())))


if __name__ == '__main__':

    parser = VerboseParser()
    parser.add_argument('infile', type=argparse.FileType('r'), help='input file to parse')
    parser.add_argument('-v', '--verbose', action='store_true', help='include \'any\'s as matches', default=False)
    parser.add_argument('-s', '--source', action='store_true', help='search by source rather than destination IP',
                        default=False)
    parser.add_argument('-c', '--comments', action='store_true', help='include commented out entries', default=False)
    parser.add_argument('ip', nargs='*', help='device IP address(es) [ignored if -i or -a specified]')
    arg_group = parser.add_mutually_exclusive_group()
    arg_group.add_argument('-i', '--invalid', action='store_true', help='display only invalid lines', default=False)
    arg_group.add_argument('-a', '--any', action='store_true', help='display only lines with ' +'an \'any\'',
                           default=False)
    arg_group.add_argument('-q', '--quiet', action='store_true', help='suppress invalid lines output', default=False)
    parser.add_argument('--disable-flag', metavar='FLAG', type=str, default='',
                        help='stop searching until the reenable flag is hit')
    parser.add_argument('--reenable-flag', metavar='FLAG', type=str, default='',
                        help='reenable searching when this flag is seen')
    args = parser.parse_args()

    VERBOSE = args.verbose
    SEARCH_DEST = not args.source
    INCLUDE_COMMENTS = args.comments
    ONLY_INVALID = args.invalid
    ONLY_ANY = args.any
    QUIET = args.quiet

    DISABLE_SEARCH, START_SEARCH = False, False
    if args.disable_flag:
        DISABLE_SEARCH = True
        DISABLE_SEARCH_FLAG = args.disable_flag
    if args.reenable_flag:
        START_SEARCH = True
        START_SEARCH_FLAG = args.reenable_flag

    ANY = IPSet(IPNetwork('0.0.0.0/0'))
    invalid_acls, sanity_check = [], []
    searching = True
    sanity = ""

    basic_match = re.compile('^(!\s*)?(access-list [0-9]*\s+)?(permit|deny)')
    acl_match = re.compile('^(!\s*)?(access-list\s[0-9]*\s+)?(permit|deny)\s+(tcp|udp|ip|icmp|\S+)\s+' +
                           '((?P<sourceany>any?)|host\s+(?P<sourcehost>[0-9.]*)|(?P<sourcenet>[0-9.]+\s+[0-9.]+))\s+' +
                           '(((n?eq|gt|lt)\s+\S+\s+)|range\s+\S+\s+\S+\s+)?' +
                           '((?P<destany>any?)|host\s+(?P<desthost>[0-9.]*)|(?P<destnet>[0-9.]+\s+[0-9.]+))')

    # Parse the input IPs/CIDR given to us
    search_ips = IPSet()
    for i in args.ip:
        if '/' in i:
            net = IPNetwork(i)
            search_ips.add(net)
        else:
            search_ips.add(IPAddress(i))

    # Parse each line in the file
    for line in args.infile:
        line = line.rstrip()
        m = acl_match.search(line)

        # Evaluate whether we're within a section we should ignore
        if not searching:
            # If we've currently stopped searching but see the flag to resume, re-enable searching
            if START_SEARCH and START_SEARCH in line:
                searching = True
            # If we've stopped searching and didn't hit a flag to resume, continue
            else:
                continue
        # If we're currently searching and we see the flag to stop searching, stop searching and move on
        elif searching and DISABLE_SEARCH and DISABLE_SEARCH_FLAG in line:
            searching = False
            continue

        # We're processing an ACL line (commented out or no)
        if m:
            if (line.startswith('!') and INCLUDE_COMMENTS) or not line.startswith('!'):
                try:
                    dest = return_dest(m)
                    source = return_source(m)

                    # If we're just looking for invalids, we're done - bad ones will be caught by the exception already
                    if ONLY_INVALID:
                        continue

                    # If we're just looking for 'anys', need to check if it's a source or destination search
                    elif ONLY_ANY:
                        if SEARCH_DEST:
                            if dest == ANY:
                                print line
                        else:
                            if source == ANY:
                                print line

                    # Default search, we're looking for matching destinations
                    elif SEARCH_DEST:
                        # If we're in verbose mode, we don't have to treat 'any' differently
                        if VERBOSE:
                            if search_ips.intersection(dest):
                                print line
                        else:
                            if dest != ANY and search_ips.intersection(dest):
                                print line

                    # Non-default search, we're looking for matching sources
                    elif not SEARCH_DEST:
                        # If we're in verbose mode, we don't have to treat 'any' differently
                        if VERBOSE:
                            if search_ips.intersection(source):
                                print line
                        else:
                            if source != ANY and search_ips.intersection(source):
                                print line

                except AddrFormatError:
                    if not line.startswith('!'):
                        invalid_acls.append(line)

    if not QUIET:
        if invalid_acls:
            print "\nInvalid ACLs"
            print "------------"
            for a in invalid_acls:
                print a