# Cisco ACL Searcher
Given a configuration file from a Cisco router, this can be used with various flags to search in a number of ways.  This script does NOT support searching Cisco ASAs or any router utilizing object-groups.  It also currently does not support named ACLs.

## Search for ACL Entries That Overlap w/ an IP
The script's primary and most basic usage: given a list of IP addresses and/or networks in CIDR notation, and an input file, it will return the access-list entries that overlap with one of the inputs.  This searches the destination of the rule, by default.  For example,

```
./acl_searcher.py my_acl.txt 10.0.0.113 10.0.1.0/24
```

### Searching Source Instead of Destination
By default, this searches the destination of the rule.  To search for the source instead, add the `-s` or `--source` flag.

### Including Lines That Match 'any'
Additionally, by default, rules with the keyword 'any' in the destination (if searching by destination) or in the source (if searching by source) will not be displayed.  To include these in the output, add the `-h` or `--help` flag. 

### Including Comments
The script can also match on and include valid entries that happen to be commented out.  To include these in the output, add the `-c` or `--comments` flag.

## Searching for Invalid Lines
The script will collect and print invalid lines at the end.  Most commonly, these are valid wildcard masks that don't correspond to a subnet netmask.  The router may accept them, but probably won't give the desired behavior.

### Suppressing Invalid Line Output
To suppress this default behavior, add `--q` or `--quiet`.

### Explicitly Searching for Invalid Lines
To only search for invalid lines in the config, rather than searching by IP address or CIDR subnet,  use `-i` or `--invalid`.  For example,

```
./acl_searcher.py -i my_acl.txt 
```

## Searching for Sources or Destinations with the Keyword 'any'
To search for lines that match on any destination, use `-a` or `--any`.  To search for lines that match on any source, include `-s` or `--source` as well.  For example, to match on any lines that match any source, use
```
./acl_searcher.py -a -s my_acl.txt
```

## Ignoring a Section of the Config
If a certain section of the config should be ignored, the script can be given a string to disable searching when seen, and a string to re-enable searching when seen.  These are the `--disable-flag` and `--reenable-flag` arguments, respectively.  To ignore a block of the configuration that starts with "STANDARD CONFIG" and ends with "END STANDARD CONFIG", something like the following example can be used.
```
./acl_searcher.py --disable_flag "STANDARD CONFIG" --reenable-flag "END STANDARD CONFIG" 172.16.8.2
```
