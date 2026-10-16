#!/usr/bin/env python3
"""Fresh sysfs in a disposable virtual-only Network: validate both views."""
import sys
from sysfs_oracle import check_fresh_network


def main():
    check_fresh_network(sys.argv[1])
    print('PASS raw/high-level network lists, symlinks, ifindex and MTU vs rtnetlink')


if __name__ == '__main__':
    main()
