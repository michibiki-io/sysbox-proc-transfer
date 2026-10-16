#!/usr/bin/env python3
"""Disposable virtual-only sandbox: compare sysfs with independent rtnetlink."""
import sys
from sysfs_oracle import check_network


def main():
    check_network(sys.argv[1])
    print('PASS raw/high-level network lists, symlinks, ifindex and MTU vs rtnetlink')


if __name__ == '__main__':
    main()
