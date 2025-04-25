#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Utility functions for FortiParser.
"""

def print_table(title, headers, rows):
    """Print an ASCII table given headers and rows of data."""
    cols = len(headers)
    widths = [len(h) for h in headers]
    for r in rows:
        for i, cell in enumerate(r):
            widths[i] = max(widths[i], len(str(cell)))
    sep = '+' + '+'.join('-'*(w+2) for w in widths) + '+'
    print(f"\n{title}")
    print(sep)
    # header
    hrow = '|' + '|'.join(f' {headers[i].ljust(widths[i])} ' for i in range(cols)) + '|'
    print(hrow)
    print(sep)
    # rows
    for r in rows:
        row = '|' + '|'.join(f' {str(r[i]).ljust(widths[i])} ' for i in range(cols)) + '|'
        print(row)
    print(sep) 
