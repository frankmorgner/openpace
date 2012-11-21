"""
Copyright (c) 2010-2012 Dominik Oepen and Frank Morgner

This file is part of OpenPACE.

OpenPACE is free software: you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free
Software Foundation, either version 3 of the License, or (at your option)
any later version.

OpenPACE is distributed in the hope that it will be useful, but WITHOUT ANY
WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
details.

You should have received a copy of the GNU General Public License along with
OpenPACE.  If not, see <http://www.gnu.org/licenses/>.
"""

import os
import sys

from chat import CVC

def hash_dir(dir):
    os.chdir(dir)
    #TODO: Deal with existing symlinks
    files = os.listdir(dir)
    for file in files:
        try:
            cvc = CVC(open(dir + file).read())
            print "Linking " + cvc.get_chr() + " to " + file
            os.symlink(dir + file, cvc.get_chr())
        except Exception:
            pass

if __name__ == "__main__":
    dir = "/home/do/workspace/vsmartcard/npa-example-data/ecdh/"

    if len(sys.argv) > 1:
        dirlist = sys.argv[1:]
    elif os.environ.has_key('SSL_CERT_DIR'):
        dirlist = os.environ['SSL_CERT_DIR'].split(':')
    else:
        dirlist = [os.path.join(dir, '')]

    for d in dirlist:
        if os.path.isdir(d) and os.access(d, os.W_OK):
            hash_dir(d)
