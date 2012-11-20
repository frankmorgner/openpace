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
