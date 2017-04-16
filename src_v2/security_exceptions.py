import sys,os
class SecurityException(Exception):
    def __init__(self,exception_msg):
        super(SecurityException,self).__init__(exception_msg)
        self.exception_msg=exception_msg

def do_stuff():
    try:
        if 1==1:
            raise SecurityException("exception occured")
        else:
            print "nothing"
    except Exception as e:
        print str(e.message)
    input=raw_input('enter')
    print input



do_stuff()