#!/usr/bin/env python3

import sys
import time
import userv

class TestService(userv.ServiceContext):

    def run_main(self):
        print('Daemonized. Now doing the work (which is sleeping).')

        try:
            while True:
                time.sleep(10)
                print('Delightful sleeping time')
        except BaseException as e:
            print('We have been stopped', str(e))
            raise

def main():
    action = sys.argv[1]

    sc = TestService(stdout=sys.stdout,
                     stderr=sys.stderr,
                     pidfile='/tmp/test_userv.pid')

    if action == 'start':
        sc.start()
    elif action == 'stop':
        print(sc.stop())
    elif action == 'restart':
        sc.restart()
    elif action == 'status':
        print(sc.status())
    else:
        print("I don't know what that action is:", action)

main()
