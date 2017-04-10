# Author : Ashok Koduru, Parul Singh
# Date   : 8th April 2017
# Task   : UDP Class used as a universal socket API

import socket, threading
import constants as constants


class UDP:
    def __init__(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.handlers = dict()
        self.live_threads = 0
        self.threads = []
        self.running_thread = 0
        self.host = None
        self.content_to_hanger = ""
        self.condition = threading.Condition()
        self.onhang = False

    def start_udp(self, host, hostip, hostport, live_threads):
        self.socket.bind((hostip, hostport))
        self.live_threads = live_threads
        self.host = host
        for each in range(self.live_threads):
            condition = threading.Condition()
            lt = []
            thr = threading.Thread(target=self.send_message, args=(condition, lt))
            thr.daemon = True
            thr.start()
            self.threads.append((thr, condition, lt))

        receiving_thread = threading.Thread(target=self.receive_message)
        receiving_thread.daemon = True
        receiving_thread.start()

    def send_message(self, condition, lt):
        while True:
            condition.acquire()
            if len(lt) == 0:
                condition.wait()
            content = lt.pop()
            condition.release()
            self.handlers[MessageParser.get_message_type(content[0])](self.obj_of_handlers,
                                                                      content[0],
                                                                      content[1])

    def receive_message(self):
        while True:
            content = self.socket.recvfrom(constants.BUFFER_SIZE)
            try:
                if MessageParser.get_message_type(content[0]) in self.handlers:
                    running_thread = self.running_thread
                    thr, condition, lt = self.threads[running_thread]
                    condition.acquire()
                    lt.append(content)
                    condition.notify()
                    condition.release()
                    self.running_thread = (running_thread + 1) % self.live_threads
                else:
                    self.condition.acquire()
                    if self.onhang:
                        self.content_to_hanger = content
                        self.condition.notify()

                    self.condition.release()
            except:
                print "Thread Error"

    def receive(self, timeout):
        self.onhang = True
        self.condition.wait(timeout=timeout)
        self.onhang = False
        if self.content_to_hanger == "":
            self.condition.release()
            raise socket.timeout()
        content = self.content_to_hanger
        self.content_to_hanger = ""
        self.condition.release()
        return content





