#!/usr/bin/env python3

from threading import Timer, Lock
from pymetasploit3.msfrpc import ShellSession



class MsfRpcConsoleType:
    Console = 0
    Meterpreter = 1
    Shell = 2


class MsfRpcConsole(object):

    def __init__(self, rpc, token=None, cb=None, num=None):
        """
        Emulates the msfconsole in msf except over RPC.

        Mandatory Arguments:
        - rpc : an msfrpc client object

        Optional Arguments:
        - cb : a callback function that gets called when data is received from the console.
        """

        self.callback = cb
        self.num=num

        if token is not None:
            self.console = rpc.sessions.session(token)
            self.type_ = MsfRpcConsoleType.Shell if isinstance(self.console, ShellSession) else MsfRpcConsoleType.Meterpreter
            self.prompt = '>>> '
            self.callback(dict(data='', prompt=self.prompt), self.num)
        else:
            self.console = rpc.consoles.console()
            self.type_ = MsfRpcConsoleType.Console
            self.prompt = ''

        self.lock = Lock()
        self.running = True
        self._poller()

    def _poller(self):
        self.lock.acquire()
        if not self.running:
            return
        d = self.console.read()
        self.lock.release()

        if self.type_ == MsfRpcConsoleType.Console:
            if d['data'] or self.prompt != d['prompt']:
                self.prompt = d['prompt']
                if self.callback is not None:
                    self.callback(d, self.num)
                else:
                    print(d['data'])
        else:
            if d:
                if self.callback is not None:
                    self.callback(dict(data=d, prompt=self.prompt), self.num)
                else:
                    print(d)
        Timer(0.5, self._poller).start()

    def execute(self, command):
        """
        Execute a command on the console.

        Mandatory Arguments:
        - command : the command to execute
        """
        if not command.endswith('\n'):
            command += '\n'
        self.lock.acquire()
        self.console.write(command)
        self.lock.release()

    def __del__(self):
        self.console.destroy()
        self.running = False
