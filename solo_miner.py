import os
from signal import signal, SIGINT
import context as ctx
import traceback
import threading
import requests
import binascii
import hashlib
import logging
import random
import socket
import time
import json
import sys
from multiprocessing import Process

# Input your Bitcoin Address
myname = input("What is the miner's name you want to appear at the pool's GUI? : ")
address = input("Input your BTC address : ")
password = input("Input password for auto authentication : ")
pool_address = input("Input pool URL : ")
pool_port = input("Input the port to connect to : ")


def handler(signal_received, frame):
    # Handle any cleanup hereF
    ctx.fShutdown = True
    print('Terminating miner, please wait..')


def logg(msg):
    # basic logging
    # include timestamp
    logging.basicConfig(level=logging.INFO, filename="miner.log", format='%(asctime)s %(message)s')
    logging.info(msg)


def get_current_block_height():
    # returns the current network height 
    r = requests.get('https://blockchain.info/latestblock')
    return int(r.json()['height'])


def calculate_hash_rate(nonce, last_updated):
    if nonce % 1000000 == 999999:
        now = time.time()
        hash_rate = round(1000000 / (now - last_updated))
        sys.stdout.write("\r%s hash/s" % (str(hash_rate)))
        sys.stdout.flush()
        return now
    else:
        return last_updated


def check_for_shutdown(t):
    # handle shutdown 
    n = t.n
    if ctx.fShutdown:
        if n != -1:
            ctx.list_of_Threads_Running[n] = False
            t.exit = True
            sys.exit(t)


class ExitedThread(threading.Thread):
    def __init__(self, arg, n):
        super(ExitedThread, self).__init__()
        self.exit = False
        self.arg = arg
        self.n = n

    def run(self):
        self.thread_handler(self.arg, self.n)
        pass

    def thread_handler(self, arg, n):
        while True:
            check_for_shutdown(self)
            if self.exit:
                break
            ctx.list_of_Threads_Running[n] = True
            try:
                self.thread_handler2(arg)
            except Exception as e:
                logg("ThreadHandler()")
                logg(e)
            ctx.list_of_Threads_Running[n] = False

            time.sleep(1)

    def thread_handler2(self, arg):
        raise NotImplementedError("must impl this func")

    def check_self_shutdown(self):
        check_for_shutdown(self)

    def try_exit(self):
        self.exit = True
        ctx.list_of_Threads_Running[self.n] = False
        sys.exit()


def bitcoin_miner(t, restarted=False):
    if restarted:
        logg('[*] Bitcoin Miner restarted')
        time.sleep(1)
    target = (ctx.nbits[2:] + '00' * (int(ctx.nbits[:2], 16) - 3)).zfill(64)
    print('Target hash should be <= ' + str(target))
    ctx.extra_nonce_2 = hex(random.randint(0, 2 ** 32 - 1))[2:].zfill(2 * ctx.extra_nonce_2_size)  # create random

    coinbase = ctx.coin_base_1 + ctx.extra_nonce_1 + ctx.extra_nonce_2 + ctx.coin_base_2
    coinbase_hash_bin = hashlib.sha256(hashlib.sha256(binascii.unhexlify(coinbase)).digest()).digest()

    merkle_root = coinbase_hash_bin
    for h in ctx.merkle_branch:
        merkle_root = hashlib.sha256(hashlib.sha256(merkle_root + binascii.unhexlify(h)).digest()).digest()

    merkle_root = binascii.hexlify(merkle_root).decode()

    # little endian
    merkle_root = ''.join([merkle_root[i] + merkle_root[i + 1] for i in range(0, len(merkle_root), 2)][::-1])

    work_on = get_current_block_height()

    ctx.nHeightDiff[work_on + 1] = 0

    _diff = int("00000000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", 16)

    logg('[*] Working to solve block with height {}'.format(work_on + 1))

    if len(sys.argv) >= 1:
        random_nonce = False
    else:
        random_nonce = True

    nNonce = 0

    last_updated = int(time.time())

    while True:
        t.check_self_shutdown()
        if t.exit:
            break

        if ctx.previous_hash != ctx.updatedPrevHash:
            logg('[*] New block {} detected on network '.format(ctx.previous_hash))
            logg('[*] Best difficulty while trying to solve block {} was {}'.format(work_on + 1,
                                                                                    ctx.nHeightDiff[work_on + 1]))
            ctx.updatedPrevHash = ctx.previous_hash
            bitcoin_miner(t, restarted=True)
            break

        if random_nonce:
            nonce = hex(random.randint(0, 2 ** 32 - 1))[2:].zfill(8)  # nNonce   #hex(int(nonce,16)+1)[2:]
        else:
            nonce = hex(nNonce)[2:].zfill(8)

        block_header = ctx.version + ctx.previous_hash + merkle_root + ctx.n_time + ctx.nbits + nonce + \
                      '000000800000000000000000000000000000000000000000000000000000000000000000000000000000000080020000'
        current_hash = hashlib.sha256(hashlib.sha256(binascii.unhexlify(block_header)).digest()).digest()
        current_hash = binascii.hexlify(current_hash).decode()
        #
        # # Logg all hashes that start with 7 zeros or more
        # if current_hash.startswith('0000000'): logg('[*] New hash: {} for block {}'.format(current_hash, work_on + 1))

        this_hash = int(current_hash, 16)

        difficulty = _diff / this_hash

        if ctx.nHeightDiff[work_on + 1] < difficulty:
            # new best difficulty for block at x height
            ctx.nHeightDiff[work_on + 1] = difficulty

        if not random_nonce:
            # hash meter, only works with regular nonce.
            last_updated = calculate_hash_rate(nNonce, last_updated)

        if current_hash < target:
            logg('[*] Block {} solved.'.format(work_on + 1))
            logg('[*] Block hash: {}'.format(current_hash))
            logg('[*] Blockheader: {}'.format(block_header))
            payload = bytes('{"params": ["' + address + '", "' + ctx.job_id + '", "' + ctx.extra_nonce_2 \
                            + '", "' + ctx.n_time + '", "' + nonce + '"], "id": 1, "method": "mining.submit"}\n',
                            'utf-8')
            logg('[*] Payload: {}'.format(payload))
            ctx.sock.sendall(payload)
            ret = ctx.sock.recv(1024)
            logg('[*] Pool response: {}'.format(ret))
            return True

        # increment nonce by 1, in case we don't want random 
        nNonce += 1


def block_listener(t):
    # init a connection to pool
    user_name = myname.encode() + address.encode()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((pool_address, int(pool_port)))
    # send a handle subscribe message 
    sock.sendall(b'{"id": 1, "method": "mining.subscribe", "params": []}\n')
    lines = sock.recv(1024).decode().split('\n')
    response = json.loads(lines[0])
    ctx.sub_details, ctx.extra_nonce_1, ctx.extra_nonce_2_size = response['result']
    # send and handle authorize message

    sock.sendall(b'{"params": ["' + address.encode() + b'", "password"], "id": 2, "method": "mining.authorize"}\n')
    response = b''
    while response.count(b'\n') < 4 and not (b'mining.notify' in response): response += sock.recv(1024)

    responses = [json.loads(res) for res in response.decode().split('\n') if
                 len(res.strip()) > 0 and 'mining.notify' in res]
    logg(responses)

    (ctx.job_id, ctx.previous_hash, ctx.coin_base_1, ctx.coin_base_2, ctx.merkle_branch, ctx.version, ctx.nbits, ctx.n_time, ctx.clean_jobs) = responses[0]['params']
    logg("[*] Coin_base_1:")
    logg(ctx.coin_base_1)
    logg("[*] Coin_base_2:")
    logg(ctx.coin_base_2)
    # do this one time, will be overwritten by mining loop when new block is detected
    ctx.updatedPrevHash = ctx.previous_hash
    # set sock 
    ctx.sock = sock

    while True:
        t.check_self_shutdown()
        if t.exit:
            break

        # check for new block
        response = b''
        while response.count(b'\n') < 4 and not (b'mining.notify' in response): response += sock.recv(1024)

        responses = [json.loads(res) for res in response.decode().split('\n') if
                     len(res.strip()) > 0 and 'mining.notify' in res]
        logg(responses)

        if responses[0]['params'][1] != ctx.previous_hash:
            # new block detected on network 
            # update context job data
            ctx.job_id, ctx.previous_hash, ctx.coin_base_1, ctx.coin_base_2, ctx.merkle_branch, ctx.version, ctx.nbits, ctx.n_time, ctx.clean_jobs = responses[0]['params']


class CoinMinerThread(ExitedThread):
    def __init__(self, arg=None):
        super(CoinMinerThread, self).__init__(arg, n=0)

    def thread_handler2(self, arg):
        self.thread_bitcoin_miner(arg)

    def thread_bitcoin_miner(self, arg):
        ctx.list_of_Threads_Running[self.n] = True
        check_for_shutdown(self)
        try:
            ret = bitcoin_miner(self)
            logg("[*] Miner returned %s\n\n" % "true" if ret else "false")
        except Exception as e:
            logg("[*] Miner()")
            logg(e)
            traceback.print_exc()
        ctx.list_of_Threads_Running[self.n] = False

    pass


class NewSubscribeThread(ExitedThread):
    def __init__(self, arg=None):
        super(NewSubscribeThread, self).__init__(arg, n=1)

    def thread_handler2(self, arg):
        self.thread_new_block(arg)

    def thread_new_block(self, arg):
        ctx.list_of_Threads_Running[self.n] = True
        check_for_shutdown(self)
        try:
            block_listener(self)
        except Exception as e:
            logg("[*] Subscribe thread()")
            logg(e)
            traceback.print_exc()
        ctx.list_of_Threads_Running[self.n] = False
    pass


def start_mining():
    subscribe_t = NewSubscribeThread(None)
    subscribe_t.start()
    logg("[*] Subscribe thread started.")

    time.sleep(4)
    mining_processes = []
    for counter in range(os.cpu_count() - 1):
        process = Process(target=CoinMinerThread, args=(None,))
        process.start()
        logg("[*] Bitcoin mining process no : " + str(counter) + " has started")
        print('Bitcoin mining process no : " + str(counter) + " has started')
        mining_processes.append(process)
        
    for process in mining_processes:
        process.join()


if __name__ == '__main__':
    signal(SIGINT, handler)
    start_mining()
