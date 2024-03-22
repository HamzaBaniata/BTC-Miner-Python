# solominer
Solo Mining in python for BTC Block Reward, Pure luck

This is a solominer. Random nonce between 0-4294967295 or regular nonce starting from 0 is checked to see if you could accidentally solve the mining problem using Python and Get BTC Block Reward. This miner requests job from solockpool and starts hashing the block header. Whenever a new block is detected on the network, the miner restarts automatically in order to request a new job from the pool server. If a nonce is found, the blockheader data is submited to ckpool  automatically. 

It is based on Luck given the very low probability due to high hashrate all around the world, but still possible.

The Script will store in miner.log file hashes having more than 7 zeros in the beginning (just to check your miner is actually running). Although the current difficulty for getting mining reward is much higher. Most events are stored in the miner.log. 

### You can input your BTC address once you run the code.



To run the miner:
``` python
# This will start the miner, with random nonce search
python3 solo_miner.py
[*] Bitcoin Miner Started
# This will start the miner, with regular nonce search
python3 solo_miner.py 1
[*] Bitcoin Miner Started
