from cryptos.electrumx_client import rpc_send_and_wait, rpc_send

host = "electrum.akinbo.org"
port = 50001
method = "blockchain.address.listunspent"
params = ["1AoZAu5Kif5MTkaNWbHiXGdcNEgFGVqDgB"]

rpc_send(host, port, method, params)
print('yes')
import time
time.sleep(2)
#print(result)