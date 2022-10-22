from cryptos.coins_async.bitcoin import Bitcoin
from cryptos.main import generate_private_key


b = Bitcoin(testnet=True)


if __name__ == "__main__":
    private_key = generate_private_key()
    print(f'Private key: {private_key}')
    print(f'Address: {b.privtoaddr(private_key)}')
    print(f'Segwit Script Address: {b.privtop2w(private_key)}')
    print(f'Native Segwit Address: {b.privtosegwitaddress(private_key)}')