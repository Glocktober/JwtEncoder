from JwtEncoder import JwtEncoder
from secrets import token_bytes

with open('priv.pem', 'rb') as f:
    privkey = f.read()

with open('pub.pem', 'rb') as f:
    pubkey = f.read()

with open('ecpriv.pem', 'rb') as f:
    ecprivkey = f.read()

with open('ecpub.pem', 'rb') as f:
    ecpubkey = f.read()

with open('sym.key', 'rb') as f:
    lsymkey = f.read()

symkey = token_bytes(256)

paytempl = {
    'age': 82, 
    'sub': 'Revolution', 
    'sn': 'Franklin', 
    'given': 'Ben', 
    'aud': ['G.Washington', 'A.Hamilton'] 
}


def default_symmetric(config_file=None):

    j = JwtEncoder(config_file)

    pay = paytempl.copy()

    #print(pay)
    tok = j.encode(pay)
    # print(tok)
    resp = j.decode(tok, audience='G.Washington')
    for k in pay:
        assert pay[k] == resp[k]
    # print(resp)

    print(f'len sig: {len(tok.split(".")[2])}')


print('******* test 1 - Defaults')
default_symmetric()

print('******* test 2 - Sym key specified')
default_symmetric({
    'key': symkey, 
    'ttl': None
    })
print('******* test 3 - Sym ISS')
default_symmetric({
    'key': symkey, 
    'iss': 'joseCuervo',
    'ttl': 2*60
    })

print('******* test 4 - Sym HS512')
default_symmetric({
    'key': lsymkey, 
    'iss': 'joseCuervo',
    'alg': 'HS512',
    })
print('******* test 5 - Asym defaults')
default_symmetric({
    'privkey': privkey,
    'pubkey' : pubkey,
    'ttl': 2*60
})
print('******* test 6 - Asym spec')
default_symmetric({
    'privkey': privkey,
    'pubkey' : pubkey,
    'alg': 'RS384',
    'iss': 'BetterTequila',
    'ttl': 200
})


print('******* test 7 - EC ES256')
default_symmetric({
    'privkey': ecprivkey,
    'pubkey' : ecpubkey,
    'alg': 'ES256',
    'iss': 'BetterTequila',
    'ttl': 20
})
print('******* test 8 - EC ES256k')
default_symmetric({
    'privkey': ecprivkey,
    'pubkey' : ecpubkey,
    'alg': 'ES256K',
    'iss': 'BetterTequila',
    'ttl': 20
})
print('******* test 9 - EC ES384')
default_symmetric({
    'privkey': ecprivkey,
    'pubkey' : ecpubkey,
    'alg': 'ES384',
    'iss': 'BetterTequila',
    'ttl': 20
})
print('******* test 10 - EC ES512')
default_symmetric({
    'privkey': ecprivkey,
    'pubkey' : ecpubkey,
    'alg': 'ES512',
    'iss': 'BetterTequila',
    'ttl': None
})