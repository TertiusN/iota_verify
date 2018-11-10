""" 
The following code has been written as a basis for identity verification without documentation
the intention is to build a trusted network of verifying entities to view supporting documentation to claims of identity
after an identity has been verified by a trusted authority, it is signed and a hash is provided
the person can then use this hash alongside their knowledge to verify themselves.

This scheme will not eliminate verification completely, but may reduce the burden of needing to show multiple 
documents to entities requiring it.

SOURCES:
https://gitorious.org/electrum/electrum
https://pyota.readthedocs.io/en/latest/getting_started.html

AUTHOR:
pergamum - 2018

DEPENDENCIES:
python2

mkdir ~/virtualenvironment
virtualenv ~/virtualenvironment/iota_id
cd ~/virtualenvironment/iota_id/bin
source activate

pip install -r requirements.txt
"""

import ecdsa, os
import base64
import hashlib
from ecdsa.util import string_to_number

from argparse import ArgumentParser
from sys import argv
import urllib2
import json

from iota import (
  __version__,
  Address,
  Iota,
  ProposedTransaction,
  Tag,
  TryteString,
  transaction
)

node = 'https://iota-3.de:14267'

# secp256k1, http://www.oid-info.com/get/1.3.132.0.10
_p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
_r = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
_b = 0x0000000000000000000000000000000000000000000000000000000000000007
_a = 0x0000000000000000000000000000000000000000000000000000000000000000
_Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
_Gy = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8
curve_secp256k1 = ecdsa.ellipticcurve.CurveFp( _p, _a, _b )
generator_secp256k1 = ecdsa.ellipticcurve.Point( curve_secp256k1, _Gx, _Gy, _r )
oid_secp256k1 = (1,3,132,0,10)
SECP256k1 = ecdsa.curves.Curve("SECP256k1", curve_secp256k1, generator_secp256k1, oid_secp256k1 ) 

addrtype = 0

# from http://eli.thegreenplace.net/2009/03/07/computing-modular-square-roots-in-python/

def modular_sqrt(a, p):
    """ Find a quadratic residue (mod p) of 'a'. p
    must be an odd prime.
    
    Solve the congruence of the form:
    x^2 = a (mod p)
    And returns x. Note that p - x is also a root.
    
    0 is returned is no square root exists for
    these a and p.
    
    The Tonelli-Shanks algorithm is used (except
    for some simple cases in which the solution
    is known from an identity). This algorithm
    runs in polynomial time (unless the
    generalized Riemann hypothesis is false).
    """
    # Simple cases
    #
    if legendre_symbol(a, p) != 1:
        return 0
    elif a == 0:
        return 0
    elif p == 2:
        return p
    elif p % 4 == 3:
        return pow(a, (p + 1) / 4, p)
    
    # Partition p-1 to s * 2^e for an odd s (i.e.
    # reduce all the powers of 2 from p-1)
    #
    s = p - 1
    e = 0
    while s % 2 == 0:
        s /= 2
        e += 1
        
    # Find some 'n' with a legendre symbol n|p = -1.
    # Shouldn't take long.
    #
    n = 2
    while legendre_symbol(n, p) != -1:
        n += 1
        
    # Here be dragons!
    # Read the paper "Square roots from 1; 24, 51,
    # 10 to Dan Shanks" by Ezra Brown for more
    # information
    #
    
    # x is a guess of the square root that gets better
    # with each iteration.
    # b is the "fudge factor" - by how much we're off
    # with the guess. The invariant x^2 = ab (mod p)
    # is maintained throughout the loop.
    # g is used for successive powers of n to update
    # both a and b
    # r is the exponent - decreases with each update
    #
    x = pow(a, (s + 1) / 2, p)
    b = pow(a, s, p)
    g = pow(n, s, p)
    r = e
    
    while True:
        t = b
        m = 0
        for m in xrange(r):
            if t == 1:
                break
            t = pow(t, 2, p)
            
        if m == 0:
            return x
        
        gs = pow(g, 2 ** (r - m - 1), p)
        g = (gs * gs) % p
        x = (x * gs) % p
        b = (b * g) % p
        r = m
        
def legendre_symbol(a, p):
    """ Compute the Legendre symbol a|p using
    Euler's criterion. p is a prime, a is
    relatively prime to p (if p divides
    a, then a|p = 0)
    
    Returns 1 if a has a square root modulo
    p, -1 otherwise.
    """
    ls = pow(a, (p - 1) / 2, p)
    return -1 if ls == p - 1 else ls

__b58chars = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
__b58base = len(__b58chars)

def b58encode(v):
    """ encode v, which is a string of bytes, to base58.		
    """

    long_value = 0
    for (i, c) in enumerate(v[::-1]):
        long_value += (256**i) * ord(c)

    result = ''
    while long_value >= __b58base:
        div, mod = divmod(long_value, __b58base)
        result = __b58chars[mod] + result
        long_value = div
    result = __b58chars[long_value] + result

    # Bitcoin does a little leading-zero-compression:
    # leading 0-bytes in the input become leading-1s
    nPad = 0
    for c in v:
        if c == '\0': nPad += 1
        else: break

    return (__b58chars[0]*nPad) + result

def msg_magic(message):
    return "\x18Bitcoin Signed Message:\n" + chr( len(message) ) + message

def Hash(data):
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()

def hash_160(public_key):
    md = hashlib.new('ripemd160')
    md.update(hashlib.sha256(public_key).digest())
    return md.digest()

def hash_160_to_bc_address(h160):
    vh160 = chr(addrtype) + h160
    h = Hash(vh160)
    addr = vh160 + h[0:4]
    return b58encode(addr)

def public_key_to_bc_address(public_key):
    h160 = hash_160(public_key)
    return hash_160_to_bc_address(h160)

def encode_point(pubkey, compressed=False):
    order = generator_secp256k1.order()
    p = pubkey.pubkey.point
    x_str = ecdsa.util.number_to_string(p.x(), order)
    y_str = ecdsa.util.number_to_string(p.y(), order)
    if compressed:
        return chr(2 + (p.y() & 1)) + x_str
    else:
        return chr(4) + x_str + y_str

def sign_message(private_key, message, compressed=False):
    public_key = private_key.get_verifying_key()
    signature = private_key.sign_digest( Hash( msg_magic( message ) ), sigencode = ecdsa.util.sigencode_string )
    address = public_key_to_bc_address(encode_point(public_key, compressed))
    assert public_key.verify_digest( signature, Hash( msg_magic( message ) ), sigdecode = ecdsa.util.sigdecode_string)
    for i in range(4):
        nV = 27 + i
        if compressed:
            nV += 4
        sig = base64.b64encode( chr(nV) + signature )
        try:
            if verify_message( address, sig, message):
                return sig
        except:
            continue
    else:
        raise BaseException("error: cannot sign message")

def verify_message(address, signature, message):
    """ See http://www.secg.org/download/aid-780/sec1-v2.pdf for the math """
    from ecdsa import numbertheory, ellipticcurve, util
    curve = curve_secp256k1
    G = generator_secp256k1
    order = G.order()
    # extract r,s from signature
    sig = base64.b64decode(signature)
    if len(sig) != 65: raise BaseException("Wrong encoding")
    r,s = util.sigdecode_string(sig[1:], order)
    nV = ord(sig[0])
    if nV < 27 or nV >= 35:
        return False
    if nV >= 31:
        compressed = True
        nV -= 4
    else:
        compressed = False
    recid = nV - 27
    # 1.1
    x = r + (recid/2) * order
    # 1.3
    alpha = ( x * x * x  + curve.a() * x + curve.b() ) % curve.p()
    beta = modular_sqrt(alpha, curve.p())
    y = beta if (beta - recid) % 2 == 0 else curve.p() - beta
    # 1.4 the constructor checks that nR is at infinity
    R = ellipticcurve.Point(curve, x, y, order)
    # 1.5 compute e from message:
    h = Hash( msg_magic( message ) )
    e = string_to_number(h)
    minus_e = -e % order
    # 1.6 compute Q = r^-1 (sR - eG)
    inv_r = numbertheory.inverse_mod(r,order)
    Q = inv_r * ( s * R + minus_e * G )
    public_key = ecdsa.VerifyingKey.from_public_point( Q, curve = SECP256k1 )
    # check that Q is the public key
    public_key.verify_digest( sig[1:], h, sigdecode = ecdsa.util.sigdecode_string)
    # check that we get the original signing address
    addr = public_key_to_bc_address(encode_point(public_key, compressed))
    if address == addr:
        return True
    else:
        #print addr
        return False


def send_message(address, depth, message, tag, uri, value):
    # Ensure seed is not displayed in cleartext.
    seed = 'NO9SEED9REQUIRED999999999999999999999999999'
    # Create the API instance.
    api = Iota(uri, seed)

    print 'Starting transfer please wait...\n'
    # For more information, see :py:meth:`Iota.send_transfer`.
    bundle = api.send_transfer(
        depth=depth,
        # One or more :py:class:`ProposedTransaction` objects to add to the
        # bundle.
        transfers=[
            ProposedTransaction(
                # Recipient of the transfer.
                address=Address(address),

                # Amount of IOTA to transfer.
                # By default this is a zero value transfer.
                value=value,

                # Optional tag to attach to the transfer.
                tag=Tag(tag),

                # Optional message to include with the transfer.
                message=TryteString.from_string(message),
            ),
        ],
    )

    print 'Transfer complete. TX hash: ',bundle['bundle'].transactions[0].hash
    #print 'Signature upload success: ',TryteString(bundle['bundle'].transactions[0].signature_message_fragment).decode()

def get_message(txHash):

    print 'Fetching TX details...\n'

    command = {
        'command': 'getTrytes',
        'hashes': [tx_hash]
    }

    stringified = json.dumps(command)

    headers = {
        'content-type': 'application/json',
        'X-IOTA-API-Version': '1'
    }

    request = urllib2.Request(url="https://iota-3.de:14267", data=stringified, headers=headers)
    returnData = urllib2.urlopen(request).read()

    jsonData = json.loads(returnData)

    txtrytes = jsonData['trytes'][0][0:2187]

    trytes = TryteString(bytes(txtrytes))
    message = trytes.decode()

    return message

def get_avl_address():

    api = Iota(node, b'NO9SEED9REQUIRED999999999999999999999999999')

    # Find the first unused address, starting with index 0:
    avl_address = api.get_new_addresses(index=0, count=None)

    address = bytes(avl_address['addresses'][0])
    return address
        
if __name__ == '__main__':

    #Create signing authority, in final version secret should be supplied by trusted entity
    secret = os.urandom(32)
    private_key = ecdsa.SigningKey.from_string( secret, curve = SECP256k1 )
    public_key = private_key.get_verifying_key()
    bitcoinaddress = public_key_to_bc_address( encode_point(public_key) )

    name = raw_input('Your Name: ')

    sig = sign_message(private_key, name)
    print 'Sending to tangle (signature): ',sig

    address = get_avl_address()
    send_message(address, 3, sig, 'IDENTIY9VERIFICATION', node, 0)
    print 'Verified by BTC address: ',bitcoinaddress, '\nPlease store for future reference\n\n'

    #Fetch signature, confirm identity
    tx_hash = raw_input('Enter TX Hash: ')
    btc_address = raw_input('Enter BTC Address (Verifiying Entity): ')
    text = raw_input('Enter Name: ')

    message = get_message(tx_hash)

    print 'Verify: ',verify_message(btc_address, message, text)
    print 'Approved by: ', btc_address 

    
