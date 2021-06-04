import hmac
import time
from binascii import a2b_hex, b2a_hex
from hashlib import pbkdf2_hmac, sha1, md5

#Function to generate PTK
def PRF(key, A, B):
    nByte = 64
    i = 0
    R = b''
    while(i <= ((nByte * 8 + 159) / 160)):
        hmacsha1 = hmac.new(key, A + chr(0x00).encode() + B + chr(i).encode(), sha1)
        R = R + hmacsha1.digest()
        i += 1
    return R[0:nByte]

#Function to return parameters for creating PTK for each trial
def MakeAB(aNonce, sNonce, apMac, cliMac):
    A = b"Pairwise key expansion"
    B = min(apMac, cliMac) + max(apMac, cliMac) + min(aNonce, sNonce) + max(aNonce, sNonce)
    return (A, B)

#Create MIC for given password
def MakeMIC(pwd, ssid, A, B, data, wpa = False):
    pmk = pbkdf2_hmac('sha1', pwd.encode('ascii'), ssid.encode('ascii'), 4096, 32)
    ptk = PRF(pmk, A, B)
    hmacFunc = md5 if wpa else sha1
    mics = [hmac.new(ptk[0:16], i, hmacFunc).digest() for i in data]
    return (mics, ptk, pmk)

#Function to take arguments and return result based on password list
def TestPwds(S, ssid, aNonce, sNonce, apMac, cliMac, data, data2, data3, targMic, targMic2, targMic3):
    A, B = MakeAB(aNonce, sNonce, apMac, cliMac)
    for i in S:
        mic, _, _ = MakeMIC(i, ssid, A, B, [data])
        v = b2a_hex(mic[0]).decode()[:-8]
        if(v != targMic):
            continue
        mic2, _, _ = MakeMIC(i, ssid, A, B, [data2])
        v2 = b2a_hex(mic2[0]).decode()[:-8]
        if(v2 != targMic2):
            continue
        mic3, _, _ = MakeMIC(i, ssid, A, B, [data3])
        v3 = b2a_hex(mic3[0]).decode()[:-8]
        if(v3 != targMic3):
            continue
        print('----Password Found----')
        print('Desired MIC1:\t\t' + targMic)
        print('Computed MIC1:\t\t' + v)
        print('\nDesired MIC2:\t\t' + targMic2)
        print('Computed MIC2:\t\t' + v2)
        print('\nDesired MIC3:\t\t' + targMic3)
        print('Computed MIC3:\t\t' + v3)
        print('Password:\t\t' + i)
        return i
    return None

#Running the Python program
if __name__ == "__main__":
    start = time.time()
    with open('passwd.txt') as f:
        S = []
        for l in f:
            S.append(l.strip())

    #Assigning values taken from Wireshark
    ssid = "Harkonen"
    aNonce = a2b_hex('225854b0444de3af06d1492b852984f04cf6274c0e3218b8681756864db7a055')
    sNonce = a2b_hex("59168bc3a5df18d71efb6423f340088dab9e1ba2bbc58659e07b3764b0de8570")
    apMac = a2b_hex("00146c7e4080")
    cliMac = a2b_hex("001346fe320c")
    mic1 = "d5355382b8a9b806dcaf99cdaf564eb6"
    data1 = a2b_hex("0103007502010a0010000000000000000159168bc3a5df18d71efb6423f340088dab9e1ba2bbc58659e07b3764b0de8570000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001630140100000fac040100000fac040100000fac020100")
    mic2 = "1e228672d2dee930714f688c5746028d"
    data2 = a2b_hex("010300970213ca00100000000000000002225854b0444de3af06d1492b852984f04cf6274c0e3218b8681756864db7a055192eeef7fd968ec80aee3dfb875e8222370000000000000000000000000000000000000000000000000000000000000000383ca9185462eca4ab7ff51cd3a3e6179a8391f5ad824c9e09763794c680902ad3bf0703452fbb7c1f5f1ee9f5bbd388ae559e78d27e6b121f")
    mic3 = "9dc81ca6c4c729648de7f00b436335c8"
    data3 = a2b_hex("0103005f02030a0010000000000000000200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")

    #Running the test with given values
    TestPwds(S, ssid, aNonce, sNonce, apMac, cliMac, data1, data2, data3, mic1, mic2, mic3)
    end = time.time()
    print(f"Time to execute: {end-start}")
