with open('mhk.pub', 'r') as f:
    pubkey = [int(line.rstrip()) for line in f.readlines()]

nbit = len(pubkey)
ciphertext = 131270045445233864607384589491494427653045154021726955640117783095539861156263050441962095668641162283126113

A = Matrix(ZZ, nbit + 1, nbit + 1)

# fill in the identity matrix
for i in range(nbit):
    A[i, i] = 1

# replace the bottom row with your public key
for i in range(nbit):
    A[i, nbit] = pubkey[i]

# last element is the encoded message
A[nbit, nbit] = -ciphertext

res = A.LLL()
print('LLL completed, looking for row')

for i in res:
    success = True

    for j in i:
        if j != 0 and j != 1:
            success = False
            break

    if success:
        print(''.join(row))
        exit()

for i in res.T:
    success = True

    for j in i:
        if j != 0 and j != 1:
            success = False
            break

    if success:
        print(''.join(row))
        exit()
