
'''
This file contains lots of functions which are related to cryptography.
Not all of these I created myself, and I do not take credit for any of them.
Some of these functions were created as part of the tasks in:
    Cryptopals
    Mystery Twister C3
'''
import base64,sys,hashlib,itertools,math
from Crypto.Cipher import AES

englishCharacterFrequencies = {
    'a': 0.0651738, 'b': 0.0124248, 'c': 0.0217339, 'd': 0.0349835, 'e': 0.1041442, 'f': 0.0197881, 'g': 0.0158610,
    'h': 0.0492888, 'i': 0.0558094, 'j': 0.0009033, 'k': 0.0050529, 'l': 0.0331490, 'm': 0.0202124, 'n': 0.0564513,
    'o': 0.0596302, 'p': 0.0137645, 'q': 0.0008606, 'r': 0.0497563, 's': 0.0515760, 't': 0.0729357, 'u': 0.0225134,
    'v': 0.0082903, 'w': 0.0171272, 'x': 0.0013692, 'y': 0.0145984, 'z': 0.0007836, ' ': 0.1918182
}


def getEnglishScore(inputBytes):
    '''
    Returns a score which is the sum of the probabilities in how each letter of the input data
    appears in the English language. Uses the above probabilities.
    '''
    score = 0
    for byte in inputBytes:
        score += englishCharacterFrequencies.get(chr(byte).lower(), 0)
    return score

def hexToBase64(hexString):
    '''
    Produces the base 64 decoding of a hex encoded string
    '''
    decodedHexString = bytes.fromhex(hexString)
    b64EncodedString = base64.b64encode(decodedHexString)
    return b64EncodedString.decode()

def xorHex(hex1,hex2):
    '''
    XORs two equal-length hex encoded buffers
    '''
    return hex(int(hex1,16)^int(hex2,16))[2:]

def xorSingleChar(byteText, keyValue):
    '''
    XORs every byte of the input with the given keyValue
    '''
    output = b''
    for char in byteText:
        output += convertToBytes(char ^ keyValue,'int')
    return output

def xorSingleCharBruteForce(byteCipher):
    '''
    Tries every possible byte for the single-char key. Decrypts the ciphertext with that
    byte and computes the english score for each plaintext. The plaintext with the highest
    score is likely to be the one decrypted with the correct value of key.
    '''
    englishScores = {}
    bestKey = ''
    bestEnglishScore = 0
    bestByteText = b''
    for candidate in range(256):
        byteText = xorSingleChar(byteCipher,candidate)
        englishScores[candidate] = getEnglishScore(byteText)
        if englishScores[candidate] > bestEnglishScore:
            bestKey = int(candidate)
            bestEnglishScore = englishScores[bestKey]
            bestByteText = byteText
    # returns the english score, best key, and the plain text
    return bestEnglishScore,bestKey,bestByteText

def xorRepeatingKey(byteText,byteKey):
    '''
    This encrypts a message using a repeating key XOR encryption.
    The plaintext and key are both strings.
    '''
    index = 0
    encryptedText = b''
    for char in byteText:
        encryptedText += convertToBytes(char ^ byteKey[index%len(byteKey)],'int')
        index += 1
    return encryptedText

def convertToBytes(value,varType,encoding='utf-8'):
    '''
    This function converts variables to bytes.
    '''
    byteValue = b''
    if varType == 'str':
        # string
        byteValue = bytes(value,encoding)
    if varType == 'bin':
        # binary
        byteValue = int(value, 2).to_bytes(len(value) // 8, byteorder='big')
    if varType == 'hex':
        # hexadecimal
        byteValue = bytes.fromhex(value)
    if varType == 'bool':
        # boolean
        if value:
            byteValue = b'1'
        else:
            byteValue = b'0'
    if varType == 'int':
        # integer
        byteValue = bytes(chr(value),encoding)
    if varType == 'b64':
        # base 64
        byteValue = base64.b64decode(value)

    return byteValue

def byteToBits(byte):
    '''
    This function converts a byte to a list of bits.
    '''
    bits = b''
    for i in [1,2,4,8,16,32,64,128]:
        bits += convertToBytes(byte&i != 0,'bool')
    bits = bits[::-1]
    return bits

def hammingDistance(byteText1,byteText2):
    '''
    This function calculates the number of differing bits between two strings.
    '''
    hammingDistance = 0
    for i in range(min(len(byteText1),len(byteText2))):
        bits1 = byteToBits(byteText1[i])
        bits2 = byteToBits(byteText2[i])
        for b in range(8):
            if bits1[b] != bits2[b]:
                hammingDistance += 1
    return hammingDistance

def xorRepeatingKeyBruteForce(byteCipher,showProgress=False):
    '''
    This function brute forces a repeating-key XOR encryption statistically.
    My version of this is special, in that it is very dynamic and accurate at determining exactly
    the correct possible key sizes.
    '''
    # First calculate the most likely key size by comparing sections of the cipher
    # to determine their hamming distance and normalise the result.
    keySizes = {0:1000.0}
    sectionsToCompare = 3 # careful not to make this too high
    for keySize in range(1,min(len(byteCipher)//sectionsToCompare,30)):
        sections = []
        if sectionsToCompare > len(byteCipher)//keySize:
            sectionsToCompare = len(byteCipher)//keySize
        # Record sections of the cipher
        for s in range(sectionsToCompare):
            sections.append(byteCipher[s:keySize+s])
        # Average the hamming distance between each of these sections and every other one
        totalHammingDistance = 0
        for section1 in sections:
            for section2 in sections:
                if section1 != section2:
                    totalHammingDistance += hammingDistance(section1,section2)
        normalisedAverageHammingDistance = float(totalHammingDistance)/(keySize**2) # get average and normalise it
        # Add this value to the dictionary
        keySizes[keySize] =  float(normalisedAverageHammingDistance)
    # Get the top 'x' key sizes
    numOfKeySizesToTry = 5 # The top 'numOfKeySizesToTry' key sizes will be stored and tried next
    bestNormalisedAverageHammingDistances = sorted(keySizes.values())[:numOfKeySizesToTry]
    bestKeySizes = []
    for keySize in keySizes.keys():
        if keySizes[keySize] in bestNormalisedAverageHammingDistances:
            bestKeySizes.append(keySize)
    # Go through each key size
    bestDecryptions = []
    # FIND OUT WHAT THE REST OF THIS FUNCTION DOES [todo]
    keysDone = -1
    for keySize in bestKeySizes:
        keysDone += 1
        byteKey = b''
        # Break the ciphertext into blocks that are 'keySize' in length
        for i in range(keySize):
            if showProgress:
                sys.stdout.write("CRACKING: %d/%d\t%d%%   \r" % (keysDone*keySize+i,keySize*numOfKeySizesToTry,int(i*100/keySize/numOfKeySizesToTry+keysDone*100/numOfKeySizesToTry)))
                sys.stdout.flush()
            block = b''
            # Transpose the blocks - make a block that is the ith byte of every block
            for j in range(i,len(byteCipher),keySize):
                block += convertToBytes(byteCipher[j],'int')
            # Solve each block as if it was single-character XOR
            byteKey += convertToBytes(xorSingleCharBruteForce(block)[1],'int')
        # Record the plaintext of the key and the key
        bestDecryptions.append((byteKey,xorRepeatingKey(byteCipher,byteKey)))
    # Get the decryption with the highest english score
    return max(bestDecryptions, key=lambda k: getEnglishScore(k[1])) # <-- Pretty cool syntax, I want to learn how to do it.

def aesEcbDecrypt(byteCipher,byteKey):
    cipherAlgorithm = AES.new(byteKey, AES.MODE_ECB)
    return cipherAlgorithm.decrypt(byteCipher)

def countAesEcbRepetitions(ciphertext):
    '''
    Counts the number of repeated chunks of the ciphertext and returns it.
    '''
    chunks = [ciphertext[i:i + AES.block_size] for i in range(0, len(ciphertext), AES.block_size)]
    numDuplicates = len(chunks) - len(set(chunks))
    return numDuplicates

def detectEcbEncryptedCiphertext(ciphertexts):
    '''
    Detects which ciphertext among the given one is the one most likely encrypted with AES in ECB mode.
    '''
    best = (-1, 0)     # index of best candidate, repetitions of best candidate
    # For each ciphertext
    for i in range(len(ciphertexts)):
        # Count the block repetitions
        repetitions = countAesEcbRepetitions(ciphertexts[i])
        # Keep the ciphertext with most repetitions
        best = max(best, (i, repetitions), key=lambda t: t[1])
    # Return the ciphertext with most repetitions
    return best

def sha1BruteForce(byteHash,possibleByteChars = list(range(256)),size=1):
    '''
    This function brute forces a SHA-1 hash. 
    Size is the starting size to begin progressing from.
    '''

    pwd = ''
    while pwd == '':

        possibleBytePwds = itertools.product(possibleByteChars,repeat=size)

        total = len(possibleByteChars)**size
        tried = 0.0
        for bytePwd in possibleBytePwds:
            tried += 1
            sys.stdout.write("CRACKING: %d\t%d/%d\t%d%%  \r" % (size,tried,total,int(tried/total*100)))
            sys.stdout.flush()
            pwd = ''.join([byte.decode() for byte in bytePwd])
            byteHashOfPwd = hashlib.sha1(pwd.encode()).digest()
            if byteHashOfPwd != byteHash:
                pwd = ''
        size += 1
    return pwd

def clearLine():
    print("                                                                                    ")

# CRYPTOPALS #
# S1C1
print("S1C1 - Convert hex to base64")
assert(hexToBase64("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d")=="SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t")
clearLine()
# S1C2
print("S1C2 - Fixed XOR")
assert(xorHex("1c0111001f010100061a024b53535009181c","686974207468652062756c6c277320657965")=="746865206b696420646f6e277420706c6179")
clearLine()
# S1C3
print("S1C3 - Single-byte XOR cipher")
byteCipher = convertToBytes("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736",'hex')
assert(xorSingleChar(byteCipher, xorSingleCharBruteForce(byteCipher)[1]) == b"Cooking MC's like a pound of bacon")
clearLine()
# S1C4
print("S1C4 - Detect single-character XOR")
try:
    file = open("S1C4.txt","r").readlines()
    bestEnglishScore = 0
    bestKey = ''
    bestByteText = b''
    lineNum = 0
    for line in file:
        lineNum += 1
        sys.stdout.write("CRACKING: %d/%d\t%d%%   \r" % (lineNum,len(file),int(lineNum/len(file)*100)))
        sys.stdout.flush()
        bytesLine = convertToBytes(line.strip(),'hex')
        score,key,byteText = xorSingleCharBruteForce(bytesLine)
        if score > bestEnglishScore:
            bestEnglishScore = int(score)
            bestKey = int(key)
            bestByteText = byteText
    assert(bestByteText == b"Now that the party is jumping\n")
except:
    print("CANCELLED")
clearLine()
# S1C5
print("S1C5 - Implement repeating-key XOR")
file = open("S1C5.txt","r").read()
bytesText = convertToBytes(file,'str')
assert(xorRepeatingKey(bytesText,b"ICE").hex() == "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f")
clearLine()

# S1C6
print("S1C6 - Break repeating-key XOR")
try:
    file = open("S1C6.txt","r").read()
    assert(byteToBits(5) == b"00000101")
    assert(hammingDistance(b"this is a test",b"wokka wokka!!!") == 37)
    byteCipher = convertToBytes(file,'b64')
    key, byteText = xorRepeatingKeyBruteForce(byteCipher,showProgress=True)
    assert(key == b"Terminator X: Bring the noise")
except:
    print("CANCELLED")

clearLine()
# S1C7
print("S1C7 - AES in ECB mode")
file = open("S1C7.txt","r").read()
byteCipher = convertToBytes(file,'b64')
byteText = aesEcbDecrypt(byteCipher,b"YELLOW SUBMARINE")
assert(byteText[:8] == b"I'm back")
clearLine()
# S1C8
print("S1C8 - Detect AES in ECB mode")
try:
    result = detectEcbEncryptedCiphertext([convertToBytes(line.strip(),'hex') for line in open("S1C8.txt")])
    print("The ciphertext encrypted in ECB mode is the one at position",result[0],"which contains", result[1], "repetitions\n")
except:
    print("CANCELLED")
clearLine()
# OTHER STUFF #
# Cracking SHA-1 Code
print("Cracking SHA-1")
try:
    possibleByteChars = [convertToBytes(char,'str') for char in ['(','Q','=','w','i','n','*','5']]
    print(sha1BruteForce(convertToBytes('67ae1a64661ac8b4494666f58c4822408dd0a3e4','hex'),possibleByteChars,8))
except:
    print("CANCELLED")
clearLine()

