
'''
This file contains lots of functions which are related to cryptography.
Not all of these I created myself, and I do not take credit for any of them.
Most of these are functions created to go through the Cryptopals course.
'''
import base64

englishCharacterFrequencies = {
    'a': 0.0651738, 'b': 0.0124248, 'c': 0.0217339, 'd': 0.0349835, 'e': 0.1041442, 'f': 0.0197881, 'g': 0.0158610,
    'h': 0.0492888, 'i': 0.0558094, 'j': 0.0009033, 'k': 0.0050529, 'l': 0.0331490, 'm': 0.0202124, 'n': 0.0564513,
    'o': 0.0596302, 'p': 0.0137645, 'q': 0.0008606, 'r': 0.0497563, 's': 0.0515760, 't': 0.0729357, 'u': 0.0225134,
    'v': 0.0082903, 'w': 0.0171272, 'x': 0.0013692, 'y': 0.0145984, 'z': 0.0007836, ' ': 0.1918182
}

def bytesToString(inputBytes):
    string = ''
    for byte in inputBytes:
        string += chr(byte)
    return string

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
        output += bytes([char ^ keyValue])
    return output

def singleCharXorBruteForce(cipherBytes):
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
        byteText = xorSingleChar(cipherBytes,candidate)
        englishScores[candidate] = getEnglishScore(byteText)
        if englishScores[candidate] > bestEnglishScore:
            bestKey = int(candidate)
            bestEnglishScore = englishScores[bestKey]
            bestByteText = byteText
    # returns the english score, best key, and the plain text
    return bestEnglishScore,bestKey,bestByteText

def xorRepeatingString(byteText,byteKey):
    '''
    This encrypts a message using a repeating key XOR encryption.
    The plaintext and key are both strings.
    '''
    
    index = 0
    encryptedText = b''
    for char in byteText:
        encryptedText += bytes(chr(char ^ byteKey[index%3]),'utf-8')
        index += 1
    return encryptedText

# CRYPTOPALS
# S1C1
assert(hexToBase64("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d")=="SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t")
# S1C2
assert(xorHex("1c0111001f010100061a024b53535009181c","686974207468652062756c6c277320657965")=="746865206b696420646f6e277420706c6179")
# S1C3
ciphertextBytes = bytes.fromhex("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
assert(xorSingleChar(ciphertextBytes, singleCharXorBruteForce(ciphertextBytes)[1]) == b"Cooking MC's like a pound of bacon")
# S1C4
file = open("ciphertextFile.txt","r").readlines()
bestEnglishScore = 0
bestKey = ''
bestByteText = b''
for line in file:
    bytesLine = bytes.fromhex(line.strip())
    score,key,byteText = singleCharXorBruteForce(bytesLine)
    if score > bestEnglishScore:
        bestEnglishScore = int(score)
        bestKey = int(key)
        bestByteText = byteText
assert(bestByteText == b"Now that the party is jumping\n")
# S1C5
encryptedText = xorRepeatingString(b"secretmessage",b"secretkey")
assert(xorRepeatingString(encryptedText,b"secretkey") == b"secretmessage")
