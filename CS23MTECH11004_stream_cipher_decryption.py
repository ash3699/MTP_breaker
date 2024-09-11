cipher_text = []         # list to store ciphertext
plain_text = []          # list to store plaintext
key_list = [-1]*200      # list to store key
text_creator = ''         
key_string = ''          # string to store key in hexadecimal value
length_largest_ciphertext = 0

def get_possible_keys(m1, m2, c1, c2, k, m):
    # Calling functions key_finder and key_validity_check
    key1 = key_finder(m1, m2, c1, c2) 
    key1 = key_validity_check(k, key1)

    # Calling functions key_finder and key_validity_check
    key2 = key_finder(m2, m1, c1, c2)
    key2 = key_validity_check(k, key2)
                
    # if key2 is valid update key_list with key1
    if(key1!= -1):
        key_list[m] = key1

    # if key2 is vaalid update key_list with key2
    if(key2 != -1):
        key_list[m] = key2

# Function to find a char in key 
def key_finder(m1,m2,c1,c2):
    k1 = m1 ^ c1
    k2 = m2 ^ c2
    if(k1==k2):
        return k1
    else:
        return -1

# Function to find if the key char at index k is valid or not   
def key_validity_check(k, key_check):
    for i in range(0, len(cipher_text)):
        cipher = cipher_text[i]
        if k < len(cipher):
            cipher_hexa_at_k = cipher[k] + cipher[k+1]
            cipher_int_at_k = int(cipher_hexa_at_k, 16)
            plain_text_at_k = cipher_int_at_k ^ key_check

            # consider key as valid only if plaintext is space or alphabets
            if plain_text_at_k == 32:
                continue
            elif 65 <= plain_text_at_k <= 90:
                continue
            elif 97 <= plain_text_at_k <= 122:
                continue
            else:
                if (k == 0 and key_check == 172):
                    print(f'came here {key_check}:{i}')
                return -1
            
    return key_check

# Function to update keys
def key_updater(file_name):
    modified_plaintext = []
    # Open the file for reading, text file contains the partial messages obtained and modified
    with open(file_name, 'r') as file:
        # Iterate through each line in the file;
        for line in file:
            # Append each line to the list (removing trailing newline characters)
            modified_plaintext.append(line.strip())

    # updating the key using the modified partial key
    for i in range(0,len(cipher_text)):
        ciphertext = cipher_text[i]
        plaintext = modified_plaintext[i]
        for j in range(0,len(ciphertext),2):
            pt = plaintext[int(j/2)]
            pt_int = ord(pt)
            if pt_int == 35:
                continue
            c1 = ciphertext[j] + ciphertext[j+1]
            c1_int = int(c1, 16)
            key_list[int(j/2)] = c1_int ^ pt_int

# Function to convert key from list of integers to a string of hexadecimals
def convert_int_to_hexa(keyList):
    key_string = ''
    for i in range(0, len(keyList)):
        key_hexa = hex(keyList[i])[2:]
        key_string = key_string + key_hexa
    return key_string

# Fuction to decrypt ciphertext using key generated
def decrypt_ciphertext():
    # Iterating from first ciphertext to last
    for i in range(0, len(cipher_text)):
        # Iterating through the length of ith ciphertext
        for j in range(0,int(len(cipher_text[i])),2):
            m = int(j/2)
            if(key_list[m] != -1):
                cipher_bitstring = cipher_text[i][j] + cipher_text[i][j+1]
                cipher_text_xor = key_list[m]^int(cipher_bitstring, 16)
                # Updates the final plaintext after ciphertext xor key
                plain_text[i] = plain_text[i][0:m] + chr(cipher_text_xor) + plain_text[i][m+1:]

# Main function
def main():
    global key_list
    global text_creator
    global length_largest_ciphertext
    
    # Open the file for reading
    with open('streamciphertexts.txt', 'r') as file:
        # Iterate through each line in the file
        for line in file:
            # updates the length of largest cipher text
            length_largest_ciphertext = max(length_largest_ciphertext, len(line))
            # Append each line to the list (removing trailing newline characters)
            cipher_text.append(line.strip())

    # Creating a string of size 200 with '#' as placeholder
    for i in range(0,200):
        text_creator = text_creator + '#'

    # Creating a list of 12 strings for plain text
    for i in range(0,len(cipher_text)):
        plain_text.append(text_creator)

    # Performing XOR for all pairs of ciphertexts to find key
    for i in range(1, len(cipher_text)-1):
        for j in range (i+1, len(cipher_text)):

            # Copying ith cipher-text to line_1 and jth cipher_text to line_2
            line_1 = cipher_text[i]
            line_2 = cipher_text[j]
            
            # Iterating through all the characters of two ciphertexts
            for k in range(0, min(len(line_1), len(line_2)), 2):
                
                m = int(k/2)

                if key_list[m] != -1:
                    continue
                
                # c1 and c2 are hexadecimal value at mth position of lin2_1 and line_2. c1_int and c2_int are int values of c1 and c2
                c1 = line_1[k] + line_1[k+1]
                c2 = line_2[k] + line_2[k+1]
                c1_int = int(c1, 16)
                c2_int = int(c2, 16)
                  
                # performing c1 XOR C2
                c1_xor_c2 = c1_int ^ c2_int
                
                # if c1 xor c2 is in the range of A to Z
                if 65 <= c1_xor_c2 <= 90:
                    m1 = 32
                    m2 = c1_xor_c2+32
                    get_possible_keys(m1, m2, c1_int, c2_int, k, m)

                # if c1 xor c2 is in the range of a to z
                if 97 <= c1_xor_c2 <= 122:
                    m1 = 32
                    m2 = c1_xor_c2-32
                    get_possible_keys(m1, m2, c1_int, c2_int, k, m)

    decrypt_ciphertext()

    print(f'\nFirst partial key obtained: {key_list} \n')

    # Updating key using the partial key obtained
    key_updater('deciphered_message1.txt')
    print(f'\nKey after first update: {key_list} \n')
    key_updater('deciphered_message2.txt')
    print(f'\nKey after second update: {key_list} \n')
    key_updater('deciphered_message3.txt')
    print(f'\nKey after third update: {key_list} \n')
    key_updater('deciphered_message4.txt')

    decrypt_ciphertext()

    key_list = key_list[0:int(length_largest_ciphertext/2)]

    print(f'\nComplete key as a list of integers containing ASCII value of char: {key_list} \n')

    print(f'key as a string of hexadecimal values: {convert_int_to_hexa(key_list)} \n')

    # Prints all the plaintext
    for i in range(0,len(plain_text)):
        print(f'message {i+1}: {plain_text[i][0:int(len(cipher_text[i])/2)]} \n')

if __name__ == "__main__":
    main()

