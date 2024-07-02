import math
import random
import string
import hashlib
import requests
from collections import defaultdict

def convert(seconds):
    seconds = seconds % (24 * 3600)
    hour = seconds // 3600
    seconds %= 3600
    minutes = seconds // 60
    seconds %= 60

    return "%d:%02d:%02d" % (hour, minutes, seconds)

def commonly_used(passwd):
    with open('10-million-password-list-top-1000000.txt') as f:
        if passwd in f.read():
            return True
        else:
            return False

def how_many_guesses(passwd):
    # declare varibles
    number_of_nums = 0
    number_of_letters_lower = 0
    number_of_letters_upper = 0
    # special values: ~`!@#$%^&*()_-+={[}]|\:;"'<,>.?/
    number_of_special = 0

    # check if commonly used password or not
    x = commonly_used(passwd)

    # check for conditions in password
    has_numbers = any(c.isdigit() for c in passwd)
    has_lowercase = any(c.islower() for c in passwd)
    has_uppercase = any(c.isupper() for c in passwd)
    has_special_chars = any(not c.isalnum() for c in passwd)

    if has_numbers == True:
        number_of_nums = 10

    if has_lowercase == True:
        number_of_letters_lower = 26

    if has_uppercase == True:
        number_of_letters_upper = 26

    if has_special_chars == True:
        number_of_special = 32

    # 1. get the total possible combinations
    possible_number_chars = number_of_nums + number_of_letters_lower + number_of_letters_upper + number_of_special
    possible_combinations = possible_number_chars ** (len(passwd))

    if x == True:

        # 2. calculate password entropy
        password_entropy = 0

        # 3. how long it will take in seconds to crack
        time_to_crack = 60

        # 4. moores law for how many years before it can be cracked in under an hour
        moores = 0

    else:

        # 2. calculate password entropy (https://www.google.com/search?sca_esv=8935ef200ca57f75&sxsrf=ADLYWIKwyHoz1cY6N5sLzW-JnUKZEnwQ-g:1717207061017&q=password+entropy&uds=ADvngMjwX4dvqjExbCg9zqvMuh5VQVlbqt8hhXsttmxeGNhS4eMrEhTA33S1fHRoNxJnZwQdK6nD5BpTeTtJ3iBhyU7Vfz0ykekRf8k7zLDWm3Ci18EfbCD4Q82SxPibFV_aPsRT5ufYu4qq8jf4btnsTRLIHGvPEpLYF_Oof7EIO5wwTKW1tsdF_WrN8OGfnxtI-4xFD_HKHTnKwF7yUGOqa-iyhoqKPgfLsQEDS4nVKhluW8U1C6MyNZuXSW2mlzRv11MYB3RuCyqN1ms89n5DV0Y7B3u6Nd2UBCmLd_iIsm4_O6rKI541HKQSP4mmLKC8utLpU5ox&udm=2&prmd=ivnsmbtz&sa=X&ved=2ahUKEwiIs4LnprmGAxVyEVkFHdqTCXcQtKgLegQIDRAB&biw=1912&bih=924&dpr=1#vhid=ekDV1GVZC9rAFM&vssid=mosaic)
        password_entropy = math.log(possible_combinations, 2)

        # 3. how long it will take in seconds to crack (https://www.password-depot.de/en/know-how/brute-force-attacks.htm)
        time_to_crack = possible_combinations / 2000000000

        # 4. moores law for how many years before it can be cracked in under an hour (https://www.scientificamerican.com/article/the-mathematics-of-hacking-passwords/)
        moores = 2 * math.log(time_to_crack, 2)

    return possible_combinations, password_entropy, convert(time_to_crack), moores

def password_generator():
    # method 1: random length pin or specified, random number of nums, lower, upper, special, add option of hashing or not
    print("Would you like to\n 1. Specify a length between 8-16\n or \n 2. Use a random length between 8-16")
    choice = int(input("Enter your choice: "))
    if choice == 1:
        password_length = int(input("Enter the length between 8-16 digits: "))
        if password_length > 16 or password_length < 8:
            print("Invalid length, please try again")
            exit()

    elif choice == 2:
        password_length = random.randint(8,16)
        print(password_length)

    # Define character sets
    lowercase_chars = string.ascii_lowercase
    uppercase_chars = string.ascii_uppercase
    digits = string.digits
    special_chars = string.punctuation

    # Ensure each type is represented at least once
    random_string = [
        random.choice(lowercase_chars),
        random.choice(uppercase_chars),
        random.choice(digits),
        random.choice(special_chars)
    ]

    # Fill the remaining length with random choices from all character sets
    all_chars = lowercase_chars + uppercase_chars + digits + special_chars
    random_string += random.choices(all_chars, k=password_length - 4)
    random.shuffle(random_string)
    return ''.join(random_string)

def is_compromised(passwd):
    #https://sanatinia.medium.com/securely-check-if-a-password-is-compromised-in-python-be74bf52b0cc
    sha1 = hashlib.sha1()
    sha1.update(passwd.encode())
    hex_digest = sha1.hexdigest().upper()

    hex_digest_f5 = hex_digest[:5]
    hex_digest_remaining = hex_digest[5:]

    r = requests.get("https://api.pwnedpasswords.com/range/{}".format(hex_digest_f5))

    leaked_passwd_freq = defaultdict(int)

    for passwd_freq in r.content.splitlines():
        pass_parts = passwd_freq.split(b":")
        passwd = pass_parts[0].decode()
        freq = pass_parts[1]
        leaked_passwd_freq[passwd] = int(freq)

    if hex_digest_remaining in leaked_passwd_freq:
        return leaked_passwd_freq[hex_digest_remaining]

    return 0

def recommendations(passwd):
    #https://dev.to/otumianempire/custom-password-validation-in-python-function-for-password-validation-376a

    #1. Check if it's common or not
    common_check = commonly_used(passwd)
    if common_check == True:
        print("Your password is Commonly used, this means it has already been or has a high likelihood of being compromised from leaks or password. Moving on to the next diagnostic ")

    else:
        print("Your password is not commonly used, moving on to the next diagnostic")

    #2. Check length(between 8 and 16 chars preferrably)
    passwd_length = len(passwd)
    if passwd_length < 8:
        print("your password is too short and may not meet requirements and/or can be guessed easier")

    elif passwd_length > 16:
        print("your password may be too long and may not meet requirements and guidelines and/or could be forgotten easier")

    else:
        print("your password is a good length, moving on to the next diagnostic")

    #3. Must have a number
    has_numbers = any(c.isdigit() for c in passwd)
    if has_numbers == False:
        print("your password should have at least one number")

    else:
        print("your password has at least one number which is good, moving on to next diagnostic")

    #4. Must have a lower case character
    has_lowercase = any(c.islower() for c in passwd)
    if has_lowercase == False:
        print("your password should have at least one lower case letter")

    else:
        print("your password has at least one lower case letter which is good, moving on to next diagnostic")

    #5. Must have an uppercase letter
    has_uppercase = any(c.isupper() for c in passwd)
    if has_uppercase == False:
        print("your password should have at least one upper case letter")

    else:
        print("your password has at least one upper case letter which is good, moving on to next diagnostic")

    #6. Must have a special character
    has_special_chars = any(not c.isalnum() for c in passwd)
    if has_special_chars == False:
        print("your password should have at least one special character")

    else:
        print("your password has at least one special which is good, moving on to next diagnostic")

    #7. No spaces
    has_space = ' ' in passwd
    if has_space == True:
        print("your password has a space(s) in it, which is not allowed")

    else:
        print("your password has no spaces in it, which is good. Concluding diagnostic, thank you!")

def main():
    password = input("Enter your password: ")

    #testing commonly used
    common_checker = commonly_used(password)
    if common_checker == True:
        print("your password is commonly used")

    else:
        print("your password is not commonly used")

    #testing how_many_guesses
    num_coms, entropy, TTC, moore = how_many_guesses(password)
    print("number of combinations is {}".format(num_coms))
    print("password entropy is {}".format(entropy))
    print("time to crack is {}".format(TTC))
    print("number of years before cracked in an under an hour is {}".format(moore))

    #testing password generator
    generated_password = password_generator()
    print(generated_password)

    #test if compromised
    compromise_checker = is_compromised(password)
    if compromise_checker > 0:
        print("your password has been compromised {} times".format(compromise_checker))

    else:
        print("no data breaches detected")

    #test recommendations
    recommendations(password)

if __name__ == "__main__":
    main()