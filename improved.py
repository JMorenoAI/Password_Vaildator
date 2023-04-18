#!/usr/bin/env python3

"""
My Python Password Validator
"""

# imports go here.
import inspect

# the following are module level dunders (metadata) for the authorship information.
__author__ = 'Joshua Moreno'
__version__ = '1.0'
__date__ = '2023.04.06'
__status__ = 'Development'


class PasswordValidator:
    __UPPERCASE_MIN = 2
    __LOWERCASE_MIN = 2
    __DIGITAL_MIN = 2
    __SYMBOL_MIN = 2

    def __init__(self, password=None, debug_mode=False):
        self.__password = password
        self.__debug_mode = debug_mode

    def __str__(self):
        if self.__password is None:
            return "None"
        else:
            return self.__password

    def is_uppercase_valid(self):
        count = sum(1 for char in self.__password if char.isupper())

        if self.__debug_mode:
            print(f"{count:3d} = {inspect.currentframe().f_code.co_name}")

        if count >= PasswordValidator.__UPPERCASE_MIN:
            return True
        else:
            print(f"Password must have at least {PasswordValidator.__UPPERCASE_MIN} uppercase letters.")
            return False

    def is_lowercase_valid(self):
        count = sum(1 for char in self.__password if char.islower())

        if self.__debug_mode:
            print(f"{count:3d} = {inspect.currentframe().f_code.co_name}")

        if count >= PasswordValidator.__LOWERCASE_MIN:
            return True
        else:
            print(f"Password must have at least {PasswordValidator.__LOWERCASE_MIN} lowercase letters.")
            return False

    def is_valid(self, password=None):

        if password is None:
            raise Exception("Password can't be empty")

        self.__password = password

        if self.__debug_mode:
            print("===============DEBUG MODE===============")
            print(f"password = {self}")

        uppercase_valid = self.is_uppercase_valid()
        lowercase_valid = self.is_lowercase_valid()

        if uppercase_valid and lowercase_valid:
            return True
        else:
            return False


pv = PasswordValidator(debug_mode=True)
if pv.is_valid("A1c!*"):
    print("password valid")
else:
    print("password invalid")
