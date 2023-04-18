import PasswordValidator as PV
import AdvancedPasswordValidator as APV

__author__ = 'Joshua Moreno'
__version__ = '1.0'
__date__ = '2023.04.06'
__status__ = 'Development'


def display_errors(pw):
    """
    Prints error messages for an invalid password.

    :param pw: A PasswordValidator or AdvancedPasswordValidator object.
    """
    print("password invalid")
    for e in pw.errors:
        print(f"{e.log['password']} Password must contain {e.log['min_required']} {e.log['error_type']} "
              f"but yours only contained {e.log['char_count']}")


def default_validation():
    """
    Demonstrates the use of the PasswordValidator module by validating three passwords.
    """
    pw = PV.PasswordValidator(debug_mode=False)
    if pw.is_valid("AAbb12!*"):
        print("password valid")
    else:
        display_errors(pw)

    print()

    if pw.is_valid("AAAbbb123!*"):
        print("password valid")
    else:
        display_errors(pw)

    print()

    if pw.is_valid("CCCdd1!"):
        print("password valid")
    else:
        display_errors(pw)

    print()


def advanced_validator():
    """
    Demonstrates the use of the AdvancedPasswordValidator module by validating three passwords.
    """
    apv = APV.AdvancedPasswordValidator(debug_mode=False)
    if apv.is_valid("AAbb12!*^%&"):
        print("password valid")
    else:
        display_errors(apv)

    print()

    if apv.is_valid("ACbd%&"):
        print("password valid")
    else:
        display_errors(apv)

    print()

    if apv.is_valid("AAAccc34!*"):
        print("password valid")
    else:
        display_errors(apv)

    print()


if __name__ == '__main__':
    default_validation()
    advanced_validator()
