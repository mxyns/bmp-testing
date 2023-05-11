import unittest


def print_test_header(test: unittest.TestCase):
    print("=====", test._testMethodName, "=====")
