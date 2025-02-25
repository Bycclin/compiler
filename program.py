'''
Program that demonstrates usage of many Python built-in functions and statements.
'''

#import random Remove random to work on for later.
import sys

# Original examples
print(sys.path)
print("Hello world")
#print(random.random())
print(range(1, 10))
print(list(range(1, 10)))
print(zip([1, 2, 3], [4, 5, 6]))
print(3 / 4)
print(exec("print('Hello world')"))
print(len([1, 2, 3]))
print(list([1, 2, 3]))
print(map(lambda x: x + 1, [1, 2, 3]))
print(1 + 1)

# Additional built-in functions used as separate statements:

# Numeric and sequence operations
print(abs(-5))
print(all([True, True, False]))
print(any([False, False, True]))
print(bin(42))
print(bool(0))
print(divmod(8, 3))
print(float("3.14"))
print(format(123, "04d"))
print(pow(2, 3))
print(round(3.14159, 2))
print(sum([1, 2, 3]))
print(max([1, 2, 3]))
print(min([1, 2, 3]))

# Type and object information
print(callable(len))
print(chr(65))
print(dict(a=1, b=2))
print(type(123))
print(isinstance(3, int))
print(issubclass(bool, int))
print(id(42))
print(hash("hello"))
print(hex(255))
print(oct(64))
print(repr([1, 2, 3]))
print(vars())  # Displays the local symbol table

# Sequence and iterable helpers
print(list(enumerate([10, 20, 30])))
print(list(filter(lambda x: x > 0, [-1, 0, 1])))
print(list(iter([1, 2, 3])))
print(list(map(lambda x: x * 2, [1, 2, 3])))
print(next(iter([10, 20, 30])))
print(list(reversed([1, 2, 3])))
print(list(zip([1, 2, 3], [4, 5, 6])))

# Collection types
print(frozenset([1, 2, 3]))
print(set([1, 1, 2, 2, 3]))
print(sorted([3, 1, 2]))
print(tuple([1, 2, 3]))

# Object attributes and methods
print(dir([]))
print(getattr(str, "upper"))
print(hasattr("abc", "upper"))

# Working with files (open and read a few characters from this file)
with open(__file__, "r") as f:
    print(f.read(10))

# Using ord to get Unicode code point
print(ord("A"))

# Using reversed on a list (converted to list for printing)
print(list(reversed([1, 2, 3])))

# Using vars (shows local variables)
print(vars())

# Using exec to execute a statement
exec("print('Executed')")

# --- More Built-in Functions and Statements Added Below ---

# Input/Output function
# user_input = input("Enter something: ")  # Input will pause execution and wait for user input
# print(f"You entered: {user_input}")

# String and type conversion functions
print(str(123))
print(int("456"))
print(float(7))
print(complex(1, 2))
print(ascii('你好')) # ASCII representation

# Bytes and bytearray
print(bytes([65, 66, 67])) # Creates a bytes object
print(bytearray([68, 69, 70])) # Creates a mutable bytearray object

# More object introspection
print(globals() is globals()) # globals() returns the global namespace dictionary
print(locals() is locals())   # locals() returns the local namespace dictionary (here, it's global)
class MyClass:
    attribute = 10
    def method(self):
        pass
obj = MyClass()
print(getattr(obj, 'attribute'))
setattr(obj, 'attribute', 20) # Set attribute value
print(obj.attribute)
delattr(obj, 'attribute') # Delete attribute
# try:
#     print(obj.attribute) # This will raise AttributeError
# except AttributeError as e:
#     print(f"AttributeError caught: {e}")


# Compilation and evaluation
code_str = 'result = 10 * 2'
compiled_code = compile(code_str, '<string>', 'exec') # Compile string code to code object
namespace = {}
exec(compiled_code, namespace) # Execute compiled code in namespace
print(namespace['result'])

expression_str = '2 + 3'
evaluated_result = eval(expression_str) # Evaluate a string as a Python expression
print(evaluated_result)

# Help system (interactive, so demonstrating with print output of help object)
help_str = help(list)
# print(help_str) # help() itself is interactive in a REPL, printing help(list) will show help text in console

# Conditional statement (if/else)
x = 5
if x > 0:
    print("x is positive")
else:
    print("x is not positive")

# Loop statements (for and while)
print("For loop:")
for i in range(3):
    print(i)

print("While loop:")
count = 0
while count < 3:
    print(count)
    count += 1

# Function definition (def)
def greet(name):
    return f"Hello, {name}!"
print(greet("World"))

# Error handling (try/except)
try:
    result = 10 / 0
except ZeroDivisionError as e:
    print(f"Error: {e}")

# Assertion (assert)
assert 1 + 1 == 2, "Math is broken!"
# assert 1 + 1 == 3, "This assertion will fail and raise AssertionError" # Uncomment to see AssertionError

# Delete statement (del)
my_var = 50
print(my_var)
del my_var
# try:
#     print(my_var) # This will raise NameError
# except NameError as e:
#     print(f"NameError caught: {e}")

# Pass statement (placeholder)
def test(e):
    return e + 1

print(test(3))

print("Program finished.")