# Ex 17: Complex String Formatting

name = input("Enter your name: ")
number = int(input("Enter your favourite number: "))

formatted_number = f"{number:02}"

print(f"Hello {name}, your favourite number is {formatted_number}")