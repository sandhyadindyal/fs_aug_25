num_person = int(input("Enter the number of person: "))

phonebook = {input("Enter the person's name: "): input("Enter the phone number: ") for _ in range(num_person)}

print(phonebook)

# Print out the phone number of one of the people in the dictionary
print(f"The phone number of Sam is: ", phonebook["Sam"])

# Change the phone number of one of the people in the dictionary
phonebook["Sam"] = 6861031

# Print out all the keys and values in the dictionary using a loop, separated by a colon
print("Names and Phone numbers in the phone book:")
for key, value in phonebook.items():
    print(f"{key}: {value}")
