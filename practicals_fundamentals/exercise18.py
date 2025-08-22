# Calculating with List

numbers = []  # Initialize an empty list to store the numbers

for i in range(5):
    num = int(input(f"Enter number {i+1}: "))
    i += 1
    numbers.append(num)

# Calculate the sum of the numbers
total_sum = sum(numbers)

 # Calculate the average of the numbers

average = total_sum / len(numbers)

    # Print the sum and average
print(f"Sum of the 5 numbers: {total_sum}")
print(f"Average of the 5 numbers: {average}")




