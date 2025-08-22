Ex 18: 

def calculate_sum_and_average():
    numbers = []  # Initialize an empty list to store the numbers

    print("Please enter five numbers:")

    # Loop to get five numbers from the user
    for i in range(5):
        while True:  # Loop to ensure valid integer input
            try:
                num = int(input(f"Enter number {i + 1}: "))
                numbers.append(num)
                break  # Exit the inner loop if input is valid
            except ValueError:
                print("Invalid input. Please enter an integer.")

    # Calculate the sum of the numbers
    total_sum = sum(numbers)

    # Calculate the average of the numbers
    # Use float() to ensure floating-point division for accurate average
    average = total_sum / len(numbers)

    # Print the sum and average
    print(f"\nSum of the numbers: {total_sum}")
    print(f"Average of the numbers: {average}")

# Call the function to execute the program
calculate_sum_and_average()



