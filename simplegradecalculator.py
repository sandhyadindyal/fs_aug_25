print('Welcome to the Simple Grade Calculator')
subject_num = int(input("How many subjects do you have?: "))
marks = 0
for i in range(subject_num):
    mark=int(input(f"Enter the marks for subject {i+1}: "))
    marks=marks+mark

averageMarks=marks/subject_num

print(f"Total score = {marks}")
print(f"Average score is: {averageMarks}")

if averageMarks >= 90:
    print("Grade: A")
elif averageMarks >= 80:
    print("Grade: B")
elif averageMarks >= 70:
    print("Grade: C")
elif averageMarks >= 60:
     print("Grade: D")
else:
    print("Grade: F")
    