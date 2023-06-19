"""Make a Function to check whether a number entered by the user is Armstrong or not.
Your function should take a number ‘n’ as an argument and display the appropriate
message. (function with argument and return type)"""

def armstrong(num):
    n=int(num)
    sum=0
    for i in range(len(num)):
        r=n%10
        q=n//10
        sum=sum+pow(r,len(num))
        n=q
    return sum

num=input("Enter the number: ")
if int(num)==armstrong(num):
    print("Armstrong")
else:
    print("Not Armstrong")