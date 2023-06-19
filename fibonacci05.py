def fibonacci():
    num=int(input("Enter the number: "))
    a=0
    b=1
    for i in range(num):
        print(a,end=' ')
        c=a+b
        a=b
        b=c
fibonacci()