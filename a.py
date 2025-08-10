def calc(*numbers):
    if not numbers:
        return 1

    result = 1
    for num in numbers:
        result *= num  

    return result

product1 = calc(1, 2, 3)
print(product1)  

product2 = calc(4, 5)
print(product2)  