import random, sys; 


lines = open(sys.argv[1]).readlines()
random.shuffle(lines)

for entry in lines:
    print(entry, end = '')

