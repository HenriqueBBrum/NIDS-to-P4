from datetime import datetime


v = "CACO"
start = datetime.now()
if "$" in v:
    print(v)

end = datetime.now()
print('Duration: {}'.format(end - start))

v = v + "$"
start = datetime.now()

if "$" in v:
    print(v)

end = datetime.now()
print('Duration: {}'.format(end - start))


start = datetime.now()

if "$" in range(0, 100):
    print("fuck")
else:
    print("cacoooooooooo")

end = datetime.now()
print('Duration: {}'.format(end - start))