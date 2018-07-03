import random,time,threading,sys
from pymongo import MongoClient

client = MongoClient('mongodb://admin:admin@35.187.13.95:27017/EpServer')


def min_product(product):
    min_value = sys.maxsize
    min_key = ''
    for key,value in product.items():
        if(value < min_value):
            min_value = value
            min_key = key
    return (min_key,min_value)

pulse = 10
# Get the sampleDB database
db = client['EpServer']
collection = db.price
def update_values():
    product1 = {}
    product2 = {}
    product3 = {}
    product4 = {}
    i=0
    for document in collection.find({}):
        _id = document['_id']
        data = {}
        data['product1'] = random.randint(8000,10000)
        data['product2'] = random.randint(7000,9000)
        data['product3'] = random.randint(11000,13000)
        data['product4'] = random.randint(11000,13000)
        product1.update({document['name'] : data['product1']})
        product2.update({document['name'] : data['product2']})
        product3.update({document['name'] : data['product3']})
        product4.update({document['name'] : data['product4']})
        i += 1
        collection.update({'_id':_id},{'$set':data})
    print('UPDATED VALUES PRODUCT1: ' + str(product1))
    product,price = min_product(product1)
    print('Minimum price of product1 is {0} on {1}'.format(price,product))
    print('UPDATED VALUES PRODUCT2: ' + str(product2))
    product, price = min_product(product2)
    print('Minimum price of product2 is {0} on {1}'.format(price,product))
    print('UPDATED VALUES PRODUCT3: ' + str(product3))
    product, price = min_product(product3)
    print('Minimum price of product3 is {0} on {1}'.format(price,product))
    print('UPDATED VALUES PRODUCT4: ' + str(product4))
    product, price = min_product(product4)
    print('Minimum price of product4 is {0} on {1}'.format(price,product))
    threading.Timer(10,update_values).start()

update_values()
