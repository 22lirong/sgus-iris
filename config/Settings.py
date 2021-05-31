import os
class Settings:
    secretKey="a12nc)238OmPq#cxOlm*a"

    #Dev
    # host='localhost'
    # database='iris'
    # user='root'
    # password='Rong22'

    #Production
    host=os.environ['HOST']
    database=os.environ['DATABASE']
    user=os.environ['USERNAME']
    password=os.environ['PASSWORD']