import yaml
import base64
import argparse

class PostgresqlSecrets:

    def __init__(self):
        pass

    def set_secrets(self, file_name,
                    pg_username,
                    pg_password,
                    pg_host,
                    pg_database):
        print("secret_file: " + file_name)
        with open(file_name) as f:
            doc = yaml.safe_load(f)
        doc['data']['username'] = base64.b64encode(pg_username.encode('utf-8')).decode('utf-8')
        doc['data']['password'] = base64.b64encode(pg_password.encode('utf-8')).decode('utf-8')
        doc['data']['host'] = base64.b64encode(pg_host.encode('utf-8')).decode('utf-8')
        doc['data']['database'] = base64.b64encode(pg_database.encode('utf-8')).decode('utf-8')

        with open(file_name, 'w') as f:
            yaml.safe_dump(doc, f, default_flow_style=False)
        return

'''
The secrets from azure DevOps need to be passed in as positional arguments,
so the real values should be defined as a variable groups there and this
set_secrets function takes them and maps them to the specific YAML  doc[data][*.] attributes objects
'''

parser = argparse.ArgumentParser()
parser.add_argument('--PG_USERNAME', '-pg-username', help="Pass the username as an argument", type= str)
parser.add_argument('--PG_PASSWORD', '-pg-password', help="Pass the password as an argument", type= str)
parser.add_argument('--PG_HOST', '-pg-host', help="Pass the database server name as an argument", type= str)
parser.add_argument('--PG_DATABASE', '-pg-database', help="Pass the database name as an argument", type= str)
secrets = parser.parse_args()

kdb = PostgresqlSecrets()

# print("It is the username", secrets.PG_USERNAME)
# print("it's the passwd", secrets.PG_PASSWORD)
# print("it's the host", secrets.PG_HOST)
# print("it's the DATABASE", secrets.PG_DATABASE)

kdb.set_secrets("./kong_pg_secrets.yaml",
            pg_username=secrets.PG_USERNAME,
            pg_password=secrets.PG_PASSWORD,
            pg_host=secrets.PG_HOST,
            pg_database=secrets.PG_DATABASE)

"""
python set_pg_secrets.py -pg-username bgarcial@k8s-postgresql1  -pg-password my-r34l-p455w0rd -pg-host k8s-postgresql1.postgres.database.azure.com -pg-database tst-db
"""
