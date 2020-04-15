import yaml
import base64
import argparse

class KongCredentials:

    KONG_BASIC_AUTH_FILES = [
        "./Acceptance/CustomerKongConsumersAndCredentials.yaml",
        # "./Production/CustomerKongConsumersAndCredentials.yaml",
        # "./Testing/CustomerKongConsumersAndCredentials.yaml"
    ]

    # passwords = {}

    def __init__(self):
        pass

    def replacing_secrets_value(self, file_name, passwords):
        print("secret_file: " + file_name)
        # print("passwords: ", passwords)

        # Reading the YAML file
        with open(file_name) as f:
            # Convert the yaml file to python object
            docs = list(yaml.safe_load_all(f))
        # We are retrieving all KongCredentials/basic-auth resources that exist in the YAML file
        for doc in filter(lambda item: item['kind'] == "KongCredential" and item['type'] == "basic-auth", docs):
            print("Changing " + doc['config']['password'])
            # We are placing in the specific password atribute and set/replace
            # the password
            doc['config']['password'] = passwords[doc['config']['password']]

        # Writing the fake passwords to YAML file
        with open(file_name, 'w') as f:
            yaml.safe_dump_all(docs, f, default_flow_style=False)
        return

"""
Reading the secrets from azure devops. Its needs to be passed in as args
This function takes these and maps them to an object that can then be used
"""

# def get_secrets_args(self):
parser = argparse.ArgumentParser()
parser.add_argument('--RENAN_PASSWORD', '-renan', help='Renan user password', type=str)
parser.add_argument('--AYA_PASSWORD', '-aya', help='Aya user password', type=str)
# parser.add_argument('--ANNA_PASSWORD', '-anna', help='Anna user password', type=str)
# parser.add_argument('--MICHEL_PASSWORD', '-anna', help='Anna user password', type=str)
secrets = parser.parse_args()
passwords = {
    # When you make this, it means that the process
    # are going to search in the original file the
    # RENAN_PASSWORD and AYA_PASSWORD values which
    # will be replaced.
    'RENAN_PASSWORD': secrets.RENAN_PASSWORD,
    'AYA_PASSWORD': secrets.AYA_PASSWORD,
    # 'ANNA_PASSWORD': secrets.ANNA_PASSWORD,
    # 'MICHEL_PASSWORD': secrets.MICHEL_PASSWORD,
}
s = KongCredentials()
for file_path in s.KONG_BASIC_AUTH_FILES:
    s.replacing_secrets_value(file_path, passwords)

"""
python set_kong_credentials.py -renan x5rPncZGtNZH -aya qV5sl63U7tMP
"""