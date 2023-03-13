# Playbook-Store
### DO NOT USE IN PRODUCTION 
### DISCLAIMER:
This app was built for learning purposes. It pulls down the MITRE ATT&CK data from github, puts the specific fields into form fields, and stores in a postgresql database. 

This requires an env file with the following content. The values can be changed to anythig you like.
```
POSTGRES_DB=playbook
POSTGRES_USER=user
POSTGRES_PASSWORD=password
POSTGRES_URL=postgres
SECRET_KEY=secret
APP_USER=user
APP_PASSWORD=password
USER_ROLE=admin
SECURITY_PASSWORD_SALT=salty
```

requires docker and docker-compose to be installed

create the certs and start the containers

```
chmod +x startup.sh
./startup.sh
```

stop the container

```
docker-compose down
```
## General

The secbook provides a central location to store playbooks.

## Structure for Custom Files

```
secbook
├── README.md
├── extract_mitre.py
├── forms.py
├── mitre_map.py
├── models.py
├── playbook.py
├── requirements.txt
├── static
│   ├── css
│   │   ├── dropdown.css
│   │   └── main.css
│   ├── img
│   │   ├── 1662855888173.jpg
│   │   └── favicon.ico
│   └── js
│       └── dropdown.js
├── templates
│   ├── account.html
│   ├── add_play.html
│   ├── archive.html
│   ├── base.html
│   ├── index.html
│   ├── login.html
│   ├── map.html
│   ├── play.html
│   ├── status.html
│   ├── update.html
│   └── update_account.html
├── views.py
└── wsgi.py
```

.**/**

- The main directory contains most of the .py files that control the application

./**extract_mitre.py**

- uses the Python Requests module to GET mitre information to be used in the playbooks.
- When a play is created with a mitre technique, it GETS the information from the Mitre github page and stores it in an SQLite database

./**forms.py**

- contains all of the form details.

./**mitre_map.py**

- uses the Python Requests module to build the playbook map, which shows how all of the plays map the Mitre framework
- It pulls in the information from the Mitre Github page and build the map when the map is nagivated to.

./**models.py**

- contains all of the database items

./**playbook.py**

- the main file that runs the application
- contains all of the application configuration settings
- Config items need to be moved to a config.py file

./**requirements.txt**

- Lists the required Python modules to be installed for new builds

./**static**/

- contains all of the CSS, images, and javascript files

./static/css/**dropdown.css**

- controls the dropdown buttons on the homepage

./static/css/**main.css**

- contains CSS for custom formatting

./static/**img**/

- contains the image that is used for the login page and favicon

./js/**dropdown.js**

- contains the javascript that controls the dropdown buttons on the homepage

./**templates**/

- contains the html files

./templates/**base.html**

- Base template that is used in all of the other .html files
- this contains the basic structure, css, and nav menu items
- changing this page will change every page

./**views.py**

- This contains the bulk of the app and is getting to a point where new items should be separated into a new view file
- contains all of the "routes" and functions for each page

