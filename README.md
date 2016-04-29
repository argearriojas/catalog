# P3: Item Catalog
## Introduction

This project implements a web application to manage information about restaurants and each corresponding menu.

Information is stored in a database, which defined in `database_setup.py`

Unauthenticated users can view the list of restaurants and menus.

Authentication is required to create a new restaurant and menu items.

Once authenticated, user is authorized to only edit/delete restaurants or menu items that belongs to him/her.

Authentication is achieved through 3rd party providers: Google and Facebook

## Requirements

- Flask
```
$ sudo pip install werkzeug==0.8.3
$ sudo pip install flask==0.9
$ sudo pip install Flask-Login==0.1.3
```

## Install

Clone git catalog repository
```
$ git clone https://github.com/argearriojas/catalog.git
```

## Setup

Open a shell and cd to "catalog" folder.

```
$ cd catalog
```

### Database setup

run this command to create the sqlite database file
```
$ python database_setup.py
```
a new file named `restaurantmenuwithusers.db` will be created, wich will be a database with three empty tables: user, restaurant and menu_item.

At this point the Web Application can be used to manage Restaurant and Menu Information.

### Test the Web Application

run this command to start the web server at port 5000 at localhost
```
$ python finalProyect.py
```

open your favorite web browser and point it to this url: `http://localhost:5000`

The web server can be stopped at anytime by pressing `CTRL + C` key combination

### Populating the database

In order to test the Application with some data, please execute this command
```
$ python lotsofmenus.py
```

Visit again `http://localhost:5000` to explore the App with some data

### Usage

A login button is provided at the top right corner of the layout. 

At login page just press one of the two buttons provided to gain access to create new elements in the application.

Navigate through the menus, create your own, edit and delete as you need.

