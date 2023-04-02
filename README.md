# Micro KVP

A lightweight KVP implementation, you can attach to any persistent storage.

Works with MySql or MariaDB, so you can host on cPanel or as containerised app.

The application management is available entirely via simple REST APIs. There's no user-interface.

Postman collection is TBD.

## Basic Concept
Using the ADMIN_TOKEN, you can create an `App`. Each `App` will have a unique `APP_TOKEN`.
Using the `APP_TOKEN` you can create, update, delete `keys`. A key can hold any value.
Key names are unique per App.
You can perform `list`, `get`, `store`, `increment`, and `decrement` operations on keys.

## Use Cases
- TBD

## REST APIs
APIs are divided in two parts. One to manage `apps` and second to manage `keys` associated to any given app.

### Manage Apps
- TBD

### Manage Key-Value-Pairs (Keys)
- TBD

## Deployment Instructions
- Copy `.env.example` to `.env`, and replace all environment variables

### Deployment to cPanel
- TBD

### Deployment with Apache
- TBD

### Deployment using Docker
- TBD

### Deployment with Docker Compose
- TBD

Enjoy!