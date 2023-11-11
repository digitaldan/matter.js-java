
# Java / GraalVM Engine For [Matter.JS](https://github.com/project-chip/matter.js)

This project implements the native runtime dependencies in Java needed to run a [matter.js](https://github.com/project-chip/matter.js) service, similar to the [matter-node.js](https://github.com/project-chip/matter.js/tree/main/packages/matter-node.js) implementation.  This includes

* Crypto
* Network
* Storage
* Time (background tasks)
* Utils (command line and signed/unsigned byte operations)
 
##  Objectives

To Provide a working service which acts as:

* A Matter Controller: to pair and control matter devices (lights, thermostats, etc...)
* A Matter Server: to expose local objects as matter devices (for Alexa, Google Home, Apple Homekit, etc....)

Eventually this may become a openHAB addon for Matter.

## Running
For demonstration purposes, this project implements the [matter.js example shell application](https://github.com/project-chip/matter.js/tree/main/packages/matter-node-shell.js) mostly unmodified except for the readline/console shim in Java.

The following command will compile all classes (TS and Java), webpack the JS files and run the shell application 

`npm install && npm run webpack-dev && mvn clean compile exec:java -Dexec.mainClass="com.matterjs.Main"`

Note: this probably won't work on windows yet due to lazy path programming on my part