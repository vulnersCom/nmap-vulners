# nmap_vulners

[![Current Release](https://img.shields.io/github/release/vulnersCom/nmap-vulners.svg "Current Release")](https://github.com/vulnersCom/nmap-vulners/releases/latest)
[![Downloads](https://img.shields.io/github/downloads/vulnersCom/nmap-vulners/total.svg "Downloads")](https://github.com/vulnersCom/nmap-vulners/releases) [![PayPal](https://img.shields.io/badge/donate-PayPal-green.svg)](https://paypal.me/videns)

## Description

NSE script using some well-known service to provide info on vulnerabilities

![Result example](example.png)

## Dependencies:
     nmap libraries:
         http
         json
         string

The only thing you should always keep in mind is that the script depends on having software versions at hand, so it only works with -sV flag.

## Installation
     locate, where your nmap scripts are located in your system
         for *nix system it might be  ~/.nmap/scripts/ or $NMAPDIR
         for Mac it might be /usr/local/Cellar/nmap/<version>/share/nmap/scripts/
         for Windows you have to find it yourself
     copy the provided script (vulners.nse) into that directory

## Usage
    Use it as straightforward as you can:
        nmap -sV --script vulners <target>
        
It is KISS after all.
