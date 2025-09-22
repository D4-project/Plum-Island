# Proactive Land Uncovering & Monitoring 
<p align="center">
  <img alt="d4-Plum-Island" src="https://raw.githubusercontent.com/D4-project/Plum-Island/master/documentation/media/plum-overview.png" />
</p>

<center>
*Still in early developpement - Not suitable for production.*
</center>

## Description
This this tool is a orchestrator for performing surface exposure proactive discovery.
It provides jobs to agents and collect back scanning data. The final data may be stored
as-is or pushed back into the D4 ecosystem

## Technical requirements
Python 3  
Flask Appbuilder  

## Installation

To setup an environnement do;

```bash
git clone 
cd Plum-Island
./setup.sh
```
Then you could prefered web server or simply run for demo

```bash
source ./venv/bin/activate  
cd webapp  
python run.sh  
```