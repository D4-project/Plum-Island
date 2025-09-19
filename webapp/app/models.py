'''
.-..-. .--. .---.  .--. .-.         
: `' :: ,. :: .  :: .--': :         
: .. :: :: :: :: :: `;  : :    .--. 
: :; :: :; :: :; :: :__ : :__ `._-.'
:_;:_;`.__.':___.'`.__.':___.'`.__.'

This is the module containing all the data models
'''

from flask_appbuilder import Model
from sqlalchemy import Column, Integer, String
from sqlalchemy import DateTime, Boolean
from sqlalchemy import func


class ApiKeys(Model):
    '''
    Class for the key authorisation for BOTS
    '''
    id = Column(Integer, primary_key=True)
    # It will Will stored as SHA512(SALT+APIKEY)
    key =  Column(String(128), unique = True, nullable=False)
    bot = Column(Boolean, default=False)        # This Key may act as scanning bot
    automation = Column(Boolean, default=False) # This Key may feed ranges


class Bots(Model):
    '''
    Classes for the scannings bots data
    '''
    id = Column(Integer, primary_key=True)
    uid =  Column(String(150), unique = True, nullable=False) # Bot UUID Generate
    ip =  Column(String(150), unique = True, nullable=False) # Last Bot IP
    country =  Column(String(150), unique = True, nullable=False) # Last Bot Geoloc
    active = Column(Boolean, default=True) # This bot is active
    running = Column(Boolean, default=False) # This bot is currently Scanning
    last_seen = Column(DateTime, default=func.now()) # Last Bot connection


class Targets(Model):
    '''
    Class for networks and hosts targets definitions
    '''
    id = Column(Integer, primary_key=True)
    value =  Column(String(45), unique = True, nullable=False) # The CIDR or HOST
    description =  Column(String(256)) # A facultative descrition
    active = Column(Boolean, default=True) # To suspend the target


class Jobs(Model):
    '''
    Class for the Job to be run by bots.
    '''
    id = Column(Integer, primary_key=True)
    job = Column(String(256)) # Targets Bundles
    bot_id = Column(Integer)  # Bot currently or lastly on the job
    active = Column(Boolean, default=False) # Job is running
    last_seen=(Column(DateTime, default=func.now())) # Last job termination.
    job_start = Column(DateTime, default=func.now()) # Last job start time.
