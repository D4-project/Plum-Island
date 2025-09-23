"""
.-..-. .--. .---.  .--. .-.
: `' :: ,. :: .  :: .--': :
: .. :: :: :: :: :: `;  : :    .--.
: :; :: :; :: :; :: :__ : :__ `._-.'
:_;:_;`.__.':___.'`.__.':___.'`.__.'

This is the module containing all the data models
"""

from datetime import datetime, timezone
from flask_appbuilder import Model
from sqlalchemy import Column, Integer, String
from sqlalchemy import DateTime, Boolean


class ApiKeys(Model):
    """
    Class for the key authorisation for BOTS
    """

    id = Column(Integer, primary_key=True)
    # It will Will stored as scrypt.
    # The 16 first byte for identify id will be keypt in clear
    # The last 64 are unkfnown and hashed in scrypt
    keyidx = Column(String(16), unique=True, nullable=False)
    key = Column(String(256), unique=True, nullable=False)
    description = Column(String(128), nullable=False)


class Bots(Model):
    """
    Classes for the scannings bots data
    """

    id = Column(Integer, primary_key=True)
    uid = Column(String(36), unique=True, nullable=False)  # Bot UUID Generate
    ip = Column(String(150), nullable=False)  # Last Bot IP
    country = Column(String(150), nullable=False)  # Last Bot Geoloc
    active = Column(Boolean, default=True)  # This bot is active
    running = Column(Boolean, default=False)  # This bot is currently Scanning
    last_seen = Column(
        DateTime, default=datetime.now(timezone.utc)
    )  # Last Bot connection
    device_model = Column(String(128), nullable=False)  # Python Version
    agent_version = Column(String(128), nullable=False)
    system_version = Column(String(128), nullable=False)


class Targets(Model):
    """
    Class for networks and hosts targets definitions
    """

    id = Column(Integer, primary_key=True)
    value = Column(String(45), unique=True, nullable=False)  # The CIDR or HOST
    description = Column(String(256))  # A facultative descrition
    active = Column(Boolean, default=True)  # To suspend the target
    working = Column(Boolean, default=True)  # Set when jobs todo are presents
    last_scan = Column(
        DateTime, default=datetime.now(timezone.utc)
    )  # Last Scan of the Range.


class Jobs(Model):
    """
    Class for the Job to be run by bots.
    """

    id = Column(Integer, primary_key=True)
    job = Column(String(256))  # Targets Bundles
    bot_id = Column(Integer)  # Bot currently or lastly on the job
    active = Column(Boolean, default=False)  # Job is running
    finished = Column(Boolean, default=False)  # True if Job was successfull
    job_end = Column(
        DateTime, default=datetime.now(timezone.utc)
    )  # Last job termination.
    job_start = Column(
        DateTime, default=datetime.now(timezone.utc)
    )  # Last job Start time
