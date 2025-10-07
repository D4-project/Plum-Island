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
from flask import Markup as Esc
from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey, Table
from sqlalchemy import func
from sqlalchemy.orm import relationship


class ApiKeys(Model):
    """
    Class for the key authorisation for BOTS
    """

    __tablename__ = "apikeys"
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

    __tablename__ = "bots"
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


# Job to Target pivot table
assoc_jobs_targets = Table(
    "jobs_targets_assoc",
    Model.metadata,
    Column("job_id", Integer, ForeignKey("jobs.id")),
    Column("target_id", Integer, ForeignKey("targets.id")),
)


# ScanProfiles to Ports pivot table
assoc_scanprofiles_ports = Table(
    "scanprofiles_ports_assoc",
    Model.metadata,
    Column("scanprofile_id", Integer, ForeignKey("ScanProfiles.id")),
    Column("port_id", Integer, ForeignKey("Ports.id")),
)


# ScanProfiles to Nses scripts pivot table
assoc_scanprofiles_nses = Table(
    "scanprofiles_nses_assoc",
    Model.metadata,
    Column("scanprofile_id", Integer, ForeignKey("ScanProfiles.id")),
    Column("nses_id", Integer, ForeignKey("Nses.id")),
)

# ScanProfiles to Targets pivot table
assoc_scanprofiles_targets = Table(
    "scanprofiles_targets_assoc",
    Model.metadata,
    Column("scanprofile_id", Integer, ForeignKey("ScanProfiles.id")),
    Column("target_id", Integer, ForeignKey("targets.id")),
)


class Jobs(Model):
    """
    Class for the Job to be run by bots.

    A Job has one or many Targets.
    """

    __tablename__ = "jobs"
    id = Column(Integer, primary_key=True)
    uid = Column(String(36), unique=True, nullable=False)  # Bot UUID Generate
    job = Column(String, nullable=False)  # Target Bundles (list of str)
    bot_id = Column(Integer)  # Bot currently or lastly on the job
    active = Column(Boolean, default=False)  # Job is running
    finished = Column(Boolean, default=False)  # True if Job was successfull
    exported = Column(Boolean, default=False)  # True if result was exported
    job_end = Column(DateTime, default=None)  # Last job termination.
    job_start = Column(DateTime, default=None)  # Last job Start time
    job_creation = Column(DateTime, default=func.now())  # Timestamp of job creation
    targets = relationship(
        "Targets", secondary=assoc_jobs_targets, back_populates="jobs"
    )

    def __repr__(self):
        return self.job

    def job_html(self):
        """
        Display Range as HTML Tags
        """
        tags = []
        # Render nice html pills
        html = ""
        # Get all tag name for attached groups
        if self.job:
            for tag in self.job.split(","):
                if tag.endswith("/32"):
                    tag = tag[0:-3]
                if tag.endswith("/128"):
                    tag = tag[0:-4]
                tags.append(tag)
        for tag in tags:
            html += f'<span class="label label-default">{tag}</span> '
        return Esc(html)

    def targets_html(self):
        """
        Display Targets as HTML Tags
        """
        tags = []
        # Render nice html pills
        html = ""
        # Get all tag name for attached groups
        if self.targets:
            for tag in self.targets:
                tags.append(tag)
        for tag in tags:
            html += f'<span class="label label-default">{tag}</span> '
        return Esc(html)

    def duration_html(self):
        if self.job_start and self.job_end:
            diff = self.job_end - self.job_start
            seconds = diff.total_seconds()
            minutes, seconds = divmod(seconds, 60)

            if minutes == 0:
                return f"{int(seconds)}s"
            else:
                return f"{int(minutes):02d}:{int(seconds):02d}"
        else:
            return "oo"


class Protos(Model):
    """
    Class for the Protocols
        IE : UDP/TCP
    """

    __tablename__ = "Protos"
    id = Column(Integer, primary_key=True)
    value = Column(String(32), unique=True, nullable=False)  # Udp / Tcp
    name = Column(String(256), nullable=False)  # Description of the Layer 4 protocol

    def __repr__(self):
        return self.value


class Ports(Model):
    """
    Class for the Ports
    Ports have exactly one mandatory record of Protos
    """

    __tablename__ = "Ports"
    id = Column(Integer, primary_key=True)
    value = Column(Integer, nullable=False)  # Port to Scan
    name = Column(String(256), nullable=False)  # Description of the port
    proto_id = Column(Integer, ForeignKey("Protos.id"), nullable=False)
    proto = relationship("Protos", backref="ports")
    proto_to_port = Column(
        String(32 + 5), nullable=False, unique=True
    )  # (str(port.value):str(proto.id)), empeche les doubles tuple port/proto

    def __repr__(self):
        return f"{self.proto}:{self.value}"


class Nses(Model):
    """
    Class for the nsescript
    """

    __tablename__ = "Nses"
    id = Column(Integer, primary_key=True)
    name = Column(String(256), unique=True, nullable=False)  # Name of the NSE Script
    hash = Column(String(64), unique=True, nullable=False)  # SHA256 of the NSE Body
    body = Column(String, nullable=False)  # NSE Body

    def __repr__(self):
        return self.name


class ScanProfiles(Model):
    """
    A Scan profile define for a target range which are the
    Ports to scan
    Nse script to launch
    If the boolean "Default" is set..This profile will be applied to all ranges without assignations.

    A scan profile has;
    One or many Ports objects.
    Zero or many Nses script objects.
    zero or many Targets objects
    """

    __tablename__ = "ScanProfiles"
    id = Column(Integer, primary_key=True)
    name = Column(String(256), nullable=False)  # Name of the profile.
    apply_to_all = Column(Boolean, default=False)  # Name of the profile.
    ports = relationship(
        "Ports",
        secondary=assoc_scanprofiles_ports,
        backref="scanprofiles",
    )
    nses = relationship(
        "Nses", secondary=assoc_scanprofiles_nses, backref="scanprofiles"
    )
    targets = relationship(
        "Targets", secondary=assoc_scanprofiles_targets, backref="scanprofiles"
    )

    def __repr__(self):
        return self.name


class Targets(Model):
    """
    Class for networks and hosts targets definitions

    A Targets has one or many Jobs.
    """

    __tablename__ = "targets"
    id = Column(Integer, primary_key=True)
    value = Column(String(45), unique=True, nullable=False)  # The CIDR or HOST
    description = Column(String(256))  # A facultative descrition
    active = Column(Boolean, default=True)  # To suspend the target
    working = Column(Boolean, default=False)  # Set when jobs todo are presents
    last_scan = Column(DateTime, default=None)  # Last Scan of the Range.
    last_previous_scan = Column(
        DateTime, default=None
    )  # Previous Last Scan to have an idea of time for a cycle.
    jobs = relationship("Jobs", secondary=assoc_jobs_targets, back_populates="targets")

    def __repr__(self):
        return self.value

    def duration_html(self):
        if self.last_scan and self.last_previous_scan:
            diff = self.last_scan - self.last_previous_scan
            seconds = diff.total_seconds()
            minutes, seconds = divmod(seconds, 60)
            if minutes == 0:
                return f"{int(seconds)}s"
            else:
                return f"{int(minutes):02d}:{int(seconds):02d}"
        else:
            return "oo"
