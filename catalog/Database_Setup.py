import sys
import os
from sqlalchemy import Column, ForeignKey, Integer, String, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, backref
from sqlalchemy import create_engine
Base = declarative_base()


class User(Base):
    __tablename__ = 'user'
    id = Column(Integer, primary_key=True) 
    name = Column(String(200), nullable=False)
    email = Column(String(200), nullable=False)
    picture = Column(String(300))


class InstitutionName(Base):
    __tablename__ = 'institutionname'
    id = Column(Integer, primary_key=True)
    name = Column(String(250), nullable=False)
    user_id = Column(Integer, ForeignKey('user.id'))
    user = relationship(User, backref="institutionname")

    @property
    def serialize(self):
        """Return objects data in easily serializeable formats"""
        return {
            'name': self.name,
            'id': self.id
        }


class CourseName(Base):
    __tablename__ = 'coursename'
    id = Column(Integer, primary_key=True)
    name= Column(String(370), nullable=False)
    duration= Column(String(160))
    address = Column(String(24))
    fee= Column(String(270))
    feedback=Column(String(270))
    date = Column(DateTime, nullable=False)
    institutionnameid = Column(Integer, ForeignKey('institutionname.id'))
    institutionname = relationship(
        InstitutionName, backref=backref('coursename', cascade='all, delete'))
    user_id = Column(Integer, ForeignKey('user.id'))
    user = relationship(User, backref="coursename")

    @property
    def serialize(self):
        """Return objects data in easily serializeable formats"""
        return {
            
            'name': self. name,
            'duration': self. duration,
            'address': self. address,
            'fee': self. fee,
            'feedback': self. feedback,
            'date': self. date,
            'id': self. id
        }

engin = create_engine('sqlite:///institutions.db')
Base.metadata.create_all(engin)
