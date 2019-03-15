from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
import datetime
from Database_Setup import *

engine = create_engine('sqlite:///institutions.db')
# Bind the engine to the metadata of the Base class so that the
# declaratives can be accessed through a DBSession instance
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
# A DBSession() instance establishes all conversations with the database
# and represents a "staging zone" for all the objects loaded into the
# database session object. Any change made against the objects in the
# session won't be persisted into the database until you call
# session.commit(). If you're not happy about the changes, you can
# revert all of them back to the last commit by calling
# session.rollback()
session = DBSession()

# Delete InstitutionName if exisitng.
session.query(InstitutionName).delete()
# Delete CourseName if exisitng.
session.query(CourseName).delete()
# Delete User if exisitng.
session.query(User).delete()

# Create sample users data
User1 = User(
    name="Bachala Venkata Gayathri",
    email="bachala.gayathri2000@gmail.com",
    picture='http://www.enchanting-costarica.com/wp-content/'
    'uploads/2018/02/jcarvaja17-min.jpg')
session.add(User1)
session.commit()
print ("Successfully Add First User")
# Create sample institution companys
Institution1 = InstitutionName(name="Jigsaw Academy",
                               user_id=1)
session.add(Institution1)
session.commit()

Institution2 = InstitutionName(name="UpX Academy",
                               user_id=1)
session.add(Institution2)
session.commit()

Institution3 = InstitutionName(name=" Sri sai software Centers",
                               user_id=1)
session.add(Institution3)
session.commit()

Institution4 = InstitutionName(name="Web Trainings Academy Digital Marketing ",
                               user_id=1)
session.add(Institution4)
session.commit()

# Populare a institutions with models for testing
# Using different users for institutions names year also
Course1 = CourseName(name="JAVA",
                     duration="3MONTHS",
                     address="vijayawada",
                     fee="20000",
                     feedback="EXCE;LLENT",
                     date=datetime.datetime.now(),
                     institutionnameid=1,
                     user_id=1)
session.add(Course1)
session.commit()

Course2 = CourseName(name="JAVA SCRIPT",
                     duration="8MONTHS",
                     address="ONGOLE",
                     fee="40000",
                     feedback="AVERAGE",
                     date=datetime.datetime.now(),
                     institutionnameid=2,
                     user_id=1)
session.add(Course2)
session.commit()

Course3 = CourseName(name="PYTHON",
                     duration="8MONTHS",
                     address="DELHI",
                     fee="350000",
                     feedback="EXCELLENT",
                     date=datetime.datetime.now(),
                     institutionnameid=3,
                     user_id=1)
session.add(Course3)
session.commit()

Course4 = CourseName(name="WEB TECHNOLOGIES",
                     duration="7MONTS",
                     address="HYDERABAD",
                     fee="25000",
                     feedback="good",
                     date=datetime.datetime.now(),
                     institutionnameid=4,
                     user_id=1)
session.add(Course4)
session.commit()


print("Your items database has been inserted!")
