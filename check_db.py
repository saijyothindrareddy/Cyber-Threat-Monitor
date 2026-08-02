from app import app, db

with app.app_context():

    print("Tables in database:")

    for table in db.metadata.tables:
        print("-", table)