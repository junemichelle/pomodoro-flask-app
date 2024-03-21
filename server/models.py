from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import validates
from sqlalchemy import Time, DateTime
from datetime import date

db = SQLAlchemy()

class User(db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)


class Report(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String, nullable=False)
    category = db.Column(db.String, nullable=False)
    description = db.Column(db.String, nullable=False)
    date = db.Column(db.Date, nullable=False)
    hours = db.Column(db.String)
    minutes = db.Column(db.String)
    seconds = db.Column(db.String)
    completed= db.Column(db.Boolean(), nullable=True) # True if task completed
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String, nullable=False)
    category = db.Column(db.String, nullable=False)
    description = db.Column(db.String, nullable=False)
    date = db.Column(db.Date, nullable=True)
    hours = db.Column(db.String)
    minutes = db.Column(db.String)
    seconds = db.Column(db.String)
    completed= db.Column(db.Boolean(), default=False) # True if task completed
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    @staticmethod
    def create_report_entry(task):
        report_entry = Report(
            task=task.title,
            category=task.category,
            project=task.description,
            date=task.date,
            hours=task.hours,
            minutes=task.minutes,
            seconds=task.seconds,
            completed=task.completed,
            user_id=task.user_id,
        )
        db.session.add(report_entry)
        db.session.commit()
        
    @validates('status')
    def validate_status(self, key, value):
        if value not in ['ongoing', 'completed']:
            raise ValueError("Status must be either 'ongoing' or 'completed'.")
        return value
