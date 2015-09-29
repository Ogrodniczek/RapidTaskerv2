from flask_wtf import Form
from wtforms import TextField, TextAreaField
from wtforms.validators import DataRequired, Length

class NewTaskForm(Form):
    title = TextField('Enter task title',[DataRequired(), Length(min=5, max=255)])
    description = TextAreaField('Enter task description', [DataRequired(),Length(min=5, max=2000)])
