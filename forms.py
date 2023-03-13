from flask_wtf import FlaskForm, CSRFProtect
from wtforms import HiddenField, SelectField, RadioField, EmailField, StringField, PasswordField, SubmitField, BooleanField, SelectMultipleField
from wtforms.validators import DataRequired, Optional, Length, EqualTo, Email,  ValidationError
from wtforms.widgets import TextArea

csrf = CSRFProtect()

class AddPlay(FlaskForm):
    """form for adding play"""
    playbook_owner = StringField("Playbook Owner", validators=[DataRequired(), Length(max=15)])
    play_name = StringField("PlayName", validators=[DataRequired(), Length(max=15)])
    playbook_description = StringField("Description", widget=TextArea())
    severity = SelectField(
        "Severity",
        choices=[
            ("Info", "Info"),
            ("Low", "Low"),
            ("Medium", "Medium"),
            ("High", "High"),
            ("Critical", "Critical"),
            ])
    playbook_status = SelectField(
        "Playbook Status",
        choices=[
            ("Dev", "Dev"),
            ("Test", "Test"),
            ("Stage", "Stage"),
            ("Prod", "Prod")
            ])
    submit = SubmitField('Add')

class ArchivePlay(FlaskForm):
    """for sending plays to the archive"""
    button = SubmitField('Delete')

class UnArchivePlay(FlaskForm):
    """for removing from archive"""
    button = SubmitField('Unarchive')

class LoginForm(FlaskForm):
    """login form"""
    username = StringField('Username', validators=[DataRequired(message="Username required")])
    password = PasswordField('Password', validators=[DataRequired(message="Password required")])
    submit = SubmitField('Login')
    csrf_token = HiddenField(validators=[DataRequired()])

class AddAccount(FlaskForm):
    email = EmailField('Email', validators=[DataRequired(), Email()])
    username = StringField('Username', validators=[DataRequired(), Length(max=15)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=10)])
    submit = SubmitField('Login')

class UpdateAccount(FlaskForm):
    email = EmailField('Email', validators=[Optional(), Email()])
    password = PasswordField('Update Password', 
        validators=[Optional(), Length(min=10)])
    confirm_password = PasswordField('Confirm Password', 
        validators=[Optional(), EqualTo('password', message='Passwords must match'), Length(min=10)])
    submit = SubmitField('Update Account')
