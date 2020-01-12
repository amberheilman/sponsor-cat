from wtforms import Form, StringField, PasswordField, validators


class LoginForm(Form):
    email = StringField('Email Address', [validators.Length(min=6, max=35)])
    password = PasswordField('Password', [validators.DataRequired()])


class RecipientForm(Form):
    recipients = StringField('Recipients', [])


class SponsorForm(Form):
    cat_img = StringField('Cat Image', [validators.url(),
                                        validators.DataRequired()])
    cat_self_link = StringField('Cat Self Link', [validators.url(),
                                                  validators.DataRequired()])
    petfinder_id = StringField('Petfinder ID', [validators.DataRequired()])
    given_name = StringField('Given Name', [validators.DataRequired()])
    email = StringField('Email Address', [validators.Length(min=6, max=35)])
    sponsor_amount = StringField('Sponsor Amount',
                                 [validators.DataRequired(),
                                  validators.AnyOf(('95.00', '105.00'))])
    payment_type = StringField('Payment Type',
                               [validators.DataRequired(),
                                validators.AnyOf(('cash', 'check'))])

