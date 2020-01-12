from .. import app, scheduler
from ..db import execute_sql
from ..lib import petfinder
from ..views import gmail


def process_adopted():
    app.logger.info('starting scheduled adopted-cron')
    # get adoptable cats
    adoptable_sql = ("          SELECT sponsorship_emails.sponsorship_id,"
                     "                 sponsorships.petfinder_id,"
                     "                 sponsorships.cat_name,"
                     "                 sponsorships.cat_self_link,"
                     "                 sponsorships.cat_img,"
                     "                 sponsorship_emails.contact_email"
                     "            FROM sponsorship_emails"
                     " LEFT OUTER JOIN sponsorships"
                     "              ON sponsorships.id=sponsorship_id"
                     "           WHERE adoption_status != 'adopted';")
    results = execute_sql({'sql': adoptable_sql, 'fetchall': True})
    for result in results:
        sponsorship_id, cat_id, cat_name, cat_url, cat_img, email = result

        # check to see if the cats were adopted in the last day
        link = app.settings['BASE_PETFINDER_URL'] / str(cat_id)
        cat = petfinder.make_petfinder_request(link)
        if cat['animal']['status'] == 'adopted':
            app.logger.info('updating cat id:%s to adopted', cat_id)
            execute_sql({'sql': "UPDATE sponsorship_emails "
                                "   SET adoption_status='adopted',"
                                "       modified_at=now() at time zone 'utc'"
                                " WHERE sponsorship_id=%s",
                         'values': [sponsorship_id]})
            app.logger.info('sending email to:%s for adopted cat '
                            'sponsor_id:%s name:%s',
                            email,
                            sponsorship_id,
                            cat_name)
            # inform contact_email of adoption
            gmail.send_email(email,
                             'adopted-email',
                             f"{cat_name} is going home! 🎉🥳🙌🎊",
                             cat_url=cat_url,
                             cat_photo_url=cat_img,
                             cat_name=cat_name)
        else:
            app.logger.info('not adopted, skipping id:%s', cat_id)
            continue
    app.logger.info('finished running adopted-cron')
    scheduler.print_jobs()

