from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0002_onetimepassword_target_email_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='onetimepassword',
            name='target_role',
            field=models.CharField(choices=[('viewer', 'Viewer'), ('admin', 'Admin')], default='viewer', max_length=20),
        ),
    ]
