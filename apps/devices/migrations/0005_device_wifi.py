from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('devices', '0004_alter_device_color'),
    ]

    operations = [
        migrations.AddField(
            model_name='device',
            name='wifi',
            field=models.BooleanField(default=False),
        ),
    ]
